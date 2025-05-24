import pyotp
import time
from django.test import TestCase, Client
from django.conf import settings
from django.urls import reverse, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
from django.core.cache import cache
from django.contrib.auth import login
from django.http import HttpResponseRedirect

from mfa.models import User_Keys
from mfa.Common import set_next_recheck


User = get_user_model()


def create_session(request, username):
    """Create a test session for MFA authentication.

    This is used as MFA_LOGIN_CALLBACK in tests to simulate the login process.
    Mimics the example implementation from example.auth.create_session.
    """
    User = get_user_model()
    user = User.objects.get(username=username)
    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)
    # print(f"\n30 {__name__} - Test session created by tests.create_session()")
    return HttpResponseRedirect(reverse("mfa_home"))


class MFATestCase(TestCase):
    """Base test case for MFA tests.

    This class provides common functionality for all MFA test cases, including:
    - User creation and authentication
    - MFA key setup and management
    - Settings management and verification
    - URL handling for both namespaced and non-namespaced patterns
    - Session state verification
    - Common assertions for MFA functionality
    """

    # Define default settings that can be referenced by tests
    DEFAULT_MFA_SETTINGS = {
        "MFA_UNALLOWED_METHODS": (),
        "MFA_HIDE_DISABLE": (),
        "MFA_RENAME_METHODS": {},
        "TOKEN_ISSUER_NAME": "Django MFA",
        "MFA_ENFORCE_RECOVERY_METHOD": False,
        "MFA_ENFORCE_EMAIL_TOKEN": False,
        "MFA_RECHECK": False,
        "MFA_RECHECK_MIN": 0,
        "MFA_RECHECK_MAX": 0,
        "MFA_LOGIN_CALLBACK": None,
        "MFA_ALWAYS_GO_TO_LAST_METHOD": False,
        "MFA_SUCCESS_REGISTRATION_MSG": None,
        "MFA_REDIRECT_AFTER_REGISTRATION": "mfa_home",
        # Email settings
        "EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend",
        "MFA_EMAIL_SUBJECT": "Your verification code",
        "MFA_EMAIL_FROM": "security@example.com",
        # FIDO2 settings
        "FIDO_SERVER_ID": "example.com",
        "FIDO_SERVER_NAME": "Test Server",
        "FIDO_AUTHENTICATOR_ATTACHMENT": "cross-platform",
        "FIDO_USER_VERIFICATION": "preferred",
        "FIDO_AUTHENTICATION_TIMEOUT": 30000,
    }

    def setUp(self):
        """Set up test environment for MFA tests.

        Creates a test user, sets up TOTP, stores original MFA settings,
        and initializes the session with base_username.
        """
        super().setUp()
        self.username = "testuser"
        self.password = "testpass123"
        self.user = User.objects.create_user(
            username=self.username, password=self.password
        )
        self.client.login(username=self.username, password=self.password)
        cache.clear()

        # TOTP setup for testing
        self.totp_secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(self.totp_secret)

        # Store all MFA settings for cleanup
        self.original_settings = {
            key: getattr(settings, key, default)
            for key, default in self.DEFAULT_MFA_SETTINGS.items()
        }

        # Set base_username in session for all tests
        session = self.client.session
        session["base_username"] = self.username
        session.save()

    def create_totp_key(self, enabled=True):
        """Create a TOTP key for the test user.

        Args:
            enabled (bool): Whether the key should be enabled

        Returns:
            User_Keys: The created TOTP key
        """
        secret = pyotp.random_base32()
        key = User_Keys.objects.create(
            username=self.username,
            key_type="TOTP",
            properties={"secret_key": secret},
            enabled=enabled,
        )
        return key

    def create_recovery_key(self, enabled=True):
        """Create a recovery key for the test user.

        Args:
            enabled (bool): Whether the key should be enabled

        Returns:
            User_Keys: The created recovery key
        """
        codes = ["123456", "654321"]  # Example recovery codes
        key = User_Keys.objects.create(
            username=self.username,
            key_type="RECOVERY",
            properties={"codes": codes},
            enabled=enabled,
        )
        return key

    def login_user(self):
        """Log in the test user.

        Uses the test user credentials to authenticate with the test client.
        """
        self.client.login(username=self.username, password=self.password)

    def setup_mfa_session(self, method="TOTP", verified=True, id=1):
        """Set up MFA session state for testing.

        Args:
            method (str): MFA method to use (default: 'TOTP')
            verified (bool): Whether the method is verified (default: True)
            id (int): Key ID to use (default: 1)
        """
        session = self.client.session
        mfa = {"method": method, "verified": verified, "id": id}
        mfa.update(set_next_recheck())
        session["mfa"] = mfa
        session.save()

    def get_valid_totp_token(self):
        """Get a valid TOTP token for testing.

        Returns:
            str: Current valid TOTP token
        """
        key = User_Keys.objects.get(username=self.username, key_type="TOTP")
        totp = pyotp.TOTP(key.properties["secret_key"])
        return totp.now()

    def get_invalid_totp_token(self):
        """Get an invalid TOTP token for testing.

        Returns:
            str: Invalid TOTP token
        """
        return "000000"

    def tearDown(self):
        """Clean up after tests.

        Clears cache, deletes all MFA keys, and restores original settings
        to ensure test isolation.
        """
        super().tearDown()
        cache.clear()
        User_Keys.objects.all().delete()
        # Restore original settings
        for key, value in self.original_settings.items():
            setattr(settings, key, value)

    def verify_mfa_session_state(
        self, expected_verified=True, expected_method=None, expected_id=None
    ):
        """Verify the MFA session state.

        Args:
            expected_verified (bool): Expected verification state
            expected_method (str): Expected MFA method
            expected_id (int): Expected key ID
        """
        mfa = self.client.session.get("mfa", {})
        self.assertEqual(mfa.get("verified"), expected_verified)
        if expected_method:
            self.assertEqual(mfa.get("method"), expected_method)
        if expected_id:
            self.assertEqual(mfa.get("id"), expected_id)

    def verify_url_requires_mfa(self, url, method="get", data=None):
        """Verify that a URL requires MFA authentication.

        Args:
            url (str): URL to test
            method (str): HTTP method to use
            data (dict): Data to send with request
        """
        if not data:
            data = {}
        func = getattr(self.client, method.lower())
        response = func(url, data)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse("mfa_required")))

    def verify_key_state(self, key_id, expected_enabled=None, expected_last_used=None):
        """Verify the state of an MFA key.

        Args:
            key_id (int): ID of the key to verify
            expected_enabled (bool, optional): Expected enabled state
            expected_last_used (bool, optional): Whether last_used should be set
        """
        key = User_Keys.objects.get(id=key_id)
        if expected_enabled is not None:
            self.assertEqual(key.enabled, expected_enabled)
        if expected_last_used is not None:
            if expected_last_used:
                self.assertIsNotNone(key.last_used)
            else:
                self.assertIsNone(key.last_used)

    def get_mfa_url(self, url_name, *args, **kwargs):
        """Get URL for MFA endpoints.

        Args:
            url_name (str): Name of the URL pattern
            *args: Positional arguments for URL resolution
            **kwargs: Keyword arguments for URL resolution

        Returns:
            str: Resolved URL

        Raises:
            NoReverseMatch: If the URL cannot be resolved
        """
        return reverse(url_name, args=args, kwargs=kwargs)

    def get_redirect_url(self, default="mfa_home"):
        """Get the redirect URL for MFA operations.

        Args:
            default (str): Default URL name to use if no redirect is configured

        Returns:
            str: URL to redirect to after MFA operations
        """
        redirect_url = getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", default)
        try:
            return reverse(redirect_url)
        except NoReverseMatch:
            # If the redirect URL is a path, return it as is
            if redirect_url.startswith("/"):
                return redirect_url
            # Otherwise use the default
            return reverse(default)

    def verify_settings(self, expected_settings):
        """Verify that settings match expected values.

        Args:
            expected_settings (dict): Dictionary of setting names and expected values

        Example:
            self.verify_settings({
                'MFA_RECHECK': True,
                'MFA_RECHECK_MIN': 300
            })
        """
        for setting_name, expected_value in expected_settings.items():
            self.assertEqual(getattr(settings, setting_name), expected_value)

    def verify_settings_presence(self, required_settings, optional_settings=None):
        """Verify that required and optional settings are present.

        Args:
            required_settings (list): List of required setting names
            optional_settings (list, optional): List of optional setting names

        Example:
            self.verify_settings_presence(
                ['MFA_UNALLOWED_METHODS'],
                ['MFA_RECHECK']
            )
        """
        for setting in required_settings:
            self.assertTrue(hasattr(settings, setting))

        if optional_settings:
            for setting in optional_settings:
                self.assertTrue(hasattr(settings, setting))

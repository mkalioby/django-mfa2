import pyotp
import time
from django.test import TestCase, Client
from django.conf import settings
from django.urls import reverse, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
from functools import wraps
from unittest import SkipTest
from .utils.skip_reasons import SkipReason
from .utils.skip_registry import SkipRegistry
from django.core.cache import cache

from mfa.models import User_Keys
from mfa.Common import set_next_recheck
from .utils import (
    skip_if_url_missing,
    skip_if_setting_missing,
    skip_if_middleware_disabled,
    skip_if_security_gap,
    skip_if_logging_gap
)


User = get_user_model()


def skip_if_url_missing(url_name):
    """Decorator to skip tests if a URL pattern is not found.
    
    Args:
        url_name: The name of the URL pattern to check
        
    Returns:
        A decorator that will skip the test if the URL is not found
    """
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            try:
                reverse(url_name)
            except NoReverseMatch:
                self.skipTest(f"URL pattern '{url_name}' is not configured")
            return test_func(self, *args, **kwargs)
        return wrapper
    return decorator


def skip_if_setting_missing(setting_name, message=None):
    """Decorator to skip tests if a required setting is missing.
    
    Args:
        setting_name: The name of the setting to check
        message: Optional custom skip message
        
    Returns:
        A decorator that will skip the test if the setting is not found
    """
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            if not hasattr(settings, setting_name):
                msg = message or f"Required setting '{setting_name}' is not configured"
                self.skipTest(msg)
            return test_func(self, *args, **kwargs)
        return wrapper
    return decorator


class MFATestCase(TestCase):
    """Base test case for MFA tests.

    This class provides common functionality for all MFA test cases, including:
    - User creation
    - MFA key setup
    - Common assertions
    - Session handling
    - Consistent skip behavior
    """

    def setUp(self):
        """Set up test environment for MFA tests."""
        super().setUp()
        self.username = 'testuser'
        self.password = 'testpass123'
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password
        )
        self.client.login(username=self.username, password=self.password)
        cache.clear()

        # TOTP setup
        self.totp_secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(self.totp_secret)

        # Define common settings used in tests
        self.original_mfa_settings = {
            'MFA_UNALLOWED_METHODS': getattr(settings, 'MFA_UNALLOWED_METHODS', []),
            'MFA_HIDE_DISABLE': getattr(settings, 'MFA_HIDE_DISABLE', []),
            'MFA_RENAME_METHODS': getattr(settings, 'MFA_RENAME_METHODS', {}),
            'TOKEN_ISSUER_NAME': getattr(settings, 'TOKEN_ISSUER_NAME', 'Django MFA'),
            'MFA_ENFORCE_RECOVERY_METHOD': getattr(settings, 'MFA_ENFORCE_RECOVERY_METHOD', False),
        }

        # Set base_username in session for all tests
        session = self.client.session
        session["base_username"] = self.username
        session.save()

    def check_url_exists(self, url_name):
        """Check if a URL pattern exists.
        
        Args:
            url_name: The name of the URL pattern to check
            
        Returns:
            bool: True if the URL exists, False otherwise
        """
        try:
            reverse(url_name)
            return True
        except NoReverseMatch:
            return False

    def check_setting_exists(self, setting_name):
        """Check if a setting exists.
        
        Args:
            setting_name: The name of the setting to check
            
        Returns:
            bool: True if the setting exists, False otherwise
        """
        return hasattr(settings, setting_name)

    def skip_if_missing(self, url_names=None, settings=None):
        """Skip the test if any required URLs or settings are missing.
        
        Args:
            url_names: List of URL names to check
            settings: List of setting names to check
            
        Raises:
            SkipTest: If any required URL or setting is missing
        """
        if url_names:
            for url_name in url_names:
                if not self.check_url_exists(url_name):
                    self.skipTest(f"URL pattern '{url_name}' is not configured")
        
        if settings:
            for setting_name in settings:
                if not self.check_setting_exists(setting_name):
                    self.skipTest(f"Required setting '{setting_name}' is not configured")

    def create_totp_key(self, enabled=True):
        """Create a TOTP key for the test user."""
        secret = pyotp.random_base32()
        key = User_Keys.objects.create(
            username=self.username,
            key_type='TOTP',
            properties={'secret_key': secret},
            enabled=enabled
        )
        return key

    def create_recovery_key(self, enabled=True):
        """Create a recovery key for the test user."""
        codes = ['123456', '654321']  # Example recovery codes
        key = User_Keys.objects.create(
            username=self.username,
            key_type='RECOVERY',
            properties={'codes': codes},
            enabled=enabled
        )
        return key

    def login_user(self):
        """Log in the test user."""
        self.client.login(username=self.username, password=self.password)

    def setup_mfa_session(self, method='TOTP', verified=True, id=1):
        """Set up MFA session state for testing."""
        session = self.client.session
        mfa = {
            'method': method,
            'verified': verified,
            'id': id
        }
        mfa.update(set_next_recheck())
        session['mfa'] = mfa
        session.save()

    def get_valid_totp_token(self):
        """Get a valid TOTP token for testing."""
        key = User_Keys.objects.get(username=self.username, key_type='TOTP')
        totp = pyotp.TOTP(key.properties['secret_key'])
        return totp.now()

    def get_invalid_totp_token(self):
        """Get an invalid TOTP token for testing."""
        return '000000'

    def tearDown(self):
        """Clean up after tests."""
        super().tearDown()
        cache.clear()
        User_Keys.objects.all().delete()

    def verify_mfa_session_state(self, expected_verified=True, expected_method=None, expected_id=None):
        """Verify the MFA session state.

        Args:
            expected_verified (bool): Expected verification state
            expected_method (str): Expected MFA method
            expected_id (int): Expected key ID
        """
        mfa = self.client.session.get('mfa', {})
        self.assertEqual(mfa.get('verified'), expected_verified)
        if expected_method:
            self.assertEqual(mfa.get('method'), expected_method)
        if expected_id:
            self.assertEqual(mfa.get('id'), expected_id)

    def verify_url_requires_mfa(self, url, method='get', data=None):
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
        self.assertTrue(response.url.startswith(reverse('mfa_required')))

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
        if expected_last_used:
            self.assertIsNotNone(key.last_used)

    def skip_test(self, reason: SkipReason, details: str = None) -> None:
        """Helper method to skip a test with standardized message format"""
        SkipRegistry.register_skip(
            self._testMethodName,
            reason,
            details
        )
        raise SkipTest(reason.format_message(details))

    def skip_if_url_missing(self, url_name: str) -> None:
        """Skip test if URL pattern is not found"""
        try:
            reverse(url_name)
        except NoReverseMatch:
            self.skip_test(
                SkipReason.MISSING_URL,
                f"URL '{url_name}' not found"
            )

    def skip_if_setting_missing(self, setting_name: str) -> None:
        """Skip test if required setting is not configured"""
        if not hasattr(settings, setting_name):
            self.skip_test(
                SkipReason.MISSING_SETTING,
                f"Setting '{setting_name}' not configured"
            )

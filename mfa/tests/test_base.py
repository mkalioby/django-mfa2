import sys
import unittest
from django.test import TestCase, override_settings
from django.urls import reverse, path, include, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import HttpResponse
from django.contrib import admin
from mfa.models import User_Keys
from mfa.urls import urlpatterns as mfa_urlpatterns
from .base import MFATestCase

User = get_user_model()


def test_protected_view(request):
    """A simple test view that requires MFA."""
    return HttpResponse("Protected Content")


test_urlpatterns = [
    path("protected/", test_protected_view, name="test_protected_view"),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("mfa/", include(mfa_urlpatterns)),  # Include without namespace
    path("", include((test_urlpatterns, "test"))),
]


@override_settings(
    ROOT_URLCONF="mfa.tests.test_base",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        # 'mfa.middleware' is currently disabled
    ],
    MFA_REQUIRED=True,
    LOGIN_URL="/auth/login/",  # Use MFA example app's login URL
    LOGOUT_URL="/auth/logout/",  # Use MFA example app's logout URL
)
class TestMFATestCase(TestCase):
    """Test suite for the MFATestCase base class.

    These tests verify that the base test class functions correctly,
    ensuring reliable testing infrastructure for all MFA tests.

    Areas tested:
    - Key creation helpers
    - Session management
    - Verification methods
    - State assertions

    Note: MFA middleware is currently disabled in tests
    """

    def setUp(self):
        """Create a test instance of MFATestCase."""
        self.mfa_test = MFATestCase("run")
        self.mfa_test._pre_setup()
        self.mfa_test.setUp()

    def tearDown(self):
        """Clean up the test instance."""
        self.mfa_test._post_teardown()

    def test_user_setup(self):
        """Test that user is properly created in setUp."""
        self.assertIsNotNone(self.mfa_test.user)
        self.assertEqual(self.mfa_test.username, "testuser")
        self.assertTrue(self.mfa_test.user.check_password("testpass123"))

    def test_create_totp_key(self):
        """Test TOTP key creation helper method."""
        # Test enabled key
        key = self.mfa_test.create_totp_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "TOTP")
        self.assertTrue(key.enabled)
        self.assertIn("secret_key", key.properties)
        self.assertTrue(len(key.properties["secret_key"]) > 0)  # Verify secret is set

        # Test disabled key
        disabled_key = self.mfa_test.create_totp_key(enabled=False)
        self.assertFalse(disabled_key.enabled)

    def test_create_recovery_key(self):
        """Test recovery key creation helper method."""
        # Test enabled key
        key = self.mfa_test.create_recovery_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "RECOVERY")
        self.assertTrue(key.enabled)
        self.assertIn("codes", key.properties)
        self.assertEqual(len(key.properties["codes"]), 2)

        # Test disabled key
        disabled_key = self.mfa_test.create_recovery_key(enabled=False)
        self.assertFalse(disabled_key.enabled)

    def test_setup_mfa_session(self):
        """Test MFA session setup helper method."""
        # Test default values
        self.mfa_test.setup_mfa_session()
        session = self.mfa_test.client.session
        self.assertEqual(session["base_username"], self.mfa_test.username)
        self.assertTrue(session["mfa"]["verified"])
        self.assertEqual(session["mfa"]["method"], "TOTP")
        self.assertEqual(session["mfa"]["id"], 1)
        self.assertIn("next_check", session["mfa"])

        # Test custom values
        self.mfa_test.setup_mfa_session(method="RECOVERY", verified=False, id=42)
        session = self.mfa_test.client.session
        self.assertFalse(session["mfa"]["verified"])
        self.assertEqual(session["mfa"]["method"], "RECOVERY")
        self.assertEqual(session["mfa"]["id"], 42)

    def test_verify_mfa_session_state(self):
        """Test MFA session state verification."""
        # Setup test session
        self.mfa_test.setup_mfa_session(method="TOTP", verified=True, id=1)

        # Test successful verification
        self.mfa_test.verify_mfa_session_state(
            expected_verified=True, expected_method="TOTP", expected_id=1
        )

        # Test failure cases
        with self.assertRaises(AssertionError):
            self.mfa_test.verify_mfa_session_state(expected_verified=False)

        with self.assertRaises(AssertionError):
            self.mfa_test.verify_mfa_session_state(expected_method="RECOVERY")

        with self.assertRaises(AssertionError):
            self.mfa_test.verify_mfa_session_state(expected_id=2)

    def test_verify_key_state(self):
        """Test key state verification."""
        # Create test key
        key = self.mfa_test.create_totp_key()

        # Test enabled state
        self.mfa_test.verify_key_state(key.id, expected_enabled=True)

        # Test disabled state
        key.enabled = False
        key.save()
        self.mfa_test.verify_key_state(key.id, expected_enabled=False)

        # Test last_used verification (without checking enabled state)
        key.last_used = timezone.now()
        key.save()
        self.mfa_test.verify_key_state(
            key.id, expected_enabled=False, expected_last_used=True
        )

        # Test failure cases
        with self.assertRaises(AssertionError):
            self.mfa_test.verify_key_state(key.id, expected_enabled=True)

        key.last_used = None
        key.save()
        with self.assertRaises(AssertionError):
            self.mfa_test.verify_key_state(key.id, expected_last_used=True)

    def test_totp_token_generation(self):
        """Test TOTP token generation methods."""
        # Create a TOTP key first
        key = self.mfa_test.create_totp_key()

        # Test valid token generation
        valid_token = self.mfa_test.get_valid_totp_token()
        self.assertEqual(len(valid_token), 6)
        self.assertTrue(valid_token.isdigit())

        # Test invalid token generation
        invalid_token = self.mfa_test.get_invalid_totp_token()
        self.assertNotEqual(valid_token, invalid_token)
        self.assertEqual(len(invalid_token), 6)
        self.assertTrue(invalid_token.isdigit())

    def test_get_mfa_url(self):
        """Test URL resolution in get_mfa_url method.

        Verifies:
        1. Core MFA URLs resolve correctly
        2. URL construction works for both patterns
        """
        # Test core MFA URLs
        core_urls = {
            "mfa_home": "/mfa/",
            "totp_auth": "/mfa/totp/auth",
            "recovery_auth": "/mfa/recovery/auth",
            "email_auth": "/mfa/email/auth/",
            "fido2_auth": "/mfa/fido2/auth",
            "u2f_auth": "/mfa/u2f/auth",
            "mfa_methods_list": "/mfa/selct_method",
        }

        for name, expected_url in core_urls.items():
            url = self.mfa_test.get_mfa_url(name)
            self.assertEqual(url, expected_url, f"Failed to resolve {name}")

    def test_get_mfa_url_invalid(self):
        """Test URL resolution for invalid URLs.

        Verifies:
        1. Invalid URLs raise appropriate exceptions
        """
        # Test invalid URL
        with self.assertRaises(NoReverseMatch):
            self.mfa_test.get_mfa_url("nonexistent_url")

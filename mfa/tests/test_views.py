"""
Test cases for MFA views module.

Tests main MFA view functions in mfa.views module:
- index(): Main MFA dashboard showing user's registered keys
- verify(): Initiates MFA verification process for a user
- show_methods(): Displays available MFA methods for selection
- reset_cookie(): Resets MFA session cookie
- delKey(): Deletes user MFA keys
- toggleKey(): Enables/disables user MFA keys
- goto(): Redirects to MFA method authentication
- __get_callable_function__(): Loads callable functions from settings

Scenarios: Dashboard display, method selection, verification flow, session management, key management.
"""

from django.test import TestCase, override_settings
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock
from ..views import (
    verify,
    show_methods,
    reset_cookie,
    delKey,
    toggleKey,
    goto,
    __get_callable_function__,
)
from ..models import User_Keys
from .mfatestcase import MFATestCase

User = get_user_model()


class TestViewsModule(MFATestCase):
    """Additional test cases for views to achieve 100% coverage."""

    def test_verify_function_no_keys(self):
        """Handles verify request when user has no keys."""
        response = verify(self.client.get("/").wsgi_request, self.username)
        # Should redirect to show_methods
        self.assertIsInstance(response, HttpResponse)

    def test_verify_function_with_trusted_device(self):
        """Handles verify request with trusted device key."""
        # Create trusted device key
        key = User_Keys.objects.create(
            username=self.username,
            key_type="Trusted Device",
            properties={"key": "test_key"},
            enabled=True,
        )

        # Test the real verify function
        response = verify(self.client.get("/").wsgi_request, self.username)

        # Should return a response (the actual result depends on TrustedDevice.verify)
        self.assertIsNotNone(response)

    @override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_verify_function_trusted_device_success(self):
        """Handles verify request when TrustedDevice verification succeeds and calls login."""
        # Use helper method to create trusted device key
        key = self.create_trusted_device_key(enabled=True)

        # Set up session with base_username for login function
        session = self.client.session
        session["base_username"] = self.username
        session.save()

        # Use the verify_trusted_device helper to set up proper conditions
        # This ensures TrustedDevice.verify will return True
        self.verify_trusted_device(key, expect_success=True)

        # Test the verify function - should call login() when TrustedDevice.verify returns True
        response = verify(self.client.get("/").wsgi_request, self.username)

        # Should return HttpResponseRedirect from login function (create_session)
        # This verifies that line 57 (return login(request)) was executed
        self.assertIsInstance(response, HttpResponseRedirect)
        self.assertEqual(response.url, reverse("mfa_home"))

    @override_settings(MFA_ENFORCE_EMAIL_TOKEN=True)
    def test_verify_function_force_email(self):
        """Handles verify request with forced email token."""
        response = verify(self.client.get("/").wsgi_request, self.username)
        # Should handle email method
        self.assertIsInstance(response, HttpResponse)

    @override_settings(MFA_ALWAYS_GO_TO_LAST_METHOD=True)
    def test_verify_function_always_go_to_last_method(self):
        """Handles verify request with MFA_ALWAYS_GO_TO_LAST_METHOD setting enabled."""
        # Create multiple keys with different last_used timestamps
        totp_key = self.create_totp_key(enabled=True)
        fido2_key = self.create_fido2_key(enabled=True)

        # Set up session with base_username
        session = self.client.session
        session["base_username"] = self.username
        session.save()

        # Update last_used timestamps to test ordering
        # FIDO2 key should be more recent (will be selected)
        fido2_key.last_used = timezone.now()
        fido2_key.save()

        totp_key.last_used = timezone.now() - timedelta(hours=1)
        totp_key.save()

        # Test the verify function - should redirect to most recently used method
        response = verify(self.client.get("/").wsgi_request, self.username)

        # Should return HttpResponseRedirect to fido2_auth (most recent)
        self.assertIsInstance(response, HttpResponseRedirect)
        self.assertEqual(response.url, reverse("fido2_auth"))

    def test_show_methods_function(self):
        """Displays available MFA methods for selection."""
        response = show_methods(self.client.get("/").wsgi_request)
        self.assertIsInstance(response, HttpResponse)

    @override_settings(LOGIN_URL="/test/login/")
    def test_reset_cookie_function(self):
        """Resets MFA session cookie and redirects to login."""
        response = reset_cookie(self.client.get("/").wsgi_request)
        self.assertIsInstance(response, HttpResponseRedirect)
        self.assertEqual(response.url, "/test/login/")

    def test_delkey_function_success(self):
        """Deletes user MFA key successfully."""
        key = self.create_totp_key()

        request = self.client.get("/").wsgi_request
        request.method = "POST"
        request.POST = {"id": str(key.id)}
        request.user = self.user

        response = delKey(request)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"Deleted Successfully")

    def test_delkey_function_wrong_user(self):
        """Handles delKey request with wrong user."""
        key = User_Keys.objects.create(
            username="otheruser",
            key_type="TOTP",
            properties={"secret_key": "test"},
            enabled=True,
        )

        request = self.client.get("/").wsgi_request
        request.method = "POST"
        request.POST = {"id": str(key.id)}
        request.user = self.user

        response = delKey(request)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"Error: This key doesn't exist")

    def test_get_callable_function_invalid_path(self):
        """Handles invalid function path in __get_callable_function__."""
        with self.assertRaises(Exception) as cm:
            __get_callable_function__("invalid_path")
        self.assertIn("modulename.classname", str(cm.exception))

    def test_get_callable_function_nonexistent_function(self):
        """Handles nonexistent function in __get_callable_function__."""
        with patch(
            "importlib.import_module"
        ) as mock_import:  # Mock external importlib to isolate MFA project function loading
            mock_module = MagicMock()
            mock_module.nonexistent_func = None
            mock_import.return_value = mock_module

            with self.assertRaises(Exception) as cm:
                __get_callable_function__("test.module.nonexistent_func")
            self.assertIn("does not have requested function", str(cm.exception))

    @override_settings(MFA_HIDE_DISABLE=["TOTP"])
    def test_togglekey_function_hidden_method(self):
        """Handles toggleKey request with hidden method."""
        key = self.create_totp_key()

        request = self.client.get("/").wsgi_request
        request.method = "GET"
        request.GET = {"id": str(key.id)}
        request.user = self.user

        response = toggleKey(request)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"You can't change this method.")

    def test_togglekey_function_success(self):
        """Toggles user MFA key state successfully."""
        key = self.create_totp_key()
        original_state = key.enabled

        request = self.client.get("/").wsgi_request
        request.method = "GET"
        request.GET = {"id": str(key.id)}
        request.user = self.user

        response = toggleKey(request)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"OK")

        key.refresh_from_db()
        self.assertEqual(key.enabled, not original_state)

    def test_togglekey_function_wrong_count(self):
        """Handles toggleKey request with invalid key count."""
        request = self.client.get("/").wsgi_request
        request.method = "GET"
        request.GET = {"id": "999"}  # Non-existent key
        request.user = self.user

        response = toggleKey(request)
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"Error")

    def test_goto_function(self):
        """Redirects to MFA method authentication."""
        with patch(
            "mfa.views.reverse"
        ) as mock_reverse:  # Mock external Django reverse to isolate MFA project goto function
            mock_reverse.return_value = "/mfa/test_auth"
            response = goto(self.client.get("/").wsgi_request, "TEST")
            self.assertIsInstance(response, HttpResponseRedirect)
            # Verify MFA project properly handled goto function by checking redirect URL
            self.assertEqual(response.url, "/mfa/test_auth")

    def test_index_view_with_trusted_device_key(self):
        """Renders index view with trusted device key."""
        from mfa.views import index

        key = User_Keys.objects.create(
            username=self.username,
            key_type="Trusted Device",
            properties={"user_agent": "Mozilla/5.0", "key": "test_device_key"},
            enabled=True,
        )

        request = self.client.get("/").wsgi_request
        request.user = self.user

        response = index(request)
        self.assertEqual(response.status_code, 200)

    def test_index_view_with_fido2_key(self):
        """Renders index view with FIDO2 key."""
        from mfa.views import index

        key = User_Keys.objects.create(
            username=self.username,
            key_type="FIDO2",
            properties={"type": "fido-u2f"},
            enabled=True,
        )

        request = self.client.get("/").wsgi_request
        request.user = self.user

        response = index(request)
        self.assertEqual(response.status_code, 200)

    @override_settings(MFA_ENFORCE_EMAIL_TOKEN=True)
    def test_index_view_with_email_key_forced(self):
        """Renders index view with email key when forced."""
        from mfa.views import index

        key = User_Keys.objects.create(
            username=self.username, key_type="Email", properties={}, enabled=True
        )

        # Use proper HttpRequest object instead of HttpResponse
        request = self.client.get("/").wsgi_request
        request.user = self.user

        response = index(request)
        self.assertEqual(response.status_code, 200)

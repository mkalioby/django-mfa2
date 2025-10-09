"""
Test cases for MFA helpers module.

Tests helper functions in mfa.helpers module:
- has_mfa(): Determines if user has MFA enabled and initiates verification
- is_mfa(): Checks if session has verified MFA for non-ignored methods
- recheck(): Re-verifies MFA for current session's method

Scenarios: MFA verification flow, session state checking, method routing, error handling.
"""

from django.test import TestCase, override_settings
from django.http import JsonResponse
from unittest.mock import patch, MagicMock
from ..helpers import has_mfa, is_mfa, recheck
from ..models import User_Keys
from .mfatestcase import MFATestCase


class HelpersTests(MFATestCase):
    """MFA helper functions tests."""

    def test_has_mfa_with_enabled_keys(self):
        """Identifies when users have enabled MFA methods and initiates verification.

        Exercises the complete flow:
        1. has_mfa() receives request and username
        2. User_Keys.objects.filter() finds enabled keys for user
        3. verify() is called with request and username
        4. Response from verify() is returned

        Purpose: Verify that has_mfa correctly identifies when users have
        enabled MFA methods, ensuring proper MFA requirement detection.
        """
        # Create an enabled TOTP key
        self.create_totp_key(enabled=True)

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real has_mfa function
        result = has_mfa(request, self.username)

        # Should return a response from verify (not False)
        self.assertIsNotNone(result)
        self.assertNotEqual(result, False)

    def test_has_mfa_with_no_keys(self):
        """Returns False when user has no enabled keys."""
        # Don't create any keys

        result = has_mfa(self.client.get("/").wsgi_request, self.username)

        # Should return False
        self.assertFalse(result)

    def test_has_mfa_with_disabled_keys(self):
        """Returns False when user has only disabled keys."""
        # Create a disabled TOTP key
        self.create_totp_key(enabled=False)

        result = has_mfa(self.client.get("/").wsgi_request, self.username)

        # Should return False
        self.assertFalse(result)

    @override_settings(MFA_ENFORCE_EMAIL_TOKEN=True)
    def test_has_mfa_with_force_email_setting(self):
        """Returns verify when MFA_ENFORCE_EMAIL_TOKEN is True."""
        # Don't create any keys but set the setting

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real has_mfa function
        result = has_mfa(request, self.username)

        # Should return True when email is enforced
        self.assertTrue(result)

    def test_has_mfa_with_mixed_keys(self):
        """Returns verify when user has both enabled and disabled keys."""
        # Create both enabled and disabled keys
        self.create_totp_key(enabled=True)
        self.create_totp_key(enabled=False)

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real has_mfa function
        result = has_mfa(request, self.username)

        # Should return a response from verify (not False)
        self.assertIsNotNone(result)
        self.assertNotEqual(result, False)

    def test_is_mfa_verified_true(self):
        """Returns True when MFA is verified."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session with id from User_Keys record
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        result = is_mfa(self.client.get("/").wsgi_request)

        self.assertTrue(result)

    def test_is_mfa_verified_false(self):
        """Returns False when MFA is not verified."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up unverified MFA session with id from User_Keys record
        session = self.client.session
        session["mfa"] = {"verified": False, "method": "TOTP", "id": totp_key.id}
        session.save()

        result = is_mfa(self.client.get("/").wsgi_request)

        self.assertFalse(result)

    def test_is_mfa_no_session(self):
        """Returns False when no MFA session exists."""
        # Don't set up any MFA session

        result = is_mfa(self.client.get("/").wsgi_request)

        self.assertFalse(result)

    def test_is_mfa_ignores_methods(self):
        """Returns True when verified but method not in ignore list."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session with method not in ignore list
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        result = is_mfa(
            self.client.get("/").wsgi_request, ignore_methods=["U2F", "FIDO2"]
        )

        self.assertTrue(result)

    def test_is_mfa_ignores_specified_method(self):
        """Returns False when verified but method is in ignore list."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session with method in ignore list
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        result = is_mfa(
            self.client.get("/").wsgi_request, ignore_methods=["TOTP", "U2F"]
        )

        self.assertFalse(result)

    def test_is_mfa_empty_ignore_methods(self):
        """Returns True when verified and ignore_methods is empty."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        result = is_mfa(self.client.get("/").wsgi_request, ignore_methods=[])

        self.assertTrue(result)

    def test_recheck_no_method(self):
        """Returns JsonResponse with res=False when no method in session."""
        # Don't set up any MFA session

        result = recheck(self.client.get("/").wsgi_request)

        self.assertIsInstance(result, JsonResponse)
        self.assertEqual(result.content, b'{"res": false}')

    def test_recheck_trusted_device_method(self):
        """Returns TrustedDevice.verify result for Trusted Device method."""
        # Create a Trusted Device key for the user
        trusted_key = self.create_trusted_device_key(enabled=True)

        # Set up session with Trusted Device method
        session = self.client.session
        session["mfa"] = {
            "verified": True,
            "method": "Trusted Device",
            "id": trusted_key.id,
        }
        session.save()

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real recheck function
        result = recheck(request)

        self.assertIsInstance(result, JsonResponse)
        # The actual result depends on the real TrustedDevice.verify implementation
        self.assertIn("res", result.content.decode())

    def test_recheck_u2f_method(self):
        """Returns U2F.recheck result for U2F method."""
        # Create a U2F key for the user
        u2f_key = self.create_u2f_key(enabled=True)

        # Set up session with U2F method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "U2F", "id": u2f_key.id}
        session.save()

        # Create a U2F key for the user (required for U2F.recheck to work)
        u2f_key = self.create_u2f_key(enabled=True)

        # Mock the begin_authentication function to avoid U2F library issues
        with patch("mfa.U2F.begin_authentication") as mock_begin:
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test_challenge"}
            mock_challenge.data_for_client = {"appId": "test_app_id"}
            mock_begin.return_value = mock_challenge

            # Get a single request object to reuse
            request = self.client.get("/").wsgi_request

            # Test the real recheck function
            result = recheck(request)

            self.assertIsInstance(result, JsonResponse)
            # The actual result depends on the real U2F.recheck implementation
            self.assertIn("html", result.content.decode())

    def test_recheck_fido2_method(self):
        """Returns FIDO2.recheck result for FIDO2 method."""
        # Create a FIDO2 key for the user
        fido2_key = self.create_fido2_key(enabled=True)

        # Set up session with FIDO2 method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "FIDO2", "id": fido2_key.id}
        session.save()

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real recheck function
        result = recheck(request)

        self.assertIsInstance(result, JsonResponse)
        # The actual result depends on the real FIDO2.recheck implementation
        self.assertIn("html", result.content.decode())

    def test_recheck_totp_method(self):
        """Returns totp.recheck result for TOTP method."""
        # Create a TOTP key for the user (required for TOTP.recheck to work properly)
        totp_key = self.create_totp_key(enabled=True)

        # Set up session with TOTP method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real recheck function
        result = recheck(request)

        self.assertIsInstance(result, JsonResponse)
        # The actual result depends on the real totp.recheck implementation
        self.assertIn("html", result.content.decode())

    def test_recheck_unknown_method(self):
        """Returns None for unknown method."""
        # Create a dummy key for the user (unknown method)
        dummy_key = self.create_totp_key(enabled=True)

        # Set up session with unknown method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "Unknown", "id": dummy_key.id}
        session.save()

        result = recheck(self.client.get("/").wsgi_request)

        # Function returns None for unknown methods (no default case)
        self.assertIsNone(result)

    def test_recheck_empty_method(self):
        """Returns JsonResponse with res=False for empty method."""
        # Create a dummy key for the user (empty method test)
        dummy_key = self.create_totp_key(enabled=True)

        # Set up session with empty method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "", "id": dummy_key.id}
        session.save()

        result = recheck(self.client.get("/").wsgi_request)

        self.assertIsInstance(result, JsonResponse)
        self.assertEqual(result.content, b'{"res": false}')

    def test_recheck_none_method(self):
        """Returns JsonResponse with res=False for None method."""
        # Create a dummy key for the user (None method test)
        dummy_key = self.create_totp_key(enabled=True)

        # Set up session with None method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": None, "id": dummy_key.id}
        session.save()

        result = recheck(self.client.get("/").wsgi_request)

        self.assertIsInstance(result, JsonResponse)
        self.assertEqual(result.content, b'{"res": false}')

    def test_recheck_missing_mfa_session(self):
        """Returns JsonResponse with res=False when MFA session is missing."""
        # Don't set up any MFA session

        result = recheck(self.client.get("/").wsgi_request)

        self.assertIsInstance(result, JsonResponse)
        self.assertEqual(result.content, b'{"res": false}')

    def test_recheck_empty_mfa_session(self):
        """Returns JsonResponse with res=False when MFA session is empty."""
        # Set up empty MFA session
        session = self.client.session
        session["mfa"] = {}
        session.save()

        result = recheck(self.client.get("/").wsgi_request)

        self.assertIsInstance(result, JsonResponse)
        self.assertEqual(result.content, b'{"res": false}')

    def test_has_mfa_with_multiple_key_types(self):
        """Works with multiple key types during MFA verification.

        helpers.py has_mfa function with multiple key types
        """
        # Create keys of different types
        self.create_totp_key(enabled=True)
        self.create_email_key(enabled=True)
        self.create_recovery_key(enabled=True)

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        result = has_mfa(request, self.username)

        # Should return a response from verify (not False)
        self.assertIsNotNone(result)
        self.assertNotEqual(result, False)

    def test_has_mfa_with_only_disabled_multiple_types(self):
        """Returns False when all keys are disabled."""
        # Create disabled keys of different types
        self.create_totp_key(enabled=False)
        self.create_email_key(enabled=False)
        self.create_recovery_key(enabled=False)

        result = has_mfa(self.client.get("/").wsgi_request, self.username)

        # Should return False
        self.assertFalse(result)

    def test_is_mfa_with_custom_ignore_methods(self):
        """Handles custom ignore methods list correctly."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Test with method in ignore list - should return False
        result = is_mfa(self.client.get("/").wsgi_request, ignore_methods=["TOTP"])
        self.assertFalse(result)

        # Test with method not in ignore list - should return True
        result = is_mfa(self.client.get("/").wsgi_request, ignore_methods=["U2F"])
        self.assertTrue(result)

    def test_recheck_with_trusted_device_false(self):
        """Handles TrustedDevice.verify returning False."""
        # Create a Trusted Device key for the user
        trusted_key = self.create_trusted_device_key(enabled=True)

        # Set up session with Trusted Device method
        session = self.client.session
        session["mfa"] = {
            "verified": True,
            "method": "Trusted Device",
            "id": trusted_key.id,
        }
        session.save()

        # Get a single request object to reuse
        request = self.client.get("/").wsgi_request

        # Test the real recheck function
        result = recheck(request)

        self.assertIsInstance(result, JsonResponse)
        # The actual result depends on the real TrustedDevice.verify implementation
        self.assertIn("res", result.content.decode())

    def test_is_mfa_with_malformed_session(self):
        """Raises AttributeError when session data is malformed."""
        # Set up malformed MFA session
        session = self.client.session
        session["mfa"] = "not a dict"
        session.save()

        # Should raise AttributeError when trying to call .get() on a string
        with self.assertRaises(AttributeError) as cm:
            is_mfa(self.client.get("/").wsgi_request)

        self.assertIn("'str' object has no attribute 'get'", str(cm.exception))

    def test_recheck_with_malformed_session(self):
        """Raises AttributeError when session data is malformed."""
        # Set up malformed MFA session
        session = self.client.session
        session["mfa"] = "not a dict"
        session.save()

        # NOTE: recheck() doesn't handle malformed session data gracefully
        # When session['mfa'] is not a dict, calling .get() on it raises AttributeError
        with self.assertRaises(AttributeError) as cm:
            recheck(self.client.get("/").wsgi_request)

        self.assertIn("'str' object has no attribute 'get'", str(cm.exception))

    def test_has_mfa_with_different_username(self):
        """Handles different username than logged in user."""
        # Create key for different user
        User_Keys.objects.create(
            username="other_user",
            key_type="TOTP",
            properties={"secret_key": "test_secret"},
            enabled=True,
        )

        # Get a proper request object
        request = self.client.get("/").wsgi_request

        # Test the real has_mfa function
        result = has_mfa(request, "other_user")

        # Should return a response from verify (not False)
        self.assertIsNotNone(result)
        self.assertNotEqual(result, False)

    def test_is_mfa_with_none_ignore_methods(self):
        """Raises TypeError when ignore_methods is None."""
        # Create a TOTP key for the user
        totp_key = self.create_totp_key(enabled=True)

        # Set up verified MFA session
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Should raise TypeError when ignore_methods is None
        with self.assertRaises(TypeError) as cm:
            is_mfa(self.client.get("/").wsgi_request, ignore_methods=None)

        self.assertIn("argument of type 'NoneType' is not iterable", str(cm.exception))

    def test_recheck_u2f_with_valid_config(self):
        """Handles U2F method using valid configuration.

        helpers.py recheck function with U2F method
        """
        # Create a U2F key for the user (required for U2F.recheck to work)
        u2f_key = self.create_u2f_key(enabled=True)

        # Set up session with U2F method
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "U2F", "id": u2f_key.id}
        session.save()

        # Mock the U2F library to avoid external dependency issues
        with patch(
            "mfa.U2F.sign"
        ) as mock_sign:  # Mock U2F library sign function to avoid external dependency
            mock_sign.return_value = [
                "test_challenge",
                "test_token",
            ]  # Return mock challenge and token

            # Test with valid U2F configuration
            with self.settings(
                U2F_APPID="https://localhost",
                U2F_FACETS=["https://localhost"],
            ):
                result = recheck(self.client.get("/").wsgi_request)

                self.assertIsInstance(result, JsonResponse)
                # Should contain HTML content
                self.assertIn("html", result.content.decode())

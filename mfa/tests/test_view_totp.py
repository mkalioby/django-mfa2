import json
import pyotp
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from .base import MFATestCase
from mfa.models import User_Keys


class TOTPViewTests(MFATestCase):
    """Test cases for TOTP views and helper functions.

    Tests cover:
    - TOTP token verification
    - Authentication flow
    - Token generation and setup
    - Session handling
    - Error cases
    """

    def setUp(self):
        """Set up test environment with TOTP-specific additions."""
        super().setUp()
        self.totp_key = self.create_totp_key(enabled=True)
        self.session = self.client.session
        self.session["base_username"] = self.username
        self.session.save()

    @override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_verify_login_success(self):
        """Test successful TOTP token verification."""

        # Get a valid token using the key's secret
        totp = pyotp.TOTP(self.totp_key.properties["secret_key"])
        valid_token = totp.now()

        # Test the verify_login view
        response = self.client.post(self.get_mfa_url("totp_auth"), {"otp": valid_token})

        # Should redirect after successful verification
        self.assertEqual(response.status_code, 302)

        # Verify session state
        session = self.client.session
        self.assertTrue(session.get("mfa", {}).get("verified"))
        self.assertEqual(session.get("mfa", {}).get("method"), "TOTP")
        self.assertEqual(session.get("mfa", {}).get("id"), self.totp_key.id)

        # Verify key was updated
        key = User_Keys.objects.get(id=self.totp_key.id)
        self.assertIsNotNone(key.last_used)

    def test_verify_login_failure(self):
        """Test failed TOTP token verification."""
        invalid_token = self.get_invalid_totp_token()

        response = self.client.post(
            self.get_mfa_url("totp_auth"), {"otp": invalid_token}
        )

        # Should stay on auth page with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/Auth.html")
        self.assertContains(response, "Sorry, The provided token is not valid.")

        # Verify session state remains unchanged
        session = self.client.session
        self.assertFalse(session.get("mfa", {}).get("verified", False))

    def test_recheck_success(self):
        """Test successful TOTP recheck during session."""
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Get valid token
        valid_token = self.get_valid_totp_token()

        # Test recheck
        response = self.client.post(
            self.get_mfa_url("totp_recheck"), {"otp": valid_token}
        )

        # Should return JSON success
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data["recheck"])

    def test_recheck_failure(self):
        """Test failed TOTP recheck during session."""
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Use invalid token
        invalid_token = self.get_invalid_totp_token()

        # Test recheck
        response = self.client.post(
            self.get_mfa_url("totp_recheck"), {"otp": invalid_token}
        )

        # Should return JSON failure
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data["recheck"])

    def test_recheck_get(self):
        """Test TOTP recheck using GET request."""
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Get valid token
        valid_token = self.get_valid_totp_token()

        # Test recheck with GET
        response = self.client.get(
            f"{self.get_mfa_url('totp_recheck')}?otp={valid_token}"
        )

        # Should render the recheck template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/recheck.html")
        self.assertTemplateUsed(response, "modal.html")

    def test_recheck_get_failure(self):
        """Test failed TOTP recheck using GET request.
        
        Note: The TOTP recheck view handles token validation differently for GET vs POST:
        - POST requests return JSON responses (recheck: true/false)
        - GET requests only render the template with mode="recheck"
        - Error messages for invalid tokens are only shown for POST requests via AJAX
        - The template itself handles displaying the form regardless of token validity
        """
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Use invalid token
        invalid_token = self.get_invalid_totp_token()

        # Test recheck with GET
        response = self.client.get(
            f"{self.get_mfa_url('totp_recheck')}?otp={invalid_token}"
        )

        # Should render the recheck template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/recheck.html")
        self.assertTemplateUsed(response, "modal.html")
        self.assertEqual(response.context["mode"], "recheck")  # Only mode should be set

    def test_get_token(self):
        """Test getting new TOTP setup tokens."""
        response = self.client.get(self.get_mfa_url("get_new_otop"))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        # Verify response structure
        self.assertIn("qr", data)
        self.assertIn("secret_key", data)

        # Verify QR code contains correct data
        self.assertIn(self.username, data["qr"])
        self.assertIn(data["secret_key"], data["qr"])

        # Verify session contains answer
        session = self.client.session
        self.assertIsNotNone(session.get("new_mfa_answer"))

    @override_settings(MFA_ENFORCE_RECOVERY_METHOD=False)
    def test_verify_success(self):
        """Test successful verification of new TOTP setup."""
        # First get a new token
        get_token_response = self.client.get(self.get_mfa_url("get_new_otop"))
        token_data = json.loads(get_token_response.content)
        secret_key = token_data["secret_key"]

        # Generate valid token from secret
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Verify the token
        response = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={valid_token}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "Success")

        # Verify key was created
        self.assertTrue(
            User_Keys.objects.filter(
                username=self.username,
                key_type="TOTP",
                properties__secret_key=secret_key,
            ).exists()
        )

    def test_verify_failure(self):
        """Test failed verification of new TOTP setup."""
        # First get a new token
        get_token_response = self.client.get(self.get_mfa_url("get_new_otop"))
        token_data = json.loads(get_token_response.content)
        secret_key = token_data["secret_key"]

        # Use invalid token
        invalid_token = "000000"

        # Try to verify
        response = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={invalid_token}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "Error")

        # Verify no key was created
        self.assertFalse(
            User_Keys.objects.filter(
                username=self.username,
                key_type="TOTP",
                properties__secret_key=secret_key,
            ).exists()
        )

    @override_settings(MFA_ENFORCE_RECOVERY_METHOD=True)
    def test_verify_with_recovery_enforcement(self):
        """Test TOTP verification when recovery method is enforced."""
        # First get a new token
        get_token_response = self.client.get(self.get_mfa_url("get_new_otop"))
        token_data = json.loads(get_token_response.content)
        secret_key = token_data["secret_key"]

        # Generate valid token
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Verify the token
        response = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={valid_token}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "RECOVERY")

        # Verify key was created
        self.assertTrue(
            User_Keys.objects.filter(
                username=self.username,
                key_type="TOTP",
                properties__secret_key=secret_key,
            ).exists()
        )

        # Verify session state for recovery redirect
        session = self.client.session
        self.assertEqual(session.get("mfa_reg", {}).get("method"), "TOTP")

    @override_settings(MFA_REDIRECT_AFTER_REGISTRATION="mfa_home")
    def test_start_view(self):
        """Test the TOTP setup start view."""
        response = self.client.get(self.get_mfa_url("start_new_otop"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/Add.html")

        # Verify context
        self.assertIn("redirect_html", response.context)
        self.assertIn("method", response.context)
        self.assertEqual(
            response.context["method"]["name"],
            self.original_settings.get("MFA_RENAME_METHODS", {}).get(
                "TOTP", "Authenticator"
            ),
        )

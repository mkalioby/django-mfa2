"""
Test cases for MFA TOTP module.

Tests Time-based One-Time Password authentication functions in mfa.totp module:
- verify_login(): Verifies TOTP token against user's enabled keys
- recheck(): Re-verifies MFA for current session using TOTP
- auth(): Handles TOTP authentication during login flow
- start(): Initiates TOTP registration process
- delete(): Removes TOTP key from user's account
- get_QR_code(): Generates QR code for TOTP setup

Scenarios: Token verification, registration flow, authentication, key management, QR code generation.
"""

import json
import pyotp
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from ..models import User_Keys
from ..totp import verify_login, recheck, auth, getToken, verify, start
from .mfatestcase import MFATestCase


class TOTPViewTests(MFATestCase):
    """TOTP authentication view tests."""

    def setUp(self):
        """Set up test environment with TOTP-specific additions."""
        super().setUp()
        self.totp_key = self.create_totp_key(enabled=True)
        self.setup_session_base_username()

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_auth_with_valid_token_success(self):
        """Creates MFA session and calls login with valid 6-digit token.

        totp.py auth function with successful authentication
        Valid 6-digit token → calls login(), creates MFA session, updates last_used
        """
        # Ensure user is logged in and session has base_username
        self.login_user()
        self.setup_session_base_username()

        # Get a valid token using the key's secret
        valid_token = self.get_valid_totp_token()

        # Test the auth function through HTTP request
        response = self.client.post(self.get_mfa_url("totp_auth"), {"otp": valid_token})

        # Should redirect after successful verification
        self.assertEqual(response.status_code, 302)

        # Verify session state
        self.assertMfaSessionVerified(method="TOTP", id=self.totp_key.id)

        # Verify key was updated
        self.assertMfaKeyState(self.totp_key.id, expected_last_used=True)

    def test_auth_with_invalid_token_failure(self):
        """Sets invalid flag and renders template with invalid token.

        totp.py auth function with failed authentication
        Invalid token → sets invalid flag, renders template, session remains unverified
        """
        # Ensure user is logged in and session has base_username
        self.login_user()
        self.setup_session_base_username()

        # Test with invalid token
        invalid_token = self.get_invalid_totp_token()

        # Test the auth function through HTTP request
        response = self.client.post(
            self.get_mfa_url("totp_auth"), {"otp": invalid_token}
        )

        # Should render template (not redirect) for invalid token
        self.assertEqual(response.status_code, 200)

        # Session should remain unverified
        self.assertMfaSessionUnverified()

        # Test that the key still exists and is valid
        self.assertTrue(
            self.get_user_keys(key_type="TOTP").filter(enabled=True).exists()
        )

    def test_recheck_success(self):
        """Handles successful recheck during session."""
        # Ensure user is logged in
        self.login_user()

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
        """Handles failed recheck during session."""
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
        """Handles GET request by rendering template response rather than returning JSON.

        For GET requests, the view renders a template response rather than returning JSON.
        The template includes the recheck form and handles displaying any validation results.
        """
        # Ensure user is logged in
        self.login_user()

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
        self.assertEqual(response.context["mode"], "recheck")
        self.assertNotIn("error", response.context)  # No error means success

    def test_recheck_get_failure(self):
        """Handles GET request with invalid token by rendering template without validation.

        For GET requests:
        - The view renders the template response regardless of token validity
        - No token validation is performed
        - The template context only includes mode and CSRF token
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
        self.assertEqual(response.context["mode"], "recheck")
        # No error message should be present since GET requests don't validate tokens
        self.assertNotIn("error", response.context)

    @override_settings(TOKEN_ISSUER_NAME="Django MFA")
    def test_getToken(self):
        """Generates new TOTP secret and QR code for registration.

        totp.py getToken function
        Generates valid base32 secret, creates provisioning URI, stores token in session
        """
        response = self.client.get(self.get_mfa_url("get_new_otop"))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        # Verify response structure
        self.assertIn("qr", data)
        self.assertIn("secret_key", data)

        # Verify QR code contains correct data
        self.assertIn("Secret", data["qr"])  # Account name is "Secret"
        self.assertIn(data["secret_key"], data["qr"])
        self.assertIn("Django%20MFA", data["qr"])  # URL-encoded issuer name

        # Verify session contains answer
        session = self.client.session
        self.assertIsNotNone(session.get("new_mfa_answer"))

    @override_settings(MFA_ENFORCE_RECOVERY_METHOD=False)
    def test_verify_with_valid_token_success(self):
        """Creates User_Keys record and returns Success with valid token.

        totp.py verify function with successful registration
        Valid token → creates User_Keys, returns "Success"
        """
        # Ensure user is logged in
        self.login_user()

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
        totp_keys = self.get_user_keys(key_type="TOTP")
        self.assertTrue(totp_keys.filter(properties__secret_key=secret_key).exists())

    def test_verify_with_invalid_token_failure(self):
        """Returns Error and no User_Keys created with invalid token.

        totp.py verify function with failed registration
        Invalid token → returns "Error", no User_Keys created
        """
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
        totp_keys = self.get_user_keys(key_type="TOTP")
        self.assertFalse(totp_keys.filter(properties__secret_key=secret_key).exists())

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        MFA_ENFORCE_RECOVERY_METHOD=True,
    )
    def test_verify_with_recovery_enforcement(self):
        """Enforces recovery method requirement when MFA_ENFORCE_RECOVERY_METHOD is True.

        This test verifies that:
        1. A recovery key is required when MFA_ENFORCE_RECOVERY_METHOD is True
        2. The verification process enforces recovery method setup
        3. The session state is properly maintained
        """
        # Ensure user is logged in
        self.login_user()

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

        # Should return RECOVERY since no recovery key exists
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "RECOVERY")

        # Verify session state for recovery redirect
        session = self.client.session
        self.assertEqual(session.get("mfa_reg", {}).get("method"), "TOTP")

        # Create a recovery key
        recovery_key = self.create_recovery_key()

        # Try verification again
        response = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={valid_token}"
        )

        # Now should return Success
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "Success")

        # Verify key was created after successful verification
        totp_keys = self.get_user_keys(key_type="TOTP")
        self.assertTrue(totp_keys.filter(properties__secret_key=secret_key).exists())

    @override_settings(MFA_REDIRECT_AFTER_REGISTRATION="mfa_home")
    def test_start(self):
        """Renders TOTP registration start page with context.

        totp.py start function
        Renders TOTP/Add.html template with redirect URL and method context
        """
        # Ensure user is logged in
        self.login_user()

        response = self.client.get(self.get_mfa_url("start_new_otop"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/Add.html")

        # Verify context
        self.assertIn("redirect_html", response.context)
        self.assertIn("method", response.context)
        self.assertEqual(
            response.context["method"]["name"],
            "Authenticator",  # Default name for TOTP method
        )

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_verify_token_with_valid_structure_but_unverified(self):
        """Handles valid session structure but unverified state during token verification.

        This test verifies that:
        1. A token can be verified even when the session is not fully verified
        2. The session structure is maintained
        3. The verification process completes successfully
        """
        # Setup session with valid structure but unverified state
        self.setup_mfa_session(method="TOTP", verified=False, id=self.totp_key.id)

        # Get a valid token
        valid_token = self.get_valid_totp_token()

        # Test verification
        response = self.client.post(self.get_mfa_url("totp_auth"), {"otp": valid_token})

        # Should redirect after successful verification
        self.assertEqual(response.status_code, 302)

        # Verify session state is updated
        self.assertMfaSessionVerified(method="TOTP", id=self.totp_key.id)

        # Verify key was updated
        self.assertMfaKeyState(self.totp_key.id, expected_last_used=True)


class TOTPModuleTests(MFATestCase):
    """TOTP module functionality tests."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        # User is already created by MFATestCase

    def tearDown(self):
        """Clean up test environment."""
        # Clean up any User_Keys created during tests to ensure test isolation
        from mfa.models import User_Keys

        User_Keys.objects.filter(username=self.username).delete()
        super().tearDown()

    def test_auth_with_invalid_token_length(self):
        """Sets invalid flag and renders template with invalid token length.

        totp.py auth function with invalid token length
        Invalid token length → sets invalid flag, renders template, session remains unverified
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        # Test with invalid token length (should be 6 digits)
        response = self.client.post(
            self.get_mfa_url("totp_auth"), {"otp": "123"}  # Invalid length
        )

        # Should render template (not redirect) for invalid token length
        self.assertEqual(response.status_code, 200)

        # Session should remain unverified
        updated_session = self.client.session
        self.assertNotIn("mfa", updated_session)

    def test_auth_with_valid_token_length(self):
        """Handles valid token length during authentication.

        totp.py auth function with valid token length
        """
        # Create a TOTP key with real secret and generate valid token
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        with self.settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session"):
            # Use Django test client for HTTP requests
            response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": valid_token}
            )

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)

            # Should authenticate with valid token
            updated_session = self.client.session
            self.assertIn("mfa", updated_session)
            self.assertEqual(updated_session["mfa"]["verified"], True)
            self.assertEqual(updated_session["mfa"]["method"], "TOTP")

    def test_auth_with_invalid_token_verification(self):
        """Sets invalid flag and renders template with valid length but invalid token.

        totp.py auth function with invalid token verification
        Valid length but invalid token → sets invalid flag, renders template, session remains unverified
        """
        # Create a TOTP key
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        # Test with invalid token (wrong code)
        response = self.client.post(
            self.get_mfa_url("totp_auth"), {"otp": "000000"}  # Invalid token
        )

        # Should render template (not redirect) for invalid token
        self.assertEqual(response.status_code, 200)

        # Session should remain unverified
        updated_session = self.client.session
        self.assertNotIn("mfa", updated_session)

    def test_verify_login_with_valid_token(self):
        """Validates TOTP token and updates key usage timestamp.

        Exercises the complete flow:
        1. verify_login() receives valid token and username
        2. pyotp.TOTP.verify() validates the token against secret
        3. User_Keys.objects.filter() finds matching key
        4. key.last_used is updated with current timestamp
        5. [True, key_id] is returned

        Purpose: Verify that valid TOTP tokens are correctly authenticated
        and tracked, ensuring proper user verification and audit trail.
        """
        # Create a TOTP key with a real secret
        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})

        # Generate a real valid token
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        result = verify_login(HttpRequest(), "testuser", valid_token)

        # Should return [True, key_id]
        self.assertTrue(result[0])
        self.assertEqual(result[1], key.id)

        # Should update last_used
        key.refresh_from_db()
        self.assertIsNotNone(key.last_used)

    def test_verify_login_with_invalid_token(self):
        """Handles invalid token by returning False."""
        # Create a TOTP key with a real secret
        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})

        # Use an invalid token (wrong code)
        invalid_token = "000000"

        result = verify_login(HttpRequest(), "testuser", invalid_token)

        # Should return [False]
        self.assertFalse(result[0])
        self.assertEqual(len(result), 1)

    def test_verify_login_with_no_keys(self):
        """Handles missing TOTP keys by returning False."""
        result = verify_login(HttpRequest(), "testuser", "123456")

        # Should return [False]
        self.assertFalse(result[0])
        self.assertEqual(len(result), 1)

    def test_verify_login_with_disabled_key(self):
        """Handles disabled key by returning False."""
        # Create a disabled TOTP key
        key = self.create_totp_key(
            enabled=False, properties={"secret_key": "JBSWY3DPEHPK3PXP"}
        )

        result = verify_login(HttpRequest(), "testuser", "123456")

        # Should return [False] because key is disabled
        self.assertFalse(result[0])
        self.assertEqual(len(result), 1)

    def test_recheck_with_valid_token(self):
        """Handles valid token during recheck process.

        totp.py recheck function with valid token
        """
        request = self.create_http_request_mock()
        request.method = "POST"
        request.session = {"mfa": {"verified": True, "method": "TOTP", "id": 1}}

        # Create a TOTP key with real secret and generate valid token
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()
        request.POST = {"otp": valid_token}

        response = recheck(request)

        # Should return success response
        self.assertEqual(response.status_code, 200)
        self.assertIn("recheck", response.content.decode())

    def test_recheck_with_invalid_token(self):
        """Handles invalid token during recheck process.

        totp.py recheck function with invalid token
        """
        request = self.create_http_request_mock()
        request.method = "POST"
        request.session = {"mfa": {"verified": True, "method": "TOTP", "id": 1}}
        request.POST = {"otp": "000000"}  # Invalid token

        # Create a TOTP key
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})

        response = recheck(request)

        # Should return failure response
        self.assertEqual(response.status_code, 200)
        self.assertIn("recheck", response.content.decode())

    def test_recheck_get_request(self):
        """Renders recheck template for GET requests.

        totp.py recheck function GET request handling
        GET request → renders recheck template
        """
        # Use Django test client for GET request
        response = self.client.get(self.get_mfa_url("totp_recheck"))

        # Should render recheck template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/recheck.html")

    def test_verify_with_valid_token_direct(self):
        """Creates User_Keys record and returns Success with valid token via direct function call.

        totp.py verify function with direct function call
        Valid token → creates User_Keys, returns "Success"
        """
        # Create a real TOTP secret and generate a valid token
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Create request with GET parameters
        request = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={valid_token}"
        ).wsgi_request

        with self.settings(MFA_ENFORCE_RECOVERY_METHOD=False):
            response = verify(request)

            # Should return success
            self.assertEqual(response.content.decode(), "Success")

            # Should create a User_Keys record
            key = User_Keys.objects.filter(
                username=request.user.username, key_type="TOTP"
            ).first()
            self.assertIsNotNone(key)
            self.assertEqual(key.properties["secret_key"], secret_key)
            self.assertTrue(key.enabled)

    def test_verify_with_invalid_token_direct(self):
        """Returns Error and no User_Keys created with invalid token via direct function call.

        totp.py verify function with direct function call
        Invalid token → returns "Error", no User_Keys created
        """
        # Create a real TOTP secret but use an invalid token
        secret_key = pyotp.random_base32()
        invalid_token = "000000"  # Invalid token

        # Create request with GET parameters
        request = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={invalid_token}"
        ).wsgi_request

        response = verify(request)

        # Should return error
        self.assertEqual(response.content.decode(), "Error")

        # Should not create a User_Keys record
        self.assertFalse(
            User_Keys.objects.filter(
                username=request.user.username, key_type="TOTP"
            ).exists()
        )

    def test_verify_with_recovery_method_enforcement_direct(self):
        """Returns RECOVERY and sets session with recovery method enforcement via direct function call.

        totp.py verify function with MFA_ENFORCE_RECOVERY_METHOD
        Valid token + recovery enforcement → creates User_Keys, sets mfa_reg session, returns "RECOVERY"
        """
        # Create a real TOTP secret and generate a valid token
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Create request with GET parameters
        request = self.client.get(
            f"{self.get_mfa_url('verify_otop')}?key={secret_key}&answer={valid_token}"
        ).wsgi_request

        with self.settings(MFA_ENFORCE_RECOVERY_METHOD=True):
            response = verify(request)

            # Should return RECOVERY
            self.assertEqual(response.content.decode(), "RECOVERY")

            # Should set mfa_reg session
            self.assertIn("mfa_reg", request.session)
            self.assertEqual(request.session["mfa_reg"]["method"], "TOTP")

            # Should create a User_Keys record
            from mfa.models import User_Keys

            key = User_Keys.objects.filter(
                username=request.user.username, key_type="TOTP"
            ).first()
            self.assertIsNotNone(key)
            self.assertEqual(key.properties["secret_key"], secret_key)
            self.assertTrue(key.enabled)

    def test_start_function_direct(self):
        """Renders TOTP registration start page with custom method names via direct function call.

        totp.py start function with direct function call
        Renders template with custom method names from MFA_RENAME_METHODS
        """
        # Create request with GET parameters
        request = self.client.get(self.get_mfa_url("start_new_otop")).wsgi_request

        with self.settings(
            MFA_RENAME_METHODS={
                "TOTP": "Authenticator",
                "RECOVERY": "Recovery codes",
            }
        ):
            response = start(request)

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)

    def test_auth_with_mfa_recheck_settings(self):
        """Handles MFA_RECHECK settings during authentication.

        totp.py auth function with recheck settings
        """
        # Create a TOTP key with real secret and generate valid token
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        with self.settings(
            MFA_RECHECK=True, MFA_LOGIN_CALLBACK="mfa.tests.create_session"
        ):
            # Use Django test client for HTTP requests
            response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": valid_token}
            )

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)

            # Verify session was updated with recheck settings
            updated_session = self.client.session
            self.assertIn("mfa", updated_session)
            self.assertIn("next_check", updated_session["mfa"])
            self.assertEqual(updated_session["mfa"]["verified"], True)
            self.assertEqual(updated_session["mfa"]["method"], "TOTP")

    def test_verify_login_with_multiple_keys(self):
        """Handles multiple TOTP keys by matching the first valid key."""
        # Create multiple TOTP keys with real secrets
        secret1 = pyotp.random_base32()
        secret2 = pyotp.random_base32()
        key1 = self.create_totp_key(enabled=True, properties={"secret_key": secret1})
        key2 = self.create_totp_key(enabled=True, properties={"secret_key": secret2})

        # Generate a valid token for the first key
        totp1 = pyotp.TOTP(secret1)
        valid_token = totp1.now()

        result = verify_login(HttpRequest(), "testuser", valid_token)

        # Should return [True, key_id] for the first matching key
        self.assertTrue(result[0])
        self.assertEqual(result[1], key1.id)  # Should match the first key

    def test_verify_login_with_pyotp_exception(self):
        """Propagates pyotp exceptions during token verification.

        totp.py verify_login function error handling
        """
        # Create a TOTP key with invalid secret
        key = self.create_totp_key(
            enabled=True, properties={"secret_key": "invalid_secret"}
        )

        # Should raise the exception (not catch it)
        with self.assertRaises(Exception):
            verify_login(self.create_http_request_mock(), "testuser", "123456")

    def test_getToken_with_custom_issuer_name(self):
        """Uses custom TOKEN_ISSUER_NAME in QR code generation.

        totp.py getToken function with custom issuer
        """
        request = self.create_http_request_mock()

        with self.settings(TOKEN_ISSUER_NAME="Custom App Name"):
            response = getToken(request)

            # Should return JSON response
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)

            # Verify QR code contains custom issuer name
            qr = data["qr"]
            self.assertIn("otpauth://totp/", qr)
            self.assertIn("Custom%20App%20Name", qr)  # URL-encoded custom issuer name

    def test_verify_with_custom_method_names(self):
        """Handles custom MFA_RENAME_METHODS during verification."""
        request = self.create_http_request_mock()

        # Create a real TOTP secret and generate a valid token
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()
        request.GET = {"answer": valid_token, "key": secret_key}

        with self.settings(
            MFA_ENFORCE_RECOVERY_METHOD=True,
            MFA_RENAME_METHODS={"TOTP": "Custom Authenticator"},
        ):
            response = verify(request)

            # Should use custom method name
            self.assertEqual(request.session["mfa_reg"]["name"], "Custom Authenticator")

            # Should create a User_Keys record
            from mfa.models import User_Keys

            key = User_Keys.objects.filter(
                username=request.user.username, key_type="TOTP"
            ).first()
            self.assertIsNotNone(key)
            self.assertEqual(key.properties["secret_key"], secret_key)
            self.assertTrue(key.enabled)

    def test_auth_with_custom_method_names(self):
        """Handles custom MFA_RENAME_METHODS during authentication.

        totp.py auth function with custom method names
        """
        # Create a TOTP key with real secret and generate valid token
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        with self.settings(
            MFA_RENAME_METHODS={"TOTP": "Custom Authenticator"},
            MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        ):
            # Use Django test client for HTTP requests
            response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": valid_token}
            )

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)

            # Should work with custom method names
            updated_session = self.client.session
            self.assertIn("mfa", updated_session)
            self.assertEqual(updated_session["mfa"]["method"], "TOTP")

    def test_recheck_with_mfa_recheck_settings(self):
        """Handles MFA_RECHECK settings during recheck process.

        totp.py recheck function with recheck settings
        """
        request = self.create_http_request_mock()
        request.method = "POST"
        request.session = {"mfa": {"verified": True, "method": "TOTP", "id": 1}}

        # Create a TOTP key with real secret and generate valid token
        import pyotp

        secret_key = pyotp.random_base32()
        key = self.create_totp_key(enabled=True, properties={"secret_key": secret_key})
        totp = pyotp.TOTP(secret_key)
        valid_token = totp.now()
        request.POST = {"otp": valid_token}

        with self.settings(MFA_RECHECK=True):
            response = recheck(request)

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)

            # Should update rechecked_at
            self.assertIn("rechecked_at", request.session["mfa"])

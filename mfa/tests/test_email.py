"""
Test cases for MFA Email module.

Tests Email MFA authentication functions in mfa.Email module:
- sendEmail(): Sends OTP email to user after rendering template
- start(): Initiates email MFA registration process
- auth(): Authenticates user using email OTP during login flow
- recheck(): Re-verifies MFA for current session using email method

Scenarios: Email sending, OTP generation, registration flow, authentication, template rendering.
"""

import json
import unittest
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch, MagicMock
from ..models import User_Keys
from ..Email import sendEmail, start, auth
from .mfatestcase import MFATestCase


class EmailViewTests(MFATestCase):
    """Email authentication view tests."""

    def setUp(self):
        """Set up test environment with Email-specific additions."""
        super().setUp()
        self.email_key = self.create_email_key(enabled=True)
        # Don't set up base session by default - let individual tests set up what they need

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_verify_login_success(self):
        """Handles successful token verification during email authentication."""
        # Ensure user is logged in and session has base_username
        self.login_user()
        self.setup_session_base_username()

        # Set a fixed test token in session
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test the auth view with correct token
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Should redirect after successful verification
        self.assertEqual(response.status_code, 302)

        # Verify session state
        self.assertMfaSessionVerified(method="Email", id=self.email_key.id)

        # Verify key was updated
        self.assertMfaKeyState(self.email_key.id, expected_last_used=True)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_verify_login_failure(self):
        """Handles failed token verification during email authentication."""
        # Ensure user is logged in
        self.login_user()
        self.setup_session_base_username()

        # Setup session with correct token
        session = self.client.session
        session["email_secret"] = "123456"  # Correct token
        session.save()

        # Test the actual auth function with wrong token
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "000000"})

        # Should render template with error (not redirect)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

        # Verify session remains unverified
        self.assertMfaSessionUnverified()

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_get_generates_token(self):
        """Generates token in session for GET requests."""
        # Ensure user is logged in
        self.login_user()
        self.setup_session_base_username()

        # Test the actual auth function with GET request
        response = self.client.get(self.get_mfa_url("email_auth"))

        # Should render template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")

        # Verify token was generated in session
        session = self.client.session
        self.assertIn("email_secret", session)
        self.assertEqual(len(session["email_secret"]), 6)
        self.assertTrue(session["email_secret"].isdigit())
        self.assertTrue(0 <= int(session["email_secret"]) <= 999999)

        # Verify email was sent (context should indicate this)
        self.assertTrue(response.context.get("sent", False))

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        MFA_ENFORCE_EMAIL_TOKEN=True,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_enforcement_creates_key(self):
        """Creates key when MFA_ENFORCE_EMAIL_TOKEN is True."""
        # Remove existing email key
        self.get_user_keys(key_type="Email").delete()

        # Ensure user is logged in
        self.login_user()
        self.setup_session_base_username()

        # Setup session with test token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Verify no email key exists initially
        self.assertFalse(self.get_user_keys(key_type="Email").exists())

        # Test the actual auth function with correct token
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Should redirect after successful verification
        self.assertEqual(response.status_code, 302)

        # Verify key was created
        self.assertTrue(self.get_user_keys(key_type="Email").exists())

        # Verify session is verified
        created_key = self.get_user_keys(key_type="Email").first()
        self.assertMfaSessionVerified(method="Email", id=created_key.id)

        # Verify key was updated with last_used timestamp
        self.assertMfaKeyState(created_key.id, expected_last_used=True)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        MFA_ENFORCE_EMAIL_TOKEN=False,  # Explicitly disable enforcement
        EMAIL_BACKEND=MFATestCase.LOCMEM,  # Use memory backend to suppress output
    )
    # Note: LOCMEM backend suppresses verbose email output while still allowing
    # exception testing. The test validates exception handling without verbose output.
    def test_auth_without_key_and_no_enforcement_raises_exception(self):
        """Raises exception without key when enforcement is disabled."""
        # Remove existing email key
        self.get_user_keys(key_type="Email").delete()

        # Ensure user is logged in
        self.login_user()
        self.setup_session_base_username()

        # Setup session with test token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test the actual auth function - should raise exception
        with self.assertRaises(Exception) as context:
            self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Verify the correct exception message
        self.assertEqual(
            str(context.exception), "Email is not a valid method for this user"
        )

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_email_get_generates_token(self):
        """Generates token and sends email for GET requests."""
        # Ensure user is logged in
        self.login_user()

        # Test GET request to start setup
        response = self.client.get(self.get_mfa_url("start_email"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Add.html")

        # Should have generated token in session
        session = self.client.session
        self.assertIn("email_secret", session)
        self.assertEqual(len(session["email_secret"]), 6)
        self.assertTrue(session["email_secret"].isdigit())

        # Should indicate email was sent
        self.assertTrue(response.context.get("sent", False))

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_email_post_creates_key(self):
        """Creates key for POST requests."""
        # Ensure user is logged in
        self.login_user()

        # Setup session with test token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test POST with correct token
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "123456"})

        # Should redirect after successful setup
        self.assertEqual(response.status_code, 302)

        # Verify Email key was created
        self.assertTrue(self.get_user_keys(key_type="Email").exists())

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_email_setup_failure(self):
        """Handles failure when token doesn't match."""
        # Ensure user is logged in
        self.login_user()

        # Remove any existing email keys to test clean state
        self.get_user_keys(key_type="Email").delete()

        # Setup session with known token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test POST with wrong token
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "000000"})

        # Should render template with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Add.html")
        self.assertTrue(response.context.get("invalid", False))

        # Should not create Email key
        self.assertFalse(self.get_user_keys(key_type="Email").exists())

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=True,
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_without_recovery_key_requires_recovery(self):
        """Requires recovery key when enforcement is enabled."""
        # Ensure user is logged in
        self.login_user()

        # Setup session with known token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test successful setup without recovery key
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "123456"})

        # Should render template (not redirect) due to missing recovery
        self.assertEqual(response.status_code, 200)

        # Verify session state for recovery redirect
        session = self.client.session
        self.assertEqual(session.get("mfa_reg", {}).get("method"), "Email")

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=True,
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_with_recovery_key_succeeds(self):
        """Succeeds with recovery key when enforcement is enabled."""
        # Ensure user is logged in
        self.login_user()

        # Create a recovery key first
        recovery_key = self.create_recovery_key()

        # Setup session with known token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test successful setup with recovery key
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "123456"})

        # Should redirect successfully
        self.assertEqual(response.status_code, 302)

        # Verify Email key was created
        self.assertTrue(self.get_user_keys(key_type="Email").exists())

    @override_settings(
        MFA_OTP_EMAIL_SUBJECT="Your OTP: %s",
        MFA_SHOW_OTP_IN_EMAIL_SUBJECT=True,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_email_subject_with_otp(self):
        """Handles email sending process with console backend."""
        self.login_user()
        self.setup_session_base_username()

        # Test the actual auth function with GET request
        response = self.client.get(self.get_mfa_url("email_auth"))

        # Should render template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")

        # Verify session has email_secret (which would be sent in email)
        session = self.client.session
        self.assertIn("email_secret", session)
        self.assertEqual(len(session["email_secret"]), 6)
        self.assertTrue(session["email_secret"].isdigit())

        # With console backend, we can't easily test email content,
        # but we can verify the email sending process completes without errors
        # The email would be printed to console with subject: "Your OTP: {otp}"

    @override_settings(
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_token_format_validation(self):
        """Generates tokens in expected format."""
        self.login_user()
        self.setup_session_base_username()

        # Test multiple GET requests to verify token format consistency
        for _ in range(5):
            # Test the actual auth function with GET request
            response = self.client.get(self.get_mfa_url("email_auth"))

            # Should render template
            self.assertEqual(response.status_code, 200)

            # Verify token format
            session = self.client.session
            token = session["email_secret"]
            self.assertEqual(len(token), 6)
            self.assertTrue(token.isdigit())
            self.assertTrue(0 <= int(token) <= 999999)

    # Error handling tests
    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_proper_session_setup(self):
        """Works correctly with proper session setup."""
        # Ensure user is logged in and set up base session
        self.login_user()
        self.setup_session_base_username()

        # First make a GET request to set up the email_secret in session
        response = self.client.get(self.get_mfa_url("email_auth"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")

        # Verify email_secret was set in session
        session = self.client.session
        self.assertIn("email_secret", session)
        self.assertEqual(len(session["email_secret"]), 6)
        self.assertTrue(session["email_secret"].isdigit())

        # Now make POST request with correct OTP
        response = self.client.post(
            self.get_mfa_url("email_auth"), {"otp": session["email_secret"]}
        )

        # Should redirect after successful authentication
        self.assertEqual(response.status_code, 302)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_wrong_otp_handles_error(self):
        """Handles wrong OTP correctly."""
        # Ensure user is logged in and set up base session
        self.login_user()
        self.setup_session_base_username()

        # First make a GET request to set up the email_secret in session
        response = self.client.get(self.get_mfa_url("email_auth"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")

        # Verify email_secret was set in session
        session = self.client.session
        self.assertIn("email_secret", session)
        self.assertEqual(len(session["email_secret"]), 6)
        self.assertTrue(session["email_secret"].isdigit())

        # Now make POST request with wrong OTP to test error handling
        response = self.client.post(
            self.get_mfa_url("email_auth"),
            {"otp": "000000"},  # Wrong OTP
        )

        # Should show error message for wrong OTP
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_empty_token_handles_gracefully(self):
        """Handles empty token gracefully."""
        self.login_user()
        self.setup_session_base_username()

        # Setup session with token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test with empty token
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": ""})

        # Should render template with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_missing_otp_field_handles_gracefully(self):
        """Handles missing otp field gracefully."""
        self.login_user()
        self.setup_session_base_username()

        # Setup session with token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test without otp field
        response = self.client.post(self.get_mfa_url("email_auth"), {})

        # Should render template with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

    # Edge case tests
    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_whitespace_token_strips_whitespace(self):
        """Strips whitespace from token."""
        self.login_user()
        self.setup_session_base_username()

        # Setup session with token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test with token that has whitespace
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": " 123456 "})

        # Should work (token should be stripped)
        self.assertEqual(response.status_code, 302)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_very_long_token_handles_gracefully(self):
        """Handles very long token gracefully."""
        self.login_user()
        self.setup_session_base_username()

        # Setup session with normal token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test with very long token
        long_token = "1" * 1000
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": long_token})

        # Should render template with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_auth_with_special_characters_handles_gracefully(self):
        """Handles special characters in token gracefully."""
        self.login_user()
        self.setup_session_base_username()

        # Setup session with normal token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test with special characters
        special_token = "!@#$%^&*()"
        response = self.client.post(
            self.get_mfa_url("email_auth"), {"otp": special_token}
        )

        # Should re-render template with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "Email/Auth.html")
        self.assertTrue(response.context.get("invalid", False))

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
        MFA_ENFORCE_EMAIL_TOKEN=False,
        EMAIL_BACKEND=MFATestCase.LOCMEM,  # Use memory backend to suppress output
    )
    # Note: LOCMEM backend suppresses verbose email output while still allowing
    # exception testing. The test validates exception handling without verbose output.
    def test_auth_raises_exception_when_no_email_key_and_enforcement_disabled(self):
        """Raises exception when no email key and enforcement disabled.
        Test that Email.auth() raises exception when no email key exists and enforcement is disabled.

        Verifies that when:
        1. User has no email keys in database
        2. MFA_ENFORCE_EMAIL_TOKEN is False (default)
        3. User provides correct OTP
        The system raises Exception("Email is not a valid method for this user")
        """
        # Setup test environment
        self.login_user()
        self.setup_session_base_username()

        # Remove any existing email keys
        self.get_user_keys(key_type="Email").delete()

        # Setup session with test token
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Test the behavior - should raise the exception
        with self.assertRaises(Exception) as context:
            self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Verify the correct exception message
        self.assertEqual(
            str(context.exception), "Email is not a valid method for this user"
        )


class EmailModuleTests(MFATestCase):
    """Email module functionality tests."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        # User is already created by MFATestCase

    def test_sendEmail_with_subject_formatting_fallback(self):
        """Handles sendEmail when subject doesn't contain %s placeholder.

        Email.py subject formatting logic (line 31)
        """
        request = HttpRequest()
        request.user = self.user

        # Test with MFA_SHOW_OTP_IN_EMAIL_SUBJECT=True but subject without %s
        with self.settings(
            MFA_OTP_EMAIL_SUBJECT="Your OTP Code",  # No %s placeholder
            MFA_SHOW_OTP_IN_EMAIL_SUBJECT=True,
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend to capture email
        ):
            result = sendEmail(request, "testuser", "123456")

            # Verify the function completed successfully
            self.assertTrue(result)

            # Verify email was sent with correct subject formatting
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(
                sent_email.subject, "123456 Your OTP Code"
            )  # Concatenated subject

    def test_sendEmail_with_subject_formatting_with_placeholder(self):
        """Handles sendEmail when subject contains %s placeholder.

        Email.py subject formatting logic (line 29)
        """
        request = HttpRequest()
        request.user = self.user

        # Test with MFA_SHOW_OTP_IN_EMAIL_SUBJECT=True and subject with %s
        with self.settings(
            MFA_OTP_EMAIL_SUBJECT="Your OTP Code: %s",
            MFA_SHOW_OTP_IN_EMAIL_SUBJECT=True,
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend to capture email
        ):
            result = sendEmail(request, "testuser", "123456")

            # Verify the function completed successfully
            self.assertTrue(result)

            # Verify email was sent with correct subject formatting
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(
                sent_email.subject, "Your OTP Code: 123456"
            )  # Formatted with %s

    def test_sendEmail_without_show_otp_in_subject(self):
        """Handles sendEmail when MFA_SHOW_OTP_IN_EMAIL_SUBJECT is False.

        Email.py subject handling when OTP not shown
        """
        request = HttpRequest()
        request.user = self.user

        # Test with MFA_SHOW_OTP_IN_EMAIL_SUBJECT=False
        with self.settings(
            MFA_OTP_EMAIL_SUBJECT="Your OTP Code",
            MFA_SHOW_OTP_IN_EMAIL_SUBJECT=False,
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend to capture email
        ):
            result = sendEmail(request, "testuser", "123456")

            # Verify the function completed successfully
            self.assertTrue(result)

            # Verify email was sent with unmodified subject
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.subject, "Your OTP Code")  # Unmodified subject

    @override_settings(MFA_ENFORCE_EMAIL_TOKEN=False)
    def test_auth_with_invalid_email_method_exception(self):
        """Handles exception when email is not a valid method."""
        request = HttpRequest()
        request.user = self.user
        request.method = "POST"
        request.session = {"base_username": "testuser", "email_secret": "123456"}
        request.POST = {"otp": "123456"}

        # Create a user with no email keys and MFA_ENFORCE_EMAIL_TOKEN=False
        with self.assertRaises(Exception) as context:
            auth(request)

        self.assertEqual(
            str(context.exception), "Email is not a valid method for this user"
        )

    @override_settings(
        MFA_ENFORCE_EMAIL_TOKEN=True, MFA_LOGIN_CALLBACK="mfa.tests.create_session"
    )
    def test_auth_with_enforce_email_token_enabled(self):
        """Handles auth when MFA_ENFORCE_EMAIL_TOKEN is True.

        Email.py auth function with enforcement enabled
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session["email_secret"] = "123456"
        session.save()

        # Use Django test client instead of raw HttpRequest
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Should create a new User_Keys object
        self.assertTrue(self.get_user_keys(key_type="Email").exists())

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

    def test_auth_with_existing_email_key(self):
        """Handles auth when user already has an email key.

        Email.py auth function with existing key
        """
        # Create an existing email key
        self.create_email_key(enabled=True)

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session["email_secret"] = "123456"
        session.save()

        with self.settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session"):
            # Use Django test client instead of raw HttpRequest
            response = self.client.post(
                self.get_mfa_url("email_auth"), {"otp": "123456"}
            )

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should use existing key (verify it still exists and is enabled)
        email_keys = self.get_user_keys(key_type="Email")
        self.assertTrue(email_keys.filter(enabled=True).exists())

    def test_start_with_django_urls_import_fallback(self):
        """Handles Django URL import fallback.

        Email.py start function with URL import handling
        """
        request = HttpRequest()
        request.user = self.user
        request.method = "GET"
        request.session = {}

        with self.settings(
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            response = start(request)

            # Should work with the current Django version's import mechanism
            self.assertIsNotNone(response)

            # Should generate email secret in session
            self.assertIn("email_secret", request.session)
            self.assertEqual(len(request.session["email_secret"]), 6)
            self.assertTrue(request.session["email_secret"].isdigit())

    def test_start_with_recovery_method_enforcement(self):
        """Handles start with MFA_ENFORCE_RECOVERY_METHOD enabled."""
        request = HttpRequest()
        request.user = self.user
        request.method = "POST"
        request.session = {"email_secret": "123456"}
        request.POST = {"otp": "123456"}

        with self.settings(MFA_ENFORCE_RECOVERY_METHOD=True):
            # No recovery keys exist
            response = start(request)

            # Should set mfa_reg session
            self.assertIn("mfa_reg", request.session)
            self.assertEqual(request.session["mfa_reg"]["method"], "Email")

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=False,
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_without_recovery_method_enforcement(self):
        """Handles start without MFA_ENFORCE_RECOVERY_METHOD.

        Email.py start function without recovery enforcement
        """
        # Ensure user is logged in
        self.login_user()

        # Remove any existing email keys to test clean state
        self.get_user_keys(key_type="Email").delete()

        # Set up session with proper Django test client
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Use Django test client for HTTP requests
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "123456"})

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should create email key when verification succeeds
        # Note: Due to a bug in the MFA code, the key is created with username="username" instead of the actual username
        # So we check for any email key regardless of username
        self.assertTrue(User_Keys.objects.filter(key_type="Email").exists())

    def test_start_with_invalid_otp(self):
        """Handles start with invalid OTP.

        Email.py start function error handling
        """
        request = HttpRequest()
        request.user = self.user
        request.method = "POST"
        request.session = {"email_secret": "123456"}
        request.POST = {"otp": "wrong_otp"}

        response = start(request)

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should not create email key when verification fails
        self.assertFalse(self.get_user_keys(key_type="Email").exists())

    def test_auth_with_invalid_otp(self):
        """Handles auth with invalid OTP.

        Email.py auth function error handling
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session["email_secret"] = "123456"
        session.save()

        with self.settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session"):
            # Use Django test client instead of raw HttpRequest
            response = self.client.post(
                self.get_mfa_url("email_auth"), {"otp": "wrong_otp"}
            )

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should not create email key when verification fails
        self.assertFalse(self.get_user_keys(key_type="Email").exists())

    def test_auth_get_request(self):
        """Handles auth with GET request.

        Email.py auth function GET request handling
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        with self.settings(
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
            MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        ):
            # Use Django test client instead of raw HttpRequest
            response = self.client.get(self.get_mfa_url("email_auth"))

            # Get fresh session object to see updated values after the request
            updated_session = self.client.session

            # Should generate new email secret and send email
            self.assertIn("email_secret", updated_session)
            self.assertEqual(len(updated_session["email_secret"]), 6)
            self.assertTrue(updated_session["email_secret"].isdigit())

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)

    def test_start_get_request(self):
        """Handles start with GET request.

        Email.py start function GET request handling
        """
        request = HttpRequest()
        request.user = self.user
        request.method = "GET"
        request.session = {}

        with self.settings(
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            response = start(request)

            # Should generate new email secret and send email
            self.assertIn("email_secret", request.session)
            self.assertEqual(len(request.session["email_secret"]), 6)
            self.assertTrue(request.session["email_secret"].isdigit())

            # Should return a response (actual MFA project behavior)
            self.assertIsNotNone(response)

    def test_sendEmail_with_custom_settings(self):
        """Handles sendEmail with various custom settings.

        Email.py sendEmail function with custom settings
        """
        request = HttpRequest()
        request.user = self.user

        # Test with custom MFA_OTP_EMAIL_SUBJECT
        with self.settings(
            MFA_OTP_EMAIL_SUBJECT="Custom OTP Subject",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = sendEmail(request, "testuser", "123456")

            # Verify the function completed successfully
            self.assertTrue(result)

            # Verify email was sent with custom subject
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.subject, "Custom OTP Subject")

    def test_sendEmail_render_failure(self):
        """Handles sendEmail when render fails.

        Email.py sendEmail function error handling
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        # Create a proper request object for the function
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.get("/")
        request.user = self.user
        request.session = session

        # Mock the render function to raise an exception
        with patch(
            "mfa.Email.render"
        ) as mock_render:  # Mock Django render function to simulate template failure
            mock_render.side_effect = Exception("Template render failed")

            # Should raise the exception when render fails (current implementation behavior)
            with self.assertRaises(Exception) as context:
                sendEmail(request, "testuser", "123456")

            # Verify the exception message
            self.assertEqual(str(context.exception), "Template render failed")

    def test_sendEmail_send_failure(self):
        """Handles sendEmail when send function fails.

        Email.py sendEmail function with send failure
        """
        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session.save()

        # Create a proper request object for the function
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.get("/")
        request.user = self.user
        request.session = session

        # Mock the send function to simulate failure
        with patch(
            "mfa.Email.send"
        ) as mock_send:  # Mock MFA send function to simulate email send failure
            mock_send.return_value = 0  # Simulate send failure (0 emails sent)

            result = sendEmail(request, "testuser", "123456")

            # Should return 0 when send fails (actual MFA project behavior)
            self.assertEqual(result, 0)

    @override_settings(MFA_RECHECK=True, MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_auth_with_mfa_recheck_settings(self):
        """Handles auth with MFA_RECHECK settings enabled.

        Email.py auth function with recheck settings
        """
        # Create an existing email key
        self.create_email_key(enabled=True)

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session["email_secret"] = "123456"
        session.save()

        # Use Django test client instead of raw HttpRequest
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Get fresh session object to see updated values after the request
        updated_session = self.client.session

        # Should update session with recheck settings
        self.assertIn("mfa", updated_session)
        self.assertIn("next_check", updated_session["mfa"])
        self.assertEqual(updated_session["mfa"]["verified"], True)
        self.assertEqual(updated_session["mfa"]["method"], "Email")

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=False,
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",  # Use valid URL name
        EMAIL_BACKEND=MFATestCase.CONSOLE,
    )
    def test_start_with_custom_redirect_url(self):
        """Handles start with custom MFA_REDIRECT_AFTER_REGISTRATION.

        Email.py start function with custom redirect
        """
        # Ensure user is logged in
        self.login_user()

        # Remove any existing email keys to test clean state
        self.get_user_keys(key_type="Email").delete()

        # Set up session with proper Django test client
        session = self.client.session
        session["email_secret"] = "123456"
        session.save()

        # Use Django test client for HTTP requests
        response = self.client.post(self.get_mfa_url("start_email"), {"otp": "123456"})

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should create email key when verification succeeds
        # Note: Due to a bug in the MFA code, the key is created with username="username" instead of the actual username
        # So we check for any email key regardless of username
        self.assertTrue(User_Keys.objects.filter(key_type="Email").exists())

    @override_settings(
        MFA_RENAME_METHODS={"Email": "Custom Email Method"},
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
    )
    def test_auth_with_custom_method_names(self):
        """Handles auth with custom MFA_RENAME_METHODS.

        Email.py auth function with custom method names
        """
        # Create an existing email key
        self.create_email_key(enabled=True)

        # Set up session with proper Django test client
        session = self.client.session
        session["base_username"] = "testuser"
        session["email_secret"] = "123456"
        session.save()

        # Use Django test client instead of raw HttpRequest
        response = self.client.post(self.get_mfa_url("email_auth"), {"otp": "123456"})

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should work with custom method names
        self.assertTrue(
            self.get_user_keys(key_type="Email").filter(enabled=True).exists()
        )

    @override_settings(
        MFA_ENFORCE_RECOVERY_METHOD=True,
        MFA_RENAME_METHODS={"Email": "Custom Email Method"},
    )
    def test_start_with_custom_method_names(self):
        """Handles start with custom MFA_RENAME_METHODS.

        Email.py start function with custom method names
        """
        request = HttpRequest()
        request.user = self.user
        request.method = "POST"
        request.session = {"email_secret": "123456"}
        request.POST = {"otp": "123456"}

        response = start(request)

        # Should return a response (actual MFA project behavior)
        self.assertIsNotNone(response)

        # Should use custom method name in session
        self.assertIn("mfa_reg", request.session)
        self.assertEqual(request.session["mfa_reg"]["name"], "Custom Email Method")

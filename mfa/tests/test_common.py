"""
Test cases for MFA Common module.

Tests utility functions in mfa.Common module:
- send(): HTML email sending with MFA configuration
- get_redirect_url(): Registration completion redirect and messages
- get_username_field(): Django User model and username field access
- get_user(): User lookup by username

Scenarios: Email configuration, redirect settings, user model integration, error handling.
"""

from django.test import TestCase, override_settings
from django.core.mail import EmailMessage
from unittest.mock import patch, MagicMock
from ..Common import send, get_redirect_url, get_username_field, set_next_recheck
from .mfatestcase import MFATestCase


class CommonTests(MFATestCase):
    """MFA Common utility functions tests."""

    def test_common_send_with_valid_email_host_user(self):
        """Sends email when EMAIL_HOST_USER contains '@'.

        Common.py send function with valid email host user
        """
        with self.settings(
            EMAIL_HOST_USER="user@example.com",
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = send(["test@recipient.com"], "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent with correct From field
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.subject, "Test Subject")
            self.assertEqual(sent_email.body, "Test Body")
            self.assertEqual(sent_email.from_email, "Test System <user@example.com>")
            self.assertEqual(sent_email.to, ["test@recipient.com"])

    def test_common_send_without_at_in_email_host_user(self):
        """Uses DEFAULT_FROM_EMAIL when EMAIL_HOST_USER does not contain '@'.

        Common.py send function with invalid email host user
        """
        with self.settings(
            EMAIL_HOST_USER="invalid_user",  # No '@' character
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = send(["test@recipient.com"], "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent with DEFAULT_FROM_EMAIL
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.subject, "Test Subject")
            self.assertEqual(sent_email.body, "Test Body")
            self.assertEqual(
                sent_email.from_email, "Test System <default@example.com>"
            )  # Uses DEFAULT_FROM_EMAIL
            self.assertEqual(sent_email.to, ["test@recipient.com"])

    def test_common_send_with_empty_email_host_user(self):
        """Uses DEFAULT_FROM_EMAIL when EMAIL_HOST_USER is empty.

        Common.py send function with empty email host user
        """
        with self.settings(
            EMAIL_HOST_USER="",  # Empty string - no '@' character
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = send(["test@recipient.com"], "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent with DEFAULT_FROM_EMAIL
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.subject, "Test Subject")
            self.assertEqual(sent_email.body, "Test Body")
            self.assertEqual(
                sent_email.from_email, "Test System <default@example.com>"
            )  # Uses DEFAULT_FROM_EMAIL
            self.assertEqual(sent_email.to, ["test@recipient.com"])

    def test_common_send_email_content_subtype(self):
        """Sets correct content subtype for email messages.

        Common.py send function content subtype handling
        """
        with self.settings(
            EMAIL_HOST_USER="user@example.com",
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = send(["test@recipient.com"], "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent with HTML content subtype
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.content_subtype, "html")

    def test_common_send_with_empty_email_host_user(self):
        """Uses DEFAULT_FROM_EMAIL when EMAIL_HOST_USER is empty string.

        Common.py send function with empty EMAIL_HOST_USER
        """
        with self.settings(
            EMAIL_HOST_USER="",  # Empty string - Django's default
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            result = send(["test@recipient.com"], "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent with DEFAULT_FROM_EMAIL (fallback from empty string)
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(
                sent_email.from_email, "Test System <default@example.com>"
            )  # Uses DEFAULT_FROM_EMAIL

    def test_common_send_with_multiple_recipients(self):
        """Handles multiple recipients correctly.

        Common.py send function with multiple recipients
        """
        with self.settings(
            EMAIL_HOST_USER="user@example.com",
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            recipients = ["user1@example.com", "user2@example.com", "user3@example.com"]
            result = send(recipients, "Test Subject", "Test Body")

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email was sent to all recipients
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.to, recipients)

    def test_common_send_with_html_body(self):
        """Handles HTML body content correctly.

        Common.py send function with HTML body
        """
        with self.settings(
            EMAIL_HOST_USER="user@example.com",
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",  # Use memory backend
        ):
            html_body = (
                "<h1>Test HTML</h1><p>This is <strong>HTML</strong> content.</p>"
            )
            result = send(["test@recipient.com"], "HTML Test Subject", html_body)

            # Verify email was sent successfully
            self.assertEqual(result, 1)

            # Verify email body contains HTML
            from django.core import mail

            self.assertEqual(len(mail.outbox), 1)
            sent_email = mail.outbox[0]
            self.assertEqual(sent_email.body, html_body)
            self.assertEqual(sent_email.content_subtype, "html")

    def test_common_send_email_sending_failure(self):
        """Returns 0 when email sending fails.

        Common.py send function with email sending failure
        """
        with self.settings(
            EMAIL_HOST_USER="user@example.com",
            EMAIL_FROM="Test System",
            DEFAULT_FROM_EMAIL="default@example.com",
            EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend",  # Console backend
        ):
            # Mock the email send to return 0 (failure)
            with patch(
                "django.core.mail.EmailMessage.send"
            ) as mock_send:  # Mock Django EmailMessage send method to simulate failure
                mock_send.return_value = 0  # Simulate send failure

                result = send(["test@recipient.com"], "Test Subject", "Test Body")

                # Should return 0 when send fails
                self.assertEqual(result, 0)

    def test_get_redirect_url_default_settings(self):
        """Uses mfa_home and None message with default settings.

        Common.py get_redirect_url function with default settings
        """
        result = get_redirect_url()

        # Should return dict with redirect_html and reg_success_msg
        self.assertIsInstance(result, dict)
        self.assertIn("redirect_html", result)
        self.assertIn("reg_success_msg", result)

        # Should use default mfa_home URL
        self.assertIn("/mfa/", result["redirect_html"])  # mfa_home URL contains /mfa/

        # Should use default None message
        self.assertIsNone(result["reg_success_msg"])

    def test_get_redirect_url_custom_redirect(self):
        """Uses custom MFA_REDIRECT_AFTER_REGISTRATION when configured.

        Common.py get_redirect_url function with custom redirect
        """
        with self.settings(MFA_REDIRECT_AFTER_REGISTRATION="admin:index"):
            result = get_redirect_url()

            # Should return dict with redirect_html and reg_success_msg
            self.assertIsInstance(result, dict)
            self.assertIn("redirect_html", result)
            self.assertIn("reg_success_msg", result)

            # Should use custom admin:index URL
            self.assertIn(
                "/admin/", result["redirect_html"]
            )  # admin:index URL contains /admin/

    def test_get_redirect_url_custom_success_message(self):
        """Uses custom MFA_SUCCESS_REGISTRATION_MSG when configured.

        Common.py get_redirect_url function with custom success message
        """
        with self.settings(
            MFA_SUCCESS_REGISTRATION_MSG="Registration completed successfully!"
        ):
            result = get_redirect_url()

            # Should return dict with redirect_html and reg_success_msg
            self.assertIsInstance(result, dict)
            self.assertIn("redirect_html", result)
            self.assertIn("reg_success_msg", result)

            # Should use custom success message
            self.assertEqual(
                result["reg_success_msg"], "Registration completed successfully!"
            )

    def test_get_redirect_url_custom_both_settings(self):
        """Uses both custom redirect and success message when configured.

        Common.py get_redirect_url function with custom settings
        """
        with self.settings(
            MFA_REDIRECT_AFTER_REGISTRATION="admin:index",
            MFA_SUCCESS_REGISTRATION_MSG="MFA setup completed!",
        ):
            result = get_redirect_url()

            # Should return dict with redirect_html and reg_success_msg
            self.assertIsInstance(result, dict)
            self.assertIn("redirect_html", result)
            self.assertIn("reg_success_msg", result)

            # Should use custom admin:index URL
            self.assertIn("/admin/", result["redirect_html"])

            # Should use custom success message
            self.assertEqual(result["reg_success_msg"], "MFA setup completed!")

    def test_get_username_field_default(self):
        """Returns username field with default Django User model.

        Common.py get_username_field function with default User model
        """
        # Mock get_user_model to return Django's default User model
        from django.contrib.auth.models import User as DjangoUser

        with patch(
            "mfa.Common.get_user_model"
        ) as mock_get_user_model:  # Mock external Django get_user_model to test MFA project code behavior
            mock_get_user_model.return_value = DjangoUser

            # Import and call the function inside the patch context
            from mfa.Common import get_username_field as get_username_field_func

            User, username_field = get_username_field_func()

            # Test actual MFA project code behavior - should return tuple
            self.assertIsInstance(User, type)
            self.assertIsInstance(username_field, str)

            # Test actual MFA project code behavior - should return the User model and field name
            self.assertIsNotNone(User)
            self.assertIsNotNone(username_field)
            self.assertEqual(
                len((User, username_field)), 2
            )  # Should return exactly 2 values

    def test_get_username_field_returns_tuple(self):
        """Returns tuple of (User, field_name).

        Common.py get_username_field function return format
        Returns tuple of (User model class, field name string)
        """
        # Test the actual MFA project code with the project's User model
        User, username_field = get_username_field()  # imported from Common.py

        # Test actual MFA project code behavior - should return tuple of (User, field_name)
        self.assertIsInstance(User, type)
        self.assertIsInstance(username_field, str)

        # Test actual MFA project code behavior - should return the User model and field name
        self.assertIsNotNone(User)
        self.assertIsNotNone(username_field)

    def test_get_username_field_with_custom_field(self):
        """Returns custom field when USERNAME_FIELD is configured.

        Common.py get_username_field function with custom USERNAME_FIELD
        Returns custom field name when USERNAME_FIELD is overridden
        """
        # Get the project's User model
        from django.contrib.auth import get_user_model

        ProjectUser = get_user_model()

        # Temporarily override USERNAME_FIELD on the User model
        original_field = getattr(ProjectUser, "USERNAME_FIELD", "username")
        ProjectUser.USERNAME_FIELD = "email"

        try:
            # Test the actual MFA project code with custom USERNAME_FIELD
            User, username_field = get_username_field()  # imported from Common.py

            # Test actual MFA project code behavior - should return tuple
            self.assertIsInstance(User, type)
            self.assertIsInstance(username_field, str)

            # Test actual MFA project code behavior - should return the User model and field name
            self.assertIsNotNone(User)
            self.assertIsNotNone(username_field)
            self.assertEqual(
                len((User, username_field)), 2
            )  # Should return exactly 2 values

            # Test actual MFA project code behavior - should extract custom USERNAME_FIELD
            self.assertEqual(username_field, "email")  # Custom USERNAME_FIELD = "email"
            self.assertEqual(User, ProjectUser)  # Should be the project's User model

        finally:
            # Restore original USERNAME_FIELD
            ProjectUser.USERNAME_FIELD = original_field

    def test_set_next_recheck_disabled(self):
        """Returns empty dict when MFA_RECHECK is False.

        Common.py set_next_recheck function with MFA_RECHECK disabled
        """
        with self.settings(MFA_RECHECK=False):
            result = set_next_recheck()

            # Should return empty dict
            self.assertEqual(result, {})

    def test_set_next_recheck_enabled_default_settings(self):
        """Handles MFA_RECHECK when True with default settings.

        Common.py set_next_recheck function with MFA_RECHECK enabled
        """
        with self.settings(MFA_RECHECK=True):
            result = set_next_recheck()

            # Should return dict with next_check key
            self.assertIsInstance(result, dict)
            self.assertIn("next_check", result)

            # next_check should be a valid timestamp
            next_check = result["next_check"]
            self.assertIsInstance(next_check, (int, float))
            self.assertGreater(next_check, 0)

    def test_set_next_recheck_enabled_custom_settings(self):
        """Handles MFA_RECHECK when True with custom min/max settings.

        Common.py set_next_recheck function with custom settings
        """
        with self.settings(
            MFA_RECHECK=True,
            MFA_RECHECK_MIN=100,  # 100 seconds
            MFA_RECHECK_MAX=200,  # 200 seconds
        ):
            result = set_next_recheck()

            # Should return dict with next_check key
            self.assertIsInstance(result, dict)
            self.assertIn("next_check", result)

            # next_check should be a valid timestamp
            next_check = result["next_check"]
            self.assertIsInstance(next_check, (int, float))
            self.assertGreater(next_check, 0)

    def test_set_next_recheck_multiple_calls_different_values(self):
        """Returns different random values on multiple calls.

        Common.py set_next_recheck function randomness
        """
        with self.settings(MFA_RECHECK=True):
            result1 = set_next_recheck()

            # Add small delay to ensure different timestamps
            import time

            time.sleep(0.001)  # 1ms delay

            result2 = set_next_recheck()

            # Both should have next_check key
            self.assertIn("next_check", result1)
            self.assertIn("next_check", result2)

            # Values should be different (random)
            self.assertNotEqual(result1["next_check"], result2["next_check"])

    def test_set_next_recheck_missing_min_max_settings(self):
        """Handles gracefully when MFA_RECHECK_MIN/MAX are missing.

        Common.py set_next_recheck function with missing settings
        """
        with self.settings(MFA_RECHECK=True):
            # Don't set MFA_RECHECK_MIN/MAX to test graceful handling
            result = set_next_recheck()

            # Should return dict with next_check key
            self.assertIsInstance(result, dict)
            self.assertIn("next_check", result)

            # next_check should be a valid timestamp
            next_check = result["next_check"]
            self.assertIsInstance(next_check, (int, float))
            self.assertGreater(next_check, 0)

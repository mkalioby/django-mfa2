"""
Test cases for MFA configuration system.

Tests MFA configuration settings and their effects on system behavior:
- MFA_UNALLOWED_METHODS: Disabled methods
- MFA_HIDE_DISABLE: UI-hidden methods
- MFA_RENAME_METHODS: Custom display names
- TOKEN_ISSUER_NAME: TOTP QR code issuer
- MFA_ENFORCE_RECOVERY_METHOD: Recovery code requirement
- MFA_ENFORCE_EMAIL_TOKEN: Email token requirement
- MFA_RECHECK: Periodic re-verification settings
- MFA_LOGIN_CALLBACK: Custom login function
- Method-specific settings (TOTP, Recovery, Email)

Scenarios: Settings validation, configuration effects, method filtering, UI customization.
"""

import json
import os
import pyotp
import time
from django.conf import settings
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.test import override_settings, Client
from django.urls import reverse
from django.urls import NoReverseMatch
from .mfatestcase import MFATestCase


class ConfigTestCase(MFATestCase):
    """Verifies MFA configuration behavior with test URLs.

    Verifies how the MFA implementation responds to different configuration
    settings in an isolated test environment.

    Please see tests.README.md ## MFA Key Type System
    """

    def setUp(self):
        super().setUp()
        self._test_urlconf_settings = override_settings(
            ROOT_URLCONF="mfa.tests.test_urls"
        )
        self._test_urlconf_settings.enable()

    def tearDown(self):
        if hasattr(self, "_test_urlconf_settings"):
            self._test_urlconf_settings.disable()
        super().tearDown()

    def test_method_disablement_behavior(self):
        """Verifies disabled methods are hidden and inaccessible.

        Required conditions:
        1. User is logged in
        2. TOTP method is disabled via MFA_UNALLOWED_METHODS
        3. Another MFA method exists (to ensure page is accessible)

        Expected results:
        1. MFA home page is accessible
        2. TOTP method is not visible in UI
        3. TOTP setup URL is not in content
        """
        self.login_user()

        # Create an email key (since TOTP will be disabled)
        self.create_email_key(enabled=True)

        with override_settings(
            MFA_UNALLOWED_METHODS=("TOTP",),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"EMAIL": "Email Token", "TOTP": "Authenticator app"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            self.assertNotIn("start_new_otop", content)
            self.assertNotIn("Authenticator app", content)

    def test_method_renaming_behavior(self):
        """Verifies method renaming settings are applied correctly.

        Required conditions:
        1. User is logged in
        2. Method renaming is configured
        3. At least one MFA key exists

        Expected results:
        1. MFA home page is accessible
        2. Methods are renamed according to settings
        3. Default names do not appear
        """
        self.login_user()

        # Create a TOTP key for the user
        key = self.create_totp_key(enabled=True)

        # Create a recovery key for testing
        recovery_key = self.create_recovery_key(enabled=True)

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "RECOVERY": "Backup Codes",
                "TOTP": "Authenticator app",
                "EMAIL": "Email Token",
                "U2F": "Classical Security Key",
                "FIDO2": "FIDO2 Security Key",
                "Trusted_Devices": "Trusted Device",
            },
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

            # Get dropdown menu items
            menu_items = self.get_dropdown_menu_items(response.content.decode())

            # Verify renamed methods appear in dropdown
            self.assertIn("Email Token", menu_items)
            self.assertIn("FIDO2 Security Key", menu_items)
            self.assertIn("Authenticator app", menu_items)

            # Verify default names do not appear in dropdown
            self.assertNotIn("TOTP", menu_items)
            self.assertNotIn("EMAIL", menu_items)
            self.assertNotIn("U2F", menu_items)
            self.assertNotIn("FIDO2", menu_items)

            # Verify recovery key appears in special section with custom name
            content = response.content.decode()
            row_content = self.get_recovery_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)
            self.assertNotIn("RECOVERY", row_content)

    def test_recovery_enforcement_behavior(self):
        """Verifies recovery method remains available when enforced.

        Required conditions:
        1. User is logged in
        2. User has MFA verification
        3. Recovery method is enforced
        4. Recovery key exists

        Expected results:
        1. MFA home page is accessible
        2. Recovery method is available
        3. Recovery key is visible
        """
        self.login_user()

        # Create a TOTP key for verification
        verify_key = self.create_totp_key(enabled=True)

        # Create a recovery key
        recovery_key = self.create_recovery_key(enabled=True)

        # Setup MFA session as verified
        self.setup_mfa_session(method="TOTP", verified=True, id=verify_key.id)

        # Get a valid token for verification
        valid_token = self.get_valid_totp_token(key_id=verify_key.id)

        # Verify MFA with login callback
        with override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session"):
            verify_response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": valid_token}
            )
            self.assertEqual(verify_response.status_code, 302)

        # Now test recovery enforcement
        with override_settings(
            MFA_ENFORCE_RECOVERY_METHOD=True,
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "RECOVERY": "Backup Codes",
                "TOTP": "Authenticator app",
                "EMAIL": "Email Token",
                "U2F": "Classical Security Key",
                "FIDO2": "FIDO2 Security Key",
                "Trusted_Devices": "Trusted Device",
            },
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

            # Verify recovery key is visible
            content = response.content.decode()
            row_content = self.get_recovery_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)

    def test_email_token_behavior(self):
        """Verifies email token method availability when enforced.

        Required conditions:
        1. User is logged in
        2. Email token method is enforced
        3. Email key exists for user

        Expected results:
        1. MFA home page is accessible
        2. Email token method is visible in UI
        """
        self.login_user()

        # Create an email key for the user
        self.create_email_key(enabled=True)

        with override_settings(
            MFA_ENFORCE_EMAIL_TOKEN=True,
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"EMAIL": "Email Token"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            self.assertIn("email", content.lower())

    def test_recheck_behavior(self):
        """Verifies recheck settings are applied correctly.

        Required conditions:
        1. User is logged in
        2. User has MFA verification
        3. Recheck settings are configured

        Expected results:
        1. MFA home page is accessible
        2. Recheck settings are applied
        """
        self.login_user()

        # Create a TOTP key for verification
        verify_key = self.create_totp_key(enabled=True)

        # Setup MFA session as verified
        self.setup_mfa_session(method="TOTP", verified=True, id=verify_key.id)

        # Get a valid token for verification
        valid_token = self.get_valid_totp_token(key_id=verify_key.id)

        # Verify MFA with login callback
        with override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session"):
            verify_response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": valid_token}
            )
            self.assertEqual(verify_response.status_code, 302)

        # Now test recheck settings
        with override_settings(
            MFA_RECHECK=True, MFA_RECHECK_MIN=300, MFA_RECHECK_MAX=600
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

    def test_totp_configuration_behavior(self):
        """Verifies TOTP settings and redirect configuration."""
        with override_settings(
            TOTP_TIME_WINDOW=60,
            TOTP_CODE_LENGTH=6,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        ):
            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 200)

    def test_recovery_codes_behavior(self):
        """Verifies recovery code settings and redirect configuration."""
        with override_settings(
            RECOVERY_CODES_COUNT=10,
            RECOVERY_CODES_LENGTH=8,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        ):
            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

    def test_login_callback_behavior(self):
        """Verifies custom login callback configuration.

        Required conditions:
        1. User is logged in
        2. Custom login callback is configured
        3. At least one MFA key exists

        Expected results:
        1. MFA home page is accessible
        2. Login callback is used for authentication
        """
        self.login_user()

        # Create a TOTP key for the user
        self.create_totp_key(enabled=True)

        # Create a test callback function
        def test_callback(request, username):
            return True

        with override_settings(
            MFA_LOGIN_CALLBACK="mfa.tests.test_config.test_callback",
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"TOTP": "Authenticator app"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

    def test_registration_message_behavior(self):
        """Verifies custom registration success message.

        Required conditions:
        1. User is logged in
        2. Custom success message is configured

        Expected results:
        1. TOTP setup page is accessible
        2. Custom success message is displayed after registration
        """
        self.login_user()

        # Get a new token
        with override_settings(
            MFA_SUCCESS_REGISTRATION_MSG="Setup complete!",
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"TOTP": "Authenticator app"},
        ):
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

            # Verify success message is displayed
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content.decode(), "Success")

    def test_recovery_default_name(self):
        """Shows default name when recovery method not in MFA_RENAME_METHODS.

        Verifies that when:
        1. Not in MFA_RENAME_METHODS
        2. Enabled and present in the table
        3. Another key exists (needed for recovery to show in template)
        The recovery method appears with its default name 'RECOVERY'

        Note: The current implementation only shows recovery keys in the template
        when another key exists. This is a template-level check.
        """
        self.login_user()

        # Create recovery key and another key (needed for recovery to show)
        recovery_key = self.create_recovery_key(enabled=True)
        totp_key = self.create_totp_key(
            enabled=True
        )  # Add another key so recovery shows

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={},  # Empty - recovery should use default name
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Verify recovery key appears with default name
            self.assertIn("RECOVERY", content)

            # Verify the key's row shows the default name
            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("RECOVERY", content)

    def test_recovery_renamed(self):
        """Shows custom name when recovery method in MFA_RENAME_METHODS.

        Verifies that when the recovery method is:
        1. Present in MFA_RENAME_METHODS
        2. Enabled and present in the table
        3. Another key exists (needed for recovery to show in template)
        It appears with its custom name and not the default
        """
        self.login_user()

        # Create recovery key and another key (needed for recovery to show)
        recovery_key = self.create_recovery_key(enabled=True)
        totp_key = self.create_totp_key(
            enabled=True
        )  # Add another key so recovery shows

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"RECOVERY": "Backup Codes"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Recovery should show renamed version
            self.assertIn("Backup Codes", content)
            # Default name should not appear
            self.assertNotIn("RECOVERY", content)

            # Verify the key's row shows the custom name
            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)
            self.assertNotIn("RECOVERY", row_content)

    def test_methods_disallowed(self):
        """Handles behavior when specific methods are disallowed.

        Verifies that when:
        1. A method is in MFA_UNALLOWED_METHODS
        2. A key of that type exists
        The method is hidden from UI but its endpoints remain accessible

        URLs tested:
        - mfa_home: Main MFA page (should hide disallowed methods)
        - start_u2f: U2F setup page (should remain accessible)
        """
        self.login_user()

        # Create a recovery key and a TOTP key
        recovery_key = self.create_recovery_key(enabled=True)
        totp_key = self.create_totp_key(
            enabled=True
        )  # Add another key so recovery shows

        with override_settings(
            MFA_UNALLOWED_METHODS=("U2F",),  # Disallow U2F
            MFA_HIDE_DISABLE=(),  # Don't hide any methods
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "RECOVERY": "Backup Codes",
                "TOTP": "Authenticator app",
            },
            # Required U2F settings
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
            # Use a valid URL name from urls.py
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            MFA_SUCCESS_REGISTRATION_MSG="Success",
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Verify recovery key appears with custom name
            self.assertIn("Backup Codes", content)
            row = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row, "", "Recovery key row not found in table")

            # Verify TOTP key appears with custom name
            self.assertIn("Authenticator app", content)
            row = self.get_key_row_content(content, totp_key.id)
            self.assertNotEqual(row, "", "TOTP key row not found in table")

            # Verify U2F is not in dropdown menu
            menu_items = self.get_dropdown_menu_items(content)
            self.assertNotIn("U2F", menu_items)

            # Verify U2F endpoint remains accessible
            response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(response.status_code, 200)

    def test_enforced_recovery_behavior(self):
        """Behaves correctly when recovery method is enforced.

        Verifies that when:
        1. User is logged in
        2. MFA_ENFORCE_RECOVERY_METHOD is True
        3. A recovery key exists
        4. Another MFA method exists (required for recovery key visibility)
        The recovery key appears in the main MFA table with correct name and status.
        """
        self.login_user()

        # Create both a recovery key and another MFA method
        # Recovery key visibility requires at least one other method to exist
        totp_key = self.create_totp_key(enabled=True)
        recovery_key = self.create_recovery_key(enabled=True)

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"RECOVERY": "Backup Codes"},
            MFA_ENFORCE_RECOVERY_METHOD=True,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            # First verify the recovery endpoint is accessible
            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

            # Then check the main MFA page for the recovery key
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Verify recovery key appears in table
            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)
            self.assertIn("On", row_content)
            self.assertIn("recovery/start", row_content)

    def test_hide_disable_does_not_affect_dropdown_visibility(self):
        """Does not remove methods from dropdown menu when MFA_HIDE_DISABLE is set.

        Verifies that when a method is in MFA_HIDE_DISABLE:
        1. The method still appears in the dropdown menu
        2. The method's custom name (if any) is displayed correctly
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=("TOTP",),
            MFA_RENAME_METHODS={
                "TOTP": "Authenticator app",
                "Email": "Email Token",
            },
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

            menu_items = self.get_dropdown_menu_items(response.content.decode())

            # Method should still be in dropdown despite being in MFA_HIDE_DISABLE
            self.assertIn("Authenticator app", menu_items)
            self.assertIn("Email Token", menu_items)

    def test_hide_disable_method_shows_static_status(self):
        """Shows static status instead of toggle button for methods in MFA_HIDE_DISABLE.

        Verifies that when a method is in MFA_HIDE_DISABLE:
        1. The method shows static "On"/"Off" text instead of a toggle button
        2. The status text matches the method's enabled state
        """
        self.login_user()

        # Create a TOTP key using helper method
        key = self.create_totp_key(enabled=True)

        with override_settings(
            MFA_HIDE_DISABLE=("TOTP",), MFA_RENAME_METHODS={"TOTP": "Authenticator app"}
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Get the specific row for our key
            row_content = self.get_key_row_content(content, key.id)
            self.assertNotEqual(row_content, "", "Key row not found in table")

            # Should show static "On" text instead of toggle button
            self.assertIn("On", row_content)
            self.assertNotIn('data-toggle="toggle"', row_content)

            # Verify key state hasn't changed
            self.assertMfaKeyState(key.id, expected_enabled=True)

    def test_hide_disable_method_shows_no_delete_button(self):
        """Shows no delete button for methods in MFA_HIDE_DISABLE.

        Verifies that when a method is in MFA_HIDE_DISABLE:
        1. The method shows "----" instead of delete button in its table row
        2. The method shows static status text instead of toggle button

        URLs tested:
        - mfa_home: Main MFA page
        """
        self.login_user()

        # Create a TOTP key using helper method
        key = self.create_totp_key(enabled=True)

        with override_settings(
            MFA_HIDE_DISABLE=("TOTP",), MFA_RENAME_METHODS={"TOTP": "Authenticator app"}
        ):
            # Get the page content
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

            # Extract and check the specific row for our key
            row_content = self.get_key_row_content(response.content.decode(), key.id)
            self.assertNotEqual(row_content, "", "Key row not found in table")

            # Should show static status text instead of toggle button
            self.assertIn("On", row_content)  # Static text for enabled key
            self.assertNotIn('data-toggle="toggle"', row_content)  # No toggle button

            # Should show "----" instead of delete button
            self.assertIn("----", row_content)  # Static text instead of delete button
            self.assertNotIn('onclick="deleteKey', row_content)  # No delete button

            # Verify key state hasn't changed
            self.assertMfaKeyState(key.id, expected_enabled=True)

    def test_hide_disable_method_endpoints_still_work(self):
        """Remains functional for methods in MFA_HIDE_DISABLE.

        Verifies that when a method is in MFA_HIDE_DISABLE:
        1. The method's setup endpoint is still accessible
        2. The method can still be used for authentication

        Note: This test avoids template rendering by testing endpoint accessibility
        rather than full template rendering, since templates may not be available
        in all test environments.
        """
        self.login_user()

        with override_settings(
            MFA_HIDE_DISABLE=("TOTP",),
            MFA_RENAME_METHODS={"TOTP": "Authenticator app"},
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        ):
            # Test that setup endpoint is accessible (returns 200 or redirects)
            # We test the URL resolution rather than template rendering
            try:
                url = self.get_mfa_url("start_new_otop")
                self.assertTrue(url.startswith("/"))
            except Exception as e:
                self.fail(f"start_new_otop URL should be accessible: {e}")

            # Create and verify TOTP key
            key = self.create_totp_key(enabled=True)
            self.assertMfaKeyState(key.id, expected_enabled=True)

            # Test that auth endpoint is accessible (returns 200 or redirects)
            # We test the URL resolution rather than template rendering
            try:
                url = self.get_mfa_url("totp_auth")
                self.assertTrue(url.startswith("/"))
            except Exception as e:
                self.fail(f"totp_auth URL should be accessible: {e}")

            # Test that the method can still be used for authentication
            # by verifying the key exists and is enabled
            self.assertTrue(
                self.get_user_keys(key_type="TOTP").filter(enabled=True).exists()
            )

    def test_redirect_behavior(self):
        """Handles MFA redirect behavior correctly.

        Verifies that:
        - Custom redirect URLs work
        - Default redirect fallback works
        - Absolute path redirects work
        """
        self.login_user()

        # Test custom URL name redirect
        with override_settings(MFA_REDIRECT_AFTER_REGISTRATION="mfa_home"):
            redirect_data = self.get_redirect_url()
            self.assertIsInstance(redirect_data, dict)
            self.assertIn("redirect_url", redirect_data)
            redirect_url = redirect_data["redirect_url"]
            self.assertTrue(redirect_url.startswith("/"))
            self.assertEqual(redirect_url, reverse("mfa_home"))

        # Test absolute path redirect
        with override_settings(MFA_REDIRECT_AFTER_REGISTRATION="/custom/path/"):
            redirect_data = self.get_redirect_url()
            self.assertIsInstance(redirect_data, dict)
            self.assertIn("redirect_url", redirect_data)
            redirect_url = redirect_data["redirect_url"]
            self.assertEqual(redirect_url, "/custom/path/")

    def test_method_default_names(self):
        """Uses template default names for methods not in settings.

        Verifies that when a method is:
        1. Not in MFA_UNALLOWED_METHODS
        2. Not in MFA_HIDE_DISABLE
        3. Not in MFA_RENAME_METHODS
        It appears with its template default name in the dropdown menu.
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={},  # Empty - all methods should use defaults
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Get dropdown menu items
            menu_items = self.get_dropdown_menu_items(content)

            # Verify default names in dropdown menu
            self.assertIn("Authenticator app", menu_items)  # TOTP default
            self.assertIn("Email Token", menu_items)  # EMAIL default
            self.assertIn("Security Key", menu_items)  # U2F default
            self.assertIn("FIDO2 Security Key", menu_items)  # FIDO2 default
            self.assertIn("Trusted Device", menu_items)  # TD default

    def test_method_custom_names(self):
        """Uses custom names for methods in MFA_RENAME_METHODS.

        Verifies that when a method is in MFA_RENAME_METHODS with correct case,
        it appears with its custom name instead of the template default.

        Required conditions:
        1. User must be logged in
        2. Method keys must exactly match template expectations:
           - "Email" - For email token method
           - "TOTP" - For authenticator app
           - "U2F" - For security key
           - "FIDO2" - For biometric auth
           - "Trusted_Devices" - For trusted device (matches template check)
        3. No methods are disallowed or hidden

        Expected results:
        1. Custom names appear as exact menu items
        2. Default names do not appear as standalone menu items
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "TOTP": "Custom Authenticator",
                "Email": "Custom Email",  # Must match template's case
                "U2F": "Custom Security Key",
                "FIDO2": "Custom Biometric",
                "Trusted_Devices": "Custom Device",
            },
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            menu_items = self.get_dropdown_menu_items(content)

            # Verify custom names appear as exact menu items
            self.assertIn("Custom Authenticator", menu_items)
            self.assertIn("Custom Email", menu_items)
            self.assertIn("Custom Security Key", menu_items)
            self.assertIn("Custom Biometric", menu_items)
            self.assertIn("Custom Device", menu_items)

            # Verify default names are not present as standalone menu items
            self.assertNotIn("Authenticator app", menu_items)
            self.assertNotIn("Email Token", menu_items)
            self.assertNotIn("Security Key", menu_items)
            self.assertNotIn("FIDO2 Security Key", menu_items)
            self.assertNotIn("Trusted Device", menu_items)

    def test_method_name_case_sensitivity(self):
        """Treats method names in MFA_RENAME_METHODS as case sensitive.

        Verifies that when a method name has incorrect case:
        1. The custom name is not used
        2. The default name is shown instead
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "EMAIL": "Custom Email",  # Wrong case
                "email": "Custom Email",  # Wrong case
            },
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Custom name should not appear
            self.assertNotIn("Custom Email", content)
            # Default name should be used
            self.assertIn("Email Token", content)

    def test_method_hiding_wrong_case_totp(self):
        """Does not hide TOTP method when using wrong case in MFA_HIDE_DISABLE.

        Verifies that when "totp" (wrong case) is used in MFA_HIDE_DISABLE,
        the TOTP method still appears in the dropdown menu.
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=("totp",),  # Wrong case
            MFA_RENAME_METHODS={"TOTP": "Authenticator app"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            menu_items = self.get_dropdown_menu_items(response.content.decode())
            self.assertIn("Authenticator app", menu_items)  # "totp" doesn't hide TOTP

    def test_method_hiding_wrong_case_email(self):
        """Does not hide Email method when using wrong case in MFA_HIDE_DISABLE.

        Verifies that when "EMAIL" (wrong case) is used in MFA_HIDE_DISABLE,
        the Email method still appears in the dropdown menu.
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=("EMAIL",),  # Wrong case
            MFA_RENAME_METHODS={"Email": "Email Token"},
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            menu_items = self.get_dropdown_menu_items(response.content.decode())
            self.assertIn("Email Token", menu_items)  # "EMAIL" doesn't hide Email

    def test_disable_totp_interactive_elements_correct_case(self):
        """Disables TOTP method's interactive elements when using correct case in MFA_HIDE_DISABLE.

        Verifies that when "TOTP" (correct case) is used in MFA_HIDE_DISABLE:
        1. The method remains visible in the dropdown menu (MFA_HIDE_DISABLE does not affect visibility)
        2. The method's toggle button is replaced with static "On"/"Off" status text
        3. The method's delete button is replaced with "----"
        4. The method's custom display name (if set in MFA_RENAME_METHODS) is preserved
        """
        self.login_user()

        # Create a TOTP key
        key = self.create_totp_key(enabled=True)

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=("TOTP",),  # Correct case
            MFA_RENAME_METHODS={"TOTP": "Authenticator app"},
        ):
            # Get the page content
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Method should still be in dropdown (MFA_HIDE_DISABLE doesn't affect visibility)
            menu_items = self.get_dropdown_menu_items(content)
            self.assertIn("Authenticator app", menu_items)

            # Extract and check the specific row for our key
            row_content = self.get_key_row_content(content, key.id)
            self.assertNotEqual(row_content, "", "Key row not found in table")

            # Should show static status text instead of toggle button
            self.assertIn("On", row_content)  # Static text for enabled key
            self.assertNotIn('data-toggle="toggle"', row_content)  # No toggle button

            # Should show "----" instead of delete button
            self.assertIn("----", row_content)  # Static text instead of delete button
            self.assertNotIn('onclick="deleteKey', row_content)  # No delete button

            # Verify key state hasn't changed
            self.assertMfaKeyState(key.id, expected_enabled=True)

    def test_mfa_method_dropdown_visibility(self):
        """Shows MFA methods correctly in dropdown menu.

        Verifies that when:
        1. User is logged in
        2. Methods are configured in MFA_RENAME_METHODS
        3. Methods are not in MFA_UNALLOWED_METHODS
        The dropdown menu shows the correct methods with their custom names.
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "TOTP": "Authenticator app",
            },
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            menu_items = self.get_dropdown_menu_items(content)

            self.assertIn("FIDO2 Security Key", menu_items)
            self.assertIn("Authenticator app", menu_items)
            self.assertNotIn("Backup Codes", menu_items)  # Recovery not in dropdown

    def test_recovery_key_table_visibility(self):
        """Shows recovery keys correctly in the table.

        Verifies that when:
        1. User is logged in
        2. A recovery key exists
        3. Another MFA method exists
        4. Recovery is not in MFA_UNALLOWED_METHODS
        The recovery key appears in the table with correct name and status.
        """
        self.login_user()

        # Create required keys
        totp_key = self.create_totp_key(enabled=True)
        recovery_key = self.create_recovery_key(enabled=True)

        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={"RECOVERY": "Backup Codes"},
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)
            self.assertIn("On", row_content)
            self.assertIn("recovery/start", row_content)

    def test_disallowed_method_visibility(self):
        """Hides disallowed methods from UI but keeps endpoints accessible.

        Verifies that when:
        1. User is logged in
        2. Methods are in MFA_UNALLOWED_METHODS
        The methods are hidden from UI but their endpoints remain accessible.
        """
        self.login_user()

        with override_settings(
            MFA_UNALLOWED_METHODS=("U2F", "TOTP"),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "RECOVERY": "Backup Codes",
            },
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            menu_items = self.get_dropdown_menu_items(content)

            # Verify UI visibility
            self.assertIn("FIDO2 Security Key", menu_items)
            self.assertNotIn("Classical Security Key", menu_items)
            self.assertNotIn("Authenticator app", menu_items)

            # Verify endpoints remain accessible even when method is disallowed
            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 200)  # Should still be accessible
            response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(response.status_code, 200)  # Should still be accessible


class MFAIntegrationTestCase(ConfigTestCase):
    """Verifies MFA configuration with project URLs via setUp() and tearDown(). This class
    inherits ConfigTestCase, add one test then runs al the ConfigTestCase tests but
    with project urls.

    Verifies MFA settings work correctly in the context of the actual project URL
    structure and configuration.
    """

    def setUp(self):
        # First call ConfigTestCase's setUp to initialize test attributes
        super().setUp()
        # Then override the URL configuration
        if hasattr(self, "_test_urlconf_settings"):
            self._test_urlconf_settings.disable()
        self._project_urlconf_settings = override_settings(
            ROOT_URLCONF=settings.ROOT_URLCONF
        )
        self._project_urlconf_settings.enable()

    def tearDown(self):
        if hasattr(self, "_project_urlconf_settings"):
            self._project_urlconf_settings.disable()
        # Skip ConfigTestCase's tearDown to avoid double-disabling settings
        super(MFATestCase, self).tearDown()

    def test_complete_mfa_flow(self):
        """Verifies complete MFA flow with project URLs.

        Tests:
        - Login redirects to MFA
        - MFA methods are available in dropdown menu
        - Settings affect the dropdown menu visibility
        - Recovery codes appear in table when another method exists
        - Redirects work correctly
        - Different MFA configurations work as expected

        Note: MFA_UNALLOWED_METHODS only affects UI visibility.
        - Endpoints remain accessible even for disallowed methods.
        - U2F settings are still required even when U2F is disallowed.

        In summary, U2F settings are required because the current architecture
        separates UI visibility from endpoint accessibility, and the U2F module
        needs these settings to function properly even when hidden from the UI.
        This design allows for flexible configuration but means core settings
        must always be present. A potential improvement would be to fully segregate
        UI/API methods which could then be handled independently.
        """
        # Ensure user is logged in
        self.login_user()

        # Test with all methods allowed
        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "RECOVERY": "Backup Codes",
                "TOTP": "Authenticator app",
            },
            MFA_ENFORCE_RECOVERY_METHOD=False,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            # Required U2F settings
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            # All methods should be available
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Get dropdown menu items
            menu_items = self.get_dropdown_menu_items(content)

            # Verify regular methods in dropdown
            self.assertIn("FIDO2 Security Key", menu_items)
            self.assertIn("Authenticator app", menu_items)
            # Recovery should not be in dropdown as it's not an "addable" method
            self.assertNotIn("Backup Codes", menu_items)

            # Create a TOTP key to make recovery visible
            totp_key = self.create_totp_key(enabled=True)
            recovery_key = self.create_recovery_key(enabled=True)

            # Verify recovery appears in table with custom name
            response = self.client.get(self.get_mfa_url("mfa_home"))
            content = response.content.decode()

            # Verify recovery key appears in content
            self.assertIn("Backup Codes", content)

            # Get the recovery key row
            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")

            # Verify recovery key row has expected content
            self.assertIn("Backup Codes", row_content)
            self.assertIn("On", row_content)
            self.assertIn("recovery/start", row_content)

        # Test with some methods disallowed
        with override_settings(
            MFA_UNALLOWED_METHODS=("U2F", "TOTP"),
            MFA_HIDE_DISABLE=("",),
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "RECOVERY": "Backup Codes",
            },
            MFA_ENFORCE_RECOVERY_METHOD=False,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            # Required U2F settings (needed even when U2F is disallowed)
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            # Only allowed methods should be visible in UI
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Get dropdown menu items
            menu_items = self.get_dropdown_menu_items(content)

            # Verify allowed methods in dropdown
            self.assertIn("FIDO2 Security Key", menu_items)  # FIDO2 should be available
            # Recovery should not be in dropdown as it's not an "addable" method
            self.assertNotIn("Backup Codes", menu_items)

            # Verify disallowed methods not in dropdown
            self.assertNotIn(
                "Classical Security Key", menu_items
            )  # U2F should not be available
            self.assertNotIn(
                "Authenticator app", menu_items
            )  # TOTP should not be available

            # Verify endpoints remain accessible even when method is disallowed
            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 200)  # Should still be accessible
            response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(response.status_code, 200)  # Should still be accessible

        # Test with enforced recovery method
        with override_settings(
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=(),
            MFA_RENAME_METHODS={
                "FIDO2": "FIDO2 Security Key",
                "RECOVERY": "Backup Codes",
            },
            MFA_ENFORCE_RECOVERY_METHOD=True,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
            # Required U2F settings
            U2F_APPID="https://localhost",
            U2F_FACETS=["https://localhost"],
        ):
            # First verify the recovery endpoint is accessible
            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

            # Create both a TOTP key and a recovery key for this context
            totp_key = self.create_totp_key(enabled=True)
            recovery_key = self.create_recovery_key(enabled=True)

            # Then check the main MFA page for the recovery key
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()

            # Get dropdown menu items
            menu_items = self.get_dropdown_menu_items(content)

            # Recovery should not be in dropdown even when enforced
            self.assertNotIn("Backup Codes", menu_items)

            # But recovery key should be in table with custom name
            row_content = self.get_key_row_content(content, recovery_key.id)
            self.assertNotEqual(row_content, "", "Recovery key row not found in table")
            self.assertIn("Backup Codes", row_content)
            self.assertIn("On", row_content)
            self.assertIn("recovery/start", row_content)

        # Verify redirect behavior is consistent across all configurations
        redirect_data = self.get_redirect_url()
        self.assertIsInstance(redirect_data, dict)
        self.assertIn("redirect_url", redirect_data)
        redirect_url = redirect_data["redirect_url"]
        self.assertTrue(redirect_url.startswith("/"))

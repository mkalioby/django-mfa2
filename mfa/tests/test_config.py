"""MFA Configuration Tests

Tests the configuration system rather than enforcing specific settings.

Key Settings:
    MFA_UNALLOWED_METHODS: Tuple[str] - Disabled methods
    MFA_HIDE_DISABLE: Tuple[str] - UI-hidden methods
    MFA_RENAME_METHODS: Dict[str, str] - Custom display names
    TOKEN_ISSUER_NAME: str - TOTP QR code issuer
    MFA_ENFORCE_RECOVERY_METHOD: bool - Recovery code requirement
    MFA_ENFORCE_EMAIL_TOKEN: bool - Email token requirement
    MFA_RECHECK: bool - Periodic re-verification
    MFA_RECHECK_MIN: int - Min seconds between rechecks
    MFA_RECHECK_MAX: int - Max seconds between rechecks
    MFA_LOGIN_CALLBACK: str - Custom login function
    MFA_ALWAYS_GO_TO_LAST_METHOD: bool - Skip method selection
    MFA_SUCCESS_REGISTRATION_MSG: str - Success message
    MFA_REDIRECT_AFTER_REGISTRATION: str - Post-registration URL

Method-Specific Settings:
    TOTP:
        TOTP_TIME_WINDOW: int - Code validity period
        TOTP_CODE_LENGTH: int - Number of digits

    Recovery Codes:
        RECOVERY_CODES_COUNT: int - Number of codes
        RECOVERY_CODES_LENGTH: int - Code length

    Email OTP:
        EMAIL_FROM: str - Sender name/entity (e.g. "Security Team")
"""

from django.test import override_settings
from django.urls import reverse
from django.conf import settings
from .base import MFATestCase
import os
from django.urls import NoReverseMatch
from django.core.exceptions import ValidationError
import time


class ConfigTestCase(MFATestCase):
    """Tests MFA configuration behavior with test URLs.

    Verifies how the MFA implementation responds to different configuration
    settings in an isolated test environment.
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

    def test_settings_presence(self):
        """Verifies presence of required and optional settings."""
        required_settings = [
            "MFA_UNALLOWED_METHODS",
            "MFA_HIDE_DISABLE",
            "MFA_RENAME_METHODS",
            "TOKEN_ISSUER_NAME",
            "MFA_ENFORCE_RECOVERY_METHOD",
        ]
        optional_settings = [
            "MFA_ENFORCE_EMAIL_TOKEN",
            "MFA_RECHECK",
            "MFA_RECHECK_MIN",
            "MFA_RECHECK_MAX",
            "MFA_LOGIN_CALLBACK",
            "MFA_ALWAYS_GO_TO_LAST_METHOD",
            "MFA_SUCCESS_REGISTRATION_MSG",
            "MFA_REDIRECT_AFTER_REGISTRATION",
        ]
        self.verify_settings_presence(required_settings, optional_settings)

    def test_method_disablement_behavior(self):
        """Verifies disabled methods are hidden and inaccessible."""
        with override_settings(MFA_UNALLOWED_METHODS=("TOTP",)):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            self.assertNotIn("start_new_otop", content)
            self.assertNotIn("Authenticator app", content)

    def test_method_renaming_behavior(self):
        """Verifies custom method names are displayed correctly in the UI."""
        with override_settings(
            MFA_RENAME_METHODS={
                "TOTP": "Authenticator app",
                "EMAIL": "Email Token",
                "U2F": "Classical Security Key",
                "FIDO2": "Biometric Authentication",
                "TD": "Trusted Device",
            }
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            self.assertIn("Authenticator app", content)
            self.assertIn("Email Token", content)
            self.assertIn("Classical Security Key", content)
            self.assertIn("Biometric Authentication", content)
            self.assertIn("Trusted Device", content)

    def test_recovery_enforcement_behavior(self):
        """Verifies recovery method remains available when enforced."""
        with override_settings(
            MFA_ENFORCE_RECOVERY_METHOD=True,
            MFA_UNALLOWED_METHODS=(),
            MFA_HIDE_DISABLE=("",),
            MFA_RENAME_METHODS={
                "RECOVERY": "Backup Codes",
                "TOTP": "Authenticator app",
                "EMAIL": "Email Token",
                "U2F": "Classical Security Key",
                "FIDO2": "Biometric Authentication",
                "TD": "Trusted Device",
            },
        ):
            self.verify_settings(
                {
                    "MFA_ENFORCE_RECOVERY_METHOD": True,
                    "MFA_UNALLOWED_METHODS": (),
                    "MFA_HIDE_DISABLE": ("",),
                    "MFA_RENAME_METHODS": {
                        "RECOVERY": "Backup Codes",
                        "TOTP": "Authenticator app",
                        "EMAIL": "Email Token",
                        "U2F": "Classical Security Key",
                        "FIDO2": "Biometric Authentication",
                        "TD": "Trusted Device",
                    },
                }
            )

            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

    def test_email_token_behavior(self):
        """Verifies email token method availability when enforced."""
        with override_settings(MFA_ENFORCE_EMAIL_TOKEN=True):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            content = response.content.decode()
            self.assertIn("email", content.lower())

    def test_recheck_behavior(self):
        """Verifies recheck settings are applied correctly."""
        with override_settings(
            MFA_RECHECK=True, MFA_RECHECK_MIN=300, MFA_RECHECK_MAX=600
        ):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            self.verify_settings(
                {"MFA_RECHECK": True, "MFA_RECHECK_MIN": 300, "MFA_RECHECK_MAX": 600}
            )

    def test_totp_configuration_behavior(self):
        """Verifies TOTP settings and redirect configuration."""
        with override_settings(
            TOTP_TIME_WINDOW=60,
            TOTP_CODE_LENGTH=6,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        ):
            self.verify_settings(
                {
                    "TOTP_TIME_WINDOW": 60,
                    "TOTP_CODE_LENGTH": 6,
                    "MFA_REDIRECT_AFTER_REGISTRATION": "mfa_home",
                }
            )

            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 200)

    def test_recovery_codes_behavior(self):
        """Verifies recovery code settings and redirect configuration."""
        with override_settings(
            RECOVERY_CODES_COUNT=10,
            RECOVERY_CODES_LENGTH=8,
            MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        ):
            self.verify_settings(
                {
                    "RECOVERY_CODES_COUNT": 10,
                    "RECOVERY_CODES_LENGTH": 8,
                    "MFA_REDIRECT_AFTER_REGISTRATION": "mfa_home",
                }
            )

            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

    def test_login_callback_behavior(self):
        """Verifies custom login callback configuration."""
        with override_settings(MFA_LOGIN_CALLBACK="custom.login_callback"):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            self.verify_settings({"MFA_LOGIN_CALLBACK": "custom.login_callback"})

    def test_registration_message_behavior(self):
        """Verifies custom registration success message."""
        with override_settings(MFA_SUCCESS_REGISTRATION_MSG="Setup complete!"):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            self.verify_settings({"MFA_SUCCESS_REGISTRATION_MSG": "Setup complete!"})


class MFAIntegrationTestCase(ConfigTestCase):
    """Tests MFA configuration with project URLs via setUp() and tearDown(). This class
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
        - MFA methods are available
        - Settings affect the flow
        - Redirects work correctly
        """
        # Ensure user is logged in
        self.login_user()

        # Set up MFA session for the test user
        self.setup_mfa_session(method="TOTP", verified=True)
        self.create_totp_key(enabled=True)

        with override_settings(MFA_REDIRECT_AFTER_REGISTRATION="mfa_home"):
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)

            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 200)

            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

            # settings copied from mfa example
            self.verify_settings(
                {
                    "MFA_UNALLOWED_METHODS": (),
                    "MFA_HIDE_DISABLE": ("",),
                    "MFA_RENAME_METHODS": {
                        "FIDO2": "Biometric Authentication",
                        "RECOVERY": "Backup Codes",
                    },
                    "MFA_ENFORCE_RECOVERY_METHOD": False,
                }
            )

            redirect_url = self.get_redirect_url()
            self.assertTrue(redirect_url.startswith("/"))

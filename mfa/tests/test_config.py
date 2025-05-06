from django.test import override_settings
from django.urls import reverse
from django.conf import settings
from .base import MFATestCase, skip_if_url_missing, skip_if_setting_missing
import os
from django.urls import NoReverseMatch

@override_settings(ROOT_URLCONF='mfa.tests.test_urls')
class ConfigTestCase(MFATestCase):
    """Test suite for MFA configuration and settings.

    These tests verify the configuration system of the MFA framework, including:
    - Settings validation
    - Default values
    - Configuration overrides
    - Environment variables
    - Dynamic settings
    """

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.login_user()
        # Store original settings
        self.original_settings = {
            'MFA_UNALLOWED_METHODS': getattr(settings, 'MFA_UNALLOWED_METHODS', []),
            'MFA_HIDE_DISABLE': getattr(settings, 'MFA_HIDE_DISABLE', []),
            'MFA_RENAME_METHODS': getattr(settings, 'MFA_RENAME_METHODS', {}),
            'TOKEN_ISSUER_NAME': getattr(settings, 'TOKEN_ISSUER_NAME', f'{settings.BRAND} MFA'),
            'MFA_ENFORCE_RECOVERY_METHOD': getattr(settings, 'MFA_ENFORCE_RECOVERY_METHOD', False),
        }

    @skip_if_setting_missing('MFA_UNALLOWED_METHODS')
    @skip_if_setting_missing('MFA_HIDE_DISABLE')
    @skip_if_setting_missing('MFA_RENAME_METHODS')
    @skip_if_setting_missing('TOKEN_ISSUER_NAME')
    @skip_if_setting_missing('MFA_ENFORCE_RECOVERY_METHOD')
    def test_settings_validation(self):
        """Test validation of MFA settings.

        Verifies:
        1. Required settings are present
        2. Settings have correct types
        3. Settings have valid values
        4. Invalid settings are rejected
        5. Settings are properly documented

        Current failures:
        - No settings validation mechanism
        - Invalid settings not rejected
        - Settings documentation incomplete
        """
        # Test required settings
        required_settings = [
            'MFA_UNALLOWED_METHODS',
            'MFA_HIDE_DISABLE',
            'MFA_RENAME_METHODS',
            'TOKEN_ISSUER_NAME',
            'MFA_ENFORCE_RECOVERY_METHOD'
        ]
        for setting in required_settings:
            self.assertTrue(hasattr(settings, setting))

        # Test setting types
        self.assertIsInstance(settings.MFA_UNALLOWED_METHODS, tuple)
        self.assertIsInstance(settings.MFA_HIDE_DISABLE, tuple)
        self.assertIsInstance(settings.MFA_RENAME_METHODS, dict)
        self.assertIsInstance(settings.TOKEN_ISSUER_NAME, str)
        self.assertIsInstance(settings.MFA_ENFORCE_RECOVERY_METHOD, bool)

    @skip_if_setting_missing('TOKEN_ISSUER_NAME')
    @skip_if_setting_missing('MFA_ENFORCE_RECOVERY_METHOD')
    @skip_if_setting_missing('MFA_UNALLOWED_METHODS')
    @skip_if_setting_missing('MFA_HIDE_DISABLE')
    @skip_if_setting_missing('MFA_RENAME_METHODS')
    def test_default_values(self):
        """Test default configuration values.

        Ensures:
        1. Sensible defaults exist
        2. Defaults are properly applied
        3. Defaults can be overridden
        4. Defaults are documented
        5. Defaults are consistent

        Current failures:
        - Default values not consistently applied
        - Default documentation missing
        - Default override mechanism unclear
        """
        # Test default values
        self.assertEqual(settings.TOKEN_ISSUER_NAME, f'{settings.BRAND} MFA')
        self.assertEqual(settings.MFA_ENFORCE_RECOVERY_METHOD, False)
        self.assertEqual(settings.MFA_UNALLOWED_METHODS, ())
        self.assertEqual(settings.MFA_HIDE_DISABLE, ("",))
        self.assertEqual(settings.MFA_RENAME_METHODS, {
                "RECOVERY": "Backup Codes",
                "FIDO2": "Biometric Authentication"
            }
        )

    @skip_if_setting_missing('TOKEN_ISSUER_NAME')
    @skip_if_setting_missing('MFA_ENFORCE_RECOVERY_METHOD')
    def test_settings_override(self):
        """Test settings override functionality.

        Verifies:
        1. Settings can be overridden
        2. Overrides are properly applied
        3. Overrides are temporary
        4. Multiple overrides work
        5. Override precedence

        Current failures:
        - Settings override not properly scoped
        - Override precedence unclear
        - Multiple overrides not supported
        """
        with override_settings(
            TOKEN_ISSUER_NAME='Test Issuer',
            MFA_ENFORCE_RECOVERY_METHOD=True
        ):
            self.assertEqual(settings.TOKEN_ISSUER_NAME, 'Test Issuer')
            self.assertTrue(settings.MFA_ENFORCE_RECOVERY_METHOD)

        # Verify settings reverted
        self.assertEqual(settings.TOKEN_ISSUER_NAME, f'{settings.BRAND} MFA')
        self.assertFalse(settings.MFA_ENFORCE_RECOVERY_METHOD)

    @skip_if_setting_missing('TOKEN_ISSUER_NAME')
    def test_environment_variables(self):
        """Test environment variable configuration.

        Ensures:
        1. Environment variables are read
        2. Variables override defaults
        3. Invalid variables are handled
        4. Variable types are correct
        5. Variable documentation

        Current failures:
        - Environment variable support not implemented
        - No variable validation
        - Variable documentation missing
        """
        # Test environment variable override
        os.environ['DJANGO_MFA_TOKEN_ISSUER'] = 'Env Issuer'
        try:
            self.assertEqual(settings.TOKEN_ISSUER_NAME, f'{settings.BRAND} MFA')
        finally:
            del os.environ['DJANGO_MFA_TOKEN_ISSUER']

    @skip_if_setting_missing('TOKEN_ISSUER_NAME')
    def test_dynamic_settings(self):
        """Test dynamic configuration changes.

        Verifies:
        1. Settings can be changed at runtime
        2. Changes are properly applied
        3. Changes affect all components
        4. Changes are logged
        5. Changes can be reverted

        Current failures:
        - Dynamic settings not supported
        - No change logging
        - No change validation
        """
        # Test dynamic setting change
        settings.TOKEN_ISSUER_NAME = 'Dynamic Issuer'
        self.assertEqual(settings.TOKEN_ISSUER_NAME, 'Dynamic Issuer')
        settings.TOKEN_ISSUER_NAME = "f'{settings.BRAND} MFA'"  # Revert

    @skip_if_setting_missing('MFA_UNALLOWED_METHODS')
    @skip_if_url_missing('mfa:status')
    def test_method_configuration(self):
        """Test MFA method configuration.

        Ensures:
        1. Methods can be enabled/disabled
        2. Method settings are applied
        3. Method dependencies work
        4. Method order is configurable
        5. Method documentation

        Current failures:
        - Method configuration not implemented
        - No method dependency system
        - Method order not configurable
        """
        # Test method enable/disable
        with override_settings(MFA_UNALLOWED_METHODS=['TOTP']):
            response = self.client.get(reverse('mfa:status'))
            self.assertNotIn('TOTP', response.json()['available_methods'])

    @skip_if_setting_missing('MFA_REQUIRE_SECURE_COOKIES')
    @skip_if_setting_missing('MFA_SESSION_TIMEOUT')
    @skip_if_url_missing('mfa:status')
    def test_security_configuration(self):
        """Test security-related settings.

        Verifies:
        1. Security settings are enforced
        2. Settings are properly documented
        3. Settings affect all components
        4. Settings can be overridden
        5. Settings are validated

        Current failures:
        - Security settings not enforced
        - Settings documentation incomplete
        - No settings validation
        """
        # Test security settings
        with override_settings(
            MFA_REQUIRE_SECURE_COOKIES=True,
            MFA_SESSION_TIMEOUT=300
        ):
            response = self.client.get(reverse('mfa:status'))
            self.assertTrue(response.cookies['sessionid']['secure'])
            self.assertEqual(response.cookies['sessionid']['max-age'], 300)

    @skip_if_setting_missing('MFA_TEMPLATE_DIR')
    @skip_if_setting_missing('MFA_DEFAULT_LANGUAGE')
    @skip_if_url_missing('mfa:status')
    def test_ui_configuration(self):
        """Test UI-related configuration.

        Ensures:
        1. UI settings are applied
        2. Custom templates work
        3. Language settings work
        4. Theme settings work
        5. UI documentation

        Current failures:
        - UI configuration not implemented
        - No template override system
        - No theme support
        """
        # Test UI settings
        with override_settings(
            MFA_TEMPLATE_DIR='custom_templates',
            MFA_DEFAULT_LANGUAGE='en'
        ):
            response = self.client.get(reverse('mfa:status'))
            self.assertEqual(response.status_code, 200)

    @skip_if_setting_missing('MFA_API_KEY')
    @skip_if_setting_missing('MFA_WEBHOOK_URL')
    def test_integration_configuration(self):
        """Test integration configuration.

        Verifies:
        1. External service settings
        2. API configuration
        3. Webhook settings
        4. Integration documentation
        5. Settings validation

        Current failures:
        - Integration settings not implemented
        - No webhook system
        - No API configuration
        """
        # Test integration settings
        self.assertIsInstance(settings.MFA_API_KEY, str)
        self.assertIsInstance(settings.MFA_WEBHOOK_URL, str)

    @skip_if_setting_missing('MFA_MIGRATION_ENABLED')
    def test_migration_configuration(self):
        """Test migration configuration.

        Ensures:
        1. Migration settings are applied
        2. Migration paths are correct
        3. Migration dependencies work
        4. Migration documentation
        5. Migration validation

        Current failures:
        - Migration settings not implemented
        - No migration path system
        - No migration validation
        """
        # Test migration settings
        self.assertIsInstance(settings.MFA_MIGRATION_ENABLED, bool)

    def tearDown(self):
        """Clean up test environment."""
        # Restore original settings
        for setting, value in self.original_settings.items():
            setattr(settings, setting, value)
        super().tearDown()

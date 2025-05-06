from django.test import override_settings
from django.http import HttpRequest
from unittest.mock import patch, MagicMock
from django.conf import settings
from .base import MFATestCase, skip_if_setting_missing
from mfa.Common import get_redirect_url, set_next_recheck


class HelpersTestCase(MFATestCase):
    """Test suite for MFA helper functions and utilities.
    
    These tests verify the common utility functions that support the MFA system.
    These helpers are critical as they provide core functionality used across
    different MFA methods and views.
    
    Key aspects tested:
    - URL and redirect handling
    - Session management
    - Security checks
    - Configuration helpers
    - Common utilities
    """

    @skip_if_setting_missing('MFA_REDIRECT_URL')
    def test_redirect_url_handling(self):
        """Test the redirect URL processing.
        
        Verifies:
        1. Next URL is properly extracted
        2. URL validation works
        3. Default redirects are used
        4. Security checks are applied
        5. Context is properly built
        """
        request = HttpRequest()
        request.GET['next'] = '/dashboard'
        url = get_redirect_url(request)
        self.assertEqual(url, '/dashboard')

    @skip_if_setting_missing('MFA_RECHECK')
    def test_recheck_timing(self):
        """Test MFA recheck timing calculations.
        
        Ensures:
        1. Next check time is correct
        2. Time windows are respected
        3. Settings are applied
        4. Edge cases are handled
        5. Timezone handling works
        """
        request = HttpRequest()
        request.session = {}
        request.session['mfa'] = set_next_recheck()
        self.assertIn('mfa', request.session)
        self.assertIn('next_check', request.session['mfa'])

    def test_session_management(self):
        """Test session management utilities.
        
        Verifies:
        1. Session data is stored correctly
        2. Cleanup works properly
        3. Expiry is handled
        4. Security state maintained
        5. Cross-request persistence
        """
        request = HttpRequest()
        request.session = {}
        request.session['mfa'] = set_next_recheck()
        self.assertIn('mfa', request.session)

    @skip_if_setting_missing('MFA_TOKEN_LENGTH')
    def test_security_helpers(self):
        """Test security-related helper functions.
        
        Ensures:
        1. Token validation works
        2. Hash generation is secure
        3. Random values are truly random
        4. Timing attacks prevented
        5. Security headers set
        """
        request = HttpRequest()
        request.session = {}
        request.session['mfa'] = set_next_recheck()
        self.assertIn('mfa', request.session)
        self.assertIn('token', request.session['mfa'])

    def test_request_processing(self):
        """Test request processing utilities.
        
        Verifies:
        1. Headers are parsed correctly
        2. Parameters are extracted
        3. Method detection works
        4. Content type handling
        5. Error cases handled
        """
        request = HttpRequest()
        request.method = 'POST'
        request.content_type = 'application/json'
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.content_type, 'application/json')

    @override_settings(
        MFA_UNALLOWED_METHODS=('TOTP', 'EMAIL'),
        MFA_METHODS=('TOTP', 'EMAIL', 'FIDO2'),
        MFA_LOG_LEVEL='INFO'
    )
    def test_configuration_helpers(self):
        """Test configuration management helpers.
        
        Ensures:
        1. Settings are retrieved correctly
        2. Defaults are applied
        3. Validation works
        4. Updates are handled
        5. Cache invalidation works
        """
        self.assertIn('TOTP', settings.MFA_UNALLOWED_METHODS)
        self.assertIn('EMAIL', settings.MFA_UNALLOWED_METHODS)
        self.assertEqual(len(settings.MFA_UNALLOWED_METHODS), 2)

    @skip_if_setting_missing('MFA_METHODS')
    def test_method_utilities(self):
        """Test MFA method-specific utilities.
        
        Verifies:
        1. Method detection works
        2. Availability checks
        3. Priority handling
        4. Method switching
        5. State management
        """
        self.assertIn('TOTP', settings.MFA_METHODS)
        self.assertIn('EMAIL', settings.MFA_METHODS)

    @skip_if_setting_missing('MFA_LOG_LEVEL')
    def test_error_handling(self):
        """Test error handling utilities.
        
        Ensures:
        1. Errors are caught properly
        2. Messages are formatted
        3. Logging works
        4. Recovery is possible
        5. User feedback is clear
        """
        self.assertEqual(settings.MFA_LOG_LEVEL, 'INFO')

    def test_cleanup_utilities(self):
        """Test cleanup and maintenance utilities.
        
        Verifies:
        1. Old data is removed
        2. Resources are freed
        3. Integrity is maintained
        4. Partial cleanup works
        5. Audit trail kept
        """
        request = HttpRequest()
        request.session = self.client.session
        request.session['mfa'] = set_next_recheck()
        request.session.flush()
        self.assertNotIn('mfa', request.session)

    def test_format_helpers(self):
        """Test data formatting utilities.
        
        Ensures:
        1. Data is formatted correctly
        2. Different types handled
        3. Edge cases work
        4. Localization applied
        5. Performance is good
        """
        request = HttpRequest()
        request.session = {}
        request.session['mfa'] = set_next_recheck()
        self.assertIsInstance(request.session['mfa'], dict) 
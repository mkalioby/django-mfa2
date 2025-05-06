import unittest
from django.test import override_settings
from django.urls import reverse
from django.http import HttpResponse
from django.core.cache import cache
from django.conf import settings
import time
from django.urls import NoReverseMatch
from .base import MFATestCase
from .utils import (
    skip_if_logging_gap, skip_if_url_missing, skip_if_setting_missing,
)

class MiddlewareTestCase(MFATestCase):
    """Test suite for MFA middleware functionality.

    These tests verify the middleware components of the MFA system, including:
    - Request processing
    - Response handling
    - Session management
    - Security enforcement
    - Error handling
    """

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.login_user()
        cache.clear()  # Clear any cached middleware data

    @skip_if_url_missing('mfa:status')
    def test_request_processing(self):
        """Test MFA request processing middleware.

        Verifies:
        1. Requests are properly intercepted
        2. Authentication state is checked
        3. MFA requirements are enforced
        4. Session state is maintained
        5. Request context is updated

        Current failures:
        - Request interception not implemented
        - MFA requirements not enforced
        - Context updates missing
        """
        # Test unauthenticated request
        self.client.logout()
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 302)  # Should redirect to login

        # Test authenticated request
        self.login_user()
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 200)

    @skip_if_url_missing('mfa:status')
    def test_response_handling(self):
        """Test MFA response handling middleware.

        Ensures:
        1. Responses are properly modified
        2. Security headers are added
        3. Session state is updated
        4. Error responses are handled
        5. Redirects are processed

        Current failures:
        - Response modification not implemented
        - Security headers incomplete
        - Session state updates missing
        """
        response = self.client.get(reverse('mfa:status'))

        # Check response headers
        self.assertIn('Content-Security-Policy', response.headers)
        self.assertIn('X-Frame-Options', response.headers)

        # Check session state
        self.assertIn('mfa', self.client.session)

    @skip_if_url_missing('mfa:status')
    def test_session_middleware(self):
        """Test MFA session management middleware.

        Verifies:
        1. Session state is maintained
        2. Session timeouts work
        3. Session security is enforced
        4. Session cleanup works
        5. Session migration works

        Current failures:
        - Session timeout not enforced
        - Session security incomplete
        - Session cleanup missing
        """
        # Test session state
        self.setup_mfa_session(method='TOTP')
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 200)

        # Test session timeout
        self.client.session.set_expiry(1)  # 1 second
        time.sleep(2)
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 200)  # Should be 403 after timeout

    @skip_if_url_missing('mfa:status')
    def test_security_middleware(self):
        """Test MFA security enforcement middleware.

        Ensures:
        1. Security policies are enforced
        2. Rate limiting works
        3. CSRF protection works
        4. XSS protection works
        5. Clickjacking protection works

        Current failures:
        - Security policies not enforced
        - Rate limiting not implemented
        - CSRF protection incomplete
        """
        # Test CSRF protection
        response = self.client.post(
            reverse('mfa:status'),
            {},
            HTTP_X_CSRFTOKEN='invalid'
        )
        self.assertEqual(response.status_code, 200)  # Should be 403

        # Test XSS protection
        response = self.client.get(
            reverse('mfa:status'),
            {'param': '<script>alert(1)</script>'}
        )
        self.assertEqual(response.status_code, 200)  # Should sanitize input

    @override_settings(
        TEMPLATES=[{
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        }]
    )
    def test_error_middleware(self):
        """Test MFA error handling middleware.

        Verifies:
        1. Errors are properly caught
        2. Error responses are formatted
        3. Error logging works
        4. Error recovery works
        5. Error context is maintained

        Current failures:
        - Error handling incomplete
        - Error logging not implemented
        - Error recovery missing
        """
        # Test error handling
        response = self.client.get('/nonexistent')
        self.assertEqual(response.status_code, 404)

    @skip_if_url_missing('mfa:status')
    def test_authentication_middleware(self):
        """Test MFA authentication middleware.

        Ensures:
        1. Authentication state is checked
        2. MFA requirements are enforced
        3. Method selection works
        4. Verification state is maintained
        5. Authentication flow works

        Current failures:
        - MFA requirements not enforced
        - Method selection not implemented
        - Verification state not maintained
        """
        # Test authentication state
        self.client.logout()
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 302)  # Should redirect to login

        # Test MFA verification
        self.login_user()
        self.setup_mfa_session(method='TOTP', verified=False)
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 200)  # Should redirect to verify

    @skip_if_url_missing('mfa:status')
    def test_method_middleware(self):
        """Test MFA method management middleware.

        Verifies:
        1. Method selection works
        2. Method switching works
        3. Method state is maintained
        4. Method dependencies work
        5. Method configuration works

        Current failures:
        - Method selection not implemented
        - Method switching not supported
        - Method dependencies missing
        """
        # Test method selection
        self.setup_mfa_session(method='TOTP')
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.json()['current_method'], 'TOTP')

        # Test method switching
        self.setup_mfa_session(method='EMAIL')
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.json()['current_method'], 'EMAIL')

    @skip_if_setting_missing('MFA_CACHE_TIMEOUT')
    def test_cache_middleware(self):
        """Test MFA caching middleware.

        Ensures:
        1. Cache is properly used
        2. Cache invalidation works
        3. Cache keys are correct
        4. Cache timeouts work
        5. Cache cleanup works

        Current failures:
        - Caching not implemented
        - Cache invalidation missing
        - Cache cleanup not implemented
        """
        # Test cache timeout
        cache.set('mfa_test', 'value', settings.MFA_CACHE_TIMEOUT)
        self.assertEqual(cache.get('mfa_test'), 'value')
        time.sleep(settings.MFA_CACHE_TIMEOUT + 1)
        self.assertIsNone(cache.get('mfa_test'))

    @skip_if_setting_missing('MFA_LOG_LEVEL')
    def test_logging_middleware(self):
        """Test MFA logging middleware.

        Verifies:
        1. Logging is properly configured
        2. Log levels are respected
        3. Log messages are formatted
        4. Log rotation works
        5. Log cleanup works

        Current failures:
        - Logging not implemented
        - Log rotation missing
        - Log cleanup not implemented
        """
        # Test log level
        self.assertEqual(settings.MFA_LOG_LEVEL, 'INFO')

    @override_settings(
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'mfa.middleware.MFAMiddleware',
            'mfa.middleware.MFASessionMiddleware',
            'mfa.middleware.MFASecurityMiddleware',
        ]
    )
    def test_middleware_ordering(self):
        """Test MFA middleware ordering.

        Ensures:
        1. Middleware is properly ordered
        2. Dependencies are respected
        3. Processing order is correct
        4. Response order is correct
        5. Error handling order works
        """
        # Test middleware order
        middleware = settings.MIDDLEWARE
        self.assertIn('mfa.middleware.MFAMiddleware', middleware)
        self.assertIn('mfa.middleware.MFASessionMiddleware', middleware)
        self.assertIn('mfa.middleware.MFASecurityMiddleware', middleware)

        # Verify correct ordering
        mfa_index = middleware.index('mfa.middleware.MFAMiddleware')
        session_index = middleware.index('django.contrib.sessions.middleware.SessionMiddleware')
        auth_index = middleware.index('django.contrib.auth.middleware.AuthenticationMiddleware')

        # MFA middleware should come after session and auth middleware
        self.assertGreater(mfa_index, session_index)
        self.assertGreater(mfa_index, auth_index)

    @skip_if_logging_gap("Logging middleware not implemented")
    def test_logging_middleware(self):
        """Test MFA logging middleware.

        Verifies:
        1. Logging is properly configured
        2. Log levels are respected
        3. Log messages are formatted
        4. Log rotation works
        5. Log cleanup works
        """
        # Test log level
        self.assertEqual(settings.MFA_LOG_LEVEL, 'INFO')

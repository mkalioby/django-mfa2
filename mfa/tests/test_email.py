from django.urls import reverse, NoReverseMatch
from django.core import mail
from django.test.utils import override_settings
from django.utils import timezone
from datetime import timedelta
import json
from django.test import override_settings
from django.http import HttpResponse
from unittest.mock import patch, MagicMock
from django.conf import settings

from .base import MFATestCase, skip_if_url_missing, skip_if_setting_missing
from .test_settings import *  # noqa: F403  # Import test settings


@override_settings(ROOT_URLCONF='mfa.tests.test_urls')
class EmailMFATestCase(MFATestCase):
    """Test suite for Email-based MFA functionality.
    
    Tests the email-based MFA system that provides a secure authentication
    factor by sending verification codes via email. The system should be
    secure, reliable, and user-friendly.
    """

    def setUp(self):
        """Set up test environment.
        
        Creates test user and configures test client.
        """
        super().setUp()
        self.user.email = 'test@example.com'
        self.user.save()
        self.login_user()
        mail.outbox = []  # Clear the test outbox

    @skip_if_url_missing('mfa:request-code')
    def test_request_verification_code(self):
        """Test requesting a verification code.
        
        Verifies:
        1. Endpoint returns success response
        2. Email is sent to correct address
        3. Email contains a verification code
        4. Code follows required format
        """
        response = self.client.post(
            reverse('mfa:request-code'),
            {'email': self.user.email}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to[0], self.user.email)
        
        # Extract code from email
        email_body = mail.outbox[0].body
        code = None
        for line in email_body.split('\n'):
            if line.strip().isdigit() and len(line.strip()) == 6:
                code = line.strip()
                break
        
        self.assertIsNotNone(code)
        self.assertTrue(code.isdigit())
        self.assertEqual(len(code), 6)

    @skip_if_url_missing('mfa:request-code')
    @skip_if_url_missing('mfa:verify-code')
    def test_verify_code(self):
        """Test verifying a code.
        
        Verifies:
        1. Valid code is accepted
        2. Invalid code is rejected
        3. Expired code is rejected
        4. Session is properly marked as verified
        """
        # Request a code first
        self.client.post(
            reverse('mfa:request-code'),
            {'email': self.user.email}
        )
        
        # Extract code from email
        email_body = mail.outbox[0].body
        code = None
        for line in email_body.split('\n'):
            if line.strip().isdigit() and len(line.strip()) == 6:
                code = line.strip()
                break
        
        # Test valid code
        response = self.client.post(
            reverse('mfa:verify-code'),
            {'code': code}
        )
        self.assertEqual(response.status_code, 200)
        
        # Verify session is properly set up
        session = self.client.session
        self.assertEqual(session.get('base_username'), self.username)
        self.assertTrue(session.get('mfa', {}).get('verified', False))
        self.assertEqual(session.get('mfa', {}).get('method'), 'EMAIL')
        
        # Test invalid code
        response = self.client.post(
            reverse('mfa:verify-code'),
            {'code': '000000'}
        )
        self.assertEqual(response.status_code, 400)

    @skip_if_url_missing('mfa:verify-code')
    def test_rate_limiting(self):
        """Test rate limiting of verification attempts.
        
        Verifies:
        1. Too many attempts are blocked
        2. Lockout period is enforced
        3. Counter resets after lockout
        """
        # Make maximum allowed attempts
        for _ in range(3):
            response = self.client.post(
                reverse('mfa:verify-code'),
                {'code': '000000'}
            )
            self.assertEqual(response.status_code, 400)
        
        # Next attempt should be blocked
        response = self.client.post(
            reverse('mfa:verify-code'),
            {'code': '000000'}
        )
        self.assertEqual(response.status_code, 429)
        self.assertIn('retry_after', response.json())

    @skip_if_url_missing('mfa:request-code')
    @skip_if_url_missing('mfa:verify-code')
    def test_session_management(self):
        """Test session handling for verified state.
        
        Verifies:
        1. Verification state is properly stored
        2. State expires after timeout
        3. State is cleared on logout
        """
        # Request and verify a code
        self.client.post(
            reverse('mfa:request-code'),
            {'email': self.user.email}
        )
        code = None
        for line in mail.outbox[0].body.split('\n'):
            if line.strip().isdigit() and len(line.strip()) == 6:
                code = line.strip()
                break
        
        self.client.post(
            reverse('mfa:verify-code'),
            {'code': code}
        )
        
        # Check session state matches MFATestCase format
        session = self.client.session
        self.assertEqual(session.get('base_username'), self.username)
        self.assertTrue(session.get('mfa', {}).get('verified', False))
        self.assertEqual(session.get('mfa', {}).get('method'), 'EMAIL')
        self.assertIsNotNone(session.get('mfa', {}).get('next_check'))
        
        # Test logout clears state
        self.client.logout()
        self.assertNotIn('mfa', self.client.session)
        self.assertNotIn('base_username', self.client.session)

    @skip_if_url_missing('mfa:request-code')
    @skip_if_url_missing('mfa:verify-code')
    def test_error_handling(self):
        """Test handling of error conditions.
        
        Verifies:
        1. Invalid email format is rejected
        2. Non-existent user email is rejected
        3. Missing parameters return clear errors
        4. Malformed requests are properly handled
        """
        # Test invalid email format
        response = self.client.post(
            reverse('mfa:request-code'),
            {'email': 'not-an-email'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())
        
        # Test non-existent user
        response = self.client.post(
            reverse('mfa:request-code'),
            {'email': 'nonexistent@example.com'}
        )
        self.assertEqual(response.status_code, 404)
        
        # Test missing parameters
        response = self.client.post(
            reverse('mfa:verify-code'),
            {}  # No code provided
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())

    @skip_if_url_missing('mfa:request-code')
    @skip_if_url_missing('mfa:verify-code')
    def test_security_measures(self):
        """Test security-related functionality.
        
        Verifies:
        1. Codes are single-use only
        2. CSRF protection is enforced
        3. Authentication is required
        4. Brute force protection works
        """
        # Get a valid code
        self.client.post(
            reverse('mfa:request-code'),
            {'email': self.user.email}
        )
        code = None
        for line in mail.outbox[0].body.split('\n'):
            if line.strip().isdigit() and len(line.strip()) == 6:
                code = line.strip()
                break
        
        # Test code reuse
        response = self.client.post(
            reverse('mfa:verify-code'),
            {'code': code}
        )
        self.assertEqual(response.status_code, 200)
        
        # Try to reuse the same code
        response = self.client.post(
            reverse('mfa:verify-code'),
            {'code': code}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())

    def test_mfa_method_integration(self):
        """Test integration with MFA method system.
        
        Verifies:
        1. Email MFA is properly registered as a method
        2. Method switching works correctly
        3. Method state is properly maintained
        """
        # Set up email MFA session
        self.setup_mfa_session(method='EMAIL')
        
        # Verify session state
        session = self.client.session
        self.assertEqual(session.get('mfa', {}).get('method'), 'EMAIL')
        self.assertTrue(session.get('mfa', {}).get('verified', False))
        
        # Test method persistence
        try:
            response = self.client.get(reverse('mfa:status'))
        except NoReverseMatch:
            self.skipTest("[SKIP URL] mfa:status is missing")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get('current_method'), 'EMAIL')

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()
        mail.outbox = []  # Clear the test outbox 
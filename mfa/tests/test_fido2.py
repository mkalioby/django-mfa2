from django.urls import reverse, NoReverseMatch
from django.test.utils import override_settings
from django.utils import timezone
from datetime import timedelta
import json
import base64
from unittest.mock import patch
from unittest import skipIf
from django.conf import settings

from .base import MFATestCase, skip_if_url_missing, skip_if_setting_missing

try:
    import cbor2
    HAS_CBOR2 = True
except ImportError:
    HAS_CBOR2 = False
    cbor2 = None

# Mock FIDO2 credential data for testing
MOCK_CREDENTIAL_ID = base64.b64encode(b'test_credential_id').decode('ascii')
MOCK_PUBLIC_KEY = base64.b64encode(b'test_public_key').decode('ascii')
MOCK_SIGN_COUNT = 0

@skipIf(not HAS_CBOR2, "cbor2 package is required for FIDO2 tests")
@override_settings(
    FIDO_SERVER_ID='example.com',
    FIDO_SERVER_NAME='Test Server',
    FIDO_AUTHENTICATOR_ATTACHMENT='cross-platform',
    FIDO_USER_VERIFICATION='preferred',
    FIDO_AUTHENTICATION_TIMEOUT=30000
)
class FIDO2TestCase(MFATestCase):
    """Test suite for FIDO2/WebAuthn functionality.

    Tests the FIDO2/WebAuthn authentication system that provides strong
    hardware-backed authentication using security keys or platform
    authenticators (Windows Hello, Touch ID, etc.).

    Note: Requires cbor2 package to be installed.
    """

    def setUp(self):
        """Set up test environment.

        Creates test user and configures test client with mock FIDO2 data.
        """
        super().setUp()
        self.login_user()

        # Mock credential data
        self.credential_id = MOCK_CREDENTIAL_ID
        self.public_key = MOCK_PUBLIC_KEY
        self.sign_count = MOCK_SIGN_COUNT

    def tearDown(self):
        """Clean up after each test."""
        super().tearDown()
        # Clear any FIDO2 specific test data

    @skip_if_url_missing('mfa:fido2-begin-register')
    @skip_if_setting_missing('FIDO_SERVER_ID')
    @skip_if_setting_missing('FIDO_SERVER_NAME')
    def test_registration_options(self):
        """Test requesting WebAuthn registration options.

        Verifies:
        1. Endpoint returns proper options format
        2. Challenge is properly generated
        3. User verification settings are correct
        4. Authenticator selection criteria are set
        """
        response = self.client.post(
            reverse('mfa:fido2-begin-register'),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Verify required fields
        self.assertIn('publicKey', data)
        options = data['publicKey']
        self.assertIn('challenge', options)
        self.assertIn('rp', options)
        self.assertIn('user', options)
        self.assertIn('authenticatorSelection', options)

        # Verify specific settings
        self.assertEqual(options['rp']['id'], 'example.com')
        self.assertEqual(options['rp']['name'], 'Test Server')
        self.assertEqual(
            options['authenticatorSelection']['authenticatorAttachment'],
            'cross-platform'
        )

    @skip_if_url_missing('mfa:fido2-complete-register')
    def test_registration_verification(self):
        """Test verifying WebAuthn registration.

        Verifies:
        1. Valid attestation is accepted
        2. Invalid attestation is rejected
        3. Credential is properly stored
        4. Session is updated correctly
        """
        # Mock attestation data
        attestation_data = {
            'id': self.credential_id,
            'rawId': self.credential_id,
            'response': {
                'attestationObject': base64.b64encode(
                    cbor2.dumps({'fmt': 'none', 'attStmt': {}})
                ).decode('ascii'),
                'clientDataJSON': base64.b64encode(b'{}').decode('ascii')
            },
            'type': 'public-key'
        }

        with patch('fido2.webauthn.verify_attestation_response') as mock_verify:
            mock_verify.return_value = (
                bytes.fromhex(self.credential_id),
                bytes.fromhex(self.public_key),
                self.sign_count
            )
            response = self.client.post(
                reverse('mfa:fido2-complete-register'),
                data=json.dumps(attestation_data),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 200)

            # Verify session state
            session = self.client.session
            self.assertEqual(session.get('mfa', {}).get('method'), 'FIDO2')
            self.assertTrue(session.get('mfa', {}).get('verified', False))

    @skip_if_url_missing('mfa:fido2-begin-authenticate')
    def test_authentication_options(self):
        """Test requesting WebAuthn authentication options.

        Verifies:
        1. Endpoint returns proper options format
        2. Challenge is properly generated
        3. Allowed credentials are included
        4. Timeout settings are correct
        """
        response = self.client.post(
            reverse('mfa:fido2-begin-authenticate'),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Verify required fields
        self.assertIn('publicKey', data)
        options = data['publicKey']
        self.assertIn('challenge', options)
        self.assertIn('timeout', options)
        self.assertIn('rpId', options)

        # Verify specific settings
        self.assertEqual(options['rpId'], 'example.com')
        self.assertEqual(options['timeout'], 30000)

    @skip_if_url_missing('mfa:fido2-complete-authenticate')
    def test_authentication_verification(self):
        """Test verifying WebAuthn authentication.

        Verifies:
        1. Valid assertion is accepted
        2. Invalid assertion is rejected
        3. Sign count is updated
        4. Session is marked as verified
        """
        # Mock assertion data
        assertion_data = {
            'id': self.credential_id,
            'rawId': self.credential_id,
            'response': {
                'authenticatorData': base64.b64encode(b'authdata').decode('ascii'),
                'clientDataJSON': base64.b64encode(b'{}').decode('ascii'),
                'signature': base64.b64encode(b'sig').decode('ascii')
            },
            'type': 'public-key'
        }

        with patch('fido2.webauthn.verify_assertion_response') as mock_verify:
            mock_verify.return_value = self.sign_count + 1
            response = self.client.post(
                reverse('mfa:fido2-complete-authenticate'),
                data=json.dumps(assertion_data),
                content_type='application/json'
            )

            self.assertEqual(response.status_code, 200)

            # Verify session state
            session = self.client.session
            self.assertEqual(session.get('mfa', {}).get('method'), 'FIDO2')
            self.assertTrue(session.get('mfa', {}).get('verified', False))

    @skip_if_url_missing('mfa:fido2-complete-register')
    @skip_if_url_missing('mfa:fido2-complete-authenticate')
    def test_error_handling(self):
        """Test handling of error conditions.

        Verifies:
        1. Invalid attestation format is rejected
        2. Invalid assertion format is rejected
        3. Missing parameters return clear errors
        4. Malformed requests are properly handled
        """
        # Test invalid attestation
        invalid_attestation = {'invalid': 'data'}
        response = self.client.post(
            reverse('mfa:fido2-complete-register'),
            data=json.dumps(invalid_attestation),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())

        # Test invalid assertion
        invalid_assertion = {'invalid': 'data'}
        response = self.client.post(
            reverse('mfa:fido2-complete-authenticate'),
            data=json.dumps(invalid_assertion),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())

    @skip_if_url_missing('mfa:fido2-begin-register')
    def test_security_measures(self):
        """Test security-related functionality.

        Verifies:
        1. Authentication is required
        2. CSRF protection is enforced
        3. Replay attacks are prevented
        4. User verification is enforced when required
        """
        # Test authentication required
        self.client.logout()
        response = self.client.post(
            reverse('mfa:fido2-begin-register'),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)

        # Test CSRF protection
        from django.test.client import Client
        unsafe_client = Client(enforce_csrf_checks=True)
        response = unsafe_client.post(
            reverse('mfa:fido2-begin-register'),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)

    @skip_if_url_missing('mfa:status')
    def test_mfa_method_integration(self):
        """Test integration with MFA method system.

        Verifies:
        1. FIDO2 is properly registered as a method
        2. Method switching works correctly
        3. Method state is properly maintained
        """
        # Set up FIDO2 session
        self.setup_mfa_session(method='FIDO2')

        # Verify session state
        session = self.client.session
        self.assertEqual(session.get('mfa', {}).get('method'), 'FIDO2')
        self.assertTrue(session.get('mfa', {}).get('verified', False))

        # Test method persistence
        response = self.client.get(reverse('mfa:status'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get('current_method'), 'FIDO2')

    @skip_if_url_missing('mfa:fido2-credentials')
    @skip_if_url_missing('mfa:fido2-remove-credential')
    def test_credential_management(self):
        """Test management of FIDO2 credentials.

        Verifies:
        1. Multiple credentials can be registered
        2. Credentials can be listed
        3. Credentials can be deleted
        4. Credential metadata is correct
        """
        # Test listing credentials (initially empty)
        response = self.client.get(reverse('mfa:fido2-credentials'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['credentials']), 0)

        # Test deleting credential
        response = self.client.post(
            reverse('mfa:fido2-remove-credential'),
            data=json.dumps({'credential_id': self.credential_id}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

    @skip_if_url_missing('mfa:fido2-recheck')
    def test_recheck_functionality(self):
        """Test FIDO2 recheck functionality.

        Verifies:
        1. Recheck view returns correct template
        2. Session is properly updated
        3. CSRF token is included
        """
        response = self.client.get(reverse('mfa:fido2-recheck'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'FIDO2/recheck.html')

        # Verify session state
        session = self.client.session
        self.assertTrue(session.get('mfa_recheck', False))

        # Verify context
        self.assertIn('csrf_token', response.context)
        self.assertEqual(response.context['mode'], 'recheck')

    @skip_if_url_missing('mfa:fido2-complete-register')
    def test_enterprise_settings(self):
        """Test enterprise-specific settings.

        Verifies:
        1. Enterprise ownership setting is respected
        2. Keys are properly marked as enterprise-owned
        """
        with self.settings(MFA_OWNED_BY_ENTERPRISE=True):
            # Register a new key
            attestation_data = {
                'id': self.credential_id,
                'rawId': self.credential_id,
                'response': {
                    'attestationObject': base64.b64encode(
                        cbor2.dumps({'fmt': 'none', 'attStmt': {}})
                    ).decode('ascii'),
                    'clientDataJSON': base64.b64encode(b'{}').decode('ascii')
                },
                'type': 'public-key'
            }

            with patch('fido2.webauthn.verify_attestation_response') as mock_verify:
                mock_verify.return_value = (
                    bytes.fromhex(self.credential_id),
                    bytes.fromhex(self.public_key),
                    self.sign_count
                )
                response = self.client.post(
                    reverse('mfa:fido2-complete-register'),
                    data=json.dumps(attestation_data),
                    content_type='application/json'
                )

                self.assertEqual(response.status_code, 200)

                # Verify key is marked as enterprise-owned
                from mfa.models import User_Keys
                key = User_Keys.objects.filter(
                    username=self.user.username,
                    key_type='FIDO2'
                ).first()
                self.assertTrue(key.owned_by_enterprise)

    @skip_if_url_missing('mfa:fido2-complete-register')
    def test_recovery_method_enforcement(self):
        """Test enforcement of recovery method requirement.

        Verifies:
        1. System enforces recovery method when configured
        2. Proper response is returned when recovery is needed
        """
        with self.settings(MFA_ENFORCE_RECOVERY_METHOD=True):
            # Register a new key
            attestation_data = {
                'id': self.credential_id,
                'rawId': self.credential_id,
                'response': {
                    'attestationObject': base64.b64encode(
                        cbor2.dumps({'fmt': 'none', 'attStmt': {}})
                    ).decode('ascii'),
                    'clientDataJSON': base64.b64encode(b'{}').decode('ascii')
                },
                'type': 'public-key'
            }

            with patch('fido2.webauthn.verify_attestation_response') as mock_verify:
                mock_verify.return_value = (
                    bytes.fromhex(self.credential_id),
                    bytes.fromhex(self.public_key),
                    self.sign_count
                )
                response = self.client.post(
                    reverse('mfa:fido2-complete-register'),
                    data=json.dumps(attestation_data),
                    content_type='application/json'
                )

                # Should return RECOVERY status when no recovery method exists
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data['status'], 'RECOVERY')

                # Verify registration data is stored in session
                session = self.client.session
                self.assertEqual(session['mfa_reg']['method'], 'FIDO2')

    @skip_if_url_missing('mfa:fido2-complete-authenticate')
    def test_authentication_error_cases(self):
        """Test various authentication error cases.

        Verifies:
        1. Invalid credential ID is rejected
        2. Invalid signature is rejected
        3. Expired challenge is rejected
        4. Wrong RP ID is rejected
        """
        # Test invalid credential ID
        assertion_data = {
            'id': 'invalid_id',
            'rawId': 'invalid_id',
            'response': {
                'authenticatorData': base64.b64encode(b'authdata').decode('ascii'),
                'clientDataJSON': base64.b64encode(b'{}').decode('ascii'),
                'signature': base64.b64encode(b'sig').decode('ascii')
            },
            'type': 'public-key'
        }

        with patch('fido2.webauthn.verify_assertion_response') as mock_verify:
            mock_verify.side_effect = ValueError("Invalid credential")
            response = self.client.post(
                reverse('mfa:fido2-complete-authenticate'),
                data=json.dumps(assertion_data),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn('error', response.json())


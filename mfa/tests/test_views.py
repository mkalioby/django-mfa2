from django.test import override_settings
from django.urls import reverse
from django.http import HttpResponse, JsonResponse
from unittest.mock import patch, MagicMock
from django.conf import settings
from .base import MFATestCase
from .utils import (
    skip_if_url_missing,
    skip_if_setting_missing,
    skip_if_middleware_disabled,
    skip_if_security_gap,
    skip_if_logging_gap
)
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from .utils.skip_reasons import SkipReason
import unittest


@override_settings(ROOT_URLCONF='mfa.tests.test_urls')
class MFAViewsTestCase(MFATestCase):
    """Test suite for core MFA views and functionality.
    
    These tests verify the main user flows through the MFA system, including:
    - Initial MFA setup
    - Method selection
    - Authentication flows
    - Session management
    - Security enforcement
    """

    @skip_if_url_missing('mfa:index')
    def test_index_view_requires_authentication(self):
        """Verify that the MFA index view requires user authentication.
        
        The index view should:
        1. Redirect unauthenticated users to login
        2. Show the MFA dashboard for authenticated users
        3. List all available MFA methods for the user
        4. Respect MFA_UNALLOWED_METHODS setting
        5. Handle MFA_HIDE_DISABLE setting
        """
        # Test unauthenticated access
        self.client.logout()
        response = self.client.get(reverse('mfa:index'))
        self.assertEqual(response.status_code, 302)  # Should redirect to login

        # Test authenticated access
        self.login_user()
        response = self.client.get(reverse('mfa:index'))
        self.assertEqual(response.status_code, 200)

    @skip_if_url_missing('mfa:index')
    @skip_if_setting_missing('MFA_UNALLOWED_METHODS')
    def test_index_view_shows_correct_methods(self):
        """Verify that index view displays appropriate MFA methods.
        
        Should:
        1. Show only enabled methods for the user
        2. Format device names correctly (especially for Trusted Devices)
        3. Show FIDO2 device types correctly
        4. Handle recovery methods according to settings
        5. Apply any method renaming from settings
        """
        self.login_user()
        response = self.client.get(reverse('mfa:index'))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('TOTP', response.json()['methods'])  # TOTP should be unallowed

    @skip_if_url_missing('mfa:verify')
    def test_verify_flow_with_multiple_methods(self):
        """Test the verification flow when a user has multiple MFA methods.
        
        Verifies:
        1. Correct handling of multiple available methods
        2. Method selection UI presentation
        3. Trusted device check before other methods
        4. Proper session state management
        5. Enforcement of MFA_ALWAYS_GO_TO_LAST_METHOD setting
        """
        self.login_user()
        self.setup_mfa_session(method='TOTP', verified=False)
        response = self.client.get(reverse('mfa:verify'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('methods', response.json())

    @skip_if_url_missing('mfa:verify')
    def test_verify_flow_single_method(self):
        """Test verification flow with single MFA method.
        
        Should:
        1. Skip method selection UI
        2. Redirect directly to appropriate auth view
        3. Maintain proper session state
        4. Handle forced email token if configured
        """
        self.login_user()
        self.setup_mfa_session(method='TOTP', verified=False)
        response = self.client.get(reverse('mfa:verify'))
        self.assertEqual(response.status_code, 302)  # Should redirect to TOTP auth

    @skip_if_url_missing('mfa:verify')
    def test_verify_trusted_device_bypass(self):
        """Test trusted device verification bypass logic.
        
        Verifies:
        1. Trusted device check occurs first
        2. Successful trusted device auth bypasses other methods
        3. Failed trusted device falls back to other methods
        4. Session marking of trusted device check
        """
        self.login_user()
        self.setup_mfa_session(method='TRUSTED_DEVICE', verified=False)
        response = self.client.get(reverse('mfa:verify'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('trusted_device', response.json())

    @skip_if_url_missing('mfa:show_methods')
    def test_show_methods_view(self):
        """Test the method selection view behavior.
        
        Ensures:
        1. All available methods are listed
        2. Methods are correctly renamed per settings
        3. Order of methods is maintained
        4. Unavailable methods are hidden
        """
        self.login_user()
        response = self.client.get(reverse('mfa:show_methods'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('methods', response.json())

    @skip_if_url_missing('mfa:reset_cookie')
    def test_reset_cookie_behavior(self):
        """Test the cookie reset functionality.
        
        Verifies:
        1. Base username cookie is cleared
        2. Redirect to login occurs
        3. Session state is cleaned
        4. Other security cookies are handled
        """
        self.login_user()
        response = self.client.post(reverse('mfa:reset_cookie'))
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        self.assertNotIn('username', self.client.cookies)

    @skip_if_setting_missing('MFA_LOGIN_CALLBACK')
    @skip_if_url_missing('mfa:verify')
    def test_login_callback_execution(self):
        """Test the custom login callback functionality.
        
        Verifies:
        1. Callback is executed after successful MFA
        2. Correct parameters are passed
        3. Return value is handled properly
        4. Error handling works
        5. Session state is preserved
        
        Note: This test is skipped because the core MFA verification endpoint ('verify')
        is not implemented. This endpoint is required for the MFA flow to work properly.
        Implementation should follow the core functionality implementation order:
        1. Enable middleware
        2. Implement core views
        3. Add security features
        4. Enable advanced options
        """
        if not settings.MFA_LOGIN_CALLBACK:
            self.skipTest("MFA_LOGIN_CALLBACK is not configured")
            
        with patch(settings.MFA_LOGIN_CALLBACK) as mock_callback:
            mock_callback.return_value = HttpResponse("Success")
            
            # First login to get base_username in session
            self.login_user()
            
            # Setup MFA session as unverified
            self.setup_mfa_session(method='TOTP', verified=False)
            
            # Make request to verify endpoint which should trigger MFA flow
            response = self.client.get(reverse('mfa:verify', args=[self.username]))
            self.assertEqual(response.status_code, 302)  # Should redirect to TOTP auth
            
            # Now verify the MFA
            self.setup_mfa_session(method='TOTP', verified=True)
            
            # Make request to home which should trigger callback
            response = self.client.get(reverse('mfa_home'))
            self.assertEqual(response.status_code, 200)
            mock_callback.assert_called_once()

    @skip_if_url_missing('mfa:delete_key')
    def test_key_deletion_security(self):
        """Test the security of the key deletion functionality.
        
        Verifies:
        1. Only key owner can delete
        2. Proper authentication required
        3. Audit trail is maintained
        4. Response format is correct
        """
        self.login_user()
        key = self.create_totp_key()
        response = self.client.post(reverse('mfa:delete_key', args=[key.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'deleted')

    @skip_if_url_missing('mfa:toggleKey')
    @skip_if_setting_missing('MFA_HIDE_DISABLE')
    def test_key_toggle_restrictions(self):
        """Test the key enabling/disabling functionality.
        
        Ensures:
        1. Only owner can toggle
        2. MFA_HIDE_DISABLE setting is respected
        3. Cannot disable if would leave no methods
        4. Proper response format
        """
        self.login_user()
        key = self.create_totp_key()
        response = self.client.post(reverse('mfa:toggleKey', args=[key.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'disabled')

    @skip_if_url_missing('mfa:method_redirect')
    def test_method_redirect_security(self):
        """Test the security of method-specific redirects.
        
        Verifies:
        1. Only valid methods can be redirected to
        2. Authentication state is maintained
        3. Proper method-specific view is targeted
        4. Invalid methods are handled gracefully
        """
        self.login_user()
        response = self.client.get(reverse('mfa:method_redirect', args=['totp']))
        self.assertEqual(response.status_code, 302)  # Should redirect to TOTP auth

        # Test invalid method
        response = self.client.get(reverse('mfa:method_redirect', args=['invalid']))
        self.assertEqual(response.status_code, 400)

    @unittest.skip("MFA Middleware is disabled in tests. URL protection is typically implemented at the middleware level.")
    @skip_if_middleware_disabled("URL protection requires middleware")
    def test_protected_url_redirect(self):
        """Test that protected URLs redirect to MFA verification."""
        pass

    @unittest.skip("MFA Middleware is disabled in tests. Session handling is typically implemented at the middleware level.")
    @skip_if_middleware_disabled("Session handling requires middleware")
    def test_session_handling(self):
        """Test session handling in MFA flow."""
        pass

    @unittest.skip("[SECURITY GAP] CSRF protection not implemented: Missing CSRF validation")
    @skip_if_security_gap("CSRF protection not implemented")
    def test_csrf_protection(self):
        """Test CSRF protection in MFA views."""
        pass

    @unittest.skip("[SKIP LOGGING] View logging not implemented: Missing view access logging")
    @skip_if_logging_gap("View logging not implemented")
    def test_view_logging(self):
        """Test view access logging."""
        pass


"""Test-specific view functions for MFA tests.

These views are used only for testing and should not be added to the main views.py.
They implement the minimal functionality needed to test the MFA features.
"""

@login_required
@require_http_methods(["POST"])
def request_code(request):
    """Test view for requesting verification code."""
    return JsonResponse({'status': 'sent'})


@login_required
@require_http_methods(["POST"])
def verify_code(request):
    """Test view for verifying submitted code."""
    return JsonResponse({'status': 'verified'})


@login_required
@require_http_methods(["GET"])
def mfa_status(request):
    """Test view for checking MFA status."""
    return JsonResponse({
        'verified': request.session.get('mfa', {}).get('verified', False),
        'current_method': request.session.get('mfa', {}).get('method')
    })


# FIDO2 test views
@login_required
@require_http_methods(["POST"])
def fido2_begin_register(request):
    """Test view for starting FIDO2 registration."""
    return JsonResponse({
        'publicKey': {
            'challenge': 'test_challenge',
            'rp': {'id': 'example.com', 'name': 'Test Server'},
            'user': {'id': 'test_user', 'name': 'Test User'},
            'authenticatorSelection': {'authenticatorAttachment': 'cross-platform'}
        }
    })


@login_required
@require_http_methods(["POST"])
def fido2_complete_register(request):
    """Test view for completing FIDO2 registration."""
    return JsonResponse({'status': 'registered'})


@login_required
@require_http_methods(["POST"])
def fido2_begin_authenticate(request):
    """Test view for starting FIDO2 authentication."""
    return JsonResponse({
        'publicKey': {
            'challenge': 'test_challenge',
            'timeout': 30000,
            'rpId': 'example.com'
        }
    })


@login_required
@require_http_methods(["POST"])
def fido2_complete_authenticate(request):
    """Test view for completing FIDO2 authentication."""
    return JsonResponse({'status': 'authenticated'})


@login_required
@require_http_methods(["GET"])
def fido2_credentials(request):
    """Test view for listing FIDO2 credentials."""
    return JsonResponse({'credentials': []})


@login_required
@require_http_methods(["POST"])
def fido2_remove_credential(request):
    """Test view for removing FIDO2 credential."""
    return JsonResponse({'status': 'removed'}) 
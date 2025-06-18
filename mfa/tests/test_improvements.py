"""Tests for proposed improvements to django-mfa2

This file contains SKIPPED tests that document and verify proposed improvements.
These tests will fail against the current codebase but serve as:

1. Documentation of proposed design improvements
2. Ready-to-use tests if/when improvements are accepted

Current Implementation Limitations:

Recovery Keys:
- Managed at template level instead of controller
- Only show in UI when another key exists
- No business logic validation of backup purpose

Method Security:
- MFA_UNALLOWED_METHODS only affects UI visibility
- Endpoints remain accessible when methods disallowed
- No API-level enforcement of method restrictions

Proposed Solutions:

Recovery Key Improvements:
- Move visibility logic to controller layer
- Enforce backup method requirements at API level
- Provide consistent UI feedback

Method Security Improvements:
- Enforce method restrictions at API endpoints
- Return 403 Forbidden for disallowed methods
- Maintain clear separation between UI and API security
"""

from unittest import skip
from django.http import JsonResponse
from .base import MFATestCase
import json


@skip("Proposed improvement: Move recovery key visibility logic to controller")
class RecoveryKeyImprovementTests(MFATestCase):
    """Tests verifying proposed improvements to recovery key handling."""

    def test_recovery_requires_other_method(self):
        """Test that recovery key creation requires another MFA method."""
        self.login_user()

        # Attempt to create recovery key without other methods
        response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("must set up another MFA method", response.json()["error"])

        # Add TOTP key
        totp_key = self.create_totp_key(enabled=True)

        # Now recovery key creation should succeed
        response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", response.json())

    def test_recovery_api_validation(self):
        """Test that recovery key requirements are enforced at API level."""
        self.login_user()

        # Test direct API call without other methods
        response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
        self.assertEqual(response.status_code, 400)

        # Add TOTP and verify API now succeeds
        totp_key = self.create_totp_key(enabled=True)
        response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
        self.assertEqual(response.status_code, 200)

    def test_recovery_key_deletion_handling(self):
        """Test proper handling when last non-recovery method is deleted."""
        self.login_user()

        # Setup TOTP and recovery
        totp_key = self.create_totp_key(enabled=True)
        response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
        self.assertEqual(response.status_code, 200)

        # Delete TOTP key
        response = self.client.post(self.get_mfa_url("mfa_delKey"), {"id": totp_key.id})

        # Verify recovery keys were disabled
        # requires a new helper method: self.get_user_keys(key_type="RECOVERY")
        # recovery_keys = self.get_user_keys(key_type="RECOVERY")
        # for key in recovery_keys:
        #     self.assertFalse(key.enabled)
        #     self.assertMfaKeyState(key.id, expected_enabled=False)

    def test_recovery_improved_ui_flow(self):
        """Test improved UI flow for recovery keys."""
        self.login_user()

        # Check initial state (no methods)
        response = self.client.get(self.get_mfa_url("mfa_home"))
        content = response.content.decode()

        # Recovery section should exist with guidance
        self.assertIn("Recovery Codes (Backup Method)", content)
        self.assertIn(
            "Set up another MFA method first to enable recovery codes", content
        )

        # Add TOTP key
        totp_key = self.create_totp_key(enabled=True)
        response = self.client.get(self.get_mfa_url("mfa_home"))
        content = response.content.decode()

        # Recovery section should now show activation option
        self.assertIn("Generate Recovery Codes", content)
        self.assertIn(
            "Recovery codes provide backup access if other methods are unavailable",
            content,
        )

        # Generate recovery codes
        recovery_key = self.create_recovery_key(enabled=True)
        response = self.client.get(self.get_mfa_url("mfa_home"))
        content = response.content.decode()

        # Should show active recovery codes with clear purpose
        self.assertIn("Active Recovery Codes", content)
        self.assertIn(
            "Use these codes if you lose access to your other methods", content
        )


@skip("Proposed improvement: Enforce method restrictions at API level")
class MethodSecurityImprovementTests(MFATestCase):
    """Tests verifying proposed improvements to method security."""

    def test_improved_method_disablement(self):
        """Test improved security for disallowed methods."""
        self.login_user()

        with self.settings(
            MFA_UNALLOWED_METHODS=("TOTP", "U2F"),
            MFA_RENAME_METHODS={"TOTP": "Authenticator app", "U2F": "Security Key"},
        ):
            # Verify UI elements are hidden
            response = self.client.get(self.get_mfa_url("mfa_home"))
            self.assertEqual(response.status_code, 200)
            menu_items = self.get_dropdown_menu_items(response.content.decode())
            self.assertNotIn("Authenticator app", menu_items)
            self.assertNotIn("Security Key", menu_items)

            # Verify TOTP endpoints are blocked
            response = self.client.get(self.get_mfa_url("start_new_otop"))
            self.assertEqual(response.status_code, 403)
            self.assertIn(
                "authentication method is not allowed", response.json()["error"]
            )

            # Verify U2F endpoints are blocked
            response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(response.status_code, 403)
            self.assertIn(
                "authentication method is not allowed", response.json()["error"]
            )

            # Verify allowed methods still work
            response = self.client.get(self.get_mfa_url("start_fido2"))
            self.assertEqual(response.status_code, 200)

            # Verify recovery endpoints always work
            response = self.client.get(self.get_mfa_url("manage_recovery_codes"))
            self.assertEqual(response.status_code, 200)

    def test_method_disablement_api_security(self):
        """Test API-level security for disallowed methods."""
        self.login_user()

        with self.settings(MFA_UNALLOWED_METHODS=("TOTP",)):
            # Test registration endpoint
            response = self.client.post(self.get_mfa_url("get_new_otop"))
            self.assertEqual(response.status_code, 403)
            self.assertIn("not allowed", response.json()["error"])

            # Test verification endpoint
            response = self.client.post(
                self.get_mfa_url("totp_auth"), {"otp": "123456"}
            )
            self.assertEqual(response.status_code, 403)
            self.assertIn("not allowed", response.json()["error"])

            # Test management endpoint
            response = self.client.post(self.get_mfa_url("toggle_key"), {"id": 1})
            self.assertEqual(response.status_code, 403)
            self.assertIn("not allowed", response.json()["error"])

            # Recovery endpoints should still work
            response = self.client.post(self.get_mfa_url("regen_recovery_tokens"))
            self.assertEqual(response.status_code, 200)


@skip("Proposed improvement: Consistent session state handling in TOTP verification")
class TOTPVerificationImprovementTests(MFATestCase):
    """Tests verifying proposed improvements to TOTP verification handling."""

    def setUp(self):
        """Set up test environment with TOTP-specific additions."""
        super().setUp()
        self.totp_key = self.create_totp_key(enabled=True)

    def test_verify_login_failure_consistent_state(self):
        """Test that failed verification maintains consistent session state."""
        invalid_token = self.get_invalid_totp_token()

        response = self.client.post(
            self.get_mfa_url("totp_auth"), {"otp": invalid_token}
        )

        # Should stay on auth page with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/Auth.html")
        self.assertContains(response, "Sorry, The provided token is not valid.")

        # Verify session state explicitly indicates failure
        self.assertMfaSessionUnverified()

    def test_recheck_failure_consistent_state(self):
        """Test that failed recheck maintains consistent session state."""
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Use invalid token
        invalid_token = self.get_invalid_totp_token()

        # Test recheck
        response = self.client.post(
            self.get_mfa_url("totp_recheck"), {"otp": invalid_token}
        )

        # Should return JSON failure
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data["recheck"])

        # Verify session state explicitly indicates failure
        self.assertMfaSessionUnverified()

    def test_recheck_get_consistent_state(self):
        """Test that GET recheck maintains consistent session state."""
        # Setup session as already verified
        self.setup_mfa_session(method="TOTP", verified=True, id=self.totp_key.id)

        # Get valid token
        valid_token = self.get_valid_totp_token()

        # Test recheck with GET
        response = self.client.get(
            f"{self.get_mfa_url('totp_recheck')}?otp={valid_token}"
        )

        # Should render the recheck template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TOTP/recheck.html")
        self.assertTemplateUsed(response, "modal.html")
        self.assertEqual(response.context["mode"], "recheck")
        self.assertTrue(response.context["recheck_success"])

        # Verify session state is preserved
        self.assertMfaSessionVerified(method="TOTP", id=self.totp_key.id)

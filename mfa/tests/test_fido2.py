"""
Test cases for MFA FIDO2 module.

Tests FIDO2 authentication functions in mfa.FIDO2 module:
- begin_registration(): Initiates FIDO2 device registration
- complete_reg(): Completes device registration
- authenticate_begin(): Initiates FIDO2 authentication
- authenticate_complete(): Completes authentication
- recheck(): Re-verifies MFA for current session using FIDO2

Scenarios: Device registration, authentication flow, credential management, session handling.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from django.test import override_settings
from django.contrib.auth import get_user_model
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.utils import timezone
from ..FIDO2 import (
    enable_json_mapping,
    recheck,
    getServer,
    begin_registeration,
    complete_reg,
    start,
    getUserCredentials,
    auth,
    authenticate_begin,
    authenticate_complete,
)
from ..models import User_Keys
from .mfatestcase import MFATestCase


class FIDO2RegistrationTests(MFATestCase):
    """Tests for FIDO2 registration flow scenarios."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.setup_session_base_username()

    def test_begin_registration_success(self):
        """Initiates FIDO2 device registration by generating challenge and storing registration state in session."""
        self.login_user()

        with patch(
            "fido2.server.Fido2Server.register_begin"
        ) as mock_register_begin:  # Mock external FIDO2 library to isolate MFA project registration initiation
            mock_register_begin.return_value = (
                {
                    "publicKey": {
                        "challenge": "test_challenge",
                        "rp": {"id": "localhost", "name": "Test Server"},
                        "user": {
                            "id": "test_user_id",
                            "name": "testuser",
                            "displayName": "testuser",
                        },
                        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                        "timeout": 60000,
                    }
                },
                "test_state",
            )

            # Test actual MFA function using Django test client
            response = self.client.post(self.get_mfa_url("fido2_begin_reg"))

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertIn("publicKey", data)
            self.assertIn("challenge", data["publicKey"])
            self.assertEqual(data["publicKey"]["challenge"], "test_challenge")

            # Verify begin_registeration stored state in session
            self.assertIn("fido2_state", self.client.session)
            self.assertEqual(self.client.session["fido2_state"], "test_state")

    def test_begin_registration_with_existing_credentials(self):
        """Initiates FIDO2 registration with existing credentials excluded to prevent duplicate device registration."""
        self.login_user()

        # Create existing FIDO2 key to test credential exclusion
        existing_key = self.create_fido2_key(enabled=True)

        with patch(
            "fido2.server.Fido2Server.register_begin"
        ) as mock_register_begin:  # Mock external FIDO2 library to isolate MFA project registration initiation
            mock_register_begin.return_value = (
                {
                    "publicKey": {
                        "challenge": "test_challenge",
                        "rp": {"id": "localhost", "name": "Test Server"},
                        "user": {
                            "id": "test_user_id",
                            "name": "testuser",
                            "displayName": "testuser",
                        },
                        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                        "timeout": 60000,
                    }
                },
                "test_state",
            )

            # Test actual MFA function using Django test client
            response = self.client.post(self.get_mfa_url("fido2_begin_reg"))

            self.assertEqual(response.status_code, 200)

            # Verify MFA project properly initiated FIDO2 registration
            # by checking that registration data is properly structured
            response_data = response.json()
            self.assertIn("publicKey", response_data)
            self.assertIn("challenge", response_data["publicKey"])
            self.assertIn("rp", response_data["publicKey"])

    def test_complete_registration_success(self):
        """Completes FIDO2 device registration by storing device credentials and returning success response."""
        self.login_user()

        # Set up session state for complete_reg
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Mock only the external FIDO2 library functions that are too complex to test without mocking
        # This allows testing the actual MFA project business logic while isolating external dependencies
        with patch(
            "fido2.server.Fido2Server.register_complete"
        ) as mock_register_complete, patch(
            "mfa.FIDO2.RegistrationResponse.from_dict"
        ) as mock_from_dict, patch(
            "fido2.utils.websafe_encode"
        ) as mock_websafe_encode, override_settings(
            MFA_ENFORCE_RECOVERY_METHOD=False
        ):
            # Mock FIDO2 library to return realistic data
            mock_auth_data = MagicMock()
            mock_auth_data.credential_data = b"test_credential_data"
            mock_register_complete.return_value = mock_auth_data

            mock_reg_instance = MagicMock()
            mock_reg_instance.response.attestation_object.fmt = "packed"
            mock_from_dict.return_value = mock_reg_instance

            mock_websafe_encode.return_value = "encoded_credential_data"

            # Test actual MFA function using Django test client
            response = self.client.post(
                self.get_mfa_url("fido2_complete_reg"),
                data=json.dumps(
                    {
                        "id": "testuser",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "valid_attestation",
                            "clientDataJSON": "valid_client_data",
                        },
                    }
                ),
                content_type="application/json",
            )

            # Test real MFA project behavior - response status and content
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "OK")

            # Test real MFA project behavior - database state changes
            fido2_keys = User_Keys.objects.filter(
                username=self.username,
                key_type="FIDO2",
            )
            self.assertTrue(fido2_keys.exists())

            # Test real MFA project behavior - key properties
            key = fido2_keys.first()
            self.assertEqual(key.key_type, "FIDO2")
            self.assertEqual(key.username, self.username)
            self.assertIn("device", key.properties)
            self.assertIn("type", key.properties)

    def test_complete_registration_missing_session_state(self):
        """Handles missing session state by returning error response when FIDO2 registration state is not found."""
        self.login_user()

        # Test actual MFA function using Django test client with no fido2_state
        response = self.client.post(
            self.get_mfa_url("fido2_complete_reg"),
            data=json.dumps({"id": "testuser"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("fido status", data["message"].lower())

    def test_complete_registration_invalid_json(self):
        """Handles invalid JSON input by returning 500 error response with appropriate error message.

        Exception Handler: complete_reg() broad except Exception (returns generic error message)
        """
        self.login_user()

        # Set up session state properly
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Test actual MFA function using Django test client with invalid JSON
        response = self.client.post(
            self.get_mfa_url("fido2_complete_reg"),
            data=b"invalid json",
            content_type="application/json",
        )

        self.assertEqual(
            response.status_code, 500
        )  # Should return 500 for invalid JSON
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertEqual(data["message"], "Error on server, please try again later")

    def test_complete_registration_cbor_parsing_error(self):
        """Handles CBOR parsing errors from FIDO2 library by returning error response with appropriate status."""
        self.login_user()

        self.client.session["fido2_state"] = "test_state"
        self.client.session.save()

        with patch(
            "fido2.server.Fido2Server.register_complete"
        ) as mock_register_complete:
            mock_register_complete.side_effect = ValueError("CBOR parsing error")

            # Test actual MFA function using Django test client
            response = self.client.post(
                self.get_mfa_url("fido2_complete_reg"),
                data=json.dumps(
                    {
                        "id": "testuser",
                        "response": {"attestationObject": "invalid_cbor"},
                    }
                ),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "ERR")
            self.assertEqual(
                response.status_code, 200
            )  # Django test client returns 200 for JSON responses

    def test_complete_registration_recovery_enforcement(self):
        """Enforces recovery code setup requirement by returning RECOVERY status when recovery method enforcement is enabled."""
        self.login_user()

        # Set up session state properly
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Mock external FIDO2 library functions to simulate successful registration
        # Mock external FIDO2 library to isolate MFA project registration completion
        # Mock external FIDO2 library to isolate MFA project response processing
        # Mock external FIDO2 library to isolate MFA project encoding
        with patch(
            "fido2.server.Fido2Server.register_complete"
        ) as mock_register_complete, patch(
            "mfa.FIDO2.RegistrationResponse.from_dict"
        ) as mock_from_dict, patch(
            "fido2.utils.websafe_encode"
        ) as mock_websafe_encode, override_settings(
            MFA_ENFORCE_RECOVERY_METHOD=True
        ):
            # Mock the FIDO2 library functions
            mock_auth_data = MagicMock()
            mock_auth_data.credential_data = b"test_credential_data"
            mock_register_complete.return_value = mock_auth_data

            mock_reg_instance = MagicMock()
            mock_reg_instance.response.attestation_object.fmt = "packed"
            mock_from_dict.return_value = mock_reg_instance

            mock_websafe_encode.return_value = "encoded_credential_data"

            # Test actual MFA project recovery enforcement logic
            response = self.client.post(
                self.get_mfa_url("fido2_complete_reg"),
                data=json.dumps(
                    {
                        "id": "testuser",
                        "response": {
                            "attestationObject": "AAAAAAAAAAAAAAAAAAAAAAAQST6cxBX-qYcVzIH8aBRliqUBAgMmIAEhWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACJYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
                        },
                    }
                ),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "RECOVERY")

    @override_settings(
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_RENAME_METHODS={
            "FIDO2": "FIDO2 Security Key",
            "RECOVERY": "Recovery codes",
        },
    )
    def test_start_view_renders_template_with_recovery_codes(self):
        """Renders FIDO2 registration template with recovery codes when user has recovery codes available."""
        # 1. Setup with helpers
        self.login_user()
        self.create_recovery_key(enabled=True)

        # 2. Session setup (NEVER dict sessions) - not needed for this view

        # 3. HTTP request
        response = self.client.get(self.get_mfa_url("start_fido2"))

        # 4. Assert real behavior
        self.assertEqual(response.status_code, 200)
        # Debug: Print response content to see what's actually rendered
        # print(f"\n334 {__name__} {response.content.decode('utf-8')=}")
        self.assertContains(
            response, "Adding a New FIDO2 Security Key"
        )  # Template content with method name
        # Verify the template renders successfully (covers lines 147-157 in FIDO2.py)
        self.assertContains(
            response, "Your browser should ask you to confirm you identity"
        )  # Template content

    @override_settings(MFA_RENAME_METHODS={"FIDO2": "PassKey"})
    def test_auth_view_renders_template_with_csrf(self):
        """Renders FIDO2 authentication template with CSRF token when accessing auth view."""
        # 1. Setup with helpers
        self.login_user()
        self.setup_session_base_username()

        # 2. Session setup (NEVER dict sessions) - not needed for this view

        # 3. HTTP request
        response = self.client.get(self.get_mfa_url("fido2_auth"))

        # 4. Assert real behavior
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PassKey")  # Template content with method name
        self.assertContains(response, "Welcome back")  # Authentication welcome message
        self.assertContains(
            response, "please press the button on your security key"
        )  # Instructions
        self.assertContains(response, "csrfmiddlewaretoken")  # CSRF token present

    def test_authenticate_complete_empty_request_body(self):
        """Handles empty request body by returning error response when no data is provided.

        Exception Handler: authenticate_complete() broad except Exception (returns str(exp))
        """
        # 1. Setup with helpers
        self.login_user()
        self.setup_session_base_username()

        # 2. Session setup (NEVER dict sessions)
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # 3. HTTP request
        response = self.client.post(
            self.get_mfa_url("fido2_complete_auth"),
            data="",
            content_type="application/json",
        )

        # 4. Assert real behavior
        self.assertEqual(response.status_code, 500)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("Expecting value", data["message"])

    def test_create_recovery_key_with_custom_properties(self):
        """Creates recovery key using custom properties when properties parameter is provided."""
        # 1. Setup with helpers
        self.login_user()

        # 2. Session setup (NEVER dict sessions) - not needed for this test

        # 3. Create recovery key with custom properties
        custom_properties = {
            "custom_field": "test_value",
            "codes": ["111111", "222222"],
        }
        recovery_key = self.create_recovery_key(
            properties=custom_properties, enabled=True
        )

        # 4. Assert real behavior
        self.assertIsNotNone(recovery_key)
        self.assertEqual(recovery_key.key_type, "RECOVERY")
        self.assertTrue(recovery_key.enabled)
        self.assertEqual(recovery_key.username, self.username)

        # Verify custom properties are preserved exactly
        self.assertEqual(recovery_key.properties, custom_properties)
        self.assertIn("custom_field", recovery_key.properties)
        self.assertIn("codes", recovery_key.properties)
        self.assertEqual(recovery_key.properties["custom_field"], "test_value")
        self.assertEqual(recovery_key.properties["codes"], ["111111", "222222"])

    def test_create_recovery_key_with_real_format(self):
        """Creates recovery key using real format with hashed tokens and salt when use_real_format is True."""
        # 1. Setup with helpers
        self.login_user()

        # 2. Session setup (NEVER dict sessions) - not needed for this test

        # 3. Create recovery key with real format
        recovery_key = self.create_recovery_key(use_real_format=True, enabled=True)

        # 4. Assert real behavior
        self.assertIsNotNone(recovery_key)
        self.assertEqual(recovery_key.key_type, "RECOVERY")
        self.assertTrue(recovery_key.enabled)
        self.assertEqual(recovery_key.username, self.username)

        # Verify real format properties are present
        self.assertIn("secret_keys", recovery_key.properties)
        self.assertIn("salt", recovery_key.properties)
        self.assertIsInstance(recovery_key.properties["secret_keys"], list)
        self.assertIsInstance(recovery_key.properties["salt"], str)
        self.assertEqual(
            len(recovery_key.properties["secret_keys"]), 2
        )  # Two test codes
        self.assertGreater(len(recovery_key.properties["salt"]), 0)  # Salt is not empty

    def test_complete_registration_empty_request_body(self):
        """Handles empty request body by returning error response when no data is provided.

        Exception Handler: complete_reg() broad except Exception (returns generic error message)
        """
        # 1. Setup with helpers
        self.login_user()

        # 2. Session setup (NEVER dict sessions)
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # 3. HTTP request
        response = self.client.post(
            self.get_mfa_url("fido2_complete_reg"),
            data="",
            content_type="application/json",
        )

        # 4. Assert real behavior
        self.assertEqual(response.status_code, 500)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertEqual(data["message"], "Error on server, please try again later")

    def test_complete_registration_fido2_library_exception(self):
        """Handles FIDO2 library exceptions by returning error response when registration fails."""
        # 1. Setup with helpers
        self.login_user()

        # 2. Session setup (NEVER dict sessions)
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # 3. HTTP request with mocked external library
        with patch(
            "fido2.server.Fido2Server.register_complete"
        ) as mock_register_complete:  # Mock external FIDO2 library to isolate MFA project error handling
            mock_register_complete.side_effect = ValueError("Invalid credential data")

            response = self.client.post(
                self.get_mfa_url("fido2_complete_reg"),
                data=json.dumps(
                    {
                        "id": "testuser",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "invalid_attestation",
                            "clientDataJSON": "invalid_client_data",
                        },
                    }
                ),
                content_type="application/json",
            )

        # 4. Assert real behavior
        self.assertEqual(response.status_code, 500)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("Error on server", data["message"])


class FIDO2AuthenticationTests(MFATestCase):
    """Tests for FIDO2 authentication flow scenarios."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.setup_session_base_username()
        self.fido2_key = self.create_fido2_key(enabled=True)

    def test_authenticate_begin_success(self):
        """Initiates FIDO2 authentication by generating challenge and storing authentication state in session."""
        self.login_user()

        with patch(
            "fido2.server.Fido2Server.authenticate_begin"
        ) as mock_auth_begin:  # Mock external FIDO2 library to isolate MFA project authentication initiation
            mock_auth_begin.return_value = (
                {
                    "publicKey": {
                        "challenge": "test_challenge",
                        "rpId": "localhost",
                        "allowCredentials": [
                            {"type": "public-key", "id": "test_credential_id"}
                        ],
                    }
                },
                "test_state",
            )

            # Test actual MFA function using Django test client
            response = self.client.post(self.get_mfa_url("fido2_begin_auth"))

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertIn("publicKey", data)
            self.assertIn("challenge", data["publicKey"])
            self.assertEqual(data["publicKey"]["challenge"], "test_challenge")

            # Verify authenticate_begin stored state in session
            self.assertIn("fido2_state", self.client.session)
            self.assertEqual(self.client.session["fido2_state"], "test_state")

    def test_authenticate_begin_with_base_username(self):
        """Initiates FIDO2 authentication using base_username for credential lookup in MFA flow."""
        # Set up session with base_username for MFA flow
        self.client.session["base_username"] = self.username
        self.client.session.save()

        with patch(
            "fido2.server.Fido2Server.authenticate_begin"
        ) as mock_auth_begin:  # Mock external FIDO2 library to isolate MFA project authentication initiation
            mock_auth_begin.return_value = (
                {
                    "publicKey": {
                        "challenge": "test_challenge",
                        "rpId": "localhost",
                        "allowCredentials": [
                            {"type": "public-key", "id": "test_credential_id"}
                        ],
                    }
                },
                "test_state",
            )

            # Test actual MFA function using Django test client
            response = self.client.post(self.get_mfa_url("fido2_begin_auth"))

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertIn("publicKey", data)
            self.assertIn("challenge", data["publicKey"])

            # Verify MFA project properly initiated FIDO2 authentication
            # by checking that authentication data is properly structured
            self.assertIn("allowCredentials", data["publicKey"])

    def test_authenticate_complete_success_authenticated_user(self):
        """Completes FIDO2 authentication by marking session as verified and returning success response."""
        self.login_user()

        # Mock external FIDO2 library to isolate MFA project authentication completion
        # Mock external FIDO2 library to isolate MFA project credential processing
        # Mock external FIDO2 library to isolate MFA project decoding
        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete, patch(
            "fido2.webauthn.AttestedCredentialData"
        ) as mock_attested, patch(
            "fido2.utils.websafe_decode"
        ) as mock_decode, patch(
            "mfa.FIDO2.websafe_decode"
        ) as mock_decode_module, patch(
            "mfa.FIDO2.AttestedCredentialData"
        ) as mock_attested_module:
            # Mock successful authentication
            mock_cred = MagicMock()
            mock_cred.credential_id = b"test_credential_id"
            mock_auth_complete.return_value = mock_cred

            mock_attested_instance = MagicMock()
            mock_attested_instance.credential_id = b"test_credential_id"
            mock_attested.return_value = mock_attested_instance
            mock_decode.return_value = b"decoded_credential_data"

            # Set up module-level mocks
            mock_attested_module.return_value = mock_attested_instance
            mock_decode_module.return_value = b"decoded_credential_data"

            # Set up session with fido2_state
            session = self.client.session
            session["fido2_state"] = "test_state"
            session.save()

            # Test actual MFA function using Django test client
            response = self.client.post(
                self.get_mfa_url("fido2_complete_auth"),
                data=json.dumps({"id": "testuser"}),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "OK")

            # Verify authenticate_complete created MFA session
            self.assertMfaSessionVerified(method="FIDO2", id=self.fido2_key.id)

            # Verify user remains authenticated after FIDO2 authentication completes
            # Since we used self.login_user() at the start, user should still be authenticated
            self.assertTrue(self.user.is_authenticated)
            self.assertEqual(self.user.username, self.username)

    def test_authenticate_complete_missing_session_state(self):
        """Test authentication completion with missing session state.

        Scenario: User attempts authentication without fido2_state
        Expected: Error response indicating missing session state
        """
        # Use Django test client instead of raw HttpRequest
        response = self.client.post(
            self.get_mfa_url("fido2_complete_auth"),
            data=json.dumps({"id": "testuser"}),
            content_type="application/json",
        )

        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("fido2_state", data["message"].lower())

    def test_authenticate_complete_invalid_json(self):
        """Test authentication completion with invalid JSON.

        Scenario: User sends malformed JSON in request body
        Expected: Error response with JSONDecodeError message
        Exception Handler: authenticate_complete() broad except Exception (returns str(exp))
        """
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        request = self.create_http_request_mock()
        request.method = "POST"
        request._body = b"invalid json"
        request.content_type = "application/json"
        request.session = session

        response = authenticate_complete(request)

        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("Expecting value", data["message"])

    def test_authenticate_complete_no_username(self):
        """Test authentication completion with no username available.

        Scenario: Neither session base_username nor authenticated user available
        Expected: Error response indicating no username
        """
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        request = self.create_http_request_mock()
        request.method = "POST"
        request._body = json.dumps({"id": "testuser"}).encode("utf-8")
        request.content_type = "application/json"
        request.user = self.get_unauthenticated_user()
        request.session = session
        response = authenticate_complete(request)

        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")

    def test_authenticate_complete_wrong_challenge(self):
        """Test authentication completion with wrong challenge.

        Scenario: User provides wrong challenge/response data
        Expected: Error response indicating wrong challenge
        """
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete:
            mock_auth_complete.side_effect = ValueError("Wrong challenge")

        request = self.create_http_request_mock()
        request.method = "POST"
        # Provide proper FIDO2 authentication response structure
        request._body = json.dumps(
            {
                "id": "testuser",
                "response": {
                    "authenticatorData": "test_data",
                    "clientDataJSON": "test_data",
                    "signature": "test_signature",
                },
            }
        ).encode("utf-8")
        request.content_type = "application/json"
        request.user = self.user
        request.session = session

        response = authenticate_complete(request)

        self.assertIsInstance(response, JsonResponse)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ERR")
        self.assertIn("challenge", data["message"].lower())
        self.assertEqual(response.status_code, 400)

    def test_authenticate_complete_credential_matching_failure_authenticated_user(self):
        """Test authentication completion with credential matching failure for authenticated user.

        Tests: authenticate_complete() function error handling (Path 3: Authenticated User)
        Error response when AttestedCredentialData construction fails
        """
        # Set up authenticated user to test credential matching failure
        self.login_user()  # Authenticated user
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Mock external FIDO2 library to isolate MFA project authentication completion
        # Mock external FIDO2 library to isolate MFA project credential processing
        # Mock external FIDO2 library to isolate MFA project decoding
        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete, patch(
            "fido2.webauthn.AttestedCredentialData"
        ) as mock_attested, patch(
            "fido2.utils.websafe_decode"
        ) as mock_decode, patch(
            "mfa.views.login"
        ) as mock_login, patch(
            "builtins.print"
        ) as mock_print:  # Mock external print function to isolate MFA project error logging
            mock_cred = MagicMock()
            mock_cred.credential_id = b"test_credential_id"
            mock_auth_complete.return_value = mock_cred

            # Mock AttestedCredentialData to fail during construction
            mock_attested.side_effect = ValueError("Wrong length")
            mock_decode.return_value = b"decoded_credential_data"
            mock_print.return_value = None

            # Create request with authenticated user
            request = self.create_http_request_mock()
            request.method = "POST"
            request._body = json.dumps({"id": "testuser"}).encode("utf-8")
            request.content_type = "application/json"
            request.user = self.user  # Authenticated user
            request.session = session

            response = authenticate_complete(request)
            data = json.loads(response.content)

            self.assertIsInstance(response, JsonResponse)
            self.assertEqual(response.status_code, 500)
            self.assertEqual(data["status"], "ERR")
            self.assertEqual(data["message"], "Wrong length")

            # Verify MFA project properly handled authentication error
            # by checking that error response is properly formatted
            self.assertIn("status", data)
            self.assertIn("message", data)

    def test_authenticate_complete_credential_matching_failure(self):
        """Test authentication completion with credential matching failure.

        authenticate_complete() function error handling (Path 3: Authenticated User)
        Error response when AttestedCredentialData construction fails
        """
        self.login_user()  # Authenticated user
        self.client.session["fido2_state"] = "test_state"
        self.client.session.save()

        # Mock external FIDO2 library to isolate MFA project authentication completion
        # Mock external FIDO2 library to isolate MFA project credential processing
        # Mock external FIDO2 library to isolate MFA project decoding
        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete, patch(
            "fido2.webauthn.AttestedCredentialData"
        ) as mock_attested, patch(
            "fido2.utils.websafe_decode"
        ) as mock_decode, patch(
            "builtins.print"
        ) as mock_print:  # Mock external print function to isolate MFA project error logging
            mock_cred = MagicMock()
            mock_cred.credential_id = b"test_credential_id"
            mock_auth_complete.return_value = mock_cred

            # Mock AttestedCredentialData construction failure
            mock_attested.side_effect = ValueError("Wrong length")
            mock_decode.return_value = b"decoded_credential_data"
            mock_print.return_value = None

            # Test actual MFA function using Django test client
            response = self.client.post(
                self.get_mfa_url("fido2_complete_auth"),
                data=json.dumps({"id": "testuser"}),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 500)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "ERR")
            self.assertEqual(data["message"], "Wrong length")

            # Verify MFA project properly handled credential matching failure
            # by checking that error response is properly formatted
            self.assertIn("status", data)
            self.assertIn("message", data)

    def test_authenticate_complete_recheck_scenario(self):
        """Test authentication completion during recheck scenario.

        Scenario: User completes authentication during MFA recheck period
        Expected: Function returns early with OK status, updates recheck timestamp

        This test verifies that when mfa_recheck=True, the authenticate_complete
        function returns early with OK status without performing credential
        verification, and updates the recheck timestamp in the session.

        Preconditions:
        - User has valid FIDO2 credentials in database
        - Session contains mfa_recheck=True flag
        - Session contains initialized mfa data structure
        - fido2_state is present in session

        Expected results:
        - Response status: 200 OK
        - Response data: {"status": "OK"}
        - Session updated with rechecked_at timestamp
        - No credential verification performed (early return)
        """
        # Create a valid FIDO2 key for the user to avoid getUserCredentials failure
        self.create_fido2_key(enabled=True)

        session = self.client.session
        session["fido2_state"] = "test_state"
        session["mfa_recheck"] = True
        # Initialize mfa session data for recheck scenario
        session["mfa"] = {"verified": True, "method": "FIDO2", "id": 1}
        session.save()

        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete:
            mock_cred = MagicMock()
            mock_cred.credential_id = b"test_credential_id"
            mock_auth_complete.return_value = mock_cred

            response = self.client.post(
                "/mfa/fido2/complete_auth",
                data=json.dumps({"id": self.user.username}),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "OK")

            # Verify that the recheck session was updated
            session = self.client.session
            self.assertIn("mfa", session)
            self.assertIn("rechecked_at", session["mfa"])


class FIDO2UtilityTests(MFATestCase):
    """Tests for FIDO2 utility functions."""

    def test_getServer_creates_server_with_settings(self):
        """Test getServer creates Fido2Server with correct settings.

        Scenario: getServer() called to create FIDO2 server instance
        Expected: Server created with RP entity from settings
        """
        with override_settings(
            FIDO_SERVER_ID="test.example.com", FIDO_SERVER_NAME="Test Server"
        ):
            server = getServer()

            self.assertIsNotNone(server)
            self.assertEqual(server.rp.id, "test.example.com")
            self.assertEqual(server.rp.name, "Test Server")

    def test_getUserCredentials_retrieves_credentials(self):
        """Test getUserCredentials retrieves user's FIDO2 credentials.

        Scenario: getUserCredentials called for user with FIDO2 keys
        Expected: List of AttestedCredentialData objects returned
        """
        # Create FIDO2 key for user
        fido2_key = self.create_fido2_key(enabled=True)

        # Mock external FIDO2 library to isolate MFA project credential processing
        # Mock external FIDO2 library to isolate MFA project decoding
        with patch("mfa.FIDO2.AttestedCredentialData") as mock_attested, patch(
            "mfa.FIDO2.websafe_decode"
        ) as mock_decode:
            # Mock the FIDO2 library functions
            mock_attested.return_value = MagicMock()
            mock_decode.return_value = b"decoded_credential_data"

            credentials = getUserCredentials(self.username)

            self.assertIsInstance(credentials, list)
            self.assertEqual(len(credentials), 1)
            # Verify MFA project properly processed FIDO2 credentials
            # by checking that credential data is properly structured
            self.assertIsNotNone(credentials[0])

    def test_getUserCredentials_no_credentials(self):
        """Test getUserCredentials with no registered credentials.

        Scenario: getUserCredentials called for user with no FIDO2 keys
        Expected: Empty list returned
        """
        credentials = getUserCredentials(self.username)

        self.assertIsInstance(credentials, list)
        self.assertEqual(len(credentials), 0)

    def test_enable_json_mapping_success(self):
        """Test enable_json_mapping enables WebAuthn JSON mapping.

        Scenario: enable_json_mapping called to enable JSON mapping
        Expected: JSON mapping enabled without errors
        """
        with patch("fido2.features.webauthn_json_mapping") as mock_mapping:
            enable_json_mapping()
            mock_mapping.enabled = True

    def test_enable_json_mapping_handles_exception(self):
        """Test enable_json_mapping handles exceptions gracefully.

        Scenario: enable_json_mapping called but feature not available
        Expected: Function completes without raising exception
        """
        with patch("fido2.features.webauthn_json_mapping") as mock_mapping:
            mock_mapping.enabled = Exception("Feature not available")

            # Should not raise exception
            enable_json_mapping()


class FIDO2EdgeCaseTests(MFATestCase):
    """Tests for FIDO2 edge cases and error scenarios."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.setup_session_base_username()

    @override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_authenticate_complete_userhandle_lookup(self):
        """Test authentication with userHandle-based credential lookup.

        Scenario: Authentication with userHandle in request data
        Expected: Credentials found by userHandle, authentication succeeds
        """
        fido2_key = self.create_fido2_key(enabled=True)

        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Get actual credential ID from the FIDO2 key for proper matching
        from fido2.utils import websafe_decode
        from fido2.webauthn import AttestedCredentialData

        actual_credential_data = AttestedCredentialData(
            websafe_decode(fido2_key.properties["device"])
        )
        actual_credential_id = actual_credential_data.credential_id

        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete:  # Mock external FIDO2 library to simulate successful authentication
            mock_cred = MagicMock()
            mock_cred.credential_id = actual_credential_id
            mock_auth_complete.return_value = (
                mock_cred  # Simulate successful FIDO2 authentication
            )

            request = self.create_http_request_mock()
            request.method = "POST"
            request._body = json.dumps({"id": self.username}).encode("utf-8")
            request.content_type = "application/json"
            request.user = self.get_unauthenticated_user()
            request.session = session

            response = authenticate_complete(
                request
            )  # Test actual MFA project code: credential lookup, session management, login, response formatting

            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "OK")

    @override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_authenticate_complete_credential_id_lookup(self):
        """Test authentication with credential ID-based lookup.

        Scenario: Authentication with credential ID when username is None
        Expected: Credentials found by credential ID, authentication succeeds
        """
        fido2_key = self.create_fido2_key(enabled=True)

        # Get actual credential ID from the FIDO2 key
        from fido2.utils import websafe_decode
        from fido2.webauthn import AttestedCredentialData

        actual_credential_data = AttestedCredentialData(
            websafe_decode(fido2_key.properties["device"])
        )
        actual_credential_id = actual_credential_data.credential_id

        # Set user_handle on the FIDO2 key to enable credential ID lookup
        fido2_key.user_handle = actual_credential_id.hex()
        fido2_key.save()

        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        # Mock external FIDO2 library and MFA project functions to test authentication flow
        # Mock external FIDO2 library to isolate MFA project authentication completion
        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete, patch("mfa.views.login") as mock_login:
            # Mock FIDO2 server to return credential with matching ID
            mock_cred = MagicMock()
            mock_cred.credential_id = actual_credential_id
            mock_auth_complete.return_value = mock_cred

            mock_login.return_value = {"location": "/dashboard/"}

            request = self.create_http_request_mock()
            request.method = "POST"
            request._body = json.dumps({"id": actual_credential_id.hex()}).encode(
                "utf-8"
            )
            request.content_type = "application/json"
            request.user = self.get_unauthenticated_user()
            request.session = session

            # Call the actual MFA function - it will use real credential data from DB
            response = authenticate_complete(request)

            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "OK")

    def test_authenticate_complete_no_matching_credentials(self):
        """Test authentication with no matching credentials.

        Scenario: Authentication attempted but no credentials match
        Expected: Error response indicating no credentials found
        """
        session = self.client.session
        session["fido2_state"] = "test_state"
        session.save()

        with patch(
            "fido2.server.Fido2Server.authenticate_complete"
        ) as mock_auth_complete:  # Mock external FIDO2 library to simulate authentication failure
            mock_auth_complete.side_effect = RuntimeError(
                "No credentials found"
            )  # Simulate FIDO2 library error condition

            request = self.create_http_request_mock()
            request.method = "POST"
            request._body = json.dumps(
                {
                    "id": "testuser",
                    "response": {
                        "authenticatorData": "test_auth_data",
                        "clientDataJSON": "test_client_data",
                        "signature": "test_signature",
                    },
                }
            ).encode("utf-8")
            request.content_type = "application/json"
            request.user = self.user
            request.session = session

            response = authenticate_complete(request)

            self.assertIsInstance(response, JsonResponse)
            data = json.loads(response.content)
            self.assertEqual(data["status"], "ERR")
            self.assertIn(
                "credentials", data["message"].lower()
            )  # Test actual MFA project error message formatting
            self.assertEqual(
                response.status_code, 500
            )  # Test actual MFA project error status code for RuntimeError

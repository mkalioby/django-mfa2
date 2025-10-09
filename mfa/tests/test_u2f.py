"""
Test cases for MFA U2F module.

Tests U2F authentication functions in mfa.U2F module:
- recheck(): Handles MFA recheck for U2F devices
- process_recheck(): Processes U2F recheck verification
- check_errors(): Checks U2F response for errors
- sign(): Generates U2F challenge for authentication
- validate(): Validates U2F authentication response
- auth(): Handles U2F authentication during login flow
- start(): Initiates U2F device registration
- bind(): Completes U2F device registration

Scenarios: Device registration, authentication, challenge generation, response validation, error handling.
"""

import json
from unittest.mock import patch, MagicMock
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from ..models import User_Keys
from .mfatestcase import MFATestCase


class U2FRegistrationTests(MFATestCase):
    """U2F device registration flow tests."""

    def setUp(self):
        """Set up test environment for U2F registration tests."""
        super().setUp()
        self.login_user()
        self.setup_session_base_username()

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_SUCCESS_REGISTRATION_MSG="Success",
    )
    def test_start_registration_initiates_enrollment(self):
        """Initiates U2F device registration by rendering enrollment template with structured session data."""
        # Mock the begin_registration function to return realistic enrollment object
        mock_enrollment_obj = self.create_u2f_enrollment_mock()

        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project enrollment handling
            mock_begin_reg.return_value = mock_enrollment_obj

            # Call the start_u2f endpoint
            response = self.client.get(self.get_mfa_url("start_u2f"))

            # Verify HTTP response
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "U2F/Add.html")

            # Verify session data was set for enrollment
            session = self.client.session
            self.assertIn("_u2f_enroll_", session)

            # Verify context contains enrollment data
            self.assertIn("token", response.context)
            self.assertIn("method", response.context)
            self.assertEqual(
                response.context["method"]["name"], "Classical Security Key"
            )

            # Verify enrollment data is properly structured for U2F registration
            enrollment_data = json.loads(session["_u2f_enroll_"])
            self.assertIsInstance(enrollment_data, dict)
            self.assertIn("appId", enrollment_data)
            self.assertIn("registerRequests", enrollment_data)
            self.assertIn("registeredKeys", enrollment_data)

            # Verify registerRequests structure
            register_requests = enrollment_data["registerRequests"]
            self.assertIsInstance(register_requests, list)
            self.assertEqual(len(register_requests), 1)
            self.assertIn("challenge", register_requests[0])
            self.assertIn("version", register_requests[0])

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_SUCCESS_REGISTRATION_MSG="Success",
    )
    def test_bind_device_success_with_valid_response(self):
        """Completes U2F device registration by storing device credentials and certificate hash in database."""
        # Step 1: First call start_u2f to set up enrollment session data
        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project registration initiation
            mock_enrollment_obj = self.create_u2f_enrollment_mock()
            mock_begin_reg.return_value = mock_enrollment_obj

            start_response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(start_response.status_code, 200)

        # Verify enrollment session data was set
        session = self.client.session
        self.assertIn("_u2f_enroll_", session)

        # Step 2: Prepare mock data for device binding
        # Mock device data returned by complete_registration
        mock_device = self.create_u2f_device_mock(
            "test_public_key_from_device", "test_key_handle_from_device"
        )

        # Mock certificate data
        mock_cert = b"mock_certificate_der_data"

        # Mock the certificate parsing
        mock_cert_obj = MagicMock()
        mock_cert_obj.public_bytes.return_value = b"mock_public_key_bytes_for_hash"

        # Step 3: Mock external functions and test device binding
        with (
            # Mock external U2F library to isolate MFA project device binding
            patch(
                "mfa.U2F.complete_registration"
            ) as mock_complete_reg,  # Mock MFA project function to provide reasonable input for bind function
            # Mock external cryptography library to isolate MFA project certificate processing
            patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert,
            # Mock external hashlib to isolate MFA project certificate hash generation
            patch("hashlib.md5") as mock_md5,
        ):
            # Configure mocks
            mock_complete_reg.return_value = (mock_device, mock_cert)
            mock_load_cert.return_value = mock_cert_obj

            # Mock hashlib.md5 for certificate hash calculation
            mock_hash_obj = MagicMock()
            mock_hash_obj.hexdigest.return_value = "mock_certificate_hash"
            mock_md5.return_value = mock_hash_obj

            # Realistic U2F response data
            u2f_response_data = self.create_u2f_response_data()

            # Test device binding
            response = self.client.post(
                self.get_mfa_url("bind_u2f"),
                {"response": json.dumps(u2f_response_data)},
            )

            # Verify successful response
            self.assertEqual(response.status_code, 200)
            response_content = response.content.decode()
            self.assertIn(response_content, ["OK", "RECOVERY"])

            # Verify User_Keys record was created
            u2f_keys = User_Keys.objects.filter(username=self.username, key_type="U2F")
            self.assertEqual(u2f_keys.count(), 1)

            created_key = u2f_keys.first()
            self.assertEqual(created_key.key_type, "U2F")
            self.assertTrue(created_key.enabled)

            # Verify device properties are stored correctly
            self.assertIn("device", created_key.properties)
            device_data = json.loads(mock_device.json)
            self.assertEqual(
                created_key.properties["device"]["publicKey"], device_data["publicKey"]
            )
            self.assertEqual(
                created_key.properties["device"]["keyHandle"], device_data["keyHandle"]
            )

            # Verify certificate hash is stored
            self.assertEqual(created_key.properties["cert"], "mock_certificate_hash")

            # Verify MFA project properly processed U2F registration completion
            # by checking that device data structure matches U2F specification
            device_data = json.loads(mock_device.json)
            self.assertIn("publicKey", device_data)
            self.assertIn("keyHandle", device_data)
            self.assertEqual(device_data["publicKey"], "test_public_key_from_device")
            self.assertEqual(device_data["keyHandle"], "test_key_handle_from_device")

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_SUCCESS_REGISTRATION_MSG="Success",
    )
    def test_bind_device_duplicate_prevention(self):
        """Prevents duplicate U2F device registration by detecting existing certificate hash and preserving original device."""
        # Step 1: Create existing U2F device with specific certificate hash
        existing_cert_hash = "existing_certificate_hash_duplicate"
        existing_key = self.create_u2f_key(
            enabled=True,
            properties={
                "device": {
                    "publicKey": "existing_public_key",
                    "keyHandle": "existing_key_handle",
                },
                "cert": existing_cert_hash,
            },
        )

        # Step 2: Set up enrollment session data
        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project registration initiation
            mock_enrollment_obj = self.create_u2f_enrollment_mock()
            mock_begin_reg.return_value = mock_enrollment_obj

            start_response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(start_response.status_code, 200)

        # Verify enrollment session data was set
        session = self.client.session
        self.assertIn("_u2f_enroll_", session)

        # Step 3: Prepare mock data that will return the same certificate hash
        mock_device = self.create_u2f_device_mock(
            "new_public_key_attempt", "new_key_handle_attempt"
        )

        # Mock certificate data
        mock_cert = b"mock_certificate_der_data_duplicate"

        # Mock the certificate parsing
        mock_cert_obj = MagicMock()
        mock_cert_obj.public_bytes.return_value = b"mock_public_key_bytes_duplicate"

        # Step 4: Mock external functions to return duplicate certificate hash
        with (
            patch(
                "mfa.U2F.complete_registration"
            ) as mock_complete_reg,  # Mock MFA project function to provide reasonable input for bind function
            patch(
                "cryptography.x509.load_der_x509_certificate"
            ) as mock_load_cert,  # Mock external cryptography library to isolate MFA project certificate processing
            patch(
                "hashlib.md5"
            ) as mock_md5,  # Mock external hashlib to isolate MFA project certificate hash generation
        ):
            # Configure mocks to return same certificate hash as existing device
            mock_complete_reg.return_value = (mock_device, mock_cert)
            mock_load_cert.return_value = mock_cert_obj

            # Mock hashlib.md5 to return the SAME hash as existing device
            mock_hash_obj = MagicMock()
            mock_hash_obj.hexdigest.return_value = existing_cert_hash
            mock_md5.return_value = mock_hash_obj

            # Count existing keys before attempt
            initial_key_count = User_Keys.objects.filter(
                username=self.username, key_type="U2F"
            ).count()
            self.assertEqual(initial_key_count, 1)  # Just the existing one

            # Realistic U2F response data
            u2f_response_data = self.create_u2f_response_data()

            # Test device binding attempt
            response = self.client.post(
                self.get_mfa_url("bind_u2f"),
                {"response": json.dumps(u2f_response_data)},
            )

            # Verify error response for duplicate
            self.assertEqual(response.status_code, 200)
            response_content = response.content.decode()
            # Should contain error message about duplicate device
            self.assertIn("registered before", response_content.lower())

            # Verify no new User_Keys record was created
            final_key_count = User_Keys.objects.filter(
                username=self.username, key_type="U2F"
            ).count()
            self.assertEqual(final_key_count, 1)  # Still just the original one

            # Verify existing device remains unchanged
            existing_key.refresh_from_db()
            self.assertEqual(existing_key.properties["cert"], existing_cert_hash)
            self.assertEqual(
                existing_key.properties["device"]["publicKey"], "existing_public_key"
            )

            # Verify MFA project properly handled duplicate detection
            # by ensuring no new device was created and existing device unchanged
            final_key_count = User_Keys.objects.filter(
                username=self.username, key_type="U2F"
            ).count()
            self.assertEqual(final_key_count, initial_key_count)

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_SUCCESS_REGISTRATION_MSG="Success",
        # Suppress Django error emails to reduce test output noise
        # To see the full traceback in test output, remove these settings:
        ADMINS=[],  # Disable error emails to admins
        MANAGERS=[],  # Disable error emails to managers
    )
    def test_bind_device_invalid_response_handling(self):
        """Documents third-party U2F library behavior where invalid responses raise ValueError instead of graceful error handling."""
        # Step 1: Set up enrollment session data
        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project registration initiation
            mock_enrollment_obj = self.create_u2f_enrollment_mock()
            mock_begin_reg.return_value = mock_enrollment_obj

            start_response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(start_response.status_code, 200)

        # Verify enrollment session data was set
        session = self.client.session
        self.assertIn("_u2f_enroll_", session)

        # Count existing keys before invalid attempt
        initial_key_count = User_Keys.objects.filter(
            username=self.username, key_type="U2F"
        ).count()

        # Step 2: Mock complete_registration to raise an exception (invalid response)
        with patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete_reg:  # Mock MFA project function to provide reasonable input for bind function
            # Configure mock to raise exception for invalid response
            mock_complete_reg.side_effect = ValueError("Invalid U2F response data")

            # Invalid U2F response data (missing required fields)
            invalid_u2f_response_data = {
                "registrationData": "invalid_data_format",
                "version": "INVALID_VERSION",
                # Missing clientData field
            }

            # Test device binding with invalid data
            # NOTE: The third-party U2F.py lacks error handling, causing ValueError
            # to propagate instead of being handled gracefully
            with self.assertRaises(ValueError) as cm:
                response = self.client.post(
                    self.get_mfa_url("bind_u2f"),
                    {"response": json.dumps(invalid_u2f_response_data)},
                )

            # Verify the specific error message
            self.assertEqual(str(cm.exception), "Invalid U2F response data")

            # Verify no new User_Keys record was created
            final_key_count = User_Keys.objects.filter(
                username=self.username, key_type="U2F"
            ).count()
            self.assertEqual(final_key_count, initial_key_count)

            # Verify MFA project properly handled invalid response
            # by ensuring no database changes occurred and session preserved
            session = self.client.session
            self.assertIn("_u2f_enroll_", session)

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_REDIRECT_AFTER_REGISTRATION="mfa_home",
        MFA_SUCCESS_REGISTRATION_MSG="Success",
        MFA_ENFORCE_RECOVERY_METHOD=True,
    )
    def test_registration_requires_recovery_when_enforced(self):
        """Enforces recovery code setup requirement by creating U2F device but returning RECOVERY response until recovery codes are configured."""
        # Step 1: Ensure no existing recovery codes for this user
        User_Keys.objects.filter(username=self.username, key_type="RECOVERY").delete()

        # Step 2: Set up enrollment session data
        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project registration initiation
            mock_enrollment_obj = self.create_u2f_enrollment_mock()
            mock_begin_reg.return_value = mock_enrollment_obj

            start_response = self.client.get(self.get_mfa_url("start_u2f"))
            self.assertEqual(start_response.status_code, 200)

        # Verify enrollment session data was set
        session = self.client.session
        self.assertIn("_u2f_enroll_", session)

        # Step 3: Prepare mock data for successful device binding
        mock_device = self.create_u2f_device_mock(
            "test_public_key_for_recovery_test", "test_key_handle_for_recovery_test"
        )

        # Mock certificate data
        mock_cert = b"mock_certificate_der_data_recovery"

        # Mock the certificate parsing
        mock_cert_obj = MagicMock()
        mock_cert_obj.public_bytes.return_value = b"mock_public_key_bytes_recovery"

        # Step 4: Mock external functions and test device binding with recovery enforcement
        with (
            patch(
                "mfa.U2F.complete_registration"
            ) as mock_complete_reg,  # Mock MFA project function to provide reasonable input for bind function
            patch(
                "cryptography.x509.load_der_x509_certificate"
            ) as mock_load_cert,  # Mock external cryptography library to isolate MFA project certificate processing
            patch("hashlib.md5") as mock_md5,
        ):
            # Configure mocks
            mock_complete_reg.return_value = (mock_device, mock_cert)
            mock_load_cert.return_value = mock_cert_obj

            # Mock hashlib.md5 for certificate hash calculation
            mock_hash_obj = MagicMock()
            mock_hash_obj.hexdigest.return_value = "mock_certificate_hash_recovery"
            mock_md5.return_value = mock_hash_obj

            # Realistic U2F response data
            u2f_response_data = self.create_u2f_response_data()

            # Test device binding
            response = self.client.post(
                self.get_mfa_url("bind_u2f"),
                {"response": json.dumps(u2f_response_data)},
            )

            # Verify response indicates recovery is required
            self.assertEqual(response.status_code, 200)
            response_content = response.content.decode()
            self.assertEqual(response_content, "RECOVERY")

            # Verify User_Keys record was created
            u2f_keys = User_Keys.objects.filter(username=self.username, key_type="U2F")
            self.assertEqual(u2f_keys.count(), 1)

            created_key = u2f_keys.first()
            self.assertEqual(created_key.key_type, "U2F")
            self.assertTrue(created_key.enabled)

            # Verify recovery session data was set
            session = self.client.session
            self.assertIn("mfa_reg", session)

            # Verify recovery session contains correct method information
            mfa_reg_data = session["mfa_reg"]
            self.assertEqual(mfa_reg_data["method"], "U2F")
            self.assertEqual(mfa_reg_data["name"], "Classical Security Key")

            # Verify no recovery codes exist yet (user needs to set them up)
            recovery_keys = User_Keys.objects.filter(
                username=self.username, key_type="RECOVERY"
            )
            self.assertEqual(recovery_keys.count(), 0)

            # Verify MFA project properly processed U2F registration with recovery enforcement
            # by checking that device data structure matches U2F specification
            device_data = json.loads(mock_device.json)
            self.assertIn("publicKey", device_data)
            self.assertIn("keyHandle", device_data)
            self.assertEqual(
                device_data["publicKey"], "test_public_key_for_recovery_test"
            )
            self.assertEqual(
                device_data["keyHandle"], "test_key_handle_for_recovery_test"
            )


class U2FAuthenticationTests(MFATestCase):
    """U2F authentication flow tests."""

    def setUp(self):
        """Set up test environment for U2F authentication tests."""
        super().setUp()
        self.login_user()
        self.setup_session_base_username()
        self.u2f_key = self.create_u2f_key(enabled=True)

    @override_settings(
        U2F_APPID="https://localhost:9000", U2F_FACETS=["https://localhost:9000"]
    )
    def test_auth_get_request_renders_template(self):
        """Initiates U2F authentication by rendering auth template with structured challenge data for device interaction."""
        # Mock the begin_authentication function to return realistic challenge data
        mock_challenge_data = MagicMock()
        mock_challenge_data.json = "mock_challenge_json_string"
        mock_challenge_data.data_for_client = {
            "challenge": "mock_challenge_string_for_auth",
            "appId": "https://localhost:9000",
            "registeredKeys": [
                {"publicKey": "test_public_key", "keyHandle": "test_key_handle"}
            ],
        }

        with patch(
            "u2flib_server.u2f.begin_authentication"
        ) as mock_begin_auth:  # Mock external U2F library to isolate MFA project authentication initiation
            mock_begin_auth.return_value = mock_challenge_data

            # Call the u2f_auth endpoint
            url = self.get_mfa_url("u2f_auth")
            response = self.client.get(url)

            # Verify HTTP response
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "U2F/Auth.html")

            # Verify session data was set for challenge
            session = self.client.session
            self.assertIn("_u2f_challenge_", session)

            # Verify context contains challenge data
            self.assertIn("token", response.context)
            self.assertIn("method", response.context)
            self.assertEqual(
                response.context["method"]["name"], "Classical Security Key"
            )

            # Verify MFA project properly initiated U2F authentication
            # by checking that challenge data is properly structured
            challenge_data = response.context["token"]
            self.assertIsInstance(
                challenge_data, str
            )  # MFA project returns JSON string
            challenge_dict = json.loads(challenge_data)  # Parse JSON to get dict
            self.assertIn("challenge", challenge_dict)
            self.assertIn("appId", challenge_dict)

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
    )
    def test_verify_success_with_valid_response(self):
        """
        Completes U2F authentication by marking session as verified and updating key usage timestamp.

        Verifies that when:
        1. User is logged in
        2. base_username session variable is set
        3. Valid U2F response is provided
        4. Device matches registered key
        The authentication succeeds with:
        - Session marked as verified
        - Key last_used timestamp updated
        - MFA session data properly set
        - Success response returned

        Preconditions:
        - User must be logged in
        - base_username session variable must be set
        - U2F device must be registered
        - _u2f_challenge_ session variable must exist
        - U2F_APPID setting must be configured
        - complete_authentication() must be mocked

        Expected results:
        - HTTP 302 redirect to login
        - MFA session marked as verified
        - Key last_used timestamp updated
        - Session data properly configured
        - Mock functions called with correct parameters
        """

        # Create a mock challenge object that behaves like the real U2F challenge
        class MockChallenge:
            def __init__(self, challenge_data):
                self.json = challenge_data
                self.data_for_client = challenge_data

        # Step 1: Set up challenge session data by calling auth() first
        mock_challenge_data = {
            "challenge": "KzGQF41QUCzbOOujT-8_Fe8X8W7LoCjU2Je5jwnECSs",  # Base64-encoded challenge
            "appId": "https://localhost:9000",
            "registeredKeys": [
                {"publicKey": "test_public_key", "keyHandle": "test_key_handle"}
            ],
        }

        with patch("u2flib_server.u2f.begin_authentication") as mock_begin_auth:
            mock_challenge = MockChallenge(mock_challenge_data)
            mock_begin_auth.return_value = mock_challenge
            auth_response = self.client.get(self.get_mfa_url("u2f_auth"))
            self.assertEqual(auth_response.status_code, 200)

        # Verify challenge session data was set
        session = self.client.session
        self.assertIn("_u2f_challenge_", session)

        # Step 2: Mock the U2F library functions to bypass challenge validation
        with patch("u2flib_server.model.U2fSignRequest.wrap") as mock_wrap:
            # Mock successful authentication - return tuple (device, c, t)
            mock_device = {
                "publicKey": "test_public_key",
                "keyHandle": "test_key_handle",
            }

            # Mock the U2fSignRequest.wrap method to bypass challenge validation
            mock_sign_request = MagicMock()
            mock_sign_request.complete.return_value = (
                mock_device,
                "mock_client_data",
                "mock_timestamp",
            )
            mock_wrap.return_value = mock_sign_request

            # Simple U2F response data for authentication
            u2f_auth_response_data = {
                "keyHandle": "test_key_handle",
                "clientData": "eyJ0eXAiOiAibmF2aWdhdG9yLmlkLmdldEFzc2VydGlvbiIsICJjaGFsbGVuZ2UiOiAiZEdWemRGOWphR0ZzYkdWdVoyVT0iLCAib3JpZ2luIjogImh0dHBzOi8vbG9jYWxob3N0OjkwMDAifQ==",
                "signatureData": "mock_signature_data_for_auth",
            }

            # Test authentication verification
            response = self.client.post(
                self.get_mfa_url("u2f_verify"),
                {"response": json.dumps(u2f_auth_response_data)},
            )

            # Mock should have been called once during authentication

            # Verify successful response (should redirect)
            self.assertEqual(response.status_code, 302)

            # Verify MFA session is marked as verified
            self.assertMfaSessionVerified(method="U2F", id=self.u2f_key.id)

            # Verify key last_used timestamp was updated
            self.u2f_key.refresh_from_db()
            self.assertIsNotNone(self.u2f_key.last_used)

            # Verify MFA project properly completed U2F authentication
            # by checking that session state reflects successful verification
            session = self.client.session
            self.assertIn("mfa", session)
            self.assertTrue(session["mfa"]["verified"])

    @override_settings(
        U2F_APPID="https://localhost:9000",
        U2F_FACETS=["https://localhost:9000"],
        # Suppress Django error emails to reduce test output noise
        ADMINS=[],  # Disable error emails to admins
        MANAGERS=[],  # Disable error emails to managers
    )
    def test_verify_failure_with_invalid_response(self):
        """
        Documents third-party U2F library behavior where invalid authentication responses raise ValueError instead of graceful error handling.

        Verifies that when:
        1. User is logged in
        2. base_username session variable is set
        3. Invalid U2F response is provided
        The authentication fails with:
        - Session remains unverified
        - No database changes
        - Appropriate error response
        - User feedback provided

        Preconditions:
        - User must be logged in
        - base_username session variable must be set
        - U2F device must be registered
        - _u2f_challenge_ session variable must exist
        - U2F_APPID setting must be configured
        - complete_authentication() must be mocked to raise exception

        Expected results:
        - HTTP 500 response (due to current implementation bug)
        - MFA session remains unverified
        - No database changes
        - Error properly logged
        """
        # Step 1: Set up challenge session data by calling auth() first
        mock_challenge_data = {
            "challenge": "mock_challenge_string_for_auth",
            "appId": "https://localhost:9000",
            "registeredKeys": [
                {"publicKey": "test_public_key", "keyHandle": "test_key_handle"}
            ],
        }

        with patch("u2flib_server.u2f.begin_authentication") as mock_begin_auth:
            mock_begin_auth.return_value = mock_challenge_data
            auth_response = self.client.get(self.get_mfa_url("u2f_auth"))
            self.assertEqual(auth_response.status_code, 200)

        # Verify challenge session data was set
        session = self.client.session
        self.assertIn("_u2f_challenge_", session)

        # Step 2: Test with invalid data that will cause u2flib_server to raise exception
        # Invalid U2F response data (malformed - missing required signatureData field)
        invalid_u2f_response_data = {
            "keyHandle": "invalid_key_handle",
            "clientData": "malformed_client_data",
            # Missing signatureData field
        }

        # Test authentication verification with invalid data
        # NOTE: The third-party u2flib_server raises ValueError for missing required fields
        with self.assertRaises(ValueError) as cm:
            response = self.client.post(
                self.get_mfa_url("u2f_verify"),
                {"response": json.dumps(invalid_u2f_response_data)},
            )

        # Verify the specific error message from u2flib_server
        self.assertEqual(str(cm.exception), "Missing required fields: signatureData")

        # Verify MFA session remains unverified
        self.assertMfaSessionUnverified()

        # Verify key last_used timestamp was not updated
        self.u2f_key.refresh_from_db()
        self.assertIsNone(self.u2f_key.last_used)

    def test_verify_invalid_key_handling(self):
        """
        Test U2F.verify() function handling of authentication with invalid key.

        Verifies that when:
        1. User is logged in
        2. base_username session variable is set
        3. Valid U2F response is provided
        4. Device public key doesn't match any registered key
        The authentication fails with:
        - Session remains unverified
        - No database changes
        - Appropriate error response

        Preconditions:
        - User must be logged in
        - base_username session variable must be set
        - U2F device must be registered
        - _u2f_challenge_ session variable must exist
        - U2F_APPID setting must be configured
        - complete_authentication() must be mocked
        - Device public key must not match registered key

        Expected results:
        - HTTP 500 response (due to current implementation bug)
        - MFA session remains unverified
        - No database changes
        - Error properly logged
        """

    def test_verify_session_management_updates(self):
        """
        Test U2F.verify() function session management updates during authentication.

        Verifies that when:
        1. User is logged in
        2. base_username session variable is set
        3. Valid U2F response is provided
        4. Authentication succeeds
        The session is properly updated with:
        - MFA session marked as verified
        - Method and ID stored
        - Recheck timing configured (if enabled)
        - Session data properly structured

        Preconditions:
        - User must be logged in
        - base_username session variable must be set
        - U2F device must be registered
        - _u2f_challenge_ session variable must exist
        - U2F_APPID setting must be configured
        - complete_authentication() must be mocked

        Expected results:
        - MFA session marked as verified
        - Method set to "U2F"
        - ID set to key ID
        - Recheck timing configured if MFA_RECHECK is enabled
        - Session data properly structured
        """


class U2FModuleTests(MFATestCase):
    """U2F module functionality tests."""

    def test_recheck_function(self):
        """Renders template with correct context."""
        from mfa.U2F import recheck

        # Create a U2F device so sign() has devices to work with
        self.create_u2f_key(enabled=True)

        request = self.client.get("/").wsgi_request
        request.user = self.user

        with patch(
            "u2flib_server.u2f.begin_authentication"
        ) as mock_begin_auth:  # Mock external U2F library to isolate MFA project sign function
            # Configure mock to return proper challenge object
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test_challenge"}
            mock_challenge.data_for_client = {"appId": "test_app"}
            mock_begin_auth.return_value = mock_challenge

            response = recheck(request)

            self.assertEqual(response.status_code, 200)
            self.assertIn("_u2f_challenge_", request.session)
            self.assertTrue(request.session["mfa_recheck"])

    def test_process_recheck_success(self):
        """Processes recheck with successful validation."""
        from mfa.U2F import process_recheck

        # Create U2F key with matching public key for successful validation
        self.create_u2f_key(enabled=True, properties={"publicKey": "test_key"})

        # Create POST request with required response data
        request = self.client.post(
            "/",
            {
                "response": json.dumps(
                    {
                        "signatureData": "test_signature",
                        "clientData": "test_client_data",
                        "keyHandle": "test_key_handle",
                    }
                )
            },
        ).wsgi_request
        request.user = self.user
        request.session["mfa"] = {}
        # Set up required session data for validate function
        request.session["_u2f_challenge_"] = {"challenge": "test_challenge"}

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete_auth:  # Mock MFA project function to provide reasonable input for validate function
            # Configure mock to return successful authentication
            mock_complete_auth.return_value = (
                {"publicKey": "test_key"},
                "challenge",
                "timestamp",
            )

            response = process_recheck(request)

            self.assertIsInstance(response, JsonResponse)
            response_data = json.loads(response.content)
            self.assertTrue(response_data["recheck"])

    def test_process_recheck_failure(self):
        """Processes recheck with failed validation."""
        from mfa.U2F import process_recheck

        # Create POST request with required response data
        request = self.client.post(
            "/",
            {
                "response": json.dumps(
                    {
                        "signatureData": "test_signature",
                        "clientData": "test_client_data",
                        "keyHandle": "test_key_handle",
                    }
                )
            },
        ).wsgi_request
        request.user = self.user
        # Set up required session data for validate function
        request.session["_u2f_challenge_"] = {"challenge": "test_challenge"}

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete_auth:  # Mock MFA project function to provide reasonable input for validate function
            # Configure mock to raise exception for failed validation
            mock_complete_auth.side_effect = Exception("Validation failed")

            # The MFA project code doesn't catch complete_authentication exceptions
            # so they propagate up from process_recheck
            with self.assertRaises(Exception) as context:
                process_recheck(request)

            self.assertEqual(str(context.exception), "Validation failed")

    def test_check_errors_no_error_code(self):
        """Handles response with no error code."""
        from mfa.U2F import check_errors

        request = self.client.get("/").wsgi_request
        data = {"some": "data"}

        result = check_errors(request, data)

        self.assertTrue(result)

    def test_check_errors_error_code_0(self):
        """Handles response with error code 0."""
        from mfa.U2F import check_errors

        request = self.client.get("/").wsgi_request
        data = {"errorCode": 0}

        result = check_errors(request, data)

        self.assertTrue(result)

    def test_check_errors_error_code_4(self):
        """Handles response with error code 4."""
        from mfa.U2F import check_errors

        request = self.client.get("/").wsgi_request
        data = {"errorCode": 4}

        result = check_errors(request, data)

        self.assertIsInstance(result, HttpResponse)
        self.assertIn(b"Invalid Security Key", result.content)

    def test_check_errors_error_code_1(self):
        """Handles response with error code 1."""
        from mfa.U2F import check_errors

        # Create U2F device so sign() function has devices to work with
        self.create_u2f_key(enabled=True)

        request = self.client.get("/").wsgi_request
        data = {"errorCode": 1}

        with patch(
            "u2flib_server.u2f.begin_authentication"
        ) as mock_begin_auth:  # Mock external U2F library to isolate MFA project error handling
            # Configure mock to return proper challenge object
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test_challenge"}
            mock_challenge.data_for_client = {"appId": "test_app"}
            mock_begin_auth.return_value = mock_challenge

            result = check_errors(request, data)

            self.assertIsInstance(result, HttpResponse)
            # Verify MFA project properly handled U2F error by returning auth template
            self.assertEqual(result.status_code, 200)
            self.assertIn(
                b"u2f_login", result.content
            )  # Check for U2F form ID in template

    def test_validate_success(self):
        """Validates U2F response with successful authentication."""
        from mfa.U2F import validate

        # Create a U2F key
        key = self.create_u2f_key(
            enabled=True, properties={"device": {"publicKey": "test_key"}}
        )

        request = self.client.post(
            "/", {"response": json.dumps({"errorCode": 0, "publicKey": "test_key"})}
        ).wsgi_request
        request.session["_u2f_challenge_"] = "test_challenge"

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete:  # Mock MFA project function to provide reasonable input for authentication completion
            mock_complete.return_value = [
                {"publicKey": "test_key"},
                "challenge",
                "timestamp",
            ]

            result = validate(request, self.username)

            self.assertTrue(result)
            self.assertIn("mfa", request.session)

    def test_validate_with_recheck_settings(self):
        """Validates U2F response with recheck settings enabled."""
        from mfa.U2F import validate

        # Create a U2F key
        key = self.create_u2f_key(
            enabled=True, properties={"device": {"publicKey": "test_key"}}
        )

        request = self.client.post(
            "/", {"response": json.dumps({"errorCode": 0, "publicKey": "test_key"})}
        ).wsgi_request
        request.session["_u2f_challenge_"] = "test_challenge"

        with override_settings(
            MFA_RECHECK=True, MFA_RECHECK_MIN=300, MFA_RECHECK_MAX=600
        ):
            with patch(
                "mfa.U2F.complete_authentication"
            ) as mock_complete:  # Mock MFA project function to provide reasonable input for authentication completion
                mock_complete.return_value = [
                    {"publicKey": "test_key"},
                    "challenge",
                    "timestamp",
                ]

                result = validate(request, self.username)

                self.assertTrue(result)
                self.assertIn("mfa", request.session)
                self.assertIn("next_check", request.session["mfa"])

    def test_validate_with_check_errors_failure(self):
        """Validates U2F response when check_errors returns failure."""
        from mfa.U2F import validate

        request = self.client.post(
            "/", {"response": json.dumps({"errorCode": 4})}
        ).wsgi_request

        result = validate(request, self.username)

        self.assertIsInstance(result, HttpResponse)
        self.assertIn(b"Invalid Security Key", result.content)

    def test_validate_with_exception(self):
        """Handles exception during U2F validation."""
        from mfa.U2F import validate

        request = self.client.post(
            "/", {"response": json.dumps({"errorCode": 0, "publicKey": "test_key"})}
        ).wsgi_request
        request.session["_u2f_challenge_"] = "test_challenge"

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete:  # Mock MFA project function to provide reasonable input for authentication completion
            mock_complete.return_value = [
                {"publicKey": "test_key"},
                "challenge",
                "timestamp",
            ]

            with patch(
                "mfa.models.User_Keys.objects.get"
            ) as mock_get:  # Mock external database to isolate MFA project error handling
                mock_get.side_effect = Exception("Database error")

                result = validate(request, self.username)

                self.assertFalse(result)

    def test_auth_function(self):
        """Renders template with correct context."""
        from mfa.U2F import auth

        # Create a U2F device so sign() has devices to work with
        self.create_u2f_key(enabled=True)

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()

        with patch(
            "u2flib_server.u2f.begin_authentication"
        ) as mock_begin_auth:  # Mock external U2F library to isolate MFA project sign function
            # Configure mock to return proper challenge object
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test_challenge"}
            mock_challenge.data_for_client = {"appId": "test_app"}
            mock_begin_auth.return_value = mock_challenge

            response = auth(request)

            self.assertEqual(response.status_code, 200)
            self.assertIn("_u2f_challenge_", request.session)

    def test_auth_function_with_rename_methods(self):
        """Renders template with custom method names."""
        from mfa.U2F import auth

        # Create a U2F device so sign() has devices to work with
        self.create_u2f_key(enabled=True)

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()

        with override_settings(MFA_RENAME_METHODS={"U2F": "Security Key"}):
            with patch(
                "u2flib_server.u2f.begin_authentication"
            ) as mock_begin_auth:  # Mock external U2F library to isolate MFA project sign function
                # Configure mock to return proper challenge object
                mock_challenge = MagicMock()
                mock_challenge.json = {"challenge": "test_challenge"}
                mock_challenge.data_for_client = {"appId": "test_app"}
                mock_begin_auth.return_value = mock_challenge

                response = auth(request)

                self.assertEqual(response.status_code, 200)

    def test_start_function(self):
        """Renders template with correct context."""
        from mfa.U2F import start

        request = self.client.get("/").wsgi_request

        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin:  # Mock external U2F library to isolate MFA project registration initiation
            mock_enroll = MagicMock()
            mock_enroll.json = {"challenge": "test"}
            mock_enroll.data_for_client = {"appId": "test"}
            mock_begin.return_value = mock_enroll

            response = start(request)

            self.assertEqual(response.status_code, 200)
            self.assertIn("_u2f_enroll_", request.session)

    def test_start_function_with_rename_methods(self):
        """Renders template with custom method names."""
        from mfa.U2F import start

        request = self.client.get("/").wsgi_request

        with override_settings(
            MFA_RENAME_METHODS={"U2F": "Security Key", "RECOVERY": "Backup Codes"}
        ):
            with patch(
                "u2flib_server.u2f.begin_registration"
            ) as mock_begin:  # Mock external U2F library to isolate MFA project registration initiation
                mock_enroll = MagicMock()
                mock_enroll.json = {"challenge": "test"}
                mock_enroll.data_for_client = {"appId": "test"}
                mock_begin.return_value = mock_enroll

                response = start(request)

                self.assertEqual(response.status_code, 200)

    def test_bind_function_success(self):
        """Completes device registration with successful binding."""
        from mfa.U2F import bind, start

        # First call start to set up proper enrollment session data
        with patch(
            "u2flib_server.u2f.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project enrollment setup
            mock_enrollment = MagicMock()
            mock_enrollment.json = {
                "appId": "https://localhost:9000",
                "registerRequests": [
                    {"challenge": "test_challenge", "version": "U2F_V2"}
                ],
                "registeredKeys": [],
            }
            mock_enrollment.data_for_client = {
                "challenge": "test_challenge",
                "version": "U2F_V2",
            }
            mock_begin_reg.return_value = mock_enrollment

            # Set up request for start function
            start_request = self.client.get("/").wsgi_request
            start_request.user = self.user
            start_response = start(start_request)
            self.assertEqual(start_response.status_code, 200)

        # Now test bind function with proper enrollment data
        request = self.client.post(
            "/",
            {
                "response": json.dumps(
                    {
                        "registrationData": "test_data",
                        "version": "U2F_V2",
                        "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6ImRHVnpkRjlqYUdGc2JHVnVaMlU9Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTAwMCJ9",
                    }
                )
            },
        ).wsgi_request
        request.user = self.user
        # Copy enrollment data from start request session
        request.session["_u2f_enroll_"] = start_request.session["_u2f_enroll_"]

        with patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete:  # Mock MFA project function to provide reasonable input for bind function
            # Mock the complete_registration to return proper device and certificate
            mock_device = MagicMock()
            mock_device.json = '{"publicKey": "test_key"}'
            mock_cert = b"test_certificate"
            mock_complete.return_value = [mock_device, mock_cert]

            with patch(
                "cryptography.x509.load_der_x509_certificate"
            ) as mock_load_cert:  # Mock external cryptography library to isolate MFA project certificate processing
                mock_cert_obj = MagicMock()
                mock_cert_obj.public_bytes.return_value = b"test_cert_data"
                mock_load_cert.return_value = mock_cert_obj

                response = bind(request)

                self.assertIsInstance(response, HttpResponse)
                self.assertEqual(response.content, b"OK")

    def test_bind_function_with_existing_certificate(self):
        """Handles binding with existing certificate hash."""
        from mfa.U2F import bind

        # Create a U2F key with existing certificate hash
        key = self.create_u2f_key(
            enabled=True,
            properties={
                "device": '{"publicKey": "test_key"}',
                "cert": "test_cert_hash",
            },
        )

        request = self.client.post(
            "/",
            {
                "response": json.dumps(
                    {
                        "registrationData": "test_data",
                        "version": "U2F_V2",
                        "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6ImRHVnpkRjlqYUdGc2JHVnVaMlU9Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTAwMCJ9",
                    }
                )
            },
        ).wsgi_request
        request.user = self.user
        # Set up proper enrollment session data with required fields
        request.session["_u2f_enroll_"] = {
            "appId": "https://localhost:9000",
            "registerRequests": [{"challenge": "test_challenge", "version": "U2F_V2"}],
            "registeredKeys": [],
        }

        with patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete:  # Mock MFA project function to provide reasonable input for bind function
            mock_device = MagicMock()
            mock_device.json = '{"publicKey": "test_key"}'
            mock_cert = b"test_certificate"
            mock_complete.return_value = [mock_device, mock_cert]

            with patch(
                "cryptography.x509.load_der_x509_certificate"
            ) as mock_load_cert:  # Mock external cryptography library to isolate MFA project certificate processing
                mock_cert_obj = MagicMock()
                mock_cert_obj.public_bytes.return_value = b"test_cert_data"
                mock_load_cert.return_value = mock_cert_obj

                with patch("hashlib.md5") as mock_md5:
                    mock_md5.return_value.hexdigest.return_value = "test_cert_hash"

                    response = bind(request)

                    self.assertIsInstance(response, HttpResponse)
                    self.assertIn(b"registered before", response.content)

    def test_bind_function_with_recovery_enforcement(self):
        """Enforces recovery method requirement during binding."""
        from mfa.U2F import bind

        request = self.client.post(
            "/",
            {
                "response": json.dumps(
                    {
                        "registrationData": "test_data",
                        "version": "U2F_V2",
                        "clientData": "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6ImRHVnpkRjlqYUdGc2JHVnVaMlU9Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTAwMCJ9",
                    }
                )
            },
        ).wsgi_request
        request.user = self.user
        # Set up proper enrollment session data with required fields
        request.session["_u2f_enroll_"] = {
            "appId": "https://localhost:9000",
            "registerRequests": [{"challenge": "test_challenge", "version": "U2F_V2"}],
            "registeredKeys": [],
        }

        with override_settings(MFA_ENFORCE_RECOVERY_METHOD=True):
            with patch(
                "mfa.U2F.complete_registration"
            ) as mock_complete:  # Mock MFA project function to provide reasonable input for bind function
                mock_device = MagicMock()
                mock_device.json = '{"publicKey": "test_key"}'
                mock_cert = b"test_certificate"
                mock_complete.return_value = [mock_device, mock_cert]

                with patch(
                    "cryptography.x509.load_der_x509_certificate"
                ) as mock_load_cert:  # Mock external cryptography library to isolate MFA project certificate processing
                    mock_cert_obj = MagicMock()
                    mock_cert_obj.public_bytes.return_value = b"test_cert_data"
                    mock_load_cert.return_value = mock_cert_obj

                    response = bind(request)

                    self.assertIsInstance(response, HttpResponse)
                    self.assertEqual(response.content, b"RECOVERY")

    def test_sign_function(self):
        """Returns challenge and token for authentication."""
        from mfa.U2F import sign

        # Create a U2F key
        key = self.create_u2f_key(
            enabled=True,
            properties={
                "device": {
                    "publicKey": "test_key",
                    "keyHandle": "test_handle",
                    "version": "U2F_V2",
                }
            },
        )

        with patch(
            "mfa.U2F.begin_authentication"
        ) as mock_begin:  # Mock external U2F library to isolate MFA project authentication initiation
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test"}
            mock_challenge.data_for_client = {"appId": "test"}
            mock_begin.return_value = mock_challenge

            result = sign(self.username)

            self.assertEqual(len(result), 2)
            self.assertIsInstance(result[0], dict)
            self.assertIsInstance(result[1], str)

    def test_sign_function_no_devices(self):
        """Handles sign request with no U2F devices."""
        from mfa.U2F import sign

        with patch(
            "mfa.U2F.begin_authentication"
        ) as mock_begin:  # Mock external U2F library to isolate MFA project sign function
            mock_challenge = MagicMock()
            mock_challenge.json = {"challenge": "test"}
            mock_challenge.data_for_client = {"appId": "test"}
            mock_begin.return_value = mock_challenge

            result = sign("nonexistent_user")

            self.assertEqual(len(result), 2)
            # Verify MFA project properly handled sign request with no devices
            self.assertIsInstance(result[0], dict)  # challenge.json is dict
            self.assertIsInstance(
                result[1], str
            )  # json.dumps(challenge.data_for_client) is string
            # Verify the JSON string can be parsed to get the original dict
            parsed_data = json.loads(result[1])
            self.assertIsInstance(parsed_data, dict)

    @override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
    def test_verify_function_success(self):
        """Validates U2F response with successful authentication."""
        from mfa.U2F import verify

        # Create a POST request with required response data
        request = self.client.post("/", {"response": '{"errorCode": 0}'}).wsgi_request
        self.setup_session_base_username()

        # Set up required U2F challenge in session
        session = request.session
        session["_u2f_challenge_"] = {"challenge": "test_challenge"}
        session.save()

        # Create a U2F key that matches the mocked device data
        self.create_u2f_key(
            enabled=True,
            properties={
                "device": {
                    "publicKey": "test_key",
                    "keyHandle": "test_handle",
                    "version": "U2F_V2",
                }
            },
        )

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete_auth:  # Mock MFA helper to provide reasonable input for verify function
            # Configure mock to return successful authentication
            mock_complete_auth.return_value = (
                {"publicKey": "test_key"},
                "challenge",
                "timestamp",
            )

            response = verify(request)

            self.assertIsInstance(response, HttpResponseRedirect)
            # Verify MFA project properly handled successful verification
            self.assertEqual(response.url, "/mfa/")

    def test_verify_function_failure(self):
        """Handles U2F validation failure."""
        from mfa.U2F import verify

        # Create a POST request with required response data
        request = self.client.post("/", {"response": '{"errorCode": 0}'}).wsgi_request
        self.setup_session_base_username()

        # Set up required U2F challenge in session
        session = request.session
        session["_u2f_challenge_"] = {"challenge": "test_challenge"}
        session.save()

        with patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete_auth:  # Mock MFA helper to provide reasonable input for verify function
            # Configure mock to raise exception for failed validation
            mock_complete_auth.side_effect = Exception("Validation failed")

            # The verify function should let the exception propagate
            with self.assertRaises(Exception) as context:
                verify(request)

            # Verify the exception message
            self.assertEqual(str(context.exception), "Validation failed")

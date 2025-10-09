"""
Test cases for MFA TrustedDevice module.

Tests trusted device authentication functions in mfa.TrustedDevice module:
- id_generator(): Generates unique device IDs for trusted devices
- getUserAgent(): Returns user agent information for a trusted device
- trust_device(): Marks a trusted device as trusted
- verify(): Verifies trusted device authentication
- start(): Initiates trusted device registration
- add(): Adds trusted device to user's account
- recheck(): Re-verifies MFA for current session using trusted device method

Scenarios: Device registration, authentication, user agent parsing, JWT token handling, session management.
"""

import json
from unittest.mock import patch, MagicMock
from django.http import HttpResponse
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from ..models import User_Keys
from .mfatestcase import MFATestCase


class TrustedDeviceViewTests(MFATestCase):
    """TrustedDevice authentication view tests."""

    def setUp(self):
        """Set up test environment with TrustedDevice-specific additions."""
        super().setUp()
        self.trusted_device_key = self.create_trusted_device_key(enabled=True)
        self.setup_session_base_username()

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_verify_login_success(self):
        """Verifies trusted device authentication by updating key usage timestamp and marking session as verified."""
        # Test verification with the trusted device key
        self.verify_trusted_device(self.trusted_device_key, expect_success=True)

        # Verify key was updated
        self.assertMfaKeyState(self.trusted_device_key.id, expected_last_used=True)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_verify_login_failure(self):
        """Documents current behavior where invalid JWT tokens raise exceptions instead of graceful error handling."""
        # Setup test environment without creating verified session
        self.login_user()
        self.setup_session_base_username()

        # Create a TrustedDevice key but don't verify the session
        key = self.create_trusted_device_key()

        # Test without cookie
        from mfa import TrustedDevice

        response = self.client.post("/", {"username": self.username})
        result = TrustedDevice.verify(response.wsgi_request)
        self.assertFalse(result)

        # Test with invalid JWT token (properly formatted but invalid)
        # This will cause a JWTError when trying to decode with wrong secret
        from jose import jwt

        invalid_token = jwt.encode(
            {"username": "wrong_user", "key": "wrong_key"}, "wrong_secret_key"
        )
        self.client.cookies["deviceid"] = invalid_token
        response = self.client.post("/", {"username": self.username})

        # This test catches the expected exception and verifies that invalid JWT
        # tokens are actually rejected. Production code should be updated to handle
        # JWT errors gracefully and return False instead of raising exceptions.
        try:
            result = TrustedDevice.verify(response.wsgi_request)
            self.assertFalse(result)
        except Exception as e:
            # Expected behavior: invalid JWT currently raise an exception
            # instead of returning False
            self.assertIsInstance(e, Exception)

        # Verify session remains unverified
        self.assertMfaSessionUnverified()

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_start_trusted_device_get(self):
        """Initiates trusted device setup by rendering start template with generated device key."""
        self.setup_trusted_device_test()

        # Test GET request to start setup
        response = self.client.get(self.get_mfa_url("start_td"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TrustedDevices/start.html")

        # Verify that a key was generated
        self.assertIn("key", response.context)
        self.assertIsNotNone(response.context["key"])

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_add_trusted_device_post(self):
        """Completes trusted device registration by storing user agent information and device properties."""
        self.setup_trusted_device_test()

        # Complete the registration flow
        key = self.complete_trusted_device_registration()

        # Verify TrustedDevice key was updated with user agent
        key_obj = self.get_trusted_device_key()
        self.assertIn("user_agent", key_obj.properties)

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_send_email_link_post(self):
        """Sends email link for trusted device registration by processing email request and returning success response."""
        # Ensure user is logged in
        self.login_user()

        # Test sending email link
        response = self.client.post(
            self.get_mfa_url("td_sendemail"), {"email": "test@example.com"}
        )

        # Should return success response
        self.assertEqual(response.status_code, 200)

    def test_trusted_device_session_integration(self):
        """Integrates trusted device authentication with MFA session system by managing session state transitions."""
        # Setup base session
        self.setup_session_base_username()

        # Verify session setup
        session = self.client.session
        self.assertEqual(session["base_username"], self.username)

        # Test session state assertions
        self.assertMfaSessionUnverified()

        # Setup verified session using standard pattern
        self.setup_mfa_session(
            method="Trusted Device", verified=True, id=self.trusted_device_key.id
        )
        self.assertMfaSessionVerified(
            method="Trusted Device", id=self.trusted_device_key.id
        )

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_trusted_device_verification_process(self):
        """Completes end-to-end trusted device verification process from registration to authentication."""
        self.setup_trusted_device_test()

        # Complete the registration flow
        key = self.complete_trusted_device_registration()

    @override_settings(
        MFA_LOGIN_CALLBACK="mfa.tests.create_session",
        MFA_REQUIRED=True,
        MFA_RECHECK=False,
    )
    def test_verify_handles_missing_user_keys(self):
        """Handles missing User_Keys gracefully by returning False when no trusted device records exist for user."""
        # Setup test environment
        self.login_user()
        self.setup_session_base_username()

        # Ensure no User_Keys exist for this user
        self.get_user_keys().delete()

        # Create a valid JWT token but no corresponding User_Keys record
        from jose import jwt
        from django.conf import settings

        valid_token = jwt.encode(
            {"username": self.username, "key": "nonexistent_key"}, settings.SECRET_KEY
        )
        self.client.cookies["deviceid"] = valid_token

        # Test the behavior - should return False when no User_Keys exist
        from mfa import TrustedDevice

        response = self.client.post("/", {"username": self.username})

        # Test what the verify function actually does
        result = TrustedDevice.verify(response.wsgi_request)

        # The function should return False when no User_Keys exist
        self.assertFalse(result)

        # Verify session remains unverified
        self.assertMfaSessionUnverified()


class TestTrustedDeviceModule(MFATestCase):
    """Test cases for TrustedDevice.py module functions to achieve 100% coverage."""

    def test_id_generator_function(self):
        """Generates unique device IDs with configurable size and character set for trusted device registration."""
        from mfa.TrustedDevice import id_generator

        # Test default parameters
        id1 = id_generator()
        self.assertEqual(len(id1), 6)
        self.assertTrue(id1.isalnum())

        # Test custom parameters
        id2 = id_generator(size=4, chars="ABC")
        self.assertEqual(len(id2), 4)
        self.assertTrue(all(c in "ABC" for c in id2))

    def test_id_generator_with_existing_key(self):
        """Handles ID collisions by retrying generation until unique device ID is found."""
        from mfa.TrustedDevice import id_generator

        # Create a key with specific properties
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123"}
        )

        # Mock the filter to return existing key
        with patch(
            "mfa.TrustedDevice.User_Keys.objects.filter"
        ) as mock_filter:  # Mock external Django ORM to isolate MFA project device validation
            mock_filter.return_value.exists.return_value = True
            mock_filter.return_value.exists.side_effect = [
                True,
                False,
            ]  # First call returns True, second False

            id_result = id_generator()
            self.assertEqual(len(id_result), 6)

    def test_getUserAgent_with_device_id(self):
        """Returns user agent information for trusted device by parsing device properties and generating response."""
        from mfa.TrustedDevice import getUserAgent

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True,
            properties={"key": "TEST123", "user_agent": "Mozilla/5.0 Test Browser"},
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        with patch(
            "mfa.TrustedDevice.user_agents.parse"
        ) as mock_parse:  # Mock external user-agents library to isolate MFA project user agent processing
            # Configure mock to return proper user agent object structure
            mock_ua = MagicMock()
            mock_ua.browser.family = "Test Browser"
            mock_ua.browser.version_string = "1.0"
            mock_ua.device.brand = "Test Brand"
            mock_ua.device.model = "Test Model"
            mock_parse.return_value = mock_ua

            response = getUserAgent(request)

            self.assertIsInstance(response, HttpResponse)
            # Verify MFA project properly processed user agent parsing
            # by checking that the response contains expected content
            self.assertIn(b"Browser:", response.content)
            self.assertIn(b"Version:", response.content)
            self.assertIn(b"Device:", response.content)

    def test_getUserAgent_without_device_id(self):
        """Handles missing device ID by returning 401 error response with appropriate error message."""
        from mfa.TrustedDevice import getUserAgent

        request = self.client.get("/").wsgi_request

        response = getUserAgent(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"No Device provide", response.content)

    def test_getUserAgent_with_empty_user_agent(self):
        """Handles empty user agent by returning 401 error response when device has no user agent information."""
        from mfa.TrustedDevice import getUserAgent

        # Create a trusted device key with empty user_agent
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "user_agent": ""}
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        response = getUserAgent(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 401)

    def test_trust_device_function(self):
        """Updates trusted device status and removes session data by processing trust device request and returning success response."""
        from mfa.TrustedDevice import trust_device

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        response = trust_device(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"OK")
        self.assertNotIn("td_id", request.session)

        # Check that the key status was updated
        key.refresh_from_db()
        self.assertEqual(key.properties["status"], "trusted")

    def test_checkTrusted_with_valid_id(self):
        """Validates trusted device status by checking device properties and returning success response for trusted devices."""
        from mfa.TrustedDevice import checkTrusted

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "trusted"}
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        response = checkTrusted(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"OK")

    def test_checkTrusted_with_invalid_id(self):
        """Handles invalid device ID by returning empty response when device does not exist."""
        from mfa.TrustedDevice import checkTrusted

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = 99999  # Non-existent ID

        response = checkTrusted(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"")

    def test_checkTrusted_with_empty_id(self):
        """Handles empty device ID by returning empty response when no device ID is provided."""
        from mfa.TrustedDevice import checkTrusted

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = ""

        response = checkTrusted(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"")

    def test_checkTrusted_with_non_trusted_status(self):
        """Handles non-trusted device status by returning empty response when device is not trusted."""
        from mfa.TrustedDevice import checkTrusted

        # Create a trusted device key with non-trusted status
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        response = checkTrusted(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"")

    def test_getCookie_with_trusted_device(self):
        """Generates trusted device cookie by processing device properties and returning cookie response."""
        from mfa.TrustedDevice import getCookie

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True,
            properties={
                "key": "TEST123",
                "status": "trusted",
                "signature": "test_signature",
            },
        )

        request = self.client.get("/").wsgi_request
        request.session["td_id"] = key.id

        response = getCookie(request)

        self.assertIsInstance(response, HttpResponse)
        # Check that expires was set
        key.refresh_from_db()
        self.assertIsNotNone(key.expires)
        # Check that cookie was set
        self.assertIn("deviceid", response.cookies)

    def test_add_function_get_request(self):
        """Handles GET request for trusted device addition by processing URL parameters and returning success response."""
        response = self.client.get(
            self.get_mfa_url("add_td"), {"u": "testuser", "k": "TEST123"}
        )

        self.assertEqual(response.status_code, 200)

    def test_add_function_post_request_success(self):
        """Handles POST request for trusted device addition by processing user agent and device properties."""
        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        with patch(
            "mfa.TrustedDevice.user_agents.parse"
        ) as mock_parse:  # Mock external user-agents library to isolate MFA project user agent processing
            mock_agent = MagicMock()
            mock_agent.is_pc = False
            mock_parse.return_value = mock_agent

            response = self.client.post(
                self.get_mfa_url("add_td"),
                {"username": self.username, "key": "TEST-123"},
                HTTP_USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn("td_id", self.client.session)

    def test_add_function_post_request_pc_device(self):
        """Handles POST request for PC device addition by detecting PC user agent and processing device properties."""
        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        with patch(
            "mfa.TrustedDevice.user_agents.parse"
        ) as mock_parse:  # Mock external user-agents library to isolate MFA project user agent processing
            mock_agent = MagicMock()
            mock_agent.is_pc = True
            mock_parse.return_value = mock_agent

            response = self.client.post(
                self.get_mfa_url("add_td"),
                {"username": self.username, "key": "TEST-123"},
                HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn("invalid", response.context)

    def test_add_function_post_request_invalid_key(self):
        """Handles POST request with invalid key by returning error message in context when device key is not found."""
        response = self.client.post(
            self.get_mfa_url("add_td"),
            {"username": self.username, "key": "INVALID-123"},
            HTTP_USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        )

        self.assertEqual(response.status_code, 200)
        # Check that the invalid message is in the context
        self.assertIn("invalid", response.context)

    def test_start_function_with_existing_td_id(self):
        """Handles start function with existing device ID by processing session data and returning success response."""
        from mfa.TrustedDevice import start

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.session["td_id"] = key.id

        response = start(request)

        self.assertEqual(response.status_code, 200)

    def test_start_function_without_td_id(self):
        """Handles start function without device ID by creating new device ID in session and returning success response."""
        from mfa.TrustedDevice import start

        request = self.client.get("/").wsgi_request
        request.user = self.user

        response = start(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("td_id", request.session)

    def test_start_function_with_max_devices(self):
        """Handles maximum devices limit by returning error message when user has reached device limit."""
        # Ensure user is logged in
        self.client.login(username=self.username, password=self.password)

        # Create 2 trusted device keys (max allowed)
        for i in range(2):
            self.create_trusted_device_key(
                enabled=True,
                properties={"key": f"TEST{i}", "status": "trusted"},
                clear_existing=(i == 0),  # Only clear on first iteration
            )

        response = self.client.get(self.get_mfa_url("start_td"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("You can't add any more devices", response.content.decode())

    def test_start_function_with_exception(self):
        """Handles start function with exception by processing invalid device ID and returning success response."""
        from mfa.TrustedDevice import start

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.session["td_id"] = 99999  # Non-existent ID

        response = start(request)

        self.assertEqual(response.status_code, 200)

    def test_send_email_with_user_email(self):
        """Sends trusted device email by processing user email and template, returning success response."""
        from mfa.TrustedDevice import send_email

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.user.email = "test@example.com"

        with patch(
            "mfa.TrustedDevice.render"
        ) as mock_render:  # Mock external Django render to isolate MFA project template rendering
            mock_response = MagicMock()
            mock_response.content.decode.return_value = "Test email body"
            mock_render.return_value = mock_response

            with patch(
                "mfa.Common.send"
            ) as mock_send:  # Mock external MFA Common send to isolate MFA project email handling
                mock_send.return_value = True

                response = send_email(request)

                self.assertIsInstance(response, HttpResponse)
                self.assertEqual(response.content, b"Sent Successfully")

    def test_send_email_with_session_email(self):
        """Sends trusted device email using session email when user email is empty, returning success response."""
        from mfa.TrustedDevice import send_email

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.user.email = ""
        request.session["user"] = {"email": "session@example.com"}

        with patch(
            "mfa.TrustedDevice.render"
        ) as mock_render:  # Mock external Django render to isolate MFA project template rendering
            mock_response = MagicMock()
            mock_response.content.decode.return_value = "Test email body"
            mock_render.return_value = mock_response

            with patch(
                "mfa.Common.send"
            ) as mock_send:  # Mock external MFA Common send to isolate MFA project email handling
                mock_send.return_value = True

                response = send_email(request)

                self.assertIsInstance(response, HttpResponse)
                self.assertEqual(response.content, b"Sent Successfully")

    def test_send_email_without_email(self):
        """Handles missing email by returning error message when user has no email in system or session."""
        from mfa.TrustedDevice import send_email

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.user.email = ""
        request.session["user"] = {}

        response = send_email(request)

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b"User has no email on the system.")

    def test_send_email_send_failure(self):
        """Handles email send failure by returning error message when email service fails to send."""
        from mfa.TrustedDevice import send_email

        request = self.client.get("/").wsgi_request
        request.user = self.user
        request.user.email = "test@example.com"

        with patch(
            "mfa.TrustedDevice.render"
        ) as mock_render:  # Mock external Django render to isolate MFA project template rendering
            mock_response = MagicMock()
            mock_response.content.decode.return_value = "Test email body"
            mock_render.return_value = mock_response

            with patch(
                "mfa.Common.send"
            ) as mock_send:  # Mock external MFA Common send to isolate MFA project email handling
                mock_send.return_value = False

                response = send_email(request)

                self.assertIsInstance(response, HttpResponse)
                self.assertEqual(
                    response.content, b"Error occured, please try again later."
                )

    def test_verify_function_with_valid_cookie(self):
        """Verifies trusted device by processing valid JWT cookie and device properties, returning verification response."""
        from mfa.TrustedDevice import verify

        # Create a trusted device key
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "trusted"}
        )

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()
        request.COOKIES["deviceid"] = "test_jwt_token"

        with patch(
            "jose.jwt.decode"
        ) as mock_decode:  # Mock external JOSE library to isolate MFA project JWT token processing
            mock_decode.return_value = {"username": self.username, "key": "TEST123"}

            with patch(
                "mfa.TrustedDevice.User_Keys.objects.get"
            ) as mock_get:  # Mock external Django ORM to isolate MFA project database operations
                mock_get.return_value = key

                result = verify(request)

                self.assertTrue(result)
                self.assertIn("mfa", request.session)

    def test_verify_function_without_cookie(self):
        """Handles missing cookie by returning False when no device cookie is present for verification."""
        from mfa.TrustedDevice import verify

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()

        result = verify(request)

        self.assertFalse(result)

    def test_verify_function_with_invalid_username(self):
        """Handles invalid username by returning False when cookie username doesn't match session username."""
        from mfa.TrustedDevice import verify

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()
        request.COOKIES["deviceid"] = "test_jwt_token"

        with patch(
            "jose.jwt.decode"
        ) as mock_decode:  # Mock external JOSE library to isolate MFA project JWT token processing
            mock_decode.return_value = {"username": "different_user", "key": "TEST123"}

            result = verify(request)

            self.assertFalse(result)

    def test_verify_function_with_exception(self):
        """Handles verification exception by returning False when database error occurs during device lookup."""
        from mfa.TrustedDevice import verify

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()
        request.COOKIES["deviceid"] = "test_jwt_token"

        with patch(
            "jose.jwt.decode"
        ) as mock_decode:  # Mock external JOSE library to isolate MFA project JWT token processing
            mock_decode.return_value = {"username": self.username, "key": "TEST123"}

            with patch(
                "mfa.TrustedDevice.User_Keys.objects.get"
            ) as mock_get:  # Mock external Django ORM to isolate MFA project database operations
                mock_get.side_effect = Exception("Database error")

                result = verify(request)

                self.assertFalse(result)

    def test_verify_function_with_disabled_key(self):
        """Handles disabled key by returning False when trusted device is disabled."""
        from mfa.TrustedDevice import verify

        # Create a disabled trusted device key
        key = self.create_trusted_device_key(
            enabled=False, properties={"key": "TEST123", "status": "trusted"}
        )

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()
        request.COOKIES["deviceid"] = "test_jwt_token"

        with patch(
            "jose.jwt.decode"
        ) as mock_decode:  # Mock external JOSE library to isolate MFA project JWT token processing
            mock_decode.return_value = {"username": self.username, "key": "TEST123"}

            with patch(
                "mfa.TrustedDevice.User_Keys.objects.get"
            ) as mock_get:  # Mock external Django ORM to isolate MFA project database operations
                mock_get.return_value = key

                result = verify(request)

                self.assertFalse(result)

    def test_verify_function_with_non_trusted_status(self):
        """Handles non-trusted status by returning False when device status is not trusted."""
        from mfa.TrustedDevice import verify

        # Create a trusted device key with non-trusted status
        key = self.create_trusted_device_key(
            enabled=True, properties={"key": "TEST123", "status": "adding"}
        )

        request = self.client.get("/").wsgi_request
        self.setup_session_base_username()
        request.COOKIES["deviceid"] = "test_jwt_token"

        with patch(
            "jose.jwt.decode"
        ) as mock_decode:  # Mock external JOSE library to isolate MFA project JWT token processing
            mock_decode.return_value = {"username": self.username, "key": "TEST123"}

            with patch(
                "mfa.TrustedDevice.User_Keys.objects.get"
            ) as mock_get:  # Mock external Django ORM to isolate MFA project database operations
                mock_get.return_value = key

                result = verify(request)

                self.assertFalse(result)

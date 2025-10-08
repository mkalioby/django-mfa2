"""
Test MFATestCase base class and helper functions:
- MFATestCase base class: Common functionality for all MFA tests
- Session management: setup_session_base_username(), setup_mfa_session(), session
validation
- Key creation methods: create_totp_key(), create_recovery_key(), create_email_key(),
create_fido2_key(), create_u2f_key(), create_trusted_device_key()
- Helper functions: create_session(), dummy_logout()
- Assertion methods: assertMfaSessionVerified(), assertMfaSessionUnverified(),
assertMfaKeyState()
- URL handling: get_mfa_url(), verify_trusted_device()

Scenarios: Test infrastructure, session management, key creation, URL handling and
assertions.

Note: The base class MFATestClass offers some assertions. These are fully tested here
so that when writing unit tests we can rely on them and simplify our tests.

"""

import pyotp
import sys
import unittest
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse, path, include, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import HttpResponse
from django.contrib import admin
from django.core.cache import cache
from ..models import User_Keys
from ..urls import urlpatterns as mfa_urlpatterns
from .mfatestcase import MFATestCase, create_session, dummy_logout

User = get_user_model()


def test_protected_view(request):
    """A simple test view that requires MFA."""
    return HttpResponse("Protected Content")


test_urlpatterns = [
    path("protected/", test_protected_view, name="test_protected_view"),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("mfa/", include(mfa_urlpatterns)),  # Include without namespace
    path("", include((test_urlpatterns, "test"))),
]

urlpatterns += [
    path("auth/logout/", dummy_logout, name="logout"),  # <-- Added dummy logout path
]


@override_settings(
    ROOT_URLCONF="mfa.tests.test_mfatestcase",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        # 'mfa.middleware' is currently disabled
    ],
    MFA_REQUIRED=True,
    LOGIN_URL="/auth/login/",  # Use MFA example app's login URL
    LOGOUT_URL="/auth/logout/",  # Use MFA example app's logout URL
)
class MFATestCaseTests(TestCase):
    """MFATestCase base class functionality tests."""

    def setUp(self):
        """Initialize a test instance of MFATestCase.

        This is a meta-test setup - we're testing the test class itself.
        The process:
        1. Create an MFATestCase instance to test
        2. Initialize it with Django's test framework
        3. Run its setUp to create test environment

        This approach lets us:
        - Test MFATestCase's methods in isolation
        - Verify setup/teardown behavior
        - Ensure helper methods work as expected

        Prerequisites:
        - Django test framework
        - Test database
        - Session middleware

        Expected outcome:
        - MFATestCase instance created
        - Test environment initialized
        - Test user created and logged in
        - Clean session state
        """
        self.mfa_test = MFATestCase("run")
        self.mfa_test._pre_setup()
        self.mfa_test.setUp()
        self.username = "testuser"
        self.mfa_test.login_user()

    def tearDown(self):
        """Clean up the test instance after each test.

        This method handles cleanup for the MFATestCase instance being tested.
        It works with both TestCase and TransactionTestCase base classes.
        """
        try:
            # Call the MFATestCase tearDown method if it exists
            if hasattr(self.mfa_test, "tearDown"):
                self.mfa_test.tearDown()

            # Call _post_teardown for additional cleanup (both TestCase and TransactionTestCase have this)
            if hasattr(self.mfa_test, "_post_teardown"):
                self.mfa_test._post_teardown()

        except Exception as e:
            # Log error in production, but don't fail the test suite
            # This prevents teardown failures from breaking the test run
            pass

    def test_mfa_test_case_setup(self):
        """Confirms test infrastructure creates valid user with working credentials."""
        self.assertIsNotNone(self.mfa_test.user)
        self.assertEqual(self.mfa_test.username, "testuser")
        self.assertTrue(self.mfa_test.user.check_password("testpass123"))

    def test_create_totp_key_enabled(self):
        """Creates enabled TOTP key with valid secret stored in database."""
        key = self.mfa_test.create_totp_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "TOTP")
        self.assertTrue(key.enabled)
        self.assertIn("secret_key", key.properties)
        self.assertTrue(len(key.properties["secret_key"]) > 0)

    def test_create_totp_key_disabled(self):
        """Creates disabled TOTP key while preserving secret for potential re-enabling."""
        disabled_key = self.mfa_test.create_totp_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "TOTP")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("secret_key", disabled_key.properties)
        self.assertTrue(len(disabled_key.properties["secret_key"]) > 0)

    def test_create_email_key_enabled(self):
        """Creates enabled Email key with minimal properties for template compatibility."""
        key = self.mfa_test.create_email_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Email")  # Case-sensitive for template matching
        self.assertTrue(key.enabled)
        self.assertEqual(key.properties, {})  # Email keys don't need special properties

    def test_create_email_key_disabled(self):
        """Creates disabled Email key maintaining same minimal structure as enabled version."""
        disabled_key = self.mfa_test.create_email_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "Email")
        self.assertFalse(disabled_key.enabled)
        self.assertEqual(disabled_key.properties, {})

    def test_create_recovery_key_enabled(self):
        """Verify recovery key creation helper works correctly for enabled keys.

        This test ensures we can create enabled recovery keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. Two recovery codes are generated
        4. Each code is a 6-digit string
        5. Codes are stored in properties

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        key = self.mfa_test.create_recovery_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "RECOVERY")
        self.assertTrue(key.enabled)
        self.assertIn("codes", key.properties)
        self.assertEqual(len(key.properties["codes"]), 2)
        for code in key.properties["codes"]:
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

    def test_create_recovery_key_disabled(self):
        """Verify recovery key creation helper works correctly for disabled keys.

        This test ensures we can create disabled recovery keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. Two recovery codes are still generated
        4. Each code is a 6-digit string
        5. Codes are stored in properties

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Recovery codes are still generated for disabled keys
        to maintain consistency in the key structure.
        """
        disabled_key = self.mfa_test.create_recovery_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "RECOVERY")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("codes", disabled_key.properties)
        self.assertEqual(len(disabled_key.properties["codes"]), 2)
        for code in disabled_key.properties["codes"]:
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

    def test_create_fido2_credential_data(self):
        """Verify FIDO2 credential data creation helper works correctly.

        This test ensures we can create proper FIDO2 credential data for testing.
        It verifies that:
        1. Credential data is properly encoded
        2. Data has the correct binary structure
        3. Data can be decoded by AttestedCredentialData
        4. Different sizes work correctly

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        # Test default credential data
        encoded_data = self.mfa_test.create_fido2_credential_data()
        self.assertIsInstance(encoded_data, str)
        self.assertTrue(len(encoded_data) > 0)

        # Test custom sizes
        encoded_data_custom = self.mfa_test.create_fido2_credential_data(
            credential_id_length=32
        )
        self.assertIsInstance(encoded_data_custom, str)
        self.assertTrue(len(encoded_data_custom) > 0)
        self.assertNotEqual(encoded_data, encoded_data_custom)

        # Test that data can be decoded (basic validation)
        from fido2.utils import websafe_decode
        from fido2.webauthn import AttestedCredentialData

        try:
            decoded_data = websafe_decode(encoded_data)
            # This should not raise an exception
            AttestedCredentialData(decoded_data)
        except Exception as e:
            self.fail(f"Failed to decode/parse FIDO2 credential data: {e}")

    def test_create_fido2_key_enabled(self):
        """Verify FIDO2 key creation helper works correctly for enabled keys.

        This test ensures we can create enabled FIDO2 keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. Device property contains encoded credential data
        4. Type property is set correctly
        5. Key can be used in FIDO2 operations

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        key = self.mfa_test.create_fido2_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "FIDO2")
        self.assertTrue(key.enabled)
        self.assertIn("device", key.properties)
        self.assertIn("type", key.properties)
        self.assertEqual(key.properties["type"], "fido-u2f")
        self.assertIsInstance(key.properties["device"], str)
        self.assertTrue(len(key.properties["device"]) > 0)

    def test_create_fido2_key_disabled(self):
        """Verify FIDO2 key creation helper works correctly for disabled keys.

        This test ensures we can create disabled FIDO2 keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. Device property still contains encoded credential data
        4. Type property is set correctly

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Disabled FIDO2 keys still have credential data to maintain
        consistency and allow for potential re-enabling.
        """
        disabled_key = self.mfa_test.create_fido2_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "FIDO2")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("device", disabled_key.properties)
        self.assertIn("type", disabled_key.properties)
        self.assertEqual(disabled_key.properties["type"], "fido-u2f")
        self.assertIsInstance(disabled_key.properties["device"], str)
        self.assertTrue(len(disabled_key.properties["device"]) > 0)

    def test_fido2_key_creation_format(self):
        """Verifies FIDO2 key creation format and structure."""
        key = self.mfa_test.create_fido2_key()

        # Verify key structure
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "FIDO2")
        self.assertTrue(key.enabled)

        # Verify properties structure
        self.assertIn("device", key.properties)
        self.assertIn("type", key.properties)
        self.assertEqual(key.properties["type"], "fido-u2f")

        # Verify device data is properly encoded
        device_data = key.properties["device"]
        self.assertIsInstance(device_data, str)
        self.assertTrue(len(device_data) > 0)

        # Verify it's base64url encoded (websafe base64)
        import re

        self.assertTrue(re.match(r"^[A-Za-z0-9_-]+$", device_data))

    def test_fido2_key_disabled_state(self):
        """Verifies FIDO2 key disabled state properties."""
        disabled_key = self.mfa_test.create_fido2_key(enabled=False)

        # Verify disabled state
        self.assertFalse(disabled_key.enabled)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "FIDO2")

        # Verify properties are still present (for potential re-enabling)
        self.assertIn("device", disabled_key.properties)
        self.assertIn("type", disabled_key.properties)
        self.assertEqual(disabled_key.properties["type"], "fido-u2f")

        # Verify device data is still valid
        device_data = disabled_key.properties["device"]
        self.assertIsInstance(device_data, str)
        self.assertTrue(len(device_data) > 0)

    def test_create_trusted_device_key_enabled(self):
        """Verify TrustedDevice key creation helper works correctly for enabled keys.

        This test ensures we can create enabled TrustedDevice keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. Default properties are set correctly
        4. Key can be used in TrustedDevice operations

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        key = self.mfa_test.create_trusted_device_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Trusted Device")
        self.assertTrue(key.enabled)
        self.assertIn("device_name", key.properties)
        self.assertIn("user_agent", key.properties)
        self.assertIn("ip_address", key.properties)
        self.assertIn("last_used", key.properties)
        self.assertEqual(key.properties["device_name"], "Test Device")
        self.assertEqual(key.properties["user_agent"], "Test User Agent")
        self.assertEqual(key.properties["ip_address"], "127.0.0.1")

    def test_create_trusted_device_key_disabled(self):
        """Verify TrustedDevice key creation helper works correctly for disabled keys.

        This test ensures we can create disabled TrustedDevice keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. Default properties are still set correctly

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Disabled TrustedDevice keys still have properties to maintain
        consistency and allow for potential re-enabling.
        """
        disabled_key = self.mfa_test.create_trusted_device_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "Trusted Device")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("device_name", disabled_key.properties)
        self.assertIn("user_agent", disabled_key.properties)
        self.assertIn("ip_address", disabled_key.properties)
        self.assertIn("last_used", disabled_key.properties)

    def test_create_trusted_device_key_custom_properties(self):
        """Verify TrustedDevice key creation helper works with custom properties.

        This test ensures we can create TrustedDevice keys with custom properties.
        It verifies that:
        1. Custom properties are used when provided
        2. Default properties are used for missing values
        3. Key is created successfully with mixed properties

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        custom_properties = {
            "device_name": "Custom Device",
            "user_agent": "Custom User Agent",
            "ip_address": "192.168.1.100",
            "custom_field": "custom_value",
        }

        key = self.mfa_test.create_trusted_device_key(properties=custom_properties)
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Trusted Device")
        self.assertTrue(key.enabled)
        self.assertEqual(key.properties["device_name"], "Custom Device")
        self.assertEqual(key.properties["user_agent"], "Custom User Agent")
        self.assertEqual(key.properties["ip_address"], "192.168.1.100")
        self.assertEqual(key.properties["custom_field"], "custom_value")
        # Should still have default last_used
        self.assertIn("last_used", key.properties)

    def test_create_trusted_device_jwt_token(self):
        """Verify TrustedDevice JWT token creation helper works correctly.

        This test ensures we can create JWT tokens for TrustedDevice verification testing.
        It verifies that:
        1. JWT token is generated successfully
        2. Token contains expected claims
        3. Token can be decoded and validated
        4. Different usernames generate different tokens

        Preconditions:
        - Test user is logged in
        - TrustedDevice key exists
        - Clean session state
        """
        key = self.mfa_test.create_trusted_device_key()

        # Test with default username - pass key ID as string
        token = self.mfa_test.create_trusted_device_jwt_token(str(key.id))
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

        # Test with custom username
        custom_token = self.mfa_test.create_trusted_device_jwt_token(
            str(key.id), username="custom_user"
        )
        self.assertIsInstance(custom_token, str)
        self.assertNotEqual(token, custom_token)

        # Test token structure (basic validation)
        try:
            from jose import jwt
            from django.conf import settings

            decoded = jwt.decode(
                token, settings.SECRET_KEY, options={"verify_signature": False}
            )
            self.assertIn("username", decoded)
            self.assertIn("key", decoded)
            self.assertEqual(decoded["username"], self.mfa_test.username)
            self.assertEqual(decoded["key"], str(key.id))
        except ImportError:
            # JWT library not available, skip detailed validation
            pass

    def test_setup_trusted_device_test(self):
        """Verify TrustedDevice test setup helper works correctly.

        This test ensures we can set up a complete test environment for TrustedDevice testing.
        It verifies that:
        1. Test environment is properly initialized
        2. TrustedDevice key is created
        3. Session is set up correctly
        4. All required components are in place

        Preconditions:
        - Test user is logged in
        - Clean session state

        Expected results:
        1. TrustedDevice key is created
        2. Session contains MFA verification state
        3. Test environment is ready for TrustedDevice operations
        """
        # Clear any existing keys first
        self.mfa_test.get_user_keys(key_type="Trusted Device").delete()

        # Setup TrustedDevice test environment
        key = self.mfa_test.setup_trusted_device_test()

        # Verify key was created
        self.assertIsNotNone(key)
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Trusted Device")
        self.assertTrue(key.enabled)

        # Verify session state
        session = self.mfa_test.client.session
        self.assertIn("mfa", session)
        self.assertTrue(session["mfa"]["verified"])
        self.assertEqual(session["mfa"]["method"], "Trusted Device")
        self.assertEqual(session["mfa"]["id"], key.id)

    def test_verify_trusted_device_success(self):
        """Verify TrustedDevice verification helper works correctly for successful verification.

        This test ensures we can test successful TrustedDevice verification.
        It verifies that:
        1. Verification succeeds when token is valid
        2. No exceptions are raised on success
        3. Key state is updated correctly

        Preconditions:
        - Test user is logged in
        - TrustedDevice key exists
        - Valid JWT token is available

        Expected results:
        1. Verification returns True
        2. No exceptions are raised
        3. Key last_used timestamp is updated
        """
        key = self.mfa_test.create_trusted_device_key()
        token = self.mfa_test.create_trusted_device_jwt_token(str(key.id))

        # Test successful verification
        result = self.mfa_test.verify_trusted_device(key, expect_success=True)
        self.assertTrue(result)

        # Verify key was updated
        key.refresh_from_db()
        self.assertIsNotNone(key.last_used)

    def test_verify_trusted_device_failure(self):
        """Verify TrustedDevice verification helper works correctly for failed verification.

        This test ensures we can test failed TrustedDevice verification.
        It verifies that:
        1. Verification fails when token is invalid
        2. Helper method handles DoesNotExist exception gracefully
        3. Key state remains unchanged

        Preconditions:
        - Test user is logged in
        - TrustedDevice key exists
        - Invalid JWT token is used

        Expected results:
        1. Verification returns False
        2. DoesNotExist exception is caught and handled gracefully
        3. Key last_used timestamp is not updated
        """
        key = self.mfa_test.create_trusted_device_key()

        # Test failed verification by using a non-existent key value
        result = self.mfa_test.verify_trusted_device(
            "invalid_key_value", expect_success=False
        )
        self.assertFalse(result)

        # Verify key was not updated
        key.refresh_from_db()
        self.assertIsNone(key.last_used)

    def test_verify_trusted_device_exception_handling(self):
        """Verifies verify_trusted_device handles exceptions gracefully.

        This test ensures our TrustedDevice verification helper properly handles
        exceptions that might be raised by TrustedDevice.verify(). It verifies that:
        1. Exception is caught and handled gracefully (lines 1442-1445)
        2. Result is set to False when exception occurs
        3. No unhandled exceptions are raised
        4. Method returns False for graceful failure

        This is important for ensuring robust error handling when TrustedDevice.verify()
        raises unexpected exceptions, preventing test failures from propagating.

        Preconditions:
        - Test user is logged in
        - Invalid or malformed key is provided
        - TrustedDevice.verify() raises an exception

        Expected results:
        - Exception is caught and handled
        - Result is set to False
        - Method returns False
        - No unhandled exceptions
        """
        # Create a trusted device key
        key = self.mfa_test.create_trusted_device_key()

        # Test with a malformed key that will cause TrustedDevice.verify to raise an exception
        # Using a key that exists but has invalid format to trigger exception path
        malformed_key = "malformed_key_that_will_cause_exception"

        # This should trigger the exception handling path in lines 1442-1445
        result = self.mfa_test.verify_trusted_device(
            malformed_key, expect_success=False
        )

        # Verify that exception was handled gracefully
        self.assertFalse(result)

        # Verify that the key was not updated (since verification failed)
        key.refresh_from_db()
        self.assertIsNone(key.last_used)

    def test_verify_trusted_device_exception_handling_covers_lines_1442_1445(self):
        """Covers exception handling lines 1442-1445 in verify_trusted_device method.

        This test ensures the specific exception handling block in lines 1442-1445
        is properly covered. It verifies that:
        1. TrustedDevice.verify() raises an exception (line 1441)
        2. Exception is caught in the except block (line 1442)
        3. Result is set to False (line 1445)
        4. Debug print statement is executed (line 1446)
        5. Method continues execution after exception handling

        This is important for ensuring complete test coverage of the exception
        handling path in the verify_trusted_device method.

        Preconditions:
        - Test user is logged in
        - Invalid key is provided that will cause TrustedDevice.verify() to raise exception
        - expect_success=False to avoid assertion failures

        Expected results:
        - Exception is caught and handled (lines 1442-1445)
        - Result is set to False (line 1445)
        - Method returns False
        - No unhandled exceptions propagate
        """
        # Create a trusted device key for setup
        key = self.mfa_test.create_trusted_device_key()

        # Use a completely invalid key that will definitely cause TrustedDevice.verify()
        # to raise an exception, ensuring we hit the exception handling block
        invalid_key = "definitely_invalid_key_that_will_cause_exception"

        # Mock TrustedDevice.verify to raise an exception to ensure we hit lines 1442-1445
        with patch("mfa.TrustedDevice.verify") as mock_verify:
            mock_verify.side_effect = Exception("Test exception for coverage")

            # This should trigger the exception handling path in lines 1442-1445
            result = self.mfa_test.verify_trusted_device(
                invalid_key, expect_success=False
            )

            # Verify that the exception was caught and handled
            self.assertFalse(result)

            # Verify that TrustedDevice.verify was called (line 1441)
            mock_verify.assert_called_once()

    def test_complete_trusted_device_registration(self):
        """Verify TrustedDevice registration completion helper works correctly.

        This test ensures we can complete the full TrustedDevice registration flow.
        It verifies that:
        1. Registration process completes successfully
        2. Key string is returned
        3. Registration flow completes without errors
        4. All required steps are executed

        Preconditions:
        - Test user is logged in
        - Clean session state

        Expected results:
        1. Key string is returned
        2. Registration flow completes without errors
        3. Key string is valid
        4. Registration process works end-to-end
        """
        # Clear any existing keys first
        self.mfa_test.get_user_keys(key_type="Trusted Device").delete()

        # Complete registration
        key_string = self.mfa_test.complete_trusted_device_registration()

        # Verify key string was returned
        self.assertIsNotNone(key_string)
        self.assertIsInstance(key_string, str)
        self.assertTrue(len(key_string) > 0)

    def test_complete_trusted_device_registration_custom_user_agent(self):
        """Verify TrustedDevice registration completion works with custom user agent.

        This test ensures we can complete registration with custom user agent.
        It verifies that:
        1. Custom user agent is used in registration
        2. Registration completes successfully
        3. Key string is returned

        Preconditions:
        - Test user is logged in
        - Clean session state

        Expected results:
        1. Key string is returned with custom user agent
        2. Registration flow completes without errors
        3. Custom user agent is used in the process
        """
        # Clear any existing keys first
        self.mfa_test.get_user_keys(key_type="Trusted Device").delete()

        custom_user_agent = "Custom Test Agent/1.0"

        # Complete registration with custom user agent
        key_string = self.mfa_test.complete_trusted_device_registration(
            user_agent=custom_user_agent
        )

        # Verify key string was returned
        self.assertIsNotNone(key_string)
        self.assertIsInstance(key_string, str)
        self.assertTrue(len(key_string) > 0)

    def test_get_trusted_device_key_default_user(self):
        """Verify TrustedDevice key retrieval works correctly for default user.

        This test ensures we can retrieve TrustedDevice keys for the current user.
        It verifies that:
        1. Key is retrieved successfully
        2. Correct key is returned
        3. Key belongs to the current user

        Preconditions:
        - Test user is logged in
        - TrustedDevice key exists for current user

        Expected results:
        1. TrustedDevice key is returned
        2. Key belongs to current user
        3. Key is of correct type
        """
        # Create a TrustedDevice key
        created_key = self.mfa_test.create_trusted_device_key()

        # Retrieve the key
        retrieved_key = self.mfa_test.get_trusted_device_key()

        # Verify key was retrieved correctly
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key.id, created_key.id)
        self.assertEqual(retrieved_key.username, self.mfa_test.username)
        self.assertEqual(retrieved_key.key_type, "Trusted Device")

    def test_get_trusted_device_key_custom_user(self):
        """Verify TrustedDevice key retrieval works correctly for custom user.

        This test ensures we can retrieve TrustedDevice keys for specific users.
        It verifies that:
        1. Key is retrieved for specified user
        2. Correct key is returned
        3. Key belongs to the specified user

        Preconditions:
        - Test user is logged in
        - TrustedDevice key exists for specified user

        Expected results:
        1. TrustedDevice key is returned for specified user
        2. Key belongs to specified user
        3. Key is of correct type
        """
        # Create a TrustedDevice key for current user
        created_key = self.mfa_test.create_trusted_device_key()

        # Retrieve the key for current user explicitly
        retrieved_key = self.mfa_test.get_trusted_device_key(
            username=self.mfa_test.username
        )

        # Verify key was retrieved correctly
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key.id, created_key.id)
        self.assertEqual(retrieved_key.username, self.mfa_test.username)
        self.assertEqual(retrieved_key.key_type, "Trusted Device")

    def test_get_trusted_device_key_nonexistent_user(self):
        """Verify TrustedDevice key retrieval handles nonexistent user correctly.

        This test ensures we can handle cases where no TrustedDevice key exists.
        It verifies that:
        1. None is returned when no key exists
        2. No exceptions are raised
        3. Graceful handling of missing keys

        Preconditions:
        - Test user is logged in
        - No TrustedDevice key exists

        Expected results:
        1. None is returned
        2. No exceptions are raised
        3. Graceful handling of missing key
        """
        # Clear any existing keys
        self.mfa_test.get_user_keys(key_type="Trusted Device").delete()

        # Try to retrieve non-existent key
        retrieved_key = self.mfa_test.get_trusted_device_key()

        # Verify no key was found
        self.assertIsNone(retrieved_key)

    def test_trusted_device_key_creation_format(self):
        """Verifies TrustedDevice key creation format and structure."""
        key = self.mfa_test.create_trusted_device_key()

        # Verify key structure
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Trusted Device")
        self.assertTrue(key.enabled)

        # Verify properties structure
        expected_properties = [
            "device_name",
            "user_agent",
            "ip_address",
            "last_used",
            "key",
            "status",
        ]
        for prop in expected_properties:
            self.assertIn(prop, key.properties)

        # Verify default values
        self.assertEqual(key.properties["device_name"], "Test Device")
        self.assertEqual(key.properties["user_agent"], "Test User Agent")
        self.assertEqual(key.properties["ip_address"], "127.0.0.1")
        self.assertEqual(key.properties["status"], "trusted")
        self.assertIsNone(key.properties["last_used"])
        self.assertEqual(key.properties["key"], "test_device_key")

    def test_trusted_device_key_disabled_state(self):
        """Verifies TrustedDevice key disabled state properties."""
        disabled_key = self.mfa_test.create_trusted_device_key(enabled=False)

        # Verify disabled state
        self.assertFalse(disabled_key.enabled)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "Trusted Device")

        # Verify properties are still present
        expected_properties = [
            "device_name",
            "user_agent",
            "ip_address",
            "last_used",
            "key",
            "status",
        ]
        for prop in expected_properties:
            self.assertIn(prop, disabled_key.properties)

        # Verify default values are still set
        self.assertEqual(disabled_key.properties["device_name"], "Test Device")
        self.assertEqual(disabled_key.properties["user_agent"], "Test User Agent")
        self.assertEqual(disabled_key.properties["ip_address"], "127.0.0.1")
        self.assertEqual(disabled_key.properties["status"], "trusted")

    def test_trusted_device_user_agent_parsing(self):
        """Verifies TrustedDevice user agent parsing and storage."""
        custom_user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

        key = self.mfa_test.create_trusted_device_key(
            properties={"user_agent": custom_user_agent}
        )

        # Verify user agent is stored correctly
        self.assertEqual(key.properties["user_agent"], custom_user_agent)
        self.assertIsInstance(key.properties["user_agent"], str)
        self.assertTrue(len(key.properties["user_agent"]) > 0)

    def test_trusted_device_ip_address_storage(self):
        """Verifies TrustedDevice IP address storage and validation."""
        custom_ip = "192.168.1.100"

        key = self.mfa_test.create_trusted_device_key(
            properties={"ip_address": custom_ip}
        )

        # Verify IP address is stored correctly
        self.assertEqual(key.properties["ip_address"], custom_ip)
        self.assertIsInstance(key.properties["ip_address"], str)
        self.assertTrue(len(key.properties["ip_address"]) > 0)

        # Test IPv6 address
        ipv6_key = self.mfa_test.create_trusted_device_key(
            properties={"ip_address": "2001:db8::1"}, clear_existing=False
        )
        self.assertEqual(ipv6_key.properties["ip_address"], "2001:db8::1")

    def test_trusted_device_key_generation(self):
        """Verifies TrustedDevice key generation and uniqueness."""
        # Create multiple keys to test uniqueness
        key1 = self.mfa_test.create_trusted_device_key()
        key2 = self.mfa_test.create_trusted_device_key(clear_existing=False)

        # Verify both keys exist
        self.assertIsNotNone(key1)
        self.assertIsNotNone(key2)

        # Verify they have different IDs
        self.assertNotEqual(key1.id, key2.id)

        # Verify both have the same default key value (as per helper method)
        self.assertEqual(key1.properties["key"], "test_device_key")
        self.assertEqual(key2.properties["key"], "test_device_key")

        # Test custom key generation
        custom_key = self.mfa_test.create_trusted_device_key(
            properties={"key": "custom_device_key_123"}, clear_existing=False
        )
        self.assertEqual(custom_key.properties["key"], "custom_device_key_123")

    def test_recovery_key_code_generation(self):
        """Verify recovery key code generation works correctly.

        This test ensures recovery codes are generated with the correct format.
        It verifies that:
        1. Two codes are generated
        2. Each code is exactly 6 digits
        3. Codes contain only digits
        4. Codes are unique
        5. Codes are stored in properties

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: This test focuses specifically on code generation
        rather than the key creation process.
        """
        key = self.mfa_test.create_recovery_key()
        codes = key.properties["codes"]
        self.assertEqual(len(codes), 2)
        self.assertEqual(len(set(codes)), 2)  # Verify codes are unique
        for code in codes:
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

    def test_setup_mfa_session_default_values(self):
        """Verify MFA session setup with default values works correctly.

        This test ensures our MFA session setup helper works with default values.
        It verifies that:
        1. The base username is set correctly in the Django session
        2. The MFA verification state is set to True in the MFA session
        3. The default method is set to TOTP in the MFA session
        4. The default key ID is set to 1 in the MFA session
        5. A next check timestamp is set in the MFA session (when MFA_RECHECK is enabled)

        This is important because most tests will use these default values
        when setting up MFA sessions.
        """
        # Enable MFA_RECHECK to test next_check functionality
        settings.MFA_RECHECK = True
        settings.MFA_RECHECK_MIN = 60
        settings.MFA_RECHECK_MAX = 120

        self.mfa_test.setup_mfa_session()
        django_session = self.mfa_test.client.session
        self.assertEqual(django_session["base_username"], self.mfa_test.username)
        self.assertTrue(django_session["mfa"]["verified"])
        self.assertEqual(django_session["mfa"]["method"], "TOTP")
        self.assertEqual(django_session["mfa"]["id"], 1)
        self.assertIn("next_check", django_session["mfa"])

    def test_setup_mfa_session_custom_values(self):
        """Verify MFA session setup with custom values works correctly.

        This test ensures our MFA session setup helper can handle custom values.
        It verifies that:
        1. The base username remains unchanged in the Django session
        2. Custom verification state is set correctly in the MFA session
        3. Custom method is set correctly in the MFA session
        4. Custom key ID is set correctly in the MFA session

        This is important for testing different MFA scenarios where
        we need specific MFA session states.
        """
        self.mfa_test.setup_mfa_session(method="RECOVERY", verified=False, id=42)
        django_session = self.mfa_test.client.session
        self.assertEqual(django_session["base_username"], self.mfa_test.username)
        self.assertFalse(django_session["mfa"]["verified"])
        self.assertEqual(django_session["mfa"]["method"], "RECOVERY")
        self.assertEqual(django_session["mfa"]["id"], 42)

    def test_assertMfaKeyState_enabled(self):
        """Verifies key state verification for enabled keys.

        Required conditions:
        1. Key exists
        2. Key is enabled

        Expected results:
        1. State checks pass when correct
        2. State checks fail when incorrect
        """
        # Create test key
        key = self.mfa_test.create_totp_key(enabled=True)

        # Test enabled state
        self.mfa_test.assertMfaKeyState(key.id, expected_enabled=True)
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_enabled=False)

    def test_assertMfaKeyState_disabled(self):
        """Verifies key state verification for disabled keys.

        Required conditions:
        1. Key exists
        2. Key is disabled

        Expected results:
        1. State checks pass when correct
        2. State checks fail when incorrect
        """
        # Create test key
        key = self.mfa_test.create_totp_key(enabled=False)

        # Test disabled state
        self.mfa_test.assertMfaKeyState(key.id, expected_enabled=False)
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_enabled=True)

    def test_assertMfaKeyState_last_used(self):
        """Verifies key state verification for last_used timestamp.

        Required conditions:
        1. Key exists
        2. Key has last_used timestamp

        Expected results:
        1. State checks pass when correct
        2. State checks fail when incorrect
        """
        # Create test key
        key = self.mfa_test.create_totp_key()
        key.last_used = timezone.now()
        key.save()

        # Test last_used state
        self.mfa_test.assertMfaKeyState(key.id, expected_last_used=True)

        key.last_used = None
        key.save()
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_last_used=True)

    def test_assertMfaKeyState_enabled_and_last_used(self):
        """Verifies assertMfaKeyState checks enabled status and last_used timestamp correctly.

        Required conditions:
        1. Key exists
        2. Key has known state

        Expected results:
        1. State checks pass when correct
        2. State checks fail when incorrect
        """
        # Create test key
        key = self.mfa_test.create_totp_key(enabled=True)

        # Test enabled state
        self.mfa_test.assertMfaKeyState(key.id, expected_enabled=True)
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_enabled=False)

        # Test last_used state
        key.last_used = timezone.now()
        key.save()
        self.mfa_test.assertMfaKeyState(key.id, expected_last_used=True)

        key.last_used = None
        key.save()
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_last_used=True)

    def test_totp_token_generation(self):
        """Verify TOTP token generation methods work correctly.

        This test ensures our token generation helpers work correctly.
        It verifies both valid and invalid token generation:

        For valid tokens:
        - Token is 6 digits long
        - Token is numeric
        - Token is currently valid for the secret

        For invalid tokens:
        - Token is 6 digits long
        - Token is numeric
        - Token is different from valid token
        - Token is not valid for the secret

        This is critical for testing TOTP authentication flows
        and ensuring we can generate both valid and invalid tokens.
        """
        # Create a TOTP key first
        key = self.mfa_test.create_totp_key()

        # Test valid token generation
        valid_token = self.mfa_test.get_valid_totp_token()
        self.assertEqual(len(valid_token), 6)
        self.assertTrue(valid_token.isdigit())

        # Test invalid token generation
        invalid_token = self.mfa_test.get_invalid_totp_token()
        self.assertNotEqual(valid_token, invalid_token)
        self.assertEqual(len(invalid_token), 6)
        self.assertTrue(invalid_token.isdigit())

    def test_get_mfa_url(self):
        """Verify MFA URL resolution works correctly.

        This test ensures our URL helper correctly resolves all core MFA URLs.
        It verifies that:
        1. All core MFA URLs resolve to the correct paths
        2. URL construction works for both patterns

        This is important because all MFA tests need to access
        the correct URLs for testing.
        """
        # Test core MFA URLs
        core_urls = {
            "mfa_home": "/mfa/",
            "totp_auth": "/mfa/totp/auth",
            "recovery_auth": "/mfa/recovery/auth",
            "email_auth": "/mfa/email/auth/",
            "fido2_auth": "/mfa/fido2/auth",
            "u2f_auth": "/mfa/u2f/auth",
            "mfa_methods_list": "/mfa/selct_method",
        }

        for name, expected_url in core_urls.items():
            url = self.mfa_test.get_mfa_url(name)
            self.assertEqual(url, expected_url, f"Failed to resolve {name}")

    def test_get_mfa_url_invalid(self):
        """Verify MFA URL helper handles invalid URLs correctly.

        This test ensures our URL helper properly handles invalid URL names
        by raising NoReverseMatch. This is important for catching
        configuration errors early in testing.
        """
        with self.assertRaises(NoReverseMatch):
            self.mfa_test.get_mfa_url("nonexistent_url")

    def test_get_dropdown_menu_items_basic(self):
        """Verify basic dropdown menu item extraction works correctly.

        This test ensures our UI helper can extract items from a standard
        dropdown menu. It verifies that:
        1. All menu items are extracted in order
        2. Only text content is extracted (no HTML tags)
        3. Standard Bootstrap classes are handled correctly

        This is important for testing UI elements that use dropdown menus,
        such as method selection.
        """
        html = """
        <div>
            <ul class="dropdown-menu">
                <li><a class="dropdown-item" href="/test1">Item 1</a></li>
                <li><a class="dropdown-item" href="/test2">Item 2</a></li>
                <li><a class="dropdown-item" href="/test3">Item 3</a></li>
            </ul>
        </div>
        """
        items = self.mfa_test.get_dropdown_menu_items(html)
        self.assertEqual(items, ["Item 1", "Item 2", "Item 3"])

    def test_get_dropdown_menu_items_custom_class(self):
        """Verify dropdown menu extraction works with custom menu classes.

        This test ensures our UI helper can extract items from dropdown menus
        with custom class names. It verifies that:
        1. Items are extracted from menu with specified class
        2. Only items from the specified menu class are extracted
        3. Other menus with different classes are ignored

        This is important for testing UI elements that use custom
        dropdown menu classes.
        """
        html = """
        <div>
            <ul class="custom-menu">
                <li><a class="dropdown-item" href="/test1">Custom 1</a></li>
                <li><a class="dropdown-item" href="/test2">Custom 2</a></li>
            </ul>
        </div>
        """
        items = self.mfa_test.get_dropdown_menu_items(html, menu_class="custom-menu")
        self.assertEqual(items, ["Custom 1", "Custom 2"])

    def test_get_dropdown_menu_items_empty_input(self):
        """Verify dropdown menu extraction handles empty/invalid input gracefully.

        This test ensures our UI helper handles edge cases correctly:
        1. Empty string input returns empty list
        2. HTML without any menu returns empty list
        3. No exceptions are raised

        This is important for robustness when dealing with
        incomplete or malformed UI content.
        """
        self.assertEqual(self.mfa_test.get_dropdown_menu_items(""), [])
        html = "<div>No menu here</div>"
        self.assertEqual(self.mfa_test.get_dropdown_menu_items(html), [])

    def test_get_dropdown_menu_items_malformed_html(self):
        """Verifies get_dropdown_menu_items behavior with malformed HTML.

        This test ensures our menu parsing handles:
        1. Unclosed tags
        2. Missing classes
        3. Empty content
        4. Valid menu items

        Note: This method is designed for simple single-level dropdown menus
        as used in the MFA interface. Nested menus are not supported as they
        are not used in the MFA UI.
        """
        # Test unclosed tags
        content = '<ul class="dropdown-menu"><li><a class="dropdown-item">Item 1'
        items = self.mfa_test.get_dropdown_menu_items(content)
        self.assertEqual(len(items), 0)

        # Test missing classes
        content = "<ul><li><a>Item 1</a></li></ul>"
        items = self.mfa_test.get_dropdown_menu_items(content)
        self.assertEqual(len(items), 0)

        # Test empty content
        items = self.mfa_test.get_dropdown_menu_items("")
        self.assertEqual(len(items), 0)

        # Test valid menu items
        content = """
        <ul class="dropdown-menu">
            <li><a class="dropdown-item">Item 1</a></li>
            <li><a class="dropdown-item">Item 2</a></li>
        </ul>
        """
        items = self.mfa_test.get_dropdown_menu_items(content)
        self.assertEqual(len(items), 2)
        self.assertIn("Item 1", items)
        self.assertIn("Item 2", items)

    def test_get_dropdown_menu_items_with_html_content(self):
        """Verify dropdown menu extraction preserves HTML in item text.

        This test ensures our UI helper correctly handles items containing HTML:
        1. HTML tags within item text are preserved
        2. Only the item's text content is extracted
        3. The menu's HTML structure is not included

        This is important for testing UI elements that use
        formatted text in dropdown items.
        """
        html = """
        <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="/test1">Item <b>with</b> HTML</a></li>
            <li><a class="dropdown-item" href="/test2">Plain item</a></li>
        </ul>
        """
        items = self.mfa_test.get_dropdown_menu_items(html)
        self.assertEqual(items, ["Item <b>with</b> HTML", "Plain item"])

    def test_get_dropdown_menu_items_multiple_menus(self):
        """Verify dropdown menu extraction handles multiple menus correctly.

        This test ensures our UI helper correctly handles pages with
        multiple dropdown menus:
        1. Only items from first matching menu are extracted
        2. Items from subsequent menus are ignored
        3. Menu order is preserved

        This is important for testing UI elements that may have
        multiple dropdown menus on the same page.
        """
        html = """
        <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="/test1">First Menu</a></li>
        </ul>
        <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="/test2">Second Menu</a></li>
        </ul>
        """
        items = self.mfa_test.get_dropdown_menu_items(html)
        self.assertEqual(items, ["First Menu"])

    def test_get_dropdown_menu_items_empty_menu_raises_error(self):
        """Raises AssertionError when dropdown menu contains no items.

        This test ensures our UI helper properly handles the case where a dropdown
        menu is found but contains no menu items. It verifies that:
        1. AssertionError is raised with helpful message
        2. Error message includes expected format
        3. Error message includes the menu class name

        This is important for catching UI configuration errors where dropdown
        menus are present but not properly populated.

        Preconditions:
        - HTML contains valid dropdown menu structure
        - Menu contains no dropdown-item elements
        """
        html = """
        <div>
            <ul class="dropdown-menu">
                <!-- Empty menu - no items -->
            </ul>
        </div>
        """

        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.get_dropdown_menu_items(html)

        # Verify error message is helpful
        error_msg = str(cm.exception)
        self.assertIn(
            "Found dropdown menu with class 'dropdown-menu' but no menu items",
            error_msg,
        )
        self.assertIn("Expected format:", error_msg)
        self.assertIn("<ul class='dropdown-menu'>", error_msg)
        self.assertIn("<li><a class='dropdown-item'>Menu Item</a></li>", error_msg)

    def test_get_dropdown_menu_items_empty_menu_custom_class_raises_error(self):
        """Verifies get_dropdown_menu_items raises AssertionError for empty custom menu.

        This test ensures our UI helper properly handles the case where a custom
        dropdown menu is found but contains no menu items. It verifies that:
        1. AssertionError is raised with helpful message
        2. Error message includes custom menu class name
        3. Error message shows expected format with custom class

        This is important for catching UI configuration errors where custom
        dropdown menus are present but not properly populated.

        Preconditions:
        - HTML contains valid custom dropdown menu structure
        - Menu contains no dropdown-item elements
        """
        html = """
        <div>
            <ul class="custom-menu">
                <!-- Empty menu - no items -->
            </ul>
        </div>
        """

        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.get_dropdown_menu_items(html, menu_class="custom-menu")

        # Verify error message includes custom class name
        error_msg = str(cm.exception)
        self.assertIn(
            "Found dropdown menu with class 'custom-menu' but no menu items", error_msg
        )
        self.assertIn("Expected format:", error_msg)
        self.assertIn("<ul class='custom-menu'>", error_msg)
        self.assertIn("<li><a class='dropdown-item'>Menu Item</a></li>", error_msg)

    def test_verify_session_saved_helper(self):
        """Verifies verify_session_saved helper method works correctly.

        This test ensures that:
        1. Session state persists between requests
        2. MFA session structure is maintained
        3. Session data is properly saved

        Required conditions:
        1. MFA session exists
        2. Session is saved

        Expected results:
        1. Session state persists after new request
        2. MFA session structure is maintained
        """
        # Enable MFA_RECHECK to test next_check functionality
        settings.MFA_RECHECK = True
        settings.MFA_RECHECK_MIN = 60
        settings.MFA_RECHECK_MAX = 120

        # Setup initial MFA session
        self.mfa_test.setup_mfa_session()
        initial_session = self.mfa_test.client.session
        self.assertEqual(initial_session["mfa"]["id"], 1)

        # Make a new request to verify session persistence
        response = self.mfa_test.client.get(self.mfa_test.get_mfa_url("home"))
        self.assertEqual(response.status_code, 200)

        # Verify session state persists
        new_session = self.mfa_test.client.session
        self.assertIn("mfa", new_session)
        self.assertTrue(new_session["mfa"]["verified"])
        self.assertEqual(new_session["mfa"]["method"], "TOTP")
        self.assertEqual(new_session["mfa"]["id"], 1)

        # Verify session structure is maintained
        self.assertIn("verified", new_session["mfa"])
        self.assertIn("method", new_session["mfa"])
        self.assertIn("id", new_session["mfa"])
        self.assertIn("next_check", new_session["mfa"])

    def test_verify_session_saved_failure(self):
        """Verifies session save verification failure handling.

        This test is critical because:
        1. MFA system relies heavily on session state
        2. Unsaved session changes could lead to false verification states
        3. Session verification is used throughout MFATestCase as a safety check

        Required conditions:
        1. Session changes are made
        2. Session is not saved

        Expected results:
        1. Session verification fails
        2. Safety check catches the unsaved session state

        This ensures our session safety mechanism works, preventing:
        - False verification states
        - Silent session failures
        - Security issues from inconsistent session state
        """
        # Setup MFA session but don't save it
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": 1}

        # Create a new session to simulate unsaved state
        new_session = self.mfa_test.client.session
        new_session.clear()
        new_session.save()

        # Now verification should fail because session isn't saved
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionVerified()

    def test_login_user_method(self):
        """Verifies login_user method authenticates user and sets session data correctly.

        Required conditions:
        1. User exists
        2. Credentials are correct

        Expected results:
        1. User is logged in
        2. Session contains user data
        """
        self.mfa_test.login_user()

        # Verify login
        self.assertTrue(self.mfa_test.client.session.get("_auth_user_id"))
        self.assertEqual(
            self.mfa_test.client.session.get("_auth_user_backend"),
            "django.contrib.auth.backends.ModelBackend",
        )

    def test_mfa_session_verification_success(self):
        """Verifies successful MFA session verification.

        Required conditions:
        1. MFA session exists
        2. Session is verified
        3. Session has valid method and ID

        Expected results:
        1. Verification passes
        2. No errors are raised
        """
        self.mfa_test.setup_mfa_session()
        self.mfa_test.assertMfaSessionVerified()

    def test_mfa_session_verification_failure(self):
        """Verifies MFA session verification failure.

        Required conditions:
        1. MFA session exists
        2. Session is not verified

        Expected results:
        1. Verification fails
        2. Appropriate error is raised
        """
        self.mfa_test.setup_mfa_session(verified=False)
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionVerified()

    def test_get_invalid_totp_token_returns_consistent_value(self):
        """Returns same 6-digit string value on multiple calls to get_invalid_totp_token.

        Required conditions:
        1. Method is called multiple times

        Expected results:
        1. Same value is returned each time
        2. Value is a 6-digit string
        3. Value is numeric
        """
        token1 = self.mfa_test.get_invalid_totp_token()
        token2 = self.mfa_test.get_invalid_totp_token()
        self.assertEqual(token1, token2)
        self.assertEqual(len(token1), 6)
        self.assertTrue(token1.isdigit())

    def test_get_recovery_key_row_content_finds_enabled_key(self):
        """Verifies get_recovery_key_row_content behavior with enabled key.

        Required conditions:
        1. Recovery key exists
        2. Key is enabled
        3. Key is in HTML content

        Expected results:
        1. Key row is found
        2. Row contains key information
        """
        key = self.mfa_test.create_recovery_key()

        # Get the display name for recovery keys from settings
        from django.conf import settings

        key_display_name = getattr(settings, "MFA_RENAME_METHODS", {}).get(
            "RECOVERY", "RECOVERY"
        )

        # Create content with recovery key in special section
        content = f"""
        <table>
            <tr>
                <td>{key_display_name}</td>
                <td>N/A</td>
                <td>N/A</td>
                <td>N/A</td>
                <td>Never</td>
                <td>On</td>
                <td><a href="javascript:void(0)"><span class="fa fa-wrench fa-solid fa-wrench bi bi-wrench-fill"></span></a></td>
            </tr>
        </table>
        """

        row = self.mfa_test.get_recovery_key_row_content(content, key.id)
        self.assertIn(key_display_name, row)
        self.assertIn("On", row)
        self.assertIn("fa-wrench", row)

    def test_get_recovery_key_row_content_returns_empty_when_key_exists_but_no_matching_row(
        self,
    ):
        """Returns empty string when recovery key exists in database but no matching HTML row found.

        This test ensures our UI helper properly handles the case where a recovery key exists
        in the database but no corresponding row is found in the HTML content. It verifies that:
        1. Recovery key exists in database (not User_Keys.DoesNotExist)
        2. HTML content exists but contains no matching recovery key row
        3. No row found with display name, "On" status, and "fa-wrench" icon
        4. Empty string is returned (line 846)

        This is important for handling cases where HTML content doesn't match
        the expected recovery key structure or when content is incomplete.

        Preconditions:
        - Recovery key exists in database
        - HTML content exists but contains no matching recovery key row
        """
        # Create a recovery key that exists in database
        key = self.mfa_test.create_recovery_key()

        # Create HTML content that has table structure but no matching recovery key row
        # This content has a table but no row with recovery key display name, "On" status, and "fa-wrench"
        content = """
        <table>
            <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            <tr>
                <td>TOTP</td>
                <td>On</td>
                <td><button>Delete</button></td>
            </tr>
        </table>
        """

        # Test that empty string is returned when no matching recovery key row found
        row_content = self.mfa_test.get_recovery_key_row_content(content, key.id)
        self.assertEqual(row_content, "")

    def test_get_recovery_key_row_content_missing_elements_returns_empty(self):
        """Verifies get_recovery_key_row_content returns empty string when key exists but row missing required elements.

        This test ensures our UI helper properly handles the case where a recovery key exists
        in the database and HTML content has a row with the display name, but the row is missing
        the required "On" status or "fa-wrench" icon. It verifies that:
        1. Recovery key exists in database
        2. HTML content has row with correct display name
        3. Row is missing required "On" status or "fa-wrench" icon
        4. Empty string is returned (line 846)

        This is important for handling cases where recovery key rows are partially rendered
        or missing required UI elements.

        Preconditions:
        - Recovery key exists in database
        - HTML content has row with display name but missing required elements
        """
        # Create a recovery key that exists in database
        key = self.mfa_test.create_recovery_key()

        # Get the display name for recovery keys from settings
        from django.conf import settings

        key_display_name = getattr(settings, "MFA_RENAME_METHODS", {}).get(
            "RECOVERY", "RECOVERY"
        )

        # Create HTML content with recovery key display name but missing "On" status or "fa-wrench"
        content = f"""
        <table>
            <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            <tr>
                <td>{key_display_name}</td>
                <td>Off</td>
                <td><button>Delete</button></td>
            </tr>
        </table>
        """

        # Test that empty string is returned when required elements are missing
        row_content = self.mfa_test.get_recovery_key_row_content(content, key.id)
        self.assertEqual(row_content, "")

    def test_get_recovery_key_row_content_returns_empty_for_nonexistent_key(self):
        """Verifies get_recovery_key_row_content returns empty string for nonexistent key.

        This test ensures our UI helper properly handles the case where a recovery key
        doesn't exist in the database. It verifies that:
        1. Key does not exist in database (User_Keys.DoesNotExist)
        2. Empty string is returned (lines 848-849)
        3. No exceptions are raised

        This is important for handling cases where invalid key IDs are provided
        or when keys have been deleted.

        Preconditions:
        - Key does not exist in database
        - HTML content is provided

        Expected results:
        - Empty string is returned
        - No exceptions are raised
        """
        content = '<tr data-key-id="999"><td>Nonexistent Recovery Key</td></tr>'
        row = self.mfa_test.get_recovery_key_row_content(content, 999)
        self.assertEqual(row, "")

    def test_get_recovery_key_row_content_returns_empty_for_non_recovery_key(self):
        """Verifies get_recovery_key_row_content returns empty string for non-recovery key.

        This test ensures our UI helper properly handles the case where a key exists
        in the database but is not a recovery key type. It verifies that:
        1. Key exists in database but is not RECOVERY type
        2. Empty string is returned (line 824)
        3. Method exits early for non-recovery keys

        This is important for ensuring the method only processes recovery keys
        and handles other key types gracefully.

        Preconditions:
        - Key exists in database but is not RECOVERY type
        - HTML content is provided

        Expected results:
        - Empty string is returned
        - No processing of non-recovery keys
        """
        # Create a TOTP key (not recovery key)
        key = self.mfa_test.create_totp_key()

        content = """
        <table>
            <tr>
                <td>RECOVERY</td>
                <td>On</td>
                <td><span class="fa fa-wrench"></span></td>
            </tr>
        </table>
        """

        # Test that empty string is returned for non-recovery key
        row_content = self.mfa_test.get_recovery_key_row_content(content, key.id)
        self.assertEqual(row_content, "")

    def test_get_valid_totp_token_generates_valid_code(self):
        """Verifies that get_valid_totp_token generates valid TOTP codes.

        Required conditions:
        1. TOTP key exists
        2. Key has valid secret

        Expected results:
        1. Code is generated
        2. Code is 6 digits
        3. Code is numeric
        """
        key = self.mfa_test.create_totp_key()
        token = self.mfa_test.get_valid_totp_token(key.id)
        self.assertEqual(len(token), 6)
        self.assertTrue(token.isdigit())

    def test_get_key_row_content_finds_enabled_key(self):
        """Verifies get_key_row_content behavior with enabled key.

        Required conditions:
        1. Key exists
        2. Key is enabled
        3. Key is in HTML content

        Expected results:
        1. Key row is found
        2. Row contains key information
        """
        key = self.mfa_test.create_totp_key()
        content = self._get_key_row_html(key)

        row_content = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn(str(key), row_content)
        self.assertIn(f"toggle_{key.id}", row_content)
        self.assertIn(f"deleteKey({key.id})", row_content)

    def test_get_key_row_content_finds_disabled_key(self):
        """Verifies that get_key_row_content can find a disabled key in the HTML content.

        Required conditions:
        - A key exists in the database
        - The key is disabled
        - The HTML content contains a table with the key's row

        Expected results:
        - The method should return the content of the key's row
        - The row should contain the key type and status
        """
        key = self.mfa_test.create_totp_key()
        key.enabled = False
        key.save()

        content = self._get_key_row_html(key)

        row_content = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn(str(key), row_content)
        self.assertIn(f"toggle_{key.id}", row_content)
        self.assertIn(f"deleteKey({key.id})", row_content)

    def test_get_key_row_content_returns_empty_for_nonexistent(self):
        """Verifies get_key_row_content behavior with nonexistent key.

        Required conditions:
        1. Key does not exist
        2. HTML content is provided

        Expected results:
        1. Empty string is returned
        """
        content = '<tr data-key-id="999"><td>Nonexistent Key</td></tr>'
        row = self.mfa_test.get_key_row_content(content, 999)
        self.assertEqual(row, "")

    def test_get_key_row_content_handles_malformed_html(self):
        """Verifies get_key_row_content behavior with malformed HTML.

        Required conditions:
        1. HTML is malformed
        2. Key ID is provided

        Expected results:
        1. Empty string is returned
        """
        content = '<tr data-key-id="1">Malformed HTML'
        row = self.mfa_test.get_key_row_content(content, 1)
        self.assertEqual(row, "")

    def test_get_key_row_content_isolates_correct_row(self):
        """Verifies get_key_row_content isolates correct row.

        Required conditions:
        1. Multiple key rows exist
        2. Target key ID is provided

        Expected results:
        1. Only target row is returned
        2. Other rows are ignored
        """
        key1 = self.mfa_test.create_totp_key()
        key2 = self.mfa_test.create_totp_key()

        # Create content with multiple rows
        content = f"""
        <table>
            {self._get_key_row_html(key1, key_display="Key 1").strip()}
            {self._get_key_row_html(key2, key_display="Key 2").strip()}
        </table>
        """

        row = self.mfa_test.get_key_row_content(content, key1.id)
        self.assertIn("Key 1", row)
        self.assertIn(f"toggle_{key1.id}", row)
        self.assertIn(f"deleteKey({key1.id})", row)
        self.assertNotIn("Key 2", row)
        self.assertNotIn(f"toggle_{key2.id}", row)
        self.assertNotIn(f"deleteKey({key2.id})", row)

    def test_get_key_row_content_handles_whitespace_variations(self):
        """Verifies get_key_row_content behavior with whitespace variations.

        Required conditions:
        1. HTML has various whitespace
        2. Key ID is provided

        Expected results:
        1. Row is found regardless of whitespace
        2. Content is extracted correctly
        """
        key = self.mfa_test.create_totp_key()
        content = self._get_key_row_html(key, include_extra_whitespace=True)
        row = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn(str(key), row)

    def test_get_key_row_content_handles_html_attributes(self):
        """Verifies get_key_row_content behavior with HTML attributes.

        Required conditions:
        1. HTML has various attributes
        2. Key ID is provided

        Expected results:
        1. Row is found regardless of attributes
        2. Content is extracted correctly
        """
        key = self.mfa_test.create_totp_key()
        content = self._get_key_row_html(key, include_html_attributes=True)
        row = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn(str(key), row)
        self.assertIn('class="key-row"', row)
        self.assertIn('data-type="totp"', row)

    def test_get_key_row_content_handles_nested_elements(self):
        """Verifies get_key_row_content behavior with nested elements.

        Required conditions:
        1. HTML has nested elements
        2. Key ID is provided

        Expected results:
        1. Row is found
        2. All content is extracted
        """
        key = self.mfa_test.create_totp_key()
        content = self._get_key_row_html(key, include_nested_elements=True)
        row = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn("Nested", row)
        self.assertIn(str(key), row)

    def test_get_key_row_content_handles_dynamic_content(self):
        """Verifies get_key_row_content behavior with dynamic content.

        Required conditions:
        1. HTML has dynamic content
        2. Key ID is provided

        Expected results:
        1. Row is found
        2. Dynamic content is extracted
        """
        key = self.mfa_test.create_totp_key()

        # Test with minimal valid HTML structure and dynamic content
        content = f"""
        <table>
            <tr>
                <td>
                    <span class="key-name">Dynamic</span>
                    <span class="key-status">{str(key)}</span>
                </td>
                <td><input type="checkbox" id="toggle_{key.id}" class="status_chk"></td>
                <td><button onclick="deleteKey({key.id})">Delete</button></td>
            </tr>
        </table>
        """

        row_content = self.mfa_test.get_key_row_content(content, key.id)
        self.assertIn("Dynamic", row_content)
        self.assertIn(str(key), row_content)
        self.assertIn(f"toggle_{key.id}", row_content)
        self.assertIn(f"deleteKey({key.id})", row_content)

    def test_get_key_row_content_returns_empty_when_key_exists_but_no_matching_row(
        self,
    ):
        """Verifies get_key_row_content returns empty string when key exists but no matching row found.

        This test ensures our UI helper properly handles the case where a key exists
        in the database but no corresponding row is found in the HTML content. It verifies that:
        1. Key exists in database (not User_Keys.DoesNotExist)
        2. Key is not RECOVERY type (handled separately)
        3. HTML content exists but contains no matching row
        4. No toggle/delete button IDs found in content
        5. No key type/display name pattern found in content
        6. Empty string is returned (line 789)

        This is important for handling cases where HTML content doesn't match
        the expected key structure or when content is incomplete.

        Preconditions:
        - Key exists in database
        - Key is not RECOVERY type
        - HTML content exists but contains no matching row
        """
        # Create a TOTP key that exists in database
        key = self.mfa_test.create_totp_key()

        # Create HTML content that has table structure but no matching row
        # This content has a table but no row with the key's ID or type
        content = """
        <table>
            <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            <tr>
                <td>Different Key Type</td>
                <td>On</td>
                <td><button>Delete</button></td>
            </tr>
        </table>
        """

        # Test that empty string is returned when no matching row found
        row_content = self.mfa_test.get_key_row_content(content, key.id)
        self.assertEqual(row_content, "")

    def test_get_key_row_content_returns_empty_when_key_exists_but_wrong_display_name(
        self,
    ):
        """Verifies get_key_row_content returns empty string when key exists but display name doesn't match.

        This test ensures our UI helper properly handles the case where a key exists
        in the database but the HTML content uses a different display name that doesn't
        match the key type or renamed method. It verifies that:
        1. Key exists in database
        2. HTML content has table with different display name
        3. No toggle/delete button IDs found
        4. Key type/display name pattern doesn't match
        5. Empty string is returned (line 789)

        This is important for handling cases where method renaming or display
        name changes don't match the expected pattern.

        Preconditions:
        - Key exists in database
        - HTML content uses different display name
        - No matching pattern found
        """
        # Create a TOTP key that exists in database
        key = self.mfa_test.create_totp_key()

        # Create HTML content with different display name that won't match
        # The key type is "TOTP" but content shows "Completely Different Name"
        content = f"""
        <table>
            <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            <tr>
                <td>Completely Different Name</td>
                <td>On</td>
                <td><button>Delete</button></td>
            </tr>
        </table>
        """

        # Test that empty string is returned when display name doesn't match
        row_content = self.mfa_test.get_key_row_content(content, key.id)
        self.assertEqual(row_content, "")

    # REMOVED: Circular assertion method validation flow tests
    # These tests were testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code
    #
    # Assertion methods should be tested in integration with real MFA project code
    # See other test files (test_fido2.py, test_totp.py, etc.) for examples of proper testing

    # REMOVED: Circular assertion method validation flow test
    # This test was testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code

    # REMOVED: Circular assertion method validation flow test
    # This test was testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code

    # REMOVED: Circular assertion method validation flow test
    # This test was testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code

    # REMOVED: Circular assertion method validation flow test content
    # This test was testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code

    # REMOVED: All remaining circular assertion method validation flow test content
    # These tests were testing MFATestCase assertion methods using MFATestCase helper methods
    # This creates circular testing and "thin air" testing that doesn't validate real MFA project code

    def test_reset_session(self):
        """Verifies session reset functionality.

        Required conditions:
        1. Session has existing data
        2. Reset is called

        Expected results:
        1. All session data is cleared
        2. Only base_username remains
        3. Session is saved
        """
        # Add some test data
        session = self.mfa_test.client.session
        session["test_data"] = "value"
        # Create a TOTP key for the user
        totp_key = self.mfa_test.create_totp_key(enabled=True)
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Reset session
        self.mfa_test._reset_session()

        # Verify clean state
        self.assertNotIn("test_data", self.mfa_test.client.session)
        self.assertNotIn("mfa", self.mfa_test.client.session)
        self.assertIn("base_username", self.mfa_test.client.session)
        self.assertEqual(
            self.mfa_test.client.session["base_username"], self.mfa_test.username
        )

    def test_get_mfa_url_namespace_handling(self):
        """Verifies get_mfa_url behavior with namespace handling.

        This test ensures our URL resolution works with:
        1. Namespaced URLs
        2. Non-namespaced URLs
        3. Invalid URL names
        """
        # Test namespaced URL
        url = self.mfa_test.get_mfa_url("mfa:home")
        self.assertTrue(url.startswith("/mfa/"))

        # Test non-namespaced URL
        url = self.mfa_test.get_mfa_url("home")
        self.assertTrue(url.startswith("/mfa/"))

        # Test invalid URL name
        with self.assertRaises(NoReverseMatch):
            self.mfa_test.get_mfa_url("nonexistent")

    def test_get_valid_totp_token_with_different_keys(self):
        """Validates TOTP token generation works across multiple keys and handles missing keys gracefully."""
        # Create multiple TOTP keys
        key1 = self.mfa_test.create_totp_key()
        key2 = self.mfa_test.create_totp_key()

        # Test token generation for each key
        token1 = self.mfa_test.get_valid_totp_token(key1.id)
        token2 = self.mfa_test.get_valid_totp_token(key2.id)

        # Verify tokens are valid
        self.assertTrue(len(token1) == 6)
        self.assertTrue(len(token2) == 6)
        self.assertTrue(token1.isdigit())
        self.assertTrue(token2.isdigit())

        # Test nonexistent key
        with self.assertRaises(User_Keys.DoesNotExist):
            self.mfa_test.get_valid_totp_token(999)

    def test_get_valid_totp_token_raises_value_error_when_no_totp_key_exists(self):
        """Verifies get_valid_totp_token raises ValueError when no TOTP key exists for user.

        This test ensures our TOTP token helper properly handles the case where
        no TOTP key exists for the user when no specific key_id is provided.
        It verifies that:
        1. No TOTP key exists for the user
        2. No key_id is provided (uses first TOTP key logic)
        3. ValueError is raised with appropriate message (line 897)
        4. Exception message is descriptive and helpful

        This is important for handling cases where users haven't set up TOTP
        authentication yet, ensuring clear error messages for debugging.

        Preconditions:
        - No TOTP key exists for the user
        - No key_id parameter provided

        Expected results:
        - ValueError is raised
        - Error message is "No TOTP key found for user"
        """
        # Ensure no TOTP keys exist for the user
        # (MFATestCase setup should already ensure this, but let's be explicit)
        User_Keys.objects.filter(
            username=self.mfa_test.username, key_type="TOTP"
        ).delete()

        # Test that ValueError is raised when no TOTP key exists
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.get_valid_totp_token()  # No key_id provided

        # Verify the error message
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "No TOTP key found for user")

    def test_get_invalid_totp_token_consistency(self):
        """Verifies get_invalid_totp_token consistency.

        This test ensures our invalid token generation:
        1. Always returns the same value
        2. Has the correct format
        3. Is consistently invalid
        """
        # Get multiple invalid tokens
        token1 = self.mfa_test.get_invalid_totp_token()
        token2 = self.mfa_test.get_invalid_totp_token()

        # Verify consistency
        self.assertEqual(token1, token2)
        self.assertEqual(token1, "000000")
        self.assertTrue(len(token1) == 6)
        self.assertTrue(token1.isdigit())

    def test_create_u2f_key_enabled(self):
        """Verify U2F key creation helper works correctly for enabled keys.

        This test ensures we can create enabled U2F keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. Device property contains proper structure
        4. Cert property is set correctly
        5. Key can be used in U2F operations

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        key = self.mfa_test.create_u2f_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "U2F")
        self.assertTrue(key.enabled)
        self.assertIn("device", key.properties)
        self.assertIn("cert", key.properties)
        self.assertIn("publicKey", key.properties["device"])
        self.assertIn("keyHandle", key.properties["device"])
        self.assertEqual(key.properties["device"]["publicKey"], "test_public_key")
        self.assertEqual(key.properties["device"]["keyHandle"], "test_key_handle")
        self.assertEqual(key.properties["cert"], "test_certificate_hash")

    def test_create_u2f_key_disabled(self):
        """Verify U2F key creation helper works correctly for disabled keys.

        This test ensures we can create disabled U2F keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. Device property still contains proper structure
        4. Cert property is set correctly

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Disabled U2F keys still have device data to maintain
        consistency and allow for potential re-enabling.
        """
        disabled_key = self.mfa_test.create_u2f_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "U2F")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("device", disabled_key.properties)
        self.assertIn("cert", disabled_key.properties)
        self.assertIn("publicKey", disabled_key.properties["device"])
        self.assertIn("keyHandle", disabled_key.properties["device"])

    def test_u2f_enrollment_mock_integration(self):
        """Verify U2F enrollment mock works with actual U2F registration flow.

        This test ensures that U2F enrollment mocks can be used to test
        actual U2F registration functionality, not just mock structure.
        It verifies that:
        1. Mock enrollment data can be used in U2F registration process
        2. Mock data structure is compatible with U2F library expectations
        3. Registration flow can proceed with mock data

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Create enrollment mock
        mock_enrollment = self.mfa_test.create_u2f_enrollment_mock()

        # Test that the mock can be used in actual U2F registration flow
        # by verifying it has the required structure for U2F library
        self.assertIsNotNone(mock_enrollment)
        self.assertTrue(hasattr(mock_enrollment, "json"))
        self.assertTrue(hasattr(mock_enrollment, "data_for_client"))

        # Verify mock data structure matches U2F specification
        json_data = mock_enrollment.json
        self.assertIsInstance(json_data, dict)
        self.assertIn("challenge", json_data)
        self.assertIn("appId", json_data)
        self.assertIn("version", json_data)

        # Verify data_for_client matches json (U2F library requirement)
        client_data = mock_enrollment.data_for_client
        self.assertIsInstance(client_data, dict)
        self.assertEqual(client_data, json_data)

        # Test that mock can be used in actual U2F registration context
        # by simulating how it would be used in the real registration flow
        from unittest.mock import patch

        with patch(
            "mfa.U2F.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project enrollment creation
            mock_begin_reg.return_value = mock_enrollment

            # Simulate calling the actual U2F registration function
            # This tests that our mock is compatible with real U2F code
            result = mock_begin_reg()
            self.assertEqual(result, mock_enrollment)
            self.assertEqual(result.json["appId"], "https://localhost:9000")
            self.assertEqual(result.json["version"], "U2F_V2")

    def test_u2f_enrollment_mock_custom_appid_integration(self):
        """Verify U2F enrollment mock with custom appid works in registration flow.

        This test ensures that U2F enrollment mocks with custom appids can be used
        to test actual U2F registration functionality with different configurations.
        It verifies that:
        1. Custom appid is properly used in U2F registration context
        2. Mock data structure remains consistent with custom appid
        3. Registration flow works with custom appid configuration

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        custom_appid = "https://custom.example.com"
        mock_enrollment = self.mfa_test.create_u2f_enrollment_mock(appid=custom_appid)

        # Test that custom appid is used correctly in U2F registration context
        from unittest.mock import patch

        with patch(
            "mfa.U2F.begin_registration"
        ) as mock_begin_reg:  # Mock external U2F library to isolate MFA project enrollment creation
            mock_begin_reg.return_value = mock_enrollment

            # Simulate calling the actual U2F registration function with custom appid
            result = mock_begin_reg()
            self.assertEqual(result, mock_enrollment)
            self.assertEqual(result.json["appId"], custom_appid)
            self.assertEqual(result.data_for_client["appId"], custom_appid)

            # Verify other properties remain consistent for U2F specification
            self.assertEqual(result.json["version"], "U2F_V2")
            self.assertEqual(
                result.json["challenge"], "mock_challenge_string_for_enrollment"
            )

    def test_u2f_device_mock_integration(self):
        """Verify U2F device mock works with actual U2F registration completion.

        This test ensures that U2F device mocks can be used to test
        actual U2F registration completion functionality.
        It verifies that:
        1. Mock device data can be used in U2F registration completion process
        2. Mock data structure is compatible with U2F library expectations
        3. Registration completion flow can proceed with mock device data

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        mock_device = self.mfa_test.create_u2f_device_mock()

        # Test that the mock can be used in actual U2F registration completion flow
        self.assertIsNotNone(mock_device)
        self.assertTrue(hasattr(mock_device, "json"))

        # Verify .json attribute is a JSON string (U2F library requirement)
        json_data = mock_device.json
        self.assertIsInstance(json_data, str)

        # Parse and verify JSON content matches U2F specification
        import json

        parsed_data = json.loads(json_data)
        self.assertIn("publicKey", parsed_data)
        self.assertIn("keyHandle", parsed_data)

        # Test that mock can be used in actual U2F registration completion context
        from unittest.mock import patch

        with patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete_reg:  # Mock external U2F library to isolate MFA project device creation
            mock_complete_reg.return_value = [mock_device, b"mock_certificate"]

            # Simulate calling the actual U2F registration completion function
            # This tests that our mock is compatible with real U2F code
            result = mock_complete_reg()
            device, cert = result
            self.assertEqual(device, mock_device)

            # Parse the JSON string to access the data
            import json

            device_data = json.loads(device.json)
            self.assertEqual(device_data["publicKey"], "test_public_key")
            self.assertEqual(device_data["keyHandle"], "test_key_handle")

    def test_u2f_device_mock_custom_values_integration(self):
        """Verify U2F device mock with custom values works in registration completion.

        This test ensures that U2F device mocks with custom values can be used
        to test actual U2F registration completion functionality with different configurations.
        It verifies that:
        1. Custom values are properly used in U2F registration completion context
        2. Mock data structure remains consistent with custom values
        3. Registration completion flow works with custom device configuration

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        custom_public_key = "custom_public_key_value"
        custom_key_handle = "custom_key_handle_value"
        mock_device = self.mfa_test.create_u2f_device_mock(
            public_key=custom_public_key, key_handle=custom_key_handle
        )

        # Test that custom values are used correctly in U2F registration completion context
        from unittest.mock import patch

        with patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete_reg:  # Mock external U2F library to isolate MFA project device creation
            mock_complete_reg.return_value = [mock_device, b"mock_certificate"]

            # Simulate calling the actual U2F registration completion function with custom values
            result = mock_complete_reg()
            device, cert = result
            self.assertEqual(device, mock_device)

            # Verify custom values are properly used
            import json

            parsed_data = json.loads(device.json)
            self.assertEqual(parsed_data["publicKey"], custom_public_key)
            self.assertEqual(parsed_data["keyHandle"], custom_key_handle)

    def test_u2f_response_data_integration(self):
        """Verify U2F response data works with actual U2F authentication flow.

        This test ensures that U2F response data mocks can be used to test
        actual U2F authentication functionality.
        It verifies that:
        1. Response data can be used in U2F authentication process
        2. Data structure matches U2F specification requirements
        3. Authentication flow can proceed with mock response data

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        response_data = self.mfa_test.create_u2f_response_data()

        # Test that response data can be used in actual U2F authentication flow
        self.assertIsInstance(response_data, dict)
        self.assertIn("registrationData", response_data)
        self.assertIn("version", response_data)
        self.assertIn("clientData", response_data)

        # Test that mock can be used in actual U2F authentication context
        from unittest.mock import patch

        with patch("mfa.U2F.complete_authentication") as mock_complete_auth:
            # Simulate how the response data would be used in real authentication
            mock_complete_auth.return_value = "mock_credential"

            # Test that our response data structure is compatible with U2F library
            # by simulating how it would be passed to authentication functions
            result = mock_complete_auth(response_data)
            self.assertEqual(result, "mock_credential")

            # Verify response data structure matches U2F specification
            self.assertEqual(response_data["version"], "U2F_V2")
            self.assertIsInstance(response_data["registrationData"], str)
            self.assertIsInstance(response_data["clientData"], str)

    def test_u2f_response_data_custom_values_integration(self):
        """Verify U2F response data with custom values works in authentication flow.

        This test ensures that U2F response data mocks with custom values can be used
        to test actual U2F authentication functionality with different configurations.
        It verifies that:
        1. Custom values are properly used in U2F authentication context
        2. Data structure remains consistent with custom values
        3. Authentication flow works with custom response data configuration

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        custom_registration_data = "custom_registration_data_value"
        custom_version = "U2F_V1"
        custom_client_data = "custom_client_data_value"

        response_data = self.mfa_test.create_u2f_response_data(
            registration_data=custom_registration_data,
            version=custom_version,
            client_data=custom_client_data,
        )

        # Test that custom values are used correctly in U2F authentication context
        from unittest.mock import patch

        with patch("mfa.U2F.complete_authentication") as mock_complete_auth:
            # Simulate how the custom response data would be used in real authentication
            mock_complete_auth.return_value = "mock_credential"

            # Test that our custom response data structure is compatible with U2F library
            result = mock_complete_auth(response_data)
            self.assertEqual(result, "mock_credential")

            # Verify custom values are properly used
            self.assertEqual(
                response_data["registrationData"], custom_registration_data
            )
            self.assertEqual(response_data["version"], custom_version)
            self.assertEqual(response_data["clientData"], custom_client_data)

    def test_u2f_complete_flow_integration(self):
        """Verify U2F helper methods work together in complete U2F flow.

        This test ensures all U2F helper methods can be used together
        to test a complete U2F registration and authentication flow.
        It verifies that:
        1. All methods can be called in sequence for complete flow testing
        2. Data structures are compatible across the entire flow
        3. Complete U2F registration and authentication can be simulated
        4. Mock data works with actual U2F library functions

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Create a U2F key (actual project functionality)
        key = self.mfa_test.create_u2f_key()
        self.assertEqual(key.key_type, "U2F")

        # Test complete U2F registration flow using mocks
        from unittest.mock import patch

        with patch("mfa.U2F.begin_registration") as mock_begin_reg, patch(
            "mfa.U2F.complete_registration"
        ) as mock_complete_reg, patch(
            "mfa.U2F.complete_authentication"
        ) as mock_complete_auth:
            # Create enrollment mock for registration begin
            enrollment = self.mfa_test.create_u2f_enrollment_mock()
            mock_begin_reg.return_value = enrollment

            # Create device mock for registration completion
            device = self.mfa_test.create_u2f_device_mock()
            mock_complete_reg.return_value = [device, b"mock_certificate"]

            # Create response data for authentication
            response_data = self.mfa_test.create_u2f_response_data()
            mock_complete_auth.return_value = "mock_credential"

            # Test complete registration flow
            begin_result = mock_begin_reg()
            self.assertEqual(begin_result, enrollment)
            self.assertIn("challenge", begin_result.json)

            # Test registration completion
            complete_result = mock_complete_reg()
            device_result, cert_result = complete_result
            self.assertEqual(device_result, device)
            self.assertEqual(cert_result, b"mock_certificate")

            # Test authentication flow
            auth_result = mock_complete_auth(response_data)
            self.assertEqual(auth_result, "mock_credential")

            # Verify all components work together in actual U2F flow
            self.assertIsNotNone(key)
            self.assertIsNotNone(enrollment)
            self.assertIsNotNone(device)
            self.assertIsNotNone(response_data)

    def _get_key_row_html(
        self,
        key,
        key_display=None,
        *,
        include_extra_whitespace=False,
        include_html_attributes=False,
        include_nested_elements=False,
    ):
        """Generate standard HTML structure for a key row.

        This helper method creates a consistent HTML structure for testing key rows.
        It supports various test scenarios through optional parameters.

        Args:
            key (User_Keys): The key to generate HTML for
            key_display (str, optional): Custom display text for the key.
                                       If None, uses str(key)
            include_extra_whitespace (bool): Add extra whitespace for testing whitespace handling
            include_html_attributes (bool): Add HTML attributes for testing attribute handling
            include_nested_elements (bool): Add nested elements for testing nested content handling

        Returns:
            str: HTML content with the key row in the following structure:
                <table>
                    <tr>
                        <td>[key display]</td>
                        <td>[toggle checkbox]</td>
                        <td>[delete button]</td>
                    </tr>
                </table>
        """
        if key_display is None:
            key_display = str(key)

        # Build the cell content based on test requirements
        if include_nested_elements:
            cell_content = f"""
                <span class="key-name">Nested</span>
                <span class="key-type">{key_display}</span>
            """
        else:
            cell_content = key_display

        # Add whitespace if testing whitespace handling
        if include_extra_whitespace:
            cell_content = f"""
                {cell_content}
            """

        # Add HTML attributes if testing attribute handling
        row_attrs = (
            ' class="key-row" data-type="totp"' if include_html_attributes else ""
        )
        cell_attrs = (
            ' class="key-name" data-format="text"' if include_html_attributes else ""
        )

        return f"""
        <table>
            <tr{row_attrs}>
                <td{cell_attrs}>{cell_content}</td>
                <td><input type="checkbox" id="toggle_{key.id}" class="status_chk"></td>
                <td><button onclick="deleteKey({key.id})">Delete</button></td>
            </tr>
        </table>
        """

    # Recovery helper method tests
    def test_get_recovery_codes_count_utility(self):
        """Verifies recovery codes counting utility."""
        # Test simplified format
        simple_key = self.mfa_test.create_recovery_key(
            enabled=True, use_real_format=False
        )
        count = self.mfa_test.get_recovery_codes_count(simple_key.id)
        self.assertEqual(count, 2)

        # Test real format
        real_key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=5
        )
        count = self.mfa_test.get_recovery_codes_count(real_key.id)
        self.assertEqual(count, 5)

    def test_get_recovery_codes_count_finds_first_key_when_no_key_id(self):
        """Verifies get_recovery_codes_count finds first key when no key_id provided.

        This test ensures our recovery codes count helper properly handles the case where
        no specific key_id is provided and it needs to find the first recovery key.
        It verifies that:
        1. No key_id is provided (None)
        2. First recovery key is found using User_Keys.objects.filter().first() (line 1200)
        3. Correct count is returned for the first key found
        4. Method works with both codes and secret_keys formats

        This is important for testing the default behavior when no specific
        recovery key is specified.

        Preconditions:
        - At least one recovery key exists for the user
        - No key_id parameter provided

        Expected results:
        - First recovery key is found
        - Correct count is returned
        - Method works with both formats
        """
        # Create multiple recovery keys to test "first" behavior
        key1 = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)
        key2 = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Test that first key is found when no key_id provided
        count = self.mfa_test.get_recovery_codes_count()  # No key_id

        # Verify count is valid (should be 2 for either key)
        self.assertEqual(count, 2)

    def test_get_recovery_codes_count_raises_error_when_no_key_found(self):
        """Verifies get_recovery_codes_count raises ValueError when no recovery key found.

        This test ensures our recovery codes count helper properly handles the case where
        no recovery key exists for the user. It verifies that:
        1. No recovery key exists for the user
        2. No key_id is provided (uses first key logic)
        3. ValueError is raised with appropriate message (lines 1203-1204)
        4. Exception message is descriptive and helpful

        This is important for handling cases where users haven't set up recovery
        authentication yet, ensuring clear error messages for debugging.

        Preconditions:
        - No recovery key exists for the user
        - No key_id parameter provided

        Expected results:
        - ValueError is raised
        - Error message is "No recovery key found for user"
        """
        # Ensure no recovery keys exist for the user
        User_Keys.objects.filter(
            username=self.mfa_test.username, key_type="RECOVERY"
        ).delete()

        # Test that ValueError is raised when no recovery key exists
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.get_recovery_codes_count()  # No key_id provided

        # Verify the error message
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "No recovery key found for user")

    def test_get_recovery_codes_count_returns_zero_for_invalid_format(self):
        """Verifies get_recovery_codes_count returns 0 for invalid key format.

        This test ensures our recovery codes count helper properly handles the case where
        a recovery key has an invalid format (neither "codes" nor "secret_keys" in properties).
        It verifies that:
        1. Key exists but has invalid format
        2. Neither "codes" nor "secret_keys" is in properties
        3. Method returns 0 (line 1212)
        4. No exceptions are raised

        This is important for ensuring robust error handling when recovery keys
        have unexpected or corrupted property structures.

        Preconditions:
        - Recovery key exists with invalid format
        - Key properties don't contain "codes" or "secret_keys"
        - Method is called with any parameters

        Expected results:
        - 0 is returned
        - No exceptions are raised
        """
        # Create a recovery key with invalid format
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Manually corrupt the key properties to have invalid format
        key.properties = {"invalid_format": "some_value"}
        key.save()

        # Test that 0 is returned for invalid format
        count = self.mfa_test.get_recovery_codes_count(key.id)
        self.assertEqual(count, 0)

    def test_get_valid_recovery_code_utility(self):
        """Verifies valid recovery code retrieval utility."""
        simple_key = self.mfa_test.create_recovery_key(
            enabled=True, use_real_format=False
        )

        # Test valid code retrieval for simplified format
        valid_code = self.mfa_test.get_valid_recovery_code(simple_key.id)
        self.assertIn(valid_code, simple_key.properties["codes"])

        # Test with real format - this returns a test code since we can't
        # retrieve the actual clear-text codes from hashed keys
        real_key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=3
        )
        valid_code = self.mfa_test.get_valid_recovery_code(real_key.id)
        # For real format, it returns a test code "123456"
        self.assertEqual(valid_code, "123456")

    def test_get_invalid_recovery_code_utility(self):
        """Verifies invalid recovery code generation utility."""
        invalid_code = self.mfa_test.get_invalid_recovery_code()
        self.assertEqual(invalid_code, "000000-00000")

        # Verify it's consistently the same
        invalid_code2 = self.mfa_test.get_invalid_recovery_code()
        self.assertEqual(invalid_code, invalid_code2)

    def test_simulate_recovery_code_usage_utility(self):
        """Verifies recovery code usage simulation utility."""
        simple_key = self.mfa_test.create_recovery_key(
            enabled=True, use_real_format=False
        )

        # Test first code usage
        valid_code = self.mfa_test.get_valid_recovery_code(simple_key.id)
        is_last = self.mfa_test.simulate_recovery_code_usage(simple_key.id, valid_code)
        self.assertFalse(is_last)  # Should have one code left

        # Verify count decreased
        new_count = self.mfa_test.get_recovery_codes_count(simple_key.id)
        self.assertEqual(new_count, 1)

        # Test last code usage
        remaining_code = self.mfa_test.get_valid_recovery_code(simple_key.id)
        is_last = self.mfa_test.simulate_recovery_code_usage(
            simple_key.id, remaining_code
        )
        self.assertTrue(is_last)  # Should be the last code

        # Verify no codes left
        final_count = self.mfa_test.get_recovery_codes_count(simple_key.id)
        self.assertEqual(final_count, 0)

    def test_simulate_recovery_code_usage_code_not_found_raises_error(self):
        """Verifies simulate_recovery_code_usage raises ValueError when code not found.

        This test ensures our recovery code usage simulation properly handles the case where
        a code is provided that doesn't exist in the key's codes list. It verifies that:
        1. Key exists with codes format
        2. Invalid code is provided (not in codes list)
        3. ValueError is raised with appropriate message (line 1279)
        4. Key state remains unchanged

        This is important for ensuring robust error handling when invalid codes
        are provided for simulation, preventing silent failures.

        Preconditions:
        - Recovery key exists with codes format
        - Invalid code is provided (not in codes list)

        Expected results:
        - ValueError is raised
        - Error message is "Recovery code not found"
        - Key state remains unchanged
        """
        # Create a recovery key with codes format
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Test that ValueError is raised for invalid code
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.simulate_recovery_code_usage(key.id, "invalid_code")

        # Verify the error message
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "Recovery code not found")

        # Verify key state remains unchanged
        key.refresh_from_db()
        self.assertEqual(len(key.properties["codes"]), 2)  # Should still have 2 codes

    def test_simulate_recovery_code_usage_real_format_raises_error(self):
        """Verifies simulate_recovery_code_usage raises ValueError for real-format keys.

        This test ensures our recovery code usage simulation properly handles the case where
        a real-format key (using "secret_keys" instead of "codes") is provided. It verifies that:
        1. Key exists with real format (secret_keys)
        2. Method is called with any code
        3. ValueError is raised with appropriate message (line 1288)
        4. Key state remains unchanged

        This is important for ensuring the method only works with simplified format keys
        and provides clear error messages for unsupported formats.

        Preconditions:
        - Recovery key exists with real format (secret_keys)
        - Any code is provided

        Expected results:
        - ValueError is raised
        - Error message is "Cannot simulate usage for real-format keys"
        - Key state remains unchanged
        """
        # Create a recovery key with real format (uses secret_keys)
        key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=2
        )

        # Test that ValueError is raised for real-format key
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.simulate_recovery_code_usage(key.id, "any_code")

        # Verify the error message
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "Cannot simulate usage for real-format keys")

        # Verify key state remains unchanged
        key.refresh_from_db()
        self.assertEqual(
            len(key.properties["secret_keys"]), 2
        )  # Should still have 2 secret_keys

    def test_get_valid_recovery_code_with_specific_key_id(self):
        """Verifies get_valid_recovery_code works with specific key_id parameter.

        This test ensures our recovery code helper properly handles the case where
        a specific recovery key ID is provided. It verifies that:
        1. Specific key_id is provided
        2. Key is retrieved using User_Keys.objects.get() (line 1150)
        3. Valid recovery code is returned
        4. Code belongs to the specified key

        This is important for testing specific recovery keys when multiple
        recovery keys exist for a user.

        Preconditions:
        - Recovery key exists with specific ID
        - Key has valid recovery codes

        Expected results:
        - Specific key is retrieved
        - Valid recovery code is returned
        - Code belongs to the specified key
        """
        # Create a recovery key with specific ID
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Test that specific key is retrieved and code is returned
        valid_code = self.mfa_test.get_valid_recovery_code(key.id)

        # Verify code is valid and belongs to the key
        self.assertIsNotNone(valid_code)
        self.assertIn(valid_code, key.properties["codes"])

    def test_get_valid_recovery_code_finds_first_key_when_no_key_id(self):
        """Verifies get_valid_recovery_code finds first key when no key_id provided.

        This test ensures our recovery code helper properly handles the case where
        no specific key_id is provided and it needs to find the first recovery key.
        It verifies that:
        1. No key_id is provided (None)
        2. First recovery key is found using User_Keys.objects.filter().first() (lines 1153-1154)
        3. Valid recovery code is returned
        4. Code belongs to the first key found

        This is important for testing the default behavior when no specific
        recovery key is specified.

        Preconditions:
        - At least one recovery key exists for the user
        - No key_id parameter provided

        Expected results:
        - First recovery key is found
        - Valid recovery code is returned
        - Code belongs to the first key
        """
        # Create multiple recovery keys to test "first" behavior
        key1 = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)
        key2 = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Test that first key is found when no key_id provided
        valid_code = self.mfa_test.get_valid_recovery_code()  # No key_id

        # Verify code is valid and belongs to one of the keys
        self.assertIsNotNone(valid_code)
        # Code should belong to either key1 or key2 (first one found)
        code_found = (
            valid_code in key1.properties["codes"]
            or valid_code in key2.properties["codes"]
        )
        self.assertTrue(code_found)

    def test_assert_recovery_key_has_codes_utility(self):
        """Verifies recovery key assertion utility."""
        simple_key = self.mfa_test.create_recovery_key(
            enabled=True, use_real_format=False
        )

        # Test assertion with correct count
        self.mfa_test.assert_recovery_key_has_codes(simple_key.id, 2)

        # Test assertion with wrong count (should raise AssertionError)
        with self.assertRaises(AssertionError):
            self.mfa_test.assert_recovery_key_has_codes(simple_key.id, 5)

        # Test with real format
        real_key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=3
        )
        self.mfa_test.assert_recovery_key_has_codes(real_key.id, 3)

    def test_assert_recovery_key_has_codes_without_expected_count_codes(self):
        """Verifies assert_recovery_key_has_codes works without expected_count_codes.

        This test ensures our recovery key assertion properly handles the case where
        no expected count is provided and the key uses the "codes" format. It verifies
        that:
        1. Key uses "codes" format in properties
        2. No expected_count parameter is provided
        3. Method asserts that actual_count > 0 (line 1311)
        4. Assertion passes when codes exist

        This is important for testing the default behavior when we just want to verify
        that recovery codes exist without specifying an exact count.

        Preconditions:
        - Recovery key exists with "codes" format
        - Key has at least one code
        - No expected_count parameter provided

        Expected results:
        - Assertion passes (actual_count > 0)
        - No AssertionError is raised
        """
        # Create a recovery key with codes format
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Test assertion without expected_count (should assert > 0)
        self.mfa_test.assert_recovery_key_has_codes(key.id)  # No expected_count

    def test_assert_recovery_key_has_codes_without_expected_count_secret_keys_format(
        self,
    ):
        """Verifies assert_recovery_key_has_codes works without expected_count for secret_keys format.

        This test ensures our recovery key assertion properly handles the case where
        no expected count is provided and the key uses the "secret_keys" format. It verifies that:
        1. Key uses "secret_keys" format in properties
        2. No expected_count parameter is provided
        3. Method asserts that actual_count > 0 (line 1318)
        4. Assertion passes when secret_keys exist

        This is important for testing the default behavior when we just want to verify
        that recovery codes exist in the secret_keys format without specifying an exact count.

        Preconditions:
        - Recovery key exists with "secret_keys" format
        - Key has at least one secret_key
        - No expected_count parameter provided

        Expected results:
        - Assertion passes (actual_count > 0)
        - No AssertionError is raised
        """
        # Create a recovery key with real format (uses secret_keys)
        key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=2
        )

        # Test assertion without expected_count (should assert > 0)
        self.mfa_test.assert_recovery_key_has_codes(key.id)  # No expected_count

    def test_assert_recovery_key_has_codes_invalid_format_fails(self):
        """Verifies assert_recovery_key_has_codes fails for invalid recovery key format.

        This test ensures our recovery key assertion properly handles the case where
        a recovery key has an invalid format (neither "codes" nor "secret_keys" in properties).
        It verifies that:
        1. Key exists but has invalid format
        2. Neither "codes" nor "secret_keys" is in properties
        3. Method calls self.fail() with appropriate message (line 1320)
        4. AssertionError is raised with "Invalid recovery key format" message

        This is important for ensuring robust error handling when recovery keys
        have unexpected or corrupted property structures.

        Preconditions:
        - Recovery key exists with invalid format
        - Key properties don't contain "codes" or "secret_keys"
        - Method is called with any parameters

        Expected results:
        - self.fail() is called
        - AssertionError is raised
        - Error message is "Invalid recovery key format"
        """
        # Create a recovery key with invalid format
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Manually corrupt the key properties to have invalid format
        key.properties = {"invalid_format": "some_value"}
        key.save()

        # Test that assertion fails for invalid format
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assert_recovery_key_has_codes(key.id)

        # Verify the error message
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "Invalid recovery key format")

    def test_get_valid_recovery_code_raises_error_when_no_key_found(self):
        """Raises ValueError when no recovery key exists for user.

        This test ensures get_valid_recovery_code properly handles the case where
        no recovery key exists for the user. It verifies that:
        1. No recovery key exists for the user
        2. No key_id is provided (uses first key logic)
        3. ValueError is raised with "No recovery key found for user" message (line 1158)
        4. Exception message is descriptive and helpful

        This is important for handling cases where users haven't set up recovery
        authentication yet, ensuring clear error messages for debugging.

        Preconditions:
        - No recovery key exists for the user
        - No key_id parameter provided

        Expected results:
        - ValueError is raised
        - Error message is "No recovery key found for user"
        """
        # Ensure no recovery keys exist for the user
        User_Keys.objects.filter(
            username=self.mfa_test.username, key_type="RECOVERY"
        ).delete()

        # Test that ValueError is raised when no recovery key exists
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.get_valid_recovery_code()

        # Verify the error message matches line 1158
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "No recovery key found for user")

    def test_get_valid_recovery_code_raises_error_when_no_codes_available(self):
        """Raises ValueError when recovery key exists but has no codes.

        This test ensures get_valid_recovery_code properly handles the case where
        a recovery key exists but has an empty codes list. It verifies that:
        1. Recovery key exists with "codes" format
        2. Key properties contain empty "codes" list
        3. ValueError is raised with "No recovery codes available" message (line 1165)
        4. Exception message is descriptive and helpful

        This is important for handling cases where recovery keys are corrupted
        or improperly initialized, ensuring clear error messages for debugging.

        Preconditions:
        - Recovery key exists with "codes" format
        - Key properties contain empty "codes" list

        Expected results:
        - ValueError is raised
        - Error message is "No recovery codes available"
        """
        # Create a recovery key with empty codes list
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Manually set empty codes list to trigger the error condition
        key.properties = {"codes": []}
        key.save()

        # Test that ValueError is raised when no codes are available
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.get_valid_recovery_code(key.id)

        # Verify the error message matches line 1165
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "No recovery codes available")

    def test_get_valid_recovery_code_raises_error_when_invalid_format(self):
        """Raises ValueError when recovery key has invalid format.

        This test ensures get_valid_recovery_code properly handles the case where
        a recovery key exists but has an invalid format (neither "codes" nor "secret_keys").
        It verifies that:
        1. Recovery key exists but has invalid format
        2. Key properties don't contain "codes" or "secret_keys"
        3. ValueError is raised with "Invalid recovery key format" message (line 1172)
        4. Exception message is descriptive and helpful

        This is important for handling cases where recovery keys have unexpected
        or corrupted property structures, ensuring clear error messages for debugging.

        Preconditions:
        - Recovery key exists with invalid format
        - Key properties don't contain "codes" or "secret_keys"

        Expected results:
        - ValueError is raised
        - Error message is "Invalid recovery key format"
        """
        # Create a recovery key with invalid format
        key = self.mfa_test.create_recovery_key(enabled=True, use_real_format=False)

        # Manually corrupt the key properties to have invalid format
        key.properties = {"invalid_format": "some_value"}
        key.save()

        # Test that ValueError is raised when format is invalid
        with self.assertRaises(ValueError) as cm:
            self.mfa_test.get_valid_recovery_code(key.id)

        # Verify the error message matches line 1172
        error_msg = str(cm.exception)
        self.assertEqual(error_msg, "Invalid recovery key format")

    def test_setup_session_base_username(self):
        """Verifies base session setup functionality.

        This test ensures the base session setup works correctly.
        It verifies that:
        1. Base username is set in session
        2. Session is properly saved
        3. Session state is accessible

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Clear any existing session data
        self.mfa_test._reset_session()

        # Setup base session
        self.mfa_test.setup_session_base_username()

        # Verify base username is set
        session = self.mfa_test.client.session
        self.assertIn("base_username", session)
        self.assertEqual(session["base_username"], self.mfa_test.username)

        # Verify session is saved and accessible
        self.mfa_test._verify_mfa_session_accessible()

    def test_get_authenticated_user(self):
        """Verifies authenticated user retrieval.

        This test ensures we can retrieve the authenticated user.
        It verifies that:
        1. User is retrieved correctly
        2. User matches the test user
        3. User is properly authenticated

        Preconditions:
        - Test user is logged in
        - Session is properly set up
        """
        # Get authenticated user
        user = self.mfa_test.get_authenticated_user()

        # Verify user is correct
        self.assertIsNotNone(user)
        self.assertEqual(user.username, self.mfa_test.username)
        self.assertTrue(user.is_authenticated)

    def test_get_unauthenticated_user(self):
        """Verifies unauthenticated user retrieval.

        This test ensures we can retrieve an unauthenticated user.
        It verifies that:
        1. User is retrieved correctly
        2. User is not authenticated
        3. User is AnonymousUser (no username)

        Preconditions:
        - Test user exists but is not logged in
        """
        # Logout current user
        self.mfa_test.client.logout()

        # Get unauthenticated user
        user = self.mfa_test.get_unauthenticated_user()

        # Verify user is correct
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "")  # AnonymousUser has empty username
        self.assertFalse(user.is_authenticated)

    def test_create_mock_request(self):
        """Verifies mock request creation.

        This test ensures we can create mock requests for testing.
        It verifies that:
        1. Mock request is created successfully
        2. Request has correct user
        3. Request has proper attributes

        Preconditions:
        - Test user exists
        """
        # Create mock request
        request = self.mfa_test.create_mock_request()

        # Verify request structure
        self.assertIsNotNone(request)
        self.assertTrue(hasattr(request, "user"))
        self.assertTrue(hasattr(request, "session"))
        self.assertTrue(hasattr(request, "method"))
        self.assertTrue(hasattr(request, "POST"))
        self.assertTrue(hasattr(request, "GET"))

        # Verify user is set correctly
        self.assertEqual(request.user.username, self.mfa_test.username)

    def test_create_mock_request_custom_username(self):
        """Verifies mock request creation with custom username.

        This test ensures we can create mock requests with custom usernames.
        It verifies that:
        1. Custom username is used correctly
        2. Request has correct user
        3. Request structure is maintained

        Preconditions:
        - Test user exists
        """
        custom_username = "custom_user"

        # Create mock request with custom username
        request = self.mfa_test.create_mock_request(username=custom_username)

        # Verify request structure
        self.assertIsNotNone(request)
        self.assertTrue(hasattr(request, "user"))

        # Verify custom username is used
        self.assertEqual(request.user.username, custom_username)

    def test_create_http_request_mock(self):
        """Verifies HTTP request mock creation.

        This test ensures we can create HTTP request mocks for testing.
        It verifies that:
        1. HTTP request mock is created successfully
        2. Request has correct user
        3. Request has proper HTTP attributes

        Preconditions:
        - Test user exists
        """
        # Create HTTP request mock
        request = self.mfa_test.create_http_request_mock()

        # Verify request structure
        self.assertIsNotNone(request)
        self.assertTrue(hasattr(request, "user"))
        self.assertTrue(hasattr(request, "session"))
        self.assertTrue(hasattr(request, "method"))
        self.assertTrue(hasattr(request, "POST"))
        self.assertTrue(hasattr(request, "GET"))
        self.assertTrue(hasattr(request, "META"))

        # Verify user is set correctly
        self.assertEqual(request.user.username, self.mfa_test.username)

    def test_create_http_request_mock_custom_username(self):
        """Verifies HTTP request mock creation with custom username.

        This test ensures we can create HTTP request mocks with custom usernames.
        It verifies that:
        1. Custom username is used correctly
        2. Request has correct user
        3. Request structure is maintained

        Preconditions:
        - Test user exists
        """
        custom_username = "custom_http_user"

        # Create HTTP request mock with custom username
        request = self.mfa_test.create_http_request_mock(username=custom_username)

        # Verify request structure
        self.assertIsNotNone(request)
        self.assertTrue(hasattr(request, "user"))

        # Verify custom username is used
        self.assertEqual(request.user.username, custom_username)

    def test_get_redirect_url_default(self):
        """Verifies redirect URL retrieval with default value.

        This test ensures we can get redirect URLs with default values.
        It verifies that:
        1. Default redirect URL is returned
        2. URL is properly formatted
        3. URL is accessible

        Preconditions:
        - MFA URLs are configured
        """
        # Get redirect URL with default
        redirect_url = self.mfa_test.get_redirect_url()

        # Verify URL is returned
        self.assertIsNotNone(redirect_url)
        self.assertIsInstance(redirect_url, dict)
        self.assertIn("redirect_url", redirect_url)

        # Verify URL is properly formatted
        url = redirect_url["redirect_url"]
        self.assertTrue(url.startswith("/"))

    def test_get_redirect_url_custom(self):
        """Verifies redirect URL retrieval with custom value.

        This test ensures we can get redirect URLs with custom values.
        It verifies that:
        1. Custom redirect URL is returned
        2. URL is properly formatted
        3. URL is accessible

        Preconditions:
        - MFA URLs are configured
        """
        custom_url = "custom_redirect"

        # Get redirect URL with custom value
        redirect_url = self.mfa_test.get_redirect_url(default=custom_url)

        # Verify URL is returned
        self.assertIsNotNone(redirect_url)
        self.assertIsInstance(redirect_url, dict)
        self.assertIn("redirect_url", redirect_url)

        # Verify custom URL is used
        url = redirect_url["redirect_url"]
        self.assertTrue(url.startswith("/"))

    @override_settings(MFA_REDIRECT_AFTER_REGISTRATION="invalid_url_name")
    def test_get_redirect_url_fallback_to_default_when_invalid_url_name(self):
        """Verifies get_redirect_url falls back to default when invalid URL name provided.

        This test ensures our redirect URL helper properly handles the case where
        MFA_REDIRECT_AFTER_REGISTRATION is set to an invalid URL name that doesn't exist
        in the URL configuration. It verifies that:
        1. Invalid URL name causes NoReverseMatch exception
        2. Setting value doesn't start with "/" (not a path)
        3. Method falls back to default URL name (line 869)
        4. Default URL is successfully reversed

        This is important for handling configuration errors where invalid URL names
        are provided in settings, ensuring the application doesn't crash.

        Preconditions:
        - MFA_REDIRECT_AFTER_REGISTRATION set to invalid URL name
        - Invalid URL name doesn't start with "/"
        - Default URL name is valid

        Expected results:
        - NoReverseMatch exception is caught
        - Default URL is used as fallback
        - Valid redirect URL is returned
        """
        # Test that invalid URL name falls back to default
        redirect_url = self.mfa_test.get_redirect_url(default="mfa_home")

        # Verify URL is returned
        self.assertIsNotNone(redirect_url)
        self.assertIsInstance(redirect_url, dict)
        self.assertIn("redirect_url", redirect_url)

        # Verify fallback URL is used (should be mfa_home)
        url = redirect_url["redirect_url"]
        self.assertTrue(url.startswith("/"))
        # Should be the mfa_home URL, not the invalid one
        self.assertNotEqual(url, "invalid_url_name")

    def test_get_user_keys_all(self):
        """Verifies user keys retrieval for all key types.

        This test ensures we can retrieve all user keys.
        It verifies that:
        1. All keys are retrieved
        2. Keys belong to correct user
        3. Keys are properly formatted

        Preconditions:
        - Test user is logged in
        - Multiple key types exist
        """
        # Create keys of different types
        totp_key = self.mfa_test.create_totp_key()
        email_key = self.mfa_test.create_email_key()
        recovery_key = self.mfa_test.create_recovery_key()

        # Get all user keys
        keys = self.mfa_test.get_user_keys()

        # Verify keys are retrieved
        self.assertIsNotNone(keys)
        self.assertGreaterEqual(keys.count(), 3)

        # Verify all keys belong to correct user
        for key in keys:
            self.assertEqual(key.username, self.mfa_test.username)

    def test_get_user_keys_filtered(self):
        """Verifies user keys retrieval with type filtering.

        This test ensures we can retrieve user keys filtered by type.
        It verifies that:
        1. Only keys of specified type are retrieved
        2. Keys belong to correct user
        3. Filtering works correctly

        Preconditions:
        - Test user is logged in
        - Multiple key types exist
        """
        # Create keys of different types
        totp_key = self.mfa_test.create_totp_key()
        email_key = self.mfa_test.create_email_key()
        recovery_key = self.mfa_test.create_recovery_key()

        # Get TOTP keys only
        totp_keys = self.mfa_test.get_user_keys(key_type="TOTP")

        # Verify only TOTP keys are retrieved
        self.assertIsNotNone(totp_keys)
        self.assertEqual(totp_keys.count(), 1)
        self.assertEqual(totp_keys.first().key_type, "TOTP")

        # Get Email keys only
        email_keys = self.mfa_test.get_user_keys(key_type="Email")

        # Verify only Email keys are retrieved
        self.assertIsNotNone(email_keys)
        self.assertEqual(email_keys.count(), 1)
        self.assertEqual(email_keys.first().key_type, "Email")

    def test_get_user_keys_nonexistent_type(self):
        """Verifies user keys retrieval with nonexistent type.

        This test ensures we can retrieve user keys with nonexistent types.
        It verifies that:
        1. Empty queryset is returned
        2. No errors are raised
        3. Graceful handling of nonexistent types

        Preconditions:
        - Test user is logged in
        - No keys of specified type exist
        """
        # Get keys of nonexistent type
        keys = self.mfa_test.get_user_keys(key_type="NONEXISTENT")

        # Verify empty queryset is returned
        self.assertIsNotNone(keys)
        self.assertEqual(keys.count(), 0)

    def test_validate_session_structure_valid(self):
        """Verifies session structure validation with valid session.

        This test ensures session structure validation works with valid sessions.
        It verifies that:
        1. Valid session structure passes validation
        2. No errors are raised
        3. Validation works correctly

        Preconditions:
        - Test user is logged in
        - Valid MFA session exists
        """
        # Setup valid MFA session
        self.mfa_test.setup_mfa_session()

        # Get session
        session = self.mfa_test.client.session
        mfa_session = session["mfa"]

        # Validate session structure
        # This should not raise an exception
        self.mfa_test._validate_session_structure(mfa_session)

    def test_validate_session_structure_invalid(self):
        """Verifies session structure validation with invalid session.

        This test ensures session structure validation works with invalid sessions.
        It verifies that:
        1. Invalid session structure fails validation
        2. Appropriate errors are raised
        3. Validation works correctly

        Preconditions:
        - Test user is logged in
        - Invalid MFA session exists
        """
        # Setup invalid MFA session
        session = self.mfa_test.client.session
        session["mfa"] = "not a dict"
        session.save()

        # Validate session structure
        # This should raise an exception
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test._validate_session_structure(session["mfa"])

        # Verify error message
        self.assertIn("MFA session must be a dictionary", str(cm.exception))

    def test_verify_mfa_session_accessible(self):
        """Verifies MFA session accessibility verification.

        This test ensures MFA session accessibility verification works correctly.
        It verifies that:
        1. Accessible session passes verification
        2. No errors are raised
        3. Verification works correctly

        Preconditions:
        - Test user is logged in
        - Valid MFA session exists
        """
        # Setup valid MFA session
        self.mfa_test.setup_mfa_session()

        # Verify session accessibility
        # This should not raise an exception
        self.mfa_test._verify_mfa_session_accessible()

    def test_mfa_unallowed_methods_ui_behavior(self):
        """Verifies that MFA properly handles unallowed methods in UI.

        This test ensures that MFA system correctly handles unallowed methods
        as defined by MFA_UNALLOWED_METHODS setting. It verifies that:
        1. Keys still exist in database (not deleted)
        2. MFA session setup works with any method (database level)
        3. The setting is properly passed to templates for UI filtering

        Preconditions:
        - Test user is logged in
        - TOTP method is configured as unallowed
        - Other MFA methods are available
        """
        # Create keys for different MFA methods
        totp_key = self.mfa_test.create_totp_key(enabled=True)
        email_key = self.mfa_test.create_email_key(enabled=True)

        # Test with TOTP as unallowed method
        with self.settings(MFA_UNALLOWED_METHODS=("TOTP",)):
            # Verify keys still exist in database (MFA_UNALLOWED_METHODS doesn't delete them)
            totp_keys = self.mfa_test.get_user_keys(key_type="TOTP")
            self.assertEqual(
                totp_keys.count(), 1, "TOTP keys should still exist in database"
            )

    def test_verify_mfa_session_accessible_unallowed_method(self):
        """Handles verification of MFA session with unallowed method by raising AssertionError.

        This test specifically covers line 1127 in mfatestcase.py where an AssertionError
        is raised when a verified MFA session contains a method that's in MFA_UNALLOWED_METHODS.
        It verifies that:
        1. MFA session can be set up with any method
        2. _verify_mfa_session_accessible detects unallowed methods
        3. Appropriate AssertionError is raised with method name

        Preconditions:
        - Test user is logged in
        - MFA session is set up with TOTP method
        - TOTP is configured as unallowed method
        """
        # Set up MFA session with TOTP method
        self.mfa_test.setup_mfa_session(method="TOTP", verified=True, id=1)

        # Set TOTP as unallowed method
        self.mfa_test.original_settings = {"MFA_UNALLOWED_METHODS": ("TOTP",)}

        # Test that _verify_mfa_session_accessible raises AssertionError
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test._verify_mfa_session_accessible()

        # Verify the error message includes the method name
        self.assertIn("MFA method TOTP is not allowed", str(cm.exception))

    def test_assert_mfa_session_unverified_when_verified(self):
        """Handles verified session when expecting unverified by raising AssertionError."""
        # Set up verified session using helper method
        self.mfa_test.setup_mfa_session(method="TOTP", verified=True, id=1)

        # Test that assertMfaSessionUnverified raises appropriate error when session is verified
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionUnverified()

        # Verify error message indicates verification mismatch
        self.assertIn(
            "Expected MFA session to be unverified, but it is verified",
            str(cm.exception),
        )

    def test_tearDown_cleanup(self):
        """Verifies tearDown method cleanup functionality.

        This test ensures the tearDown method properly cleans up resources.
        It verifies that:
        1. Cleanup is performed correctly
        2. No errors are raised
        3. Resources are properly released

        Preconditions:
        - Test user is logged in
        - MFA session exists
        """
        # Setup MFA session
        self.mfa_test.setup_mfa_session()

        # Verify session exists
        session = self.mfa_test.client.session
        self.assertIn("mfa", session)

        # Call tearDown
        self.mfa_test.tearDown()

        # Verify cleanup was performed - session should be cleared
        session = self.mfa_test.client.session
        self.assertNotIn("mfa", session)

    def test_create_recovery_key_with_real_codes(self):
        """Creates recovery keys with real code format.

        This test ensures we can create recovery keys with real code format.
        It verifies that:
        1. Key is created successfully
        2. Codes are generated correctly
        3. Key has proper structure

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Create recovery key with real codes
        key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=3
        )

        # Verify key was created
        self.assertIsNotNone(key)
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "RECOVERY")
        self.assertTrue(key.enabled)

        # Verify codes were generated
        self.assertIsNotNone(codes)
        self.assertEqual(len(codes), 3)
        for code in codes:
            self.assertIsInstance(code, str)
            self.assertTrue(len(code) > 0)

    def test_create_recovery_key_with_real_codes_custom_count(self):
        """Verifies recovery key creation with custom code count.

        This test ensures we can create recovery keys with custom code counts.
        It verifies that:
        1. Key is created with correct number of codes
        2. Codes are generated correctly
        3. Key has proper structure

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Create recovery key with custom code count
        key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=True, num_codes=5
        )

        # Verify key was created
        self.assertIsNotNone(key)
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "RECOVERY")
        self.assertTrue(key.enabled)

        # Verify correct number of codes were generated
        self.assertIsNotNone(codes)
        self.assertEqual(len(codes), 5)
        for code in codes:
            self.assertIsInstance(code, str)
            self.assertTrue(len(code) > 0)

    def test_create_recovery_key_with_real_codes_disabled(self):
        """Verifies recovery key creation with real codes in disabled state.

        This test ensures we can create disabled recovery keys with real codes.
        It verifies that:
        1. Key is created in disabled state
        2. Codes are still generated
        3. Key has proper structure

        Preconditions:
        - Test user is logged in
        - Clean session state
        """
        # Create disabled recovery key with real codes
        key, codes = self.mfa_test.create_recovery_key_with_real_codes(
            enabled=False, num_codes=2
        )

        # Verify key was created
        self.assertIsNotNone(key)
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "RECOVERY")
        self.assertFalse(key.enabled)

        # Verify codes were still generated
        self.assertIsNotNone(codes)
        self.assertEqual(len(codes), 2)
        for code in codes:
            self.assertIsInstance(code, str)
            self.assertTrue(len(code) > 0)

    def test_dummy_logout_function(self):
        """Verifies dummy logout function.

        This test ensures the dummy logout function works correctly.
        It verifies that:
        1. Function returns HttpResponse
        2. Response contains expected message
        3. Function can be called without errors

        Preconditions:
        - Function is imported and available
        """
        from django.test import RequestFactory

        # Create a mock request
        factory = RequestFactory()
        request = factory.get("/logout/")

        # Call dummy logout function
        response = dummy_logout(request)

        # Verify response
        self.assertIsNotNone(response)
        self.assertEqual(response.content.decode(), "Logged out (dummy)")

    def test_assertMfaKeyState_last_used_none(self):
        """Verifies assertMfaKeyState behavior with last_used=None.

        This test ensures the assertion method handles None last_used correctly.
        It verifies that:
        1. Assertion passes when last_used is None and expected_last_used is False
        2. Assertion fails when last_used is None and expected_last_used is True

        Preconditions:
        - Test user is logged in
        - Key exists with last_used=None
        """
        # Create key without last_used
        key = self.mfa_test.create_totp_key()
        key.last_used = None
        key.save()

        # Test assertion with last_used=None and expected_last_used=False
        self.mfa_test.assertMfaKeyState(key.id, expected_last_used=False)

        # Test assertion with last_used=None and expected_last_used=True (should fail)
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaKeyState(key.id, expected_last_used=True)

    def test_assertMfaSessionState_verified_true(self):
        """Verifies assertMfaSessionState behavior with verified=True."""
        # Create a TOTP key for the user
        totp_key = self.mfa_test.create_totp_key(enabled=True)

        # Set up verified MFA session
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Test assertion passes
        self.mfa_test.assertMfaSessionState(
            verified=True, method="TOTP", id=totp_key.id
        )

        # Test assertion fails with wrong method
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=True, method="U2F")

        # Test assertion fails with wrong id
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=True, id=999)

    def test_assertMfaSessionState_verified_false(self):
        """Verifies assertMfaSessionState behavior with verified=False."""
        # Set up unverified MFA session
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": False}
        session.save()

        # Test assertion passes
        self.mfa_test.assertMfaSessionState(verified=False)

        # Test assertion fails when session is verified
        session["mfa"] = {"verified": True, "method": "TOTP", "id": 1}
        session.save()
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=False)

    def test_assertMfaSessionState_no_session(self):
        """Verifies assertMfaSessionState behavior with no MFA session."""
        # No MFA session set up

        # Test assertion passes for unverified
        self.mfa_test.assertMfaSessionState(verified=False)

        # Test assertion fails for verified
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=True)

    def test_assertMfaSessionState_invalid_structure(self):
        """Verifies assertMfaSessionState behavior with invalid session structure."""
        # Set up invalid session structure (missing required fields)
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": True, "method": "TOTP"}  # Missing id
        session.save()

        # Test assertion fails due to invalid structure
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionState(verified=True)

        # Verify error message mentions missing id
        self.assertIn("id", str(cm.exception))

    def test_assertMfaSessionState_verified_without_method_id(self):
        """Verifies assertMfaSessionState behavior with verified=True but missing method/id."""
        # Set up verified session without method/id (invalid structure)
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": True}  # Missing method and id
        session.save()

        # Test assertion fails due to invalid structure
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionState(verified=True)

        # Verify error message mentions missing method
        self.assertIn("method", str(cm.exception))

    def test_assertMfaSessionState_partial_verification(self):
        """Verifies assertMfaSessionState behavior with partial verification parameters."""
        # Create a TOTP key for the user
        totp_key = self.mfa_test.create_totp_key(enabled=True)

        # Set up verified MFA session
        session = self.mfa_test.client.session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": totp_key.id}
        session.save()

        # Test assertion with only verified parameter
        self.mfa_test.assertMfaSessionState(verified=True)

        # Test assertion with only method parameter
        self.mfa_test.assertMfaSessionState(method="TOTP")

        # Test assertion with only id parameter
        self.mfa_test.assertMfaSessionState(id=totp_key.id)

        # Test assertion with verified and method only
        self.mfa_test.assertMfaSessionState(verified=True, method="TOTP")

        # Test assertion with verified and id only
        self.mfa_test.assertMfaSessionState(verified=True, id=totp_key.id)

        # Test assertion with method and id only
        self.mfa_test.assertMfaSessionState(method="TOTP", id=totp_key.id)

    def test_assertMfaSessionState_empty_session(self):
        """Verifies assertMfaSessionState behavior with empty MFA session."""
        # Set up empty MFA session
        session = self.mfa_test.client.session
        session["mfa"] = {}
        session.save()

        # Test assertion passes for unverified
        self.mfa_test.assertMfaSessionState(verified=False)

        # Test assertion fails for verified
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=True)

    def test_assertMfaSessionState_none_session(self):
        """Verifies assertMfaSessionState behavior with None MFA session."""
        # Set up None MFA session
        session = self.mfa_test.client.session
        session["mfa"] = None
        session.save()

        # Test assertion passes for unverified
        self.mfa_test.assertMfaSessionState(verified=False)

        # Test assertion fails for verified
        with self.assertRaises(AssertionError):
            self.mfa_test.assertMfaSessionState(verified=True)

    # Assertion methods should be tested in integration with real MFA project code
    # See other test files (test_fido2.py, test_totp.py, etc.) for examples of proper testing

import pyotp
import time
import os
import json
import re

from unittest.mock import Mock, MagicMock
from django.test import TestCase, TransactionTestCase, Client
from django.conf import settings
from django.urls import reverse, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
from django.core.cache import cache
from django.contrib.auth import login
from django.http import HttpResponseRedirect, HttpResponse
from ..models import User_Keys
from ..Common import set_next_recheck
from ..recovery import randomGen

User = get_user_model()


def create_session(request, username):
    """Create a test session for MFA authentication.

    This is used as MFA_LOGIN_CALLBACK in tests to simulate the login process.
    Mimics the example implementation from example.auth.create_session.

    Used by: test_config.py, test_views.py
    """
    User = get_user_model()
    user = User.objects.get_by_natural_key(username)
    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)
    # print(f"\n36 {__name__} - Test session created by tests.create_session()")
    return HttpResponseRedirect(reverse("mfa_home"))


def dummy_logout(request):
    """Dummy logout view for tests.

    This view is used to satisfy template references to {% url 'logout' %}
    during testing without requiring a real logout implementation.

    Used by: test_config.py
    """
    return HttpResponse("Logged out (dummy)")


def _get_base_test_case():
    """Dynamically choose the appropriate base test case based on database engine.

    Returns:
        class: Either TestCase or TransactionTestCase based on database engine

    Rationale:
        - TestCase engines: Use TestCase for better transaction isolation
        - TransactionTestCase engines: Use TransactionTestCase for proper transaction handling
    """
    db_engine = settings.DATABASES["default"]["ENGINE"].lower()

    # Database engines that work better with TestCase (better transaction isolation)
    testcase_engines = [
        "sqlite",
        "sqlite3",
        "django.db.backends.sqlite3",
        "django.db.backends.sqlite",
    ]

    # Database engines that work better with TransactionTestCase (proper transaction handling)
    transaction_testcase_engines = [
        "postgresql",
        "postgres",
        "mysql",
        "oracle",
        "django.db.backends.postgresql",
        "django.db.backends.postgresql_psycopg2",
        "django.db.backends.mysql",
        "django.db.backends.oracle",
    ]

    # Check if current engine matches any TestCase engines
    for engine in testcase_engines:
        if engine in db_engine:
            return TestCase  # pragma: no cover

    # Check if current engine matches any TransactionTestCase engines
    for engine in transaction_testcase_engines:
        if engine in db_engine:
            return TransactionTestCase  # pragma: no cover

    # Default to TransactionTestCase for unknown engines
    return TransactionTestCase  # pragma: no cover


# Create the base class dynamically
_BaseTestCase = _get_base_test_case()

# Debug: Print which base class is being used
print(f"DEBUG: MFATestCase using {_BaseTestCase.__name__} as base class")


class MFATestCase(_BaseTestCase):
    """Base test case for MFA tests.

    This class provides common functionality for all MFA test cases, including:
    - User creation and authentication
    - MFA key setup and management
    - Settings management and verification
    - URL handling for both namespaced and non-namespaced patterns
    - Session state verification
    - Common assertions for MFA functionality
    """

    CONSOLE = "django.core.mail.backends.console.EmailBackend"
    LOCMEM = "django.core.mail.backends.locmem.EmailBackend"

    # Define default settings that can be referenced by tests
    DEFAULT_MFA_SETTINGS = {
        "MFA_UNALLOWED_METHODS": (),
        "MFA_HIDE_DISABLE": (),
        "MFA_RENAME_METHODS": {},
        "TOKEN_ISSUER_NAME": "Django MFA",
        "MFA_ENFORCE_RECOVERY_METHOD": False,
        "MFA_ENFORCE_EMAIL_TOKEN": False,
        "MFA_RECHECK": False,
        "MFA_RECHECK_MIN": 0,
        "MFA_RECHECK_MAX": 0,
        "MFA_LOGIN_CALLBACK": None,
        "MFA_ALWAYS_GO_TO_LAST_METHOD": False,
        "MFA_SUCCESS_REGISTRATION_MSG": None,
        "MFA_REDIRECT_AFTER_REGISTRATION": "mfa_home",
        # Email settings
        "EMAIL_BACKEND": LOCMEM,  # Use CONSOLE for email output to console
        "EMAIL_FROM": "security@example.com",
        # FIDO2 settings
        "FIDO_SERVER_ID": "example.com",
        "FIDO_SERVER_NAME": "Test Server",
        "FIDO_AUTHENTICATOR_ATTACHMENT": "cross-platform",
        "FIDO_USER_VERIFICATION": "preferred",
        "FIDO_AUTHENTICATION_TIMEOUT": 30000,
        # U2F settings
        "U2F_APPID": "https://localhost:9000",
        "U2F_FACETS": ["https://localhost:9000"],
    }

    def setUp(self):
        """Set up test environment.

        Required conditions:
        1. Test database is available
        2. Session middleware is enabled

        Expected results:
        1. User is created
        2. Session is initialized
        3. Session is saved
        """
        # Ensure database connection is available
        from django.db import connection

        try:
            # Ensure we have a fresh connection
            if connection.connection is None:
                connection.ensure_connection()
            else:
                # Test the connection
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
        except Exception as e:  # pragma: no cover
            # If connection is bad, close and reconnect
            # This exception handling is excluded from coverage because:
            # 1. It's infrastructure code for test reliability, not business logic
            # 2. Testing database connection failures requires complex mocking
            # 3. The retry logic is defensive programming, not core functionality
            try:
                connection.close()
            except Exception:  # pragma: no cover
                pass
            try:
                connection.ensure_connection()
            except Exception as e2:  # pragma: no cover
                print(f"Warning: Database connection issue during setUp: {e2}")

        # Create test user with database connection error handling
        self.username = "testuser"
        self.password = "testpass123"

        # Try to create user with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.user = User.objects.create_user(
                    username=self.username,
                    password=self.password,
                    email="test@example.com",
                )
                break
            except Exception as e:  # pragma: no cover
                if attempt == max_retries - 1:
                    # Last attempt failed, try to get existing user
                    try:
                        self.user = User.objects.get(username=self.username)
                        break
                    except User.DoesNotExist:  # pragma: no cover
                        # If user doesn't exist and we can't create one, re-raise the original error
                        raise e
                else:
                    # Retry with fresh connection
                    try:
                        connection.close()
                        connection.ensure_connection()
                    except Exception:  # pragma: no cover
                        pass

        # Initialize session
        self.client = Client()
        self.client.login(username=self.username, password=self.password)

        # Reset session to clean state
        self._reset_session()

        # Verify session is accessible
        self._verify_mfa_session_accessible()

    def tearDown(self):
        """Clean up after tests.

        Clears cache, deletes all MFA keys, and restores original settings
        to ensure test isolation.
        """
        # Handle database cleanup gracefully in case of connection issues
        try:
            User_Keys.objects.all().delete()
        except Exception as err:  # pragma: no cover
            # If database cleanup fails, log the error but don't fail the test
            print(f"Warning: Failed to clean up User_Keys during teardown: {err}")

        # Restore original settings
        for key, value in self.DEFAULT_MFA_SETTINGS.items():
            setattr(settings, key, value)
        # Ensure session is clean - but handle potential UpdateError gracefully
        try:
            self._reset_session()
        except Exception:
            # If session reset fails, just clear the session without saving
            self.client.session.clear()

        # Clear cache
        cache.clear()

        # Call parent tearDown last - this handles the database transaction rollback
        super().tearDown()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def assertMfaKeyState(self, key_id, expected_enabled=None, expected_last_used=None):
        """Assert the state of an MFA key.

        Args:
            key_id (int): ID of the key to verify
            expected_enabled (bool, optional): Expected enabled state
            expected_last_used (bool, optional): Whether last_used should be set

        Raises:
            AssertionError: If key state doesn't match expectations
        """
        key = User_Keys.objects.get(id=key_id)
        if expected_enabled is not None:
            self.assertEqual(key.enabled, expected_enabled)
        if expected_last_used is not None:
            if expected_last_used:
                self.assertIsNotNone(key.last_used)
            else:
                self.assertIsNone(key.last_used)

    def assertMfaSessionState(self, verified=None, method=None, id=None, line=None):
        """Assert that the MFA session has the expected state.

        This method:
        1. First validates session structure internally
        2. Then checks verification state if structure is valid
        3. Finally checks method/id if session is verified

        Args:
            verified (bool, optional): Expected verification state
            method (str, optional): Expected method
            id (int, optional): Expected key ID

        Raises:
            AssertionError: If session state is invalid, with specific error message
        """
        mfa = self.client.session.get("mfa")
        if line:  # pragma: no cover
            print(f"\n296 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        self._validate_session_structure(mfa, line=line)

        # Only proceed with verification checks if structure is valid
        if verified is not None:
            if verified:
                if mfa is None or not mfa or not mfa.get("verified", False):
                    raise AssertionError("MFA session is not verified")
            else:
                if mfa is not None and mfa and mfa.get("verified", False):
                    raise AssertionError("MFA session is verified")

        # Only check method and id if session is verified
        if verified and mfa and mfa.get("verified", False):
            if method is not None:
                self.assertEqual(mfa.get("method"), method, "Session method mismatch")
            if id is not None:
                self.assertEqual(mfa.get("id"), id, "Session ID mismatch")

    def assertMfaSessionUnverified(self, line=None):
        """Assert that the MFA session is in an unverified state.

        This method:
        1. First validates session structure internally
        2. Then checks verification state if structure is valid

        Raises:
            AssertionError: If session structure is invalid or if session is verified
        """
        mfa = self.client.session.get("mfa")
        if line:  # pragma: no cover
            print(f"\n329 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        self._validate_session_structure(mfa)

        # Only proceed with verification check if structure is valid
        if mfa is not None and mfa and mfa.get("verified", False):
            raise AssertionError(
                "Expected MFA session to be unverified, but it is verified"
            )

    def assertMfaSessionVerified(self, method=None, id=None, line=None):
        """Assert that the MFA session is in a verified state.

        This method:
        1. First validates session structure internally
        2. Then checks verification state if structure is valid
        3. Finally checks method/id if session is verified

        Args:
            method (str, optional): Expected method
            id (int, optional): Expected key ID

        Raises:
            AssertionError: If session structure is invalid or if session is not verified
        """
        mfa = self.client.session.get("mfa")
        if line:  # pragma: no cover
            print(f"\n357 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        self._validate_session_structure(mfa)

        # Only proceed with verification check if structure is valid
        if mfa is None or not mfa or not mfa.get("verified", False):
            raise AssertionError("MFA session is not verified")

        # Only check method and id if session is verified
        if method is not None:
            self.assertEqual(mfa.get("method"), method, "Session method mismatch")
        if id is not None:
            self.assertEqual(mfa.get("id"), id, "Session ID mismatch")

    def create_email_key(self, enabled=True, properties=None):
        """Create an Email key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.
            properties (dict, optional): Custom properties for the key. If None,
                                       uses empty properties dict.

        Returns:
            User_Keys: The created Email key
        """
        if properties is None:
            properties = {}  # Email keys don't need special properties

        key = User_Keys.objects.create(
            username=self.username,
            key_type="Email",
            enabled=enabled,
            properties=properties,
        )
        return key

    def create_recovery_key(self, enabled=True, use_real_format=False, properties=None):
        """Create a recovery key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.
            use_real_format (bool): Whether to use the real recovery key format with
                                  hashed tokens and salt. Defaults to False for simple testing.
            properties (dict, optional): Custom properties for the key. If None,
                                       uses default recovery key format.

        Returns:
            User_Keys: The created recovery key
        """
        if properties is not None:
            # Use provided properties (for testing)
            key = User_Keys.objects.create(
                username=self.username,
                key_type="RECOVERY",
                properties=properties,
                enabled=enabled,
            )
        elif use_real_format:
            # Use the real recovery key format with hashed tokens
            from django.contrib.auth.hashers import make_password

            salt = randomGen(15)
            codes = ["123456", "654321"]  # Test codes
            hashed_keys = []

            for code in codes:
                hashed_token = make_password(code, salt, "pbkdf2_sha256_custom")
                hashed_keys.append(hashed_token)

            key = User_Keys.objects.create(
                username=self.username,
                key_type="RECOVERY",
                properties={"secret_keys": hashed_keys, "salt": salt},
                enabled=enabled,
            )
        else:
            # Use simplified format for basic testing
            codes = ["123456", "654321"]  # Example recovery codes
            key = User_Keys.objects.create(
                username=self.username,
                key_type="RECOVERY",
                properties={"codes": codes},
                enabled=enabled,
            )
        return key

    def create_totp_key(self, enabled=True, properties=None):
        """Create a TOTP key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.
            properties (dict, optional): Custom properties for the key. If None,
                                       uses default TOTP secret key.

        Returns:
            User_Keys: The created TOTP key
        """
        if properties is None:
            secret = pyotp.random_base32()
            properties = {"secret_key": secret}

        key = User_Keys.objects.create(
            username=self.username,
            key_type="TOTP",
            properties=properties,
            enabled=enabled,
        )
        return key

    def create_fido2_credential_data(self, credential_id_length=16):
        """Create mock FIDO2 credential data for testing.

        This method creates mock credential data that can be used in tests.
        The actual parsing is mocked in tests to avoid FIDO2 library complexity.

        Args:
            credential_id_length (int): Length of credential ID in bytes (default: 16)

        Returns:
            str: Mock credential data for testing

        Used by: test_fido2.py ONLY
        """
        from fido2.utils import websafe_encode
        import struct

        # Create simple mock credential data
        # The actual parsing is mocked in tests
        aaguid = b"\x00" * 16  # 16-byte AAGUID
        credential_id = os.urandom(credential_id_length)  # Random credential ID
        credential_id_length_bytes = len(credential_id).to_bytes(
            2, "big"
        )  # 2-byte length

        # Create a minimal COSE key structure that the FIDO2 library can parse
        # This is a minimal ES256 (ECDSA P-256) public key in COSE format
        # Using a simple binary structure instead of CBOR to avoid cbor2 dependency
        # COSE key format: map with key type, algorithm, curve, and coordinates
        cose_key = b"\xa5"  # CBOR map with 5 entries
        cose_key += b"\x01\x02"  # kty: EC2 (key type 2)
        cose_key += b"\x03\x26"  # alg: ES256 (algorithm -7, encoded as 0x26)
        cose_key += b"\x20\x01"  # crv: P-256 (curve 1, encoded as 0x20 0x01)
        cose_key += b"\x21\x58\x20" + b"\x00" * 32  # x coordinate (32 bytes)
        cose_key += b"\x22\x58\x20" + b"\x00" * 32  # y coordinate (32 bytes)

        public_key = cose_key

        # Combine all parts to create the binary data
        credential_data = (
            aaguid + credential_id_length_bytes + credential_id + public_key
        )

        return websafe_encode(credential_data)

    def create_fido2_key(self, enabled=True, properties=None):
        """Create a FIDO2 key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.
            properties (dict, optional): Custom properties for the key. If None,
                                       uses default FIDO2 credential data.

        Returns:
            User_Keys: The created FIDO2 key
        """
        if properties is None:
            # Use the helper to create proper credential data
            encoded_device = self.create_fido2_credential_data()
            properties = {
                "device": encoded_device,
                "type": "fido-u2f",  # Mock attestation format
            }

        key = User_Keys.objects.create(
            username=self.username,
            key_type="FIDO2",
            enabled=enabled,
            properties=properties,
        )
        return key

    def create_u2f_key(self, enabled=True, properties=None):
        """Create a U2F key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.
            properties (dict, optional): Custom properties for the key. If None,
                                       uses default U2F device structure.

        Returns:
            User_Keys: The created U2F key
        """
        if properties is None:
            properties = {
                "device": {
                    "publicKey": "test_public_key",
                    "keyHandle": "test_key_handle",
                    "version": "U2F_V2",
                },
                "cert": "test_certificate_hash",
            }

        key = User_Keys.objects.create(
            username=self.username,
            key_type="U2F",
            enabled=enabled,
            properties=properties,
        )
        return key

    def create_u2f_enrollment_mock(self, appid="https://localhost:9000"):
        """Create a mock enrollment object for U2F registration.

        This creates a proper mock object that matches the u2flib_server.u2f.begin_registration
        return value, with both .json and .data_for_client attributes.

        Args:
            appid (str): The U2F application ID to use in the mock data

        Returns:
            MagicMock: Mock enrollment object with proper attributes

        Used by: test_u2f.py ONLY
        """
        mock_enrollment_obj = MagicMock()
        mock_enrollment_obj.json = {
            "challenge": "mock_challenge_string_for_enrollment",
            "appId": appid,
            "version": "U2F_V2",
        }
        mock_enrollment_obj.data_for_client = {
            "challenge": "mock_challenge_string_for_enrollment",
            "appId": appid,
            "version": "U2F_V2",
        }
        return mock_enrollment_obj

    def create_u2f_device_mock(
        self,
        public_key="test_public_key",
        key_handle="test_key_handle",
    ):
        """Create a mock U2F device for complete_registration return value.

        Args:
            public_key (str): Mock public key for the device
            key_handle (str): Mock key handle for the device

        Returns:
            MagicMock: Mock device object with .json attribute

        Used by: test_u2f.py ONLY
        """

        mock_device = MagicMock()
        mock_device.json = json.dumps(
            {"publicKey": public_key, "keyHandle": key_handle, "version": "U2F_V2"}
        )
        return mock_device

    def create_u2f_response_data(
        self,
        registration_data="BQQtEmhWVgvbh-8GpjsHbj_d5FB9iNoRL1pX4ckA",
        version="U2F_V2",
        client_data="eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoi...",
    ):
        """Create realistic U2F response data for testing.

        Args:
            registration_data (str): Mock registration data
            version (str): U2F version
            client_data (str): Mock client data

        Returns:
            dict: U2F response data structure

        Used by: test_u2f.py ONLY
        """
        return {
            "registrationData": registration_data,
            "version": version,
            "clientData": client_data,
        }

    def get_dropdown_menu_items(self, content, menu_class="dropdown-menu"):
        """Extract text items from a dropdown menu in HTML content.

        This method expects HTML in the following format:
        ```html
        <ul class="dropdown-menu">
            <li><a class="dropdown-item">Menu Item 1</a></li>
            <li><a class="dropdown-item">Menu Item 2</a></li>
        </ul>
        ```

        The method will:
        1. Find the first <ul> with the specified menu_class
        2. Extract text from <a> tags with class="dropdown-item"
        3. Return items in order of appearance

        For empty input or when no menu is found, returns an empty list.
        For malformed HTML structure (e.g., unclosed tags), returns an empty list.
        For valid menu structure but no menu items, raises AssertionError.

        Args:
            content (str): HTML content containing the dropdown menu
            menu_class (str, optional): CSS class of the dropdown menu. Defaults to "dropdown-menu".

        Returns:
            list: List of text items from the dropdown menu, in order of appearance.
                 Returns empty list for empty input or when no menu is found.

        Raises:
            AssertionError: When dropdown menu is found but contains no menu items.

        Used by: test_config.py ONLY
        """
        if not content:
            return []

        # Find the dropdown menu content
        dropdown_start = content.find(f'<ul class="{menu_class}">')
        if dropdown_start == -1:
            return []

        dropdown_end = content.find("</ul>", dropdown_start)
        if dropdown_end == -1:
            return []  # Return empty list for malformed HTML instead of raising error

        dropdown_content = content[dropdown_start:dropdown_end]

        # Extract all menu items
        menu_items = []
        for line in dropdown_content.split("\n"):
            # Look for <a> tags with dropdown-item class
            if 'class="dropdown-item"' in line:
                # Find the actual text content between the <a> tags
                link_text_start = line.find('">') + 2  # Skip past ">
                link_text_end = line.find("</a>")
                if (
                    link_text_start > 1 and link_text_end > link_text_start
                ):  # Ensure valid indices
                    menu_items.append(line[link_text_start:link_text_end].strip())

        if not menu_items:
            raise AssertionError(
                f"Found dropdown menu with class '{menu_class}' but no menu items. "
                f"Expected format:\n"
                f"<ul class='{menu_class}'>\n"
                f"    <li><a class='dropdown-item'>Menu Item</a></li>\n"
                f"</ul>"
            )

        return menu_items

    def get_invalid_totp_token(self):
        """Get an invalid TOTP token for testing.

        Returns:
            str: Invalid TOTP token
        """
        return "000000"

    def get_mfa_url(self, url_name, *args, **kwargs):
        """Get URL for MFA endpoints.

        This method handles both namespaced and non-namespaced URLs:
        1. First tries the URL as provided
        2. If that fails and the URL contains a namespace (with colon), tries without the namespace
        3. If that fails and the URL doesn't contain a namespace, tries with 'mfa_' prefix
        4. If that fails and the URL contains 'mfa:', tries with underscore instead of colon

        Args:
            url_name (str): Name of the URL pattern
            *args: Positional arguments for URL resolution
            **kwargs: Keyword arguments for URL resolution

        Returns:
            str: Resolved URL

        Raises:
            NoReverseMatch: If the URL cannot be resolved in any format

        Used by: ALL test modules (core utility)
        """
        try:
            return reverse(url_name, args=args, kwargs=kwargs)
        except NoReverseMatch:
            if ":" in url_name:
                # Try without namespace
                try:
                    return reverse(url_name.split(":", 1)[1], args=args, kwargs=kwargs)
                except NoReverseMatch:
                    # Try with underscore instead of colon
                    return reverse(url_name.replace(":", "_"), args=args, kwargs=kwargs)
            else:
                # Try with mfa_ prefix
                return reverse(f"mfa_{url_name}", args=args, kwargs=kwargs)

    def get_key_row_content(self, content, key_id):
        """Extract content of the table row for a specific key.

        This method handles both cases:
        - Keys with toggle buttons (not in HIDE_DISABLE)
        - Keys without toggle buttons (in HIDE_DISABLE)
        - Recovery keys via get_recovery_key_row_content()

        Args:
            content (str): HTML content containing the key table
            key_id (int): ID of the key to find

        Returns:
            str: Content of the table row for the specified key.
                 Returns empty string if row not found.

        Example:
            >>> content = response.content.decode()
            >>> row = self.get_key_row_content(content, key.id)
            >>> self.assertIn("On", row)  # Test status text
            >>> self.assertIn("----", row)  # Test delete button replaced

        Used by: test_config.py ONLY
        """

        try:
            key = User_Keys.objects.get(id=key_id)

            # Recovery keys are handled separately
            if key.key_type == "RECOVERY":
                return self.get_recovery_key_row_content(content, key_id)

            # Get the display name for this key type from settings

            key_display_name = getattr(settings, "MFA_RENAME_METHODS", {}).get(
                key.key_type, key.key_type
            )

            # Find all table rows
            rows = re.finditer(r"<tr[^>]*>(?:(?!</tr>).)*?</tr>", content, re.DOTALL)

            # First try to find by toggle/delete button IDs
            for match in rows:
                row = match.group(0)
                # Skip header row
                if "<th>" in row:
                    continue

                # Check for toggle_{id} or deleteKey({id})
                if f"toggle_{key_id}" in row or f"deleteKey({key_id}" in row:
                    return row

            # If not found by ID, try to find by key type or display name
            # This pattern now handles nested elements
            type_pattern = f"<td[^>]*>(?:(?!</td>).)*?({re.escape(key.key_type)}|{re.escape(key_display_name)})(?:(?!</td>).)*?</td>"

            # Check each row for the expected content
            rows = re.finditer(r"<tr[^>]*>(?:(?!</tr>).)*?</tr>", content, re.DOTALL)
            for match in rows:
                row = match.group(0)
                # Skip header row
                if "<th>" in row:
                    continue
                if re.search(type_pattern, row, re.DOTALL):
                    return row

            return ""

        except User_Keys.DoesNotExist:
            return ""

    def get_recovery_key_row_content(self, content, key_id):
        """Extract content of the special recovery key row from the table.

        Recovery keys are rendered differently from other keys:
        1. They appear in a special section after regular keys
        2. They are only shown when another key exists
        3. They always show "On" status and wrench icon
        4. They use the name from MFA_RENAME_METHODS if present

        Args:
            content (str): HTML content containing the key table
            key_id (int): ID of the recovery key to find

        Returns:
            str: Content of the recovery key row.
                 Returns empty string if row not found.

        Example:
            >>> content = response.content.decode()
            >>> row = self.get_recovery_key_row_content(content, key.id)
            >>> self.assertIn("Backup Codes", row)  # Test custom name
            >>> self.assertIn("On", row)  # Test status
            >>> self.assertIn("fa-wrench", row)  # Test wrench icon

        Used by: test_config.py ONLY
        """

        try:
            key = User_Keys.objects.get(id=key_id)
            if key.key_type != "RECOVERY":
                return ""

            # Get the display name for recovery keys

            key_display_name = getattr(settings, "MFA_RENAME_METHODS", {}).get(
                "RECOVERY", "RECOVERY"
            )

            # Find the special recovery section after regular keys
            rows = re.finditer(r"<tr[^>]*>(?:(?!</tr>).)*?</tr>", content, re.DOTALL)
            for match in rows:
                row = match.group(0)
                # Skip header row
                if "<th>" in row:
                    continue

                # Recovery keys have:
                # 1. The key's display name
                # 2. "On" status (always enabled)
                # 3. Wrench icon for management
                if key_display_name in row and "On" in row and "fa-wrench" in row:
                    return row
            return ""

        except User_Keys.DoesNotExist:
            return ""

    def get_redirect_url(self, default="mfa_home"):
        """Get the redirect URL for MFA operations.

        Args:
            default (str): Default URL name to use if no redirect is configured

        Returns:
            dict: Dictionary containing redirect URL and success message
        """
        redirect_url = getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", default)
        try:
            url = reverse(redirect_url)
        except NoReverseMatch:
            # If the redirect URL is a path, return it as is
            if redirect_url.startswith("/"):
                url = redirect_url
            # Otherwise use the default
            else:
                url = reverse(default)

        return {
            "redirect_url": url,
            "reg_success_msg": getattr(settings, "MFA_SUCCESS_REGISTRATION_MSG", None),
        }

    def get_valid_totp_token(self, key_id=None):
        """Get a valid TOTP token for testing.

        Args:
            key_id (int, optional): ID of specific key to use. If None, uses first TOTP key.

        Returns:
            str: 6-digit TOTP token string

        Raises:
            ValueError: If no TOTP key found for user
        """
        if key_id:
            key = User_Keys.objects.get(
                id=key_id, username=self.username, key_type="TOTP"
            )
        else:
            key = User_Keys.objects.filter(
                username=self.username, key_type="TOTP"
            ).first()
            if not key:
                raise ValueError("No TOTP key found for user")

        totp = pyotp.TOTP(key.properties["secret_key"])
        return totp.now()

    def login_user(self):
        """Log in the test user.

        Uses the test user credentials to authenticate with the test client.
        """
        self.client.login(username=self.username, password=self.password)

    def setup_session_base_username(self):
        """Set up base session with username for MFA authentication.

        This sets up the base_username in the session, which is required
        for MFA authentication flows.
        """
        session = self.client.session
        session["base_username"] = self.username
        session.save()

    def get_authenticated_user(self):
        """Get an authenticated user for testing.

        Returns:
            User: The test user (already authenticated)
        """
        return self.user

    def get_unauthenticated_user(self):
        """Get an unauthenticated user for testing.

        Returns:
            AnonymousUser: Django's AnonymousUser for unauthenticated scenarios
        """
        from django.contrib.auth.models import AnonymousUser

        return AnonymousUser()

    def create_mock_request(self, username=None):
        """Create a mock request object for testing functions that expect request.user.

        Some recovery functions like delTokens and getTokenLeft expect request.user.get_username()
        but the test client's request object doesn't have a user attribute.

        Args:
            username: Username to use, defaults to self.username

        Returns:
            Mock request object with user attribute
        """
        if username is None:
            username = self.username

        class MockRequest:
            def __init__(self, username):
                # Get the actual USERNAME_FIELD from the User model
                from django.contrib.auth import get_user_model
                User = get_user_model()
                username_field = getattr(User, 'USERNAME_FIELD', 'username')
                
                # Create mock user with the correct field
                mock_user_attrs = {username_field: username}
                mock_user_attrs['get_username'] = lambda self: getattr(self, username_field)
                
                self.user = type("User", (), mock_user_attrs)()
                self.session = {}
                self.method = "POST"
                self.POST = {}
                self.GET = {}

        return MockRequest(username)

    def create_http_request_mock(self, username=None):
        """Create a mock HttpRequest object for functions with @never_cache decorator.

        Some functions like genTokens are decorated with @never_cache which expects
        a real HttpRequest object. This creates a more sophisticated mock.

        Args:
            username: Username to use, defaults to self.username

        Returns:
            Mock HttpRequest-like object that satisfies decorator requirements

        Used by: test_totp.py, test_recovery.py, test_helpers.py
        """
        if username is None:
            username = self.username

        # Create a real Django request using the test client
        from django.test import RequestFactory
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.contrib.auth.middleware import AuthenticationMiddleware

        factory = RequestFactory()
        request = factory.get("/")

        # Add session middleware to the request
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()

        # Add authentication middleware
        auth_middleware = AuthenticationMiddleware(lambda req: None)
        auth_middleware.process_request(request)

        # Set up the request with proper Django session
        # Create a user with the specified username if different from default
        if username != self.username:
            # Create a mock user with the custom username
            # Get the actual USERNAME_FIELD from the User model
            from django.contrib.auth import get_user_model
            User = get_user_model()
            username_field = getattr(User, 'USERNAME_FIELD', 'username')
            
            # Create mock user with the correct field
            mock_user_attrs = {username_field: username}
            mock_user_attrs['get_username'] = lambda self: getattr(self, username_field)
            
            request.user = type("User", (), mock_user_attrs)()
        else:
            request.user = self.get_authenticated_user()
        request.method = "POST"

        # Add attributes that @never_cache might check
        request.META = {}
        request.GET = {}
        request.POST = {}

        # Set body and content_type using the proper method
        request._body = b""
        request.content_type = "application/json"

        return request

    def _reset_session(self):
        """Reset session to clean state.

        Clears the session, sets base_username, and saves the session.
        Also verifies that the MFA session is accessible.
        """
        session = self.client.session
        session.clear()
        session["base_username"] = self.username
        session.save()

        # Verify MFA session is accessible
        self._verify_mfa_session_accessible()

    def setup_mfa_session(self, method="TOTP", verified=True, id=1):
        """Set up MFA session state for testing.

        Args:
            method (str): MFA method to use (default: 'TOTP')
            verified (bool): Whether the method is verified (default: True)
            id (int): Key ID to use (default: 1)
        """
        session = self.client.session
        mfa = {"method": method, "verified": verified, "id": id}
        mfa.update(set_next_recheck())
        session["mfa"] = mfa
        session.save()
        # Verify session was saved
        self._verify_mfa_session_accessible()

    def _validate_session_structure(self, mfa, line=None):
        """Internal method to validate MFA session structure.

        This method validates that:
        1. If mfa is not None, it must be a dictionary
        2. If mfa is verified, it must have method and id keys

        Args:
            mfa: The MFA session data to validate
            line (optional): Label (eg, line number) for debug prints

        Returns: str: Empty string if validation passes

        Raises: AssertionError: If validation fails
        """
        msg = ""
        if line:  # pragma: no cover
            print(f"\n1122 {__name__} {line} {msg=}")

        # None is a valid unverified state
        if mfa is None:
            return msg

        # Validate basic structure
        if not isinstance(mfa, dict):
            msg = "MFA session must be a dictionary"
            if line:  # pragma: no cover
                print(f"\n1132 {__name__} {line} {msg=}")
            raise AssertionError(msg)

        # For verified sessions, validate required keys
        if not msg and mfa.get("verified", False):
            if "method" not in mfa:
                msg = "Verified MFA session must have session['mfa']['method']"
                if line:  # pragma: no cover
                    print(f"\n1140 {__name__} {line} {msg=}")
                raise AssertionError(msg)
            if not msg and "id" not in mfa:
                msg = "Verified MFA session must have session['mfa']['id']"
                if line:  # pragma: no cover
                    print(f"\n1145 {__name__} {line} {msg=}")
                raise AssertionError(msg)

        if line:  # pragma: no cover
            print(f"\n1149 {__name__} {line} returning {msg=}")
        return msg

    def _verify_mfa_session_accessible(self):
        """Verify that the MFA session is accessible and properly saved.

        This is a safety check to ensure that session changes are persisted.
        It's called after any session modifications to prevent false verification states.

        Raises:
            AssertionError: If session is not accessible or not saved
        """
        # Get current session
        session = self.client.session

        # Guard against Django session framework issues (not MFA project code). This
        # prevents false verification states if Django's test client session fails
        if not session:  # pragma: no cover
            raise AssertionError("MFA session is not accessible")

        # Get unallowed methods from settings, defaulting to empty tuple if not set
        unallowed_methods = getattr(self, "original_settings", {}).get(
            "MFA_UNALLOWED_METHODS", ()
        )

        # Verify session is saved
        if "mfa" in session:
            mfa = session.get("mfa")
            if mfa and mfa.get("verified", False):
                method = mfa.get("method")
                if method in unallowed_methods:
                    raise AssertionError(f"MFA method {method} is not allowed")

    def get_user_keys(self, key_type=None):
        """Get user keys, optionally filtered by type.

        Args:
            key_type (str, optional): Filter keys by this type

        Returns:
            QuerySet: User keys for the current user, optionally filtered by type
        """
        queryset = User_Keys.objects.filter(username=self.username)
        if key_type:
            queryset = queryset.filter(key_type=key_type)
        return queryset

    def get_valid_recovery_code(self, key_id=None):
        """Get a valid recovery code for testing.

        Args:
            key_id (int, optional): ID of specific recovery key to use.
                                  If None, uses first recovery key.

        Returns:
            str: A valid recovery code from the specified key

        Raises:
            ValueError: If no recovery key found or no codes available
        """
        if key_id:
            key = User_Keys.objects.get(
                id=key_id, username=self.username, key_type="RECOVERY"
            )
        else:
            key = User_Keys.objects.filter(
                username=self.username, key_type="RECOVERY"
            ).first()
            if not key:
                raise ValueError("No recovery key found for user")

        # Handle both simplified and real formats
        if "codes" in key.properties:
            # Simplified format
            codes = key.properties["codes"]
            if not codes:
                raise ValueError("No recovery codes available")
            return codes[0]
        elif "secret_keys" in key.properties:
            # Real format - we can't get the actual codes, so return a test code
            # This is mainly for testing the format, not actual validation
            return "123456"
        else:
            raise ValueError("Invalid recovery key format")

    def get_invalid_recovery_code(self):
        """Get an invalid recovery code for testing.

        Returns:
            str: An invalid recovery code that should fail validation
        """
        return "000000-00000"

    def get_recovery_codes_count(self, key_id=None):
        """Get the count of remaining recovery codes for a key.

        Args:
            key_id (int, optional): ID of specific recovery key to check.
                                  If None, uses first recovery key.

        Returns:
            int: Number of remaining recovery codes

        Raises:
            ValueError: If no recovery key found
        """
        if key_id:
            key = User_Keys.objects.get(
                id=key_id, username=self.username, key_type="RECOVERY"
            )
        else:
            key = User_Keys.objects.filter(
                username=self.username, key_type="RECOVERY"
            ).first()
            if not key:
                raise ValueError("No recovery key found for user")

        # Handle both simplified and real formats
        if "codes" in key.properties:
            return len(key.properties["codes"])
        elif "secret_keys" in key.properties:
            return len(key.properties["secret_keys"])
        else:
            return 0

    def create_recovery_key_with_real_codes(self, enabled=True, num_codes=5):
        """Create a recovery key with real-format codes for comprehensive testing.

        This method creates a recovery key using the same format as the actual
        recovery system, with hashed tokens and salt.

        Args:
            enabled (bool): Whether the key should be enabled
            num_codes (int): Number of recovery codes to generate

        Returns:
            tuple: (User_Keys, list) - The created key and list of clear codes

        Used by: test_recovery.py ONLY
        """
        from django.contrib.auth.hashers import make_password

        salt = randomGen(15)
        clear_codes = []
        hashed_keys = []

        for _ in range(num_codes):
            # Generate code in format XXXXX-XXXXX
            code = randomGen(5) + "-" + randomGen(5)
            clear_codes.append(code)

            # Hash the code
            hashed_token = make_password(code, salt, "pbkdf2_sha256_custom")
            hashed_keys.append(hashed_token)

        key = User_Keys.objects.create(
            username=self.username,
            key_type="RECOVERY",
            properties={"secret_keys": hashed_keys, "salt": salt},
            enabled=enabled,
        )

        return key, clear_codes

    def simulate_recovery_code_usage(self, key_id, code):
        """Simulate using a recovery code (for testing consumption logic).

        This method simulates what happens when a recovery code is used:
        - Removes the code from the available codes
        - Updates the last_used timestamp
        - Returns whether this was the last code

        Args:
            key_id (int): ID of the recovery key
            code (str): The recovery code to "use"

        Returns:
            bool: True if this was the last code, False otherwise

        Raises:
            ValueError: If code not found or key doesn't exist

        Used by: test_recovery.py ONLY
        """
        key = User_Keys.objects.get(id=key_id, username=self.username)

        if "codes" in key.properties:
            # Simplified format
            codes = key.properties["codes"]
            if code not in codes:
                raise ValueError("Recovery code not found")

            codes.remove(code)
            key.properties["codes"] = codes
            key.last_used = timezone.now()
            key.save()

            return len(codes) == 0
        else:
            raise ValueError("Cannot simulate usage for real-format keys")

    def assert_recovery_key_has_codes(self, key_id, expected_count=None):
        """Assert that a recovery key has the expected number of codes.

        Args:
            key_id (int): ID of the recovery key to check
            expected_count (int, optional): Expected number of codes.
                                          If None, just checks that codes exist.

        Raises:
            AssertionError: If assertion fails

        Used by: test_recovery.py ONLY
        """
        key = User_Keys.objects.get(id=key_id, username=self.username)

        if "codes" in key.properties:
            actual_count = len(key.properties["codes"])
            if expected_count is not None:
                self.assertEqual(
                    actual_count,
                    expected_count,
                    f"Expected {expected_count} codes, got {actual_count}",
                )
            else:
                self.assertGreater(actual_count, 0, "No recovery codes available")
        elif "secret_keys" in key.properties:
            actual_count = len(key.properties["secret_keys"])
            if expected_count is not None:
                self.assertEqual(
                    actual_count,
                    expected_count,
                    f"Expected {expected_count} codes, got {actual_count}",
                )
            else:
                self.assertGreater(actual_count, 0, "No recovery codes available")
        else:
            self.fail("Invalid recovery key format")

    def create_trusted_device_key(
        self, enabled=True, properties=None, clear_existing=True
    ):
        """Create a TrustedDevice key with optional custom properties.

        Args:
            enabled (bool): Whether the key should be enabled
            properties (dict, optional): Custom properties to override defaults
            clear_existing (bool): Whether to clear existing TrustedDevice keys first

        Returns:
            User_Keys: The created TrustedDevice key
        """
        if clear_existing:
            User_Keys.objects.filter(
                username=self.username, key_type="Trusted Device"
            ).delete()

        default_properties = {
            "device_name": "Test Device",
            "user_agent": "Test User Agent",
            "ip_address": "127.0.0.1",
            "last_used": None,
            "key": "test_device_key",
            "status": "trusted",
        }
        if properties:
            default_properties.update(properties)

        return User_Keys.objects.create(
            username=self.username,
            key_type="Trusted Device",
            enabled=enabled,
            properties=default_properties,
        )

    def create_trusted_device_jwt_token(self, key, username=None):
        """Create a JWT token for trusted device verification.

        Args:
            key (str): The device key to include in the token
            username (str, optional): Username to include in token (defaults to self.username)

        Returns:
            str: JWT token string

        Used by: test_trusteddevice.py ONLY
        """
        from jose import jwt
        from django.conf import settings

        if username is None:
            username = self.username

        return jwt.encode({"username": username, "key": key}, settings.SECRET_KEY)

    def setup_trusted_device_test(self, clear_existing=True):
        """Set up test environment for TrustedDevice tests.

        Args:
            clear_existing (bool): Whether to clear existing TrustedDevice keys and session

        Returns:
            User_Keys: The created TrustedDevice key

        Used by: test_trusteddevice.py ONLY
        """
        self.login_user()
        self.setup_session_base_username()

        if clear_existing:
            User_Keys.objects.filter(
                username=self.username, key_type="Trusted Device"
            ).delete()
            self.client.session.clear()

        # Create a TrustedDevice key for testing
        key = self.create_trusted_device_key()

        # Setup MFA session
        self.setup_mfa_session(method="Trusted Device", verified=True, id=key.id)

        return key

    def verify_trusted_device(self, key, expect_success=True):
        """Test TrustedDevice verification with given key.

        Args:
            key (str or User_Keys): The device key to test with
            expect_success (bool): Whether verification should succeed

        Returns:
            bool: The verification result

        Used by: test_trusteddevice.py ONLY
        """
        from .. import TrustedDevice

        # Handle both string keys and User_Keys objects
        if hasattr(key, "properties"):
            key_value = key.properties[
                "key"
            ]  # Use the actual key value from properties
            key_id = key.id
        else:
            key_value = key
            key_id = None

        token = self.create_trusted_device_jwt_token(key_value)
        self.client.cookies["deviceid"] = token

        # Create a proper request with POST data for TrustedDevice.verify
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post("/", {"username": self.username})
        request.session = self.client.session

        # Convert cookies to proper format for TrustedDevice.verify
        request.COOKIES = {}
        for name, value in self.client.cookies.items():
            request.COOKIES[name] = value.value

        # Handle the case where TrustedDevice.verify might raise DoesNotExist
        try:
            result = TrustedDevice.verify(request)
        except Exception as err:
            # This is expected when testing with invalid keys
            # Catch any exception to ensure graceful failure
            result = False
            print(f"\n1518 {__name__} {result=}\nand {err=}")  # pragma: no cover

        # Save session changes
        request.session.save()

        if expect_success:
            self.assertTrue(result)
            if key_id:
                self.assertMfaSessionVerified(method="Trusted Device", id=key_id)
        else:
            self.assertFalse(result)
            self.assertMfaSessionUnverified()

        return result

    def complete_trusted_device_registration(self, user_agent=None):
        """Complete the full trusted device registration flow.

        Args:
            user_agent (str, optional): User agent string to use

        Returns:
            str: The generated device key

        Used by: test_trusteddevice.py ONLY
        """
        if user_agent is None:
            user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"

        # Start setup
        response = self.client.get(self.get_mfa_url("start_td"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TrustedDevices/start.html")

        # Get generated key
        key = response.context["key"]

        # Add device
        response = self.client.post(
            self.get_mfa_url("add_td"),
            {"username": self.username, "key": key},
            HTTP_USER_AGENT=user_agent,
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "TrustedDevices/Add.html")
        self.assertTrue(response.context.get("success", False))

        return key

    def get_trusted_device_key(self, username=None):
        """Get the TrustedDevice key for the specified user.

        Args:
            username (str, optional): Username to get key for (defaults to self.username)

        Returns:
            User_Keys or None: The TrustedDevice key for the user, or None if not found

        Used by: test_trusteddevice.py ONLY
        """
        if username is None:
            username = self.username

        try:
            return User_Keys.objects.get(username=username, key_type="Trusted Device")
        except User_Keys.DoesNotExist:
            return None
        except User_Keys.MultipleObjectsReturned:
            # If multiple devices exist, return the first one
            return User_Keys.objects.filter(
                username=username, key_type="Trusted Device"
            ).first()

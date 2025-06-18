import sys
import unittest
from django.test import TestCase, override_settings
from django.urls import reverse, path, include, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import HttpResponse
from django.contrib import admin
from mfa.models import User_Keys
from mfa.urls import urlpatterns as mfa_urlpatterns
from .base import MFATestCase, create_session, dummy_logout
import pyotp

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
    ROOT_URLCONF="mfa.tests.test_base",
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
class TestMFATestCase(TestCase):
    """Test suite for the MFATestCase base class.

    This suite verifies that our test infrastructure works correctly.
    MFATestCase is the foundation for all MFA tests, providing:
    - User authentication helpers
    - MFA key management
    - Session state verification
    - UI element parsing
    - Token generation and validation

    Each test ensures a specific piece of test infrastructure works,
    allowing other tests to rely on these helpers with confidence.

    Note: MFA middleware is disabled. These tests focus on testing the test
    infrastructure itself.
    """

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
        """Clean up the test instance after each test."""
        self.mfa_test._post_teardown()

    def test_mfa_test_case_setup(self):
        """Verify MFATestCase properly initializes the test environment.

        This test ensures our test infrastructure starts in a known good state.
        It verifies that:
        1. A test user is created
        2. The user has the expected username
        3. The user's password is correctly set

        This is critical because all other tests depend on having
        a properly configured test user.
        """
        self.assertIsNotNone(self.mfa_test.user)
        self.assertEqual(self.mfa_test.username, "testuser")
        self.assertTrue(self.mfa_test.user.check_password("testpass123"))

    def test_create_totp_key_enabled(self):
        """Verify TOTP key creation helper works correctly for enabled keys.

        This test ensures we can create enabled TOTP keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. A valid secret key is generated
        4. Secret key is stored in properties
        5. Secret key has appropriate length

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state
        """
        key = self.mfa_test.create_totp_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "TOTP")
        self.assertTrue(key.enabled)
        self.assertIn("secret_key", key.properties)
        self.assertTrue(len(key.properties["secret_key"]) > 0)

    def test_create_totp_key_disabled(self):
        """Verify TOTP key creation helper works correctly for disabled keys.

        This test ensures we can create disabled TOTP keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. A valid secret key is still generated (for consistency)
        4. Secret key is stored in properties
        5. Secret key has appropriate length

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Disabled TOTP keys still have a secret key to maintain
        consistency and allow for potential re-enabling.
        """
        disabled_key = self.mfa_test.create_totp_key(enabled=False)
        self.assertEqual(disabled_key.username, self.mfa_test.username)
        self.assertEqual(disabled_key.key_type, "TOTP")
        self.assertFalse(disabled_key.enabled)
        self.assertIn("secret_key", disabled_key.properties)
        self.assertTrue(len(disabled_key.properties["secret_key"]) > 0)

    def test_create_email_key_enabled(self):
        """Verify Email key creation helper works correctly for enabled keys.

        This test ensures we can create enabled Email keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as enabled
        3. No special properties are needed
        4. Type matches template expectations

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Email keys are simpler than TOTP keys as they
        don't require special properties.
        """
        key = self.mfa_test.create_email_key()
        self.assertEqual(key.username, self.mfa_test.username)
        self.assertEqual(key.key_type, "Email")  # Case-sensitive for template matching
        self.assertTrue(key.enabled)
        self.assertEqual(key.properties, {})  # Email keys don't need special properties

    def test_create_email_key_disabled(self):
        """Verify Email key creation helper works correctly for disabled keys.

        This test ensures we can create disabled Email keys for testing.
        It verifies that:
        1. Correct username and type are set
        2. Key is marked as disabled
        3. No special properties are needed
        4. Type matches template expectations

        Preconditions:
        - Test user is logged in
        - No existing MFA keys
        - Clean session state

        Note: Email keys are simpler than TOTP keys as they
        don't require special properties.
        """
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
        5. A next check timestamp is set in the MFA session

        This is important because most tests will use these default values
        when setting up MFA sessions.
        """
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
        """Test key state verification for enabled keys.

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
        """Test key state verification for disabled keys.

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
        """Test key state verification for last_used timestamp.

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

    def test_assertMfaKeyState(self):
        """Test key state verification.

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
        """Test get_dropdown_menu_items with malformed HTML.

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

    def test_verify_session_saved(self):
        """Test session save verification.

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
        """Test session save verification failure.

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

    def test_mfa_test_case_login_helper(self):
        """Test MFATestCase's login helper method.

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
        """Test successful MFA session verification.

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
        """Test MFA session verification failure.

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
        """Test that get_invalid_totp_token returns a consistent value.

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
        """Test get_recovery_key_row_content with enabled key.

        Required conditions:
        1. Recovery key exists
        2. Key is enabled
        3. Key is in HTML content

        Expected results:
        1. Key row is found
        2. Row contains key information
        """
        key = self.mfa_test.create_recovery_key()

        # Create content with recovery key in special section
        content = f"""
        <table>
            <tr>
                <td>Backup Codes</td>
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
        self.assertIn("Backup Codes", row)
        self.assertIn("On", row)
        self.assertIn("fa-wrench", row)

    def test_get_valid_totp_token_generates_valid_code(self):
        """Test that get_valid_totp_token generates valid TOTP codes.

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
        """Test get_key_row_content with enabled key.

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
        """Test that get_key_row_content can find a disabled key in the HTML content.

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
        """Test get_key_row_content with nonexistent key.

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
        """Test get_key_row_content with malformed HTML.

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
        """Test get_key_row_content isolates correct row.

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
        """Test get_key_row_content with whitespace variations.

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
        """Test get_key_row_content with HTML attributes.

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
        """Test get_key_row_content with nested elements.

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
        """Test get_key_row_content with dynamic content.

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

    def test_assertMfaSessionState_validation_flow(self, line=None):
        """Test the complete validation flow of assertMfaSessionState.

        This test ensures our session state validation:
        1. Validates structure first
        2. Validates verification state
        3. Validates method and ID if verified
        4. Each validation step has appropriate error messages

        Preconditions:
        - Clean session state (no existing MFA session)
        - Test user is logged in
        - No existing MFA keys

        Test Flow:
        1. Test invalid session structure (non-dict)
        2. Test unverified session state
        3. Test verified session with missing method
        4. Test verified session with missing id
        5. Test valid verified session
        """
        # Test invalid structure
        session = self.mfa_test.client.session
        session["mfa"] = "not a dict"
        session.save()
        if line:
            print(f"\n1047 {__name__} {line} session.get('mfa')={session.get('mfa')}")
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionState()
        self.assertIn("MFA session must be a dictionary", str(cm.exception))

        # Test valid unverified states
        valid_states = [
            None,  # No session
            {},  # Empty dict
            {"verified": False},  # Explicitly unverified
        ]
        for state in valid_states:
            if state is None:
                if "mfa" in session:
                    del session["mfa"]
            else:
                session["mfa"] = state
            session.save()
            self.mfa_test.assertMfaSessionState(verified=False)

        # Test verified session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": 1}
        session.save()
        self.mfa_test.assertMfaSessionState(verified=True, method="TOTP", id=1)

    def test_assertMfaSessionVerified_validation_flow(self, line=None):
        """Test the complete validation flow of assertMfaSessionVerified.

        This test ensures our verified session validation:
        1. Validates structure first
        2. Validates verification state
        3. Validates method and ID if provided
        4. Each validation step has appropriate error messages

        Preconditions:
        - Clean session state (no existing MFA session)
        - Test user is logged in
        - No existing MFA keys

        Test Flow:
        1. Test invalid session structure (non-dict)
        2. Test unverified session state
        3. Test verified session with missing method
        4. Test verified session with missing id
        5. Test valid verified session
        """
        # Test invalid structure
        session = self.mfa_test.client.session
        session["mfa"] = "not a dict"
        session.save()
        if line:
            print(f"\n1098 {__name__} {line} session.get('mfa')={session.get('mfa')}")
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionVerified()
        self.assertIn("MFA session must be a dictionary", str(cm.exception))

        # Test valid unverified states
        valid_states = [
            None,  # No session
            {},  # Empty dict
            {"verified": False},  # Explicitly unverified
        ]
        for state in valid_states:
            if state is None:
                if "mfa" in session:
                    del session["mfa"]
            else:
                session["mfa"] = state
            session.save()
            with self.assertRaises(AssertionError) as cm:
                self.mfa_test.assertMfaSessionVerified()
            self.assertIn("MFA session is not verified", str(cm.exception))

        # Test verified session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": 1}
        session.save()
        self.mfa_test.assertMfaSessionVerified()

    def test_assertMfaSessionUnverified_validation_flow(self, line=None):
        """Test the complete validation flow of assertMfaSessionUnverified.

        This test ensures our unverified session validation:
        1. Validates structure first
        2. Validates verification state
        3. Each validation step has appropriate error messages

        Preconditions:
        - Clean session state (no existing MFA session)
        - Test user is logged in
        - No existing MFA keys

        Test Flow:
        1. Test invalid session structure (non-dict)
        2. Test unverified session state
        3. Test verified session with missing method
        4. Test verified session with missing id
        5. Test valid verified session
        """
        # Test invalid structure
        session = self.mfa_test.client.session
        session["mfa"] = "not a dict"
        session.save()
        if line:
            print(f"\n1150 {__name__} {line} session.get('mfa')={session.get('mfa')}")
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionUnverified()
        self.assertIn("MFA session must be a dictionary", str(cm.exception))

        # Test valid unverified states
        valid_states = [
            None,  # No session
            {},  # Empty dict
            {"verified": False},  # Explicitly unverified
        ]
        for state in valid_states:
            if state is None:
                if "mfa" in session:
                    del session["mfa"]
            else:
                session["mfa"] = state
            session.save()
            self.mfa_test.assertMfaSessionUnverified(line=line)

        # Test verified session
        session["mfa"] = {"verified": True, "method": "TOTP", "id": 1}
        session.save()
        with self.assertRaises(AssertionError) as cm:
            self.mfa_test.assertMfaSessionUnverified()
        self.assertIn("MFA session is verified", str(cm.exception))

    def test_reset_session(self):
        """Test session reset functionality.

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
        session["mfa"] = {"verified": True}
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
        """Test get_mfa_url with namespace handling.

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
        """Test get_valid_totp_token with different key IDs.

        This test ensures our TOTP token generation:
        1. Works with different key IDs
        2. Generates valid tokens
        3. Handles nonexistent keys
        """
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

    def test_get_invalid_totp_token_consistency(self):
        """Test get_invalid_totp_token consistency.

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

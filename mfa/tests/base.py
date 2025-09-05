import pyotp
import time

from django.test import TestCase, Client
from django.conf import settings
from django.urls import reverse, NoReverseMatch
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
from django.core.cache import cache
from django.contrib.auth import login
from django.http import HttpResponseRedirect, HttpResponse
from mfa.models import User_Keys
from mfa.Common import set_next_recheck


User = get_user_model()


def create_session(request, username):
    """Create a test session for MFA authentication.

    This is used as MFA_LOGIN_CALLBACK in tests to simulate the login process.
    Mimics the example implementation from example.auth.create_session.
    """
    User = get_user_model()
    user = User.objects.get(username=username)
    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)
    # print(f"\n30 {__name__} - Test session created by tests.create_session()")
    return HttpResponseRedirect(reverse("mfa_home"))


def dummy_logout(request):
    """Dummy logout view for tests.

    This view is used to satisfy template references to {% url 'logout' %}
    during testing without requiring a real logout implementation.
    """
    return HttpResponse("Logged out (dummy)")


class MFATestCase(TestCase):
    """Base test case for MFA tests.

    This class provides common functionality for all MFA test cases, including:
    - User creation and authentication
    - MFA key setup and management
    - Settings management and verification
    - URL handling for both namespaced and non-namespaced patterns
    - Session state verification
    - Common assertions for MFA functionality
    """

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
        "EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend",
        "EMAIL_FROM": "security@example.com",
        # FIDO2 settings
        "FIDO_SERVER_ID": "example.com",
        "FIDO_SERVER_NAME": "Test Server",
        "FIDO_AUTHENTICATOR_ATTACHMENT": "cross-platform",
        "FIDO_USER_VERIFICATION": "preferred",
        "FIDO_AUTHENTICATION_TIMEOUT": 30000,
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
        # Create test user
        self.username = "testuser"
        self.password = "testpass123"
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            email="test@example.com",
        )

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
        super().tearDown()
        cache.clear()
        User_Keys.objects.all().delete()
        # Restore original settings
        for key, value in self.DEFAULT_MFA_SETTINGS.items():
            setattr(settings, key, value)
        # Ensure session is clean
        self._reset_session()

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
        if line:
            print(f"\n168 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        msg = self._validate_session_structure(mfa, line=line)
        if line:
            print(f"\n173 {__name__} {line} {msg=}")
        if msg:
            raise AssertionError(msg)

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
        if line:
            print(f"\n205 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        msg = self._validate_session_structure(mfa)
        if line:
            print(f"\n210 {__name__} {line} {msg=}")
        if msg:
            raise AssertionError(msg)

        # Only proceed with verification check if structure is valid
        if mfa is not None and mfa and mfa.get("verified", False):
            raise AssertionError("MFA session is verified")

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
        if line:
            print(f"\n235 {__name__} {line} {mfa=}")

        # Always validate structure first - this will raise AssertionError if invalid
        msg = self._validate_session_structure(mfa)
        if line:
            print(f"\n240 {__name__} {line} {msg=}")
        if msg:
            raise AssertionError(msg)

        # Only proceed with verification check if structure is valid
        if mfa is None or not mfa or not mfa.get("verified", False):
            raise AssertionError("MFA session is not verified")

        # Only check method and id if session is verified
        if method is not None:
            self.assertEqual(mfa.get("method"), method, "Session method mismatch")
        if id is not None:
            self.assertEqual(mfa.get("id"), id, "Session ID mismatch")

    def create_email_key(self, enabled=True):
        """Create an Email key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.

        Returns:
            User_Keys: The created Email key
        """
        key = User_Keys.objects.create(
            username=self.username,
            key_type="Email",
            enabled=enabled,
            properties={},  # Email keys don't need special properties
        )
        return key

    def create_recovery_key(self, enabled=True):
        """Create a recovery key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.

        Returns:
            User_Keys: The created recovery key
        """
        codes = ["123456", "654321"]  # Example recovery codes
        key = User_Keys.objects.create(
            username=self.username,
            key_type="RECOVERY",
            properties={"codes": codes},
            enabled=enabled,
        )
        return key

    def create_totp_key(self, enabled=True):
        """Create a TOTP key for the test user.

        Note: In real usage, keys are always created enabled and can only be disabled
        through the UI toggle. The enabled parameter exists only for testing the
        disabled state.

        Args:
            enabled (bool): Whether the key should be enabled. This is for testing
                          only - real keys are always created enabled.

        Returns:
            User_Keys: The created TOTP key
        """
        secret = pyotp.random_base32()
        key = User_Keys.objects.create(
            username=self.username,
            key_type="TOTP",
            properties={"secret_key": secret},
            enabled=enabled,
        )
        return key

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

        For empty or invalid input, returns an empty list.
        For malformed HTML structure (e.g., unclosed tags), returns an empty list.

        Args:
            content (str): HTML content containing the dropdown menu
            menu_class (str, optional): CSS class of the dropdown menu. Defaults to "dropdown-menu".

        Returns:
            list: List of text items from the dropdown menu, in order of appearance.
                 Returns empty list for empty/invalid input.
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

        Verifies that when:
        1. HTML content contains a table row for the specified key
        2. Row contains cells for key information and actions
        The content of that specific row is extracted.

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
        """
        import re

        try:
            key = User_Keys.objects.get(id=key_id)

            # Recovery keys are handled separately
            if key.key_type == "RECOVERY":
                return self.get_recovery_key_row_content(content, key_id)

            # Get the display name for this key type from settings
            from django.conf import settings

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
        """
        import re

        try:
            key = User_Keys.objects.get(id=key_id)
            if key.key_type != "RECOVERY":
                return ""

            # Get the display name for recovery keys
            from django.conf import settings

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
            str: URL to redirect to after MFA operations
        """
        redirect_url = getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", default)
        try:
            return reverse(redirect_url)
        except NoReverseMatch:
            # If the redirect URL is a path, return it as is
            if redirect_url.startswith("/"):
                return redirect_url
            # Otherwise use the default
            return reverse(default)

    def get_valid_totp_token(self, key_id=None):
        """Get a valid TOTP token for testing.

        Required conditions:
        1. TOTP key exists
        2. Key has valid secret

        Expected results:
        1. Returns 6-digit string
        2. String is numeric
        3. String is valid for the key's secret

        Args:
            key_id: Optional ID of specific key to use. If None, uses first TOTP key.
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

    def _reset_session(self):
        """Reset session to clean state.

        Required conditions:
        1. Session middleware is enabled
        2. User is logged in

        Expected results:
        1. Session is cleared
        2. base_username is set
        3. Session is saved
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
            line (int, optional): Line number for debug prints

        Returns:
            str: Empty string if validation passes, error message if validation fails
        """
        msg = ""
        if line:
            print(f"\n669 {__name__} {line} {msg=}")

        # None is a valid unverified state
        if mfa is None:
            return msg

        # Validate basic structure
        if not isinstance(mfa, dict):
            msg = "MFA session must be a dictionary"
            if line:
                print(f"\n679 {__name__} {line} {msg=}")
            raise AssertionError(msg)

        # For verified sessions, validate required keys
        if not msg and mfa.get("verified", False):
            if "method" not in mfa:
                msg = "Verified MFA session must have session['mfa']['method']"
                if line:
                    print(f"\n687 {__name__} {line} {msg=}")
                raise AssertionError(msg)
            if not msg and "id" not in mfa:
                msg = "Verified MFA session must have session['mfa']['id']"
                if line:
                    print(f"\n692 {__name__} {line} {msg=}")
                raise AssertionError(msg)

        if line:
            print(f"\n696 {__name__} {line} returning {msg=}")
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

        # Verify session is accessible
        if not session:
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

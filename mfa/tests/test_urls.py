"""
Test cases for MFA URLs module.

Tests URL patterns and routing for MFA endpoints:
- Main MFA views: mfa_home, mfa_methods_list, mfa_reset_cookie
- TOTP URLs: totp_auth, start_new_otop, totp_recheck
- FIDO2 URLs: fido2_auth, fido2_start, fido2_complete, fido2_begin, fido2_complete_auth, fido2_recheck
- U2F URLs: u2f_auth, start_u2f, bind_u2f, u2f_recheck
- Trusted Device URLs: trusted_device_auth, trusted_device_start, trusted_device_add, trusted_device_verify, trusted_device_recheck
- Email URLs: email_auth, start_email, email_recheck
- Recovery URLs: recovery_auth, start_recovery, recovery_recheck, recovery_gen_tokens, recovery_get_tokens_left
- Helper URLs: mfa_verify

Scenarios: URL resolution, view mapping, parameter handling, routing validation.
"""

from unittest.mock import patch
from django.contrib import admin
from django.urls import resolve, reverse, path, include
from django.test import override_settings
from mfa.urls import urlpatterns as mfa_urlpatterns
from mfa import views, totp, U2F, TrustedDevice, helpers, FIDO2, Email, recovery
from .mfatestcase import MFATestCase, dummy_logout


# Use the original MFA URL patterns without namespace
urlpatterns = [
    path("admin/", admin.site.urls),
    path("mfa/", include(mfa_urlpatterns)),  # Include without namespace
]

urlpatterns += [
    path("auth/logout/", dummy_logout, name="logout"),  # <-- Added dummy logout path
]


# Test cases
class MFAURLTests(MFATestCase):
    def test_mfa_home_url(self):
        """Resolves MFA home URL correctly."""
        url = reverse("mfa_home")
        self.assertEqual(url, "/mfa/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, views.index)

    def test_totp_auth_url(self):
        """Resolves TOTP auth URL correctly."""
        url = reverse("totp_auth")
        self.assertEqual(url, "/mfa/totp/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, totp.auth)

    def test_start_new_otop_url(self):
        """Resolves start new TOTP URL correctly."""
        url = reverse("start_new_otop")
        self.assertEqual(url, "/mfa/totp/start/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, totp.start)

    def test_mfa_methods_list_url(self):
        """Resolves MFA methods list URL correctly."""
        url = reverse("mfa_methods_list")
        self.assertEqual(url, "/mfa/selct_method")
        resolved = resolve(url)
        self.assertEqual(resolved.func, views.show_methods)

    def test_recovery_auth_url(self):
        """Resolves recovery auth URL correctly."""
        url = reverse("recovery_auth")
        self.assertEqual(url, "/mfa/recovery/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, recovery.auth)

    def test_email_auth_url(self):
        """Resolves email auth URL correctly."""
        url = reverse("email_auth")
        self.assertEqual(url, "/mfa/email/auth/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, Email.auth)

    def test_fido2_auth_url(self):
        """Resolves FIDO2 auth URL correctly."""
        url = reverse("fido2_auth")
        self.assertEqual(url, "/mfa/fido2/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, FIDO2.auth)

    def test_u2f_auth_url(self):
        """Resolves U2F auth URL correctly."""
        url = reverse("u2f_auth")
        self.assertEqual(url, "/mfa/u2f/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, U2F.auth)


class TestURLsEdgeCases(MFATestCase):
    """Additional test cases for URLs to achieve 100% coverage."""

    def test_django_urls_import_fallback(self):
        """Handles fallback import path for Django URLs."""
        # Test that the import fallback works when django.urls doesn't exist
        with patch("django.urls.re_path", side_effect=ImportError):
            # This should import from django.conf.urls instead
            from .. import urls

            # Verify that urlpatterns still exists and works
            self.assertTrue(hasattr(urls, "urlpatterns"))
            self.assertGreater(len(urls.urlpatterns), 0)

    def test_all_url_patterns_resolve(self):
        """Resolves all URL patterns successfully."""
        from ..urls import urlpatterns

        # Test a subset of URL patterns that should always work
        test_urls = [
            ("mfa_home", "/mfa/"),
            ("totp_auth", "/mfa/totp/auth"),
            ("start_new_otop", "/mfa/totp/start/"),
            ("get_new_otop", "/mfa/totp/getToken"),
            ("verify_otop", "/mfa/totp/verify"),
            ("totp_recheck", "/mfa/totp/recheck"),
            ("recovery_auth", "/mfa/recovery/auth"),
            ("manage_recovery_codes", "/mfa/recovery/start"),
            ("get_recovery_token_left", "/mfa/recovery/getTokenLeft"),
            ("regen_recovery_tokens", "/mfa/recovery/genTokens"),
            ("recovery_recheck", "/mfa/recovery/recheck"),
            ("start_email", "/mfa/email/start/"),
            ("email_auth", "/mfa/email/auth/"),
            ("start_u2f", "/mfa/u2f/"),
            ("bind_u2f", "/mfa/u2f/bind"),
            ("u2f_auth", "/mfa/u2f/auth"),
            ("u2f_recheck", "/mfa/u2f/process_recheck"),
            ("u2f_verify", "/mfa/u2f/verify"),
            ("start_fido2", "/mfa/fido2/"),
            ("fido2_auth", "/mfa/fido2/auth"),
            ("fido2_begin_auth", "/mfa/fido2/begin_auth"),
            ("fido2_complete_auth", "/mfa/fido2/complete_auth"),
            ("fido2_begin_reg", "/mfa/fido2/begin_reg"),
            ("fido2_complete_reg", "/mfa/fido2/complete_reg"),
            ("fido2_recheck", "/mfa/fido2/recheck"),
            ("start_td", "/mfa/td/"),
            ("add_td", "/mfa/td/add"),
            ("td_sendemail", "/mfa/td/send_link"),
            ("td_get_useragent", "/mfa/td/get-ua"),
            ("td_trust_device", "/mfa/td/trust"),
            ("td_checkTrusted", "/mfa/u2f/checkTrusted"),
            ("td_securedevice", "/mfa/u2f/secure_device"),
            ("mfa_goto", "/mfa/goto/test"),
            ("mfa_methods_list", "/mfa/selct_method"),
            ("mfa_recheck", "/mfa/recheck"),
            ("toggle_key", "/mfa/toggleKey"),
            ("mfa_delKey", "/mfa/delete"),
            ("mfa_reset_cookie", "/mfa/reset"),
        ]

        for name, expected_url in test_urls:
            try:
                if name == "mfa_goto":
                    # Special case for goto URL with parameter
                    url = reverse(name, args=["test"])
                else:
                    url = reverse(name)
                self.assertEqual(
                    url, expected_url, f"URL {name} should resolve to {expected_url}"
                )

                # Test that the URL can be resolved back
                resolved = resolve(url)
                self.assertIsNotNone(
                    resolved.func, f"URL {url} should resolve to a function"
                )

            except Exception as e:
                self.fail(f"Failed to resolve URL {name}: {e}")

    def test_url_patterns_count(self):
        """Verifies all expected URL patterns are present."""
        from ..urls import urlpatterns

        # Should have a reasonable number of URL patterns
        self.assertGreaterEqual(len(urlpatterns), 30)

        # Verify each pattern has required attributes
        for pattern in urlpatterns:
            self.assertTrue(hasattr(pattern, "pattern"))
            self.assertTrue(hasattr(pattern, "callback"))
            if hasattr(pattern, "name"):
                self.assertIsNotNone(pattern.name)

    def test_import_all_modules(self):
        """Verifies all imported modules are accessible."""
        from .. import urls

        # Test that all imported modules are available
        imported_modules = [
            "views",
            "totp",
            "U2F",
            "TrustedDevice",
            "helpers",
            "FIDO2",
            "Email",
            "recovery",
        ]

        for module_name in imported_modules:
            self.assertTrue(
                hasattr(urls, module_name), f"Module {module_name} should be imported"
            )

    def test_url_pattern_names_uniqueness(self):
        """Verifies all URL pattern names are unique."""
        from ..urls import urlpatterns

        names = []
        for pattern in urlpatterns:
            if hasattr(pattern, "name") and pattern.name:
                names.append(pattern.name)

        # Check for duplicates
        unique_names = set(names)
        self.assertEqual(
            len(names), len(unique_names), "All URL pattern names should be unique"
        )

    def test_special_url_patterns(self):
        """Handles special URL patterns like root and goto."""
        # Test root pattern
        url = reverse("mfa_home")
        self.assertEqual(url, "/mfa/")

        # Test goto pattern with parameter
        url = reverse("mfa_goto", args=["totp"])
        self.assertEqual(url, "/mfa/goto/totp")

        # Test that goto can handle various method names
        for method in ["totp", "u2f", "fido2", "recovery", "email"]:
            url = reverse("mfa_goto", args=[method])
            self.assertTrue(url.endswith(f"/goto/{method}"))

    def test_regex_patterns(self):
        """Validates regex patterns work correctly."""
        from django.urls import resolve

        # Test patterns that use regex
        test_cases = [
            ("/mfa/", "mfa_home"),
            ("/mfa/goto/test", "mfa_goto"),
            ("/mfa/totp/start/", "start_new_otop"),
            ("/mfa/email/start/", "start_email"),
            ("/mfa/email/auth/", "email_auth"),
            ("/mfa/u2f/", "start_u2f"),
            ("/mfa/fido2/", "start_fido2"),
            ("/mfa/td/", "start_td"),
        ]

        for url_path, expected_name in test_cases:
            resolved = resolve(url_path)
            self.assertEqual(
                resolved.url_name,
                expected_name,
                f"URL {url_path} should resolve to {expected_name}",
            )

    def test_url_import_error_handling(self):
        """Handles URL import errors gracefully."""
        # This test ensures the import fallback mechanism works
        # by testing that the module can be imported even if some imports fail
        try:
            from .. import urls

            self.assertTrue(hasattr(urls, "urlpatterns"))
        except ImportError:
            self.fail("URL module should handle import errors gracefully")

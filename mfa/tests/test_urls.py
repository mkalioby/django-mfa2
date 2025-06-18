from django.urls import resolve, reverse, path, include
from django.test import override_settings
from .base import MFATestCase, dummy_logout
from mfa.urls import urlpatterns as mfa_urlpatterns
from mfa import views, totp, U2F, TrustedDevice, helpers, FIDO2, Email, recovery
from django.contrib import admin

# Use the original MFA URL patterns without namespace
urlpatterns = [
    path("admin/", admin.site.urls),
    path("mfa/", include(mfa_urlpatterns)),  # Include without namespace
]

urlpatterns += [
    path("auth/logout/", dummy_logout, name="logout"),  # <-- Added dummy logout path
]


# Test cases
class TestMFAURLs(MFATestCase):
    def test_mfa_home_url(self):
        """Test that the MFA home URL resolves correctly."""
        url = reverse("mfa_home")
        self.assertEqual(url, "/mfa/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, views.index)

    def test_totp_auth_url(self):
        """Test that the TOTP auth URL resolves correctly."""
        url = reverse("totp_auth")
        self.assertEqual(url, "/mfa/totp/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, totp.auth)

    def test_start_new_otop_url(self):
        """Test that the start new TOTP URL resolves correctly."""
        url = reverse("start_new_otop")
        self.assertEqual(url, "/mfa/totp/start/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, totp.start)

    def test_mfa_methods_list_url(self):
        """Test that the MFA methods list URL resolves correctly."""
        url = reverse("mfa_methods_list")
        self.assertEqual(url, "/mfa/selct_method")
        resolved = resolve(url)
        self.assertEqual(resolved.func, views.show_methods)

    def test_recovery_auth_url(self):
        """Test that the recovery auth URL resolves correctly."""
        url = reverse("recovery_auth")
        self.assertEqual(url, "/mfa/recovery/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, recovery.auth)

    def test_email_auth_url(self):
        """Test that the email auth URL resolves correctly."""
        url = reverse("email_auth")
        self.assertEqual(url, "/mfa/email/auth/")
        resolved = resolve(url)
        self.assertEqual(resolved.func, Email.auth)

    def test_fido2_auth_url(self):
        """Test that the FIDO2 auth URL resolves correctly."""
        url = reverse("fido2_auth")
        self.assertEqual(url, "/mfa/fido2/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, FIDO2.auth)

    def test_u2f_auth_url(self):
        """Test that the U2F auth URL resolves correctly."""
        url = reverse("u2f_auth")
        self.assertEqual(url, "/mfa/u2f/auth")
        resolved = resolve(url)
        self.assertEqual(resolved.func, U2F.auth)

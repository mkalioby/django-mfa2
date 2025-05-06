from django.test import TestCase, override_settings
from django.urls import reverse, NoReverseMatch
from django.core.exceptions import ImproperlyConfigured
from unittest import SkipTest
from .utils.decorators import (
    skip_if_url_missing,
    skip_if_view_missing,
    skip_if_setting_missing,
    skip_if_feature_disabled,
    skip_if_tdd_pending
)
from .utils.skip_reasons import SkipReason
from .utils.skip_registry import SkipRegistry

class TestDecorators(TestCase):
    """Test suite for the skip decorators.
    
    These tests verify that the decorators correctly handle test skipping
    and registry updates. They use standard Django testing methods since they
    are testing infrastructure code.
    """

    def setUp(self):
        """Set up test environment."""
        SkipRegistry.clear()

    def test_skip_if_url_missing(self):
        """Test URL missing decorator."""
        @skip_if_url_missing('nonexistent_url')
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        self.assertIn("URL 'nonexistent_url' not found", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    def test_skip_if_view_missing(self):
        """Test view missing decorator."""
        @skip_if_view_missing('nonexistent_view')
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        self.assertIn("View 'nonexistent_view' not found", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    def test_skip_if_setting_missing(self):
        """Test setting missing decorator."""
        @skip_if_setting_missing('NONEXISTENT_SETTING')
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        self.assertIn("Setting 'NONEXISTENT_SETTING' not configured", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    @override_settings(MFA_FEATURE_ENABLED=False)
    def test_skip_if_feature_disabled(self):
        """Test feature disabled decorator."""
        @skip_if_feature_disabled('feature')
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        self.assertIn("Feature 'feature' is disabled", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    def test_skip_if_tdd_pending(self):
        """Test TDD pending decorator."""
        @skip_if_tdd_pending("Implementation pending")
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        self.assertIn("Implementation pending", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    def test_decorator_chaining(self):
        """Test that decorators can be chained."""
        @skip_if_url_missing('nonexistent_url')
        @skip_if_setting_missing('NONEXISTENT_SETTING')
        def test_func(self):
            pass

        with self.assertRaises(SkipTest) as cm:
            test_func(self)

        # Should fail on first decorator (URL)
        self.assertIn("URL 'nonexistent_url' not found", str(cm.exception))
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)

    def test_decorator_registry_integration(self):
        """Test that decorators properly update the skip registry."""
        @skip_if_url_missing('nonexistent_url')
        def test_func(self):
            pass

        try:
            test_func(self)
        except SkipTest:
            pass

        summary = SkipRegistry.get_skip_summary()
        self.assertIn(SkipReason.MISSING_URL, summary)
        self.assertIn(('test_func', "URL 'nonexistent_url' not found"), summary[SkipReason.MISSING_URL]) 
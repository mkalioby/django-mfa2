from django.test import TestCase
from .utils.skip_registry import SkipRegistry
from .utils.skip_reasons import SkipReason

class TestSkipRegistry(TestCase):
    """Test suite for the skip registry.
    
    These tests verify that the skip registry correctly tracks and formats
    skipped tests. They use standard Django testing methods since they are
    testing infrastructure code.
    """

    def setUp(self):
        """Set up test environment."""
        SkipRegistry.clear()

    def test_register_skip(self):
        """Test registering a skipped test."""
        test_name = "test_mfa_authentication"
        reason = SkipReason.MISSING_URL
        details = "URL 'mfa:verify' not found"
        
        SkipRegistry.register_skip(test_name, reason, details)
        
        summary = SkipRegistry.get_skip_summary()
        self.assertIn(reason, summary)
        self.assertIn((test_name, details), summary[reason])

    def test_clear_registry(self):
        """Test clearing the registry."""
        SkipRegistry.register_skip("test1", SkipReason.MISSING_URL, "details1")
        SkipRegistry.register_skip("test2", SkipReason.MISSING_VIEW, "details2")
        
        SkipRegistry.clear()
        
        summary = SkipRegistry.get_skip_summary()
        self.assertEqual(len(summary), 0)

    def test_format_summary(self):
        """Test formatting the skip summary."""
        # Add some test skips
        SkipRegistry.register_skip(
            "test_security",
            SkipReason.SECURITY_GAP,
            "Brute force protection not implemented"
        )
        SkipRegistry.register_skip(
            "test_middleware",
            SkipReason.MIDDLEWARE_DISABLED,
            "MFA middleware is disabled"
        )
        SkipRegistry.register_skip(
            "test_url",
            SkipReason.MISSING_URL,
            "URL 'mfa:verify' not found"
        )
        
        summary = SkipRegistry.format_summary()
        
        # Verify summary contains expected sections
        self.assertIn("=== CRITICAL: Security Features ===", summary)
        self.assertIn("=== HIGH: Core Functionality ===", summary)
        self.assertIn("=== HIGH: URL & View Implementation ===", summary)
        
        # Verify test details are included
        self.assertIn("test_security", summary)
        self.assertIn("test_middleware", summary)
        self.assertIn("test_url", summary)
        
        # Verify implementation guidance is included
        self.assertIn("=== Implementation Guidance ===", summary)
        self.assertIn("1. Start with security-critical features", summary)
        
        # Verify total count is included
        self.assertIn("Found 3 test(s) requiring implementation", summary)

    def test_skip_priority_ordering(self):
        """Test that skips are ordered by priority."""
        # Add skips in random order
        SkipRegistry.register_skip("test1", SkipReason.MISSING_DEPENDENCY, "details1")
        SkipRegistry.register_skip("test2", SkipReason.SECURITY_GAP, "details2")
        SkipRegistry.register_skip("test3", SkipReason.MISSING_URL, "details3")
        
        summary = SkipRegistry.format_summary()
        
        # Verify security gap appears before missing URL
        security_index = summary.find("test2")
        url_index = summary.find("test3")
        self.assertLess(security_index, url_index)
        
        # Verify missing URL appears before missing dependency
        dependency_index = summary.find("test1")
        self.assertLess(url_index, dependency_index) 
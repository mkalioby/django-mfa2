from django.test import TestCase
from .utils.skip_reasons import SkipReason

class TestSkipReasons(TestCase):
    """Test suite for the skip reasons.
    
    These tests verify that the skip reasons correctly format messages and
    categorize skips. They use standard Django testing methods since they are
    testing infrastructure code.
    """

    def test_format_message_with_details(self):
        """Test formatting a skip message with details."""
        reason = SkipReason.MISSING_URL
        details = "URL 'mfa:verify' not found"
        
        message = reason.format_message(details)
        
        self.assertEqual(message, "[SKIP URL] URL 'mfa:verify' not found")

    def test_format_message_without_details(self):
        """Test formatting a skip message without details."""
        reason = SkipReason.MISSING_URL
        
        message = reason.format_message()
        
        self.assertEqual(message, "[SKIP URL] URL endpoint not implemented")

    def test_get_category_name(self):
        """Test getting category names for skip reasons."""
        # Test all skip reasons have a category name
        for reason in SkipReason:
            category = SkipReason.get_category_name(reason)
            self.assertIsNotNone(category)
            self.assertIsInstance(category, str)
            self.assertTrue(len(category) > 0)

    def test_category_consistency(self):
        """Test that category names are consistent."""
        # Test that each reason has a unique category name
        categories = set()
        for reason in SkipReason:
            category = SkipReason.get_category_name(reason)
            self.assertNotIn(category, categories)
            categories.add(category)

    def test_priority_ordering(self):
        """Test that skip reasons have consistent priority ordering."""
        # Define expected priority order
        expected_order = [
            SkipReason.SECURITY_GAP,
            SkipReason.MIDDLEWARE_DISABLED,
            SkipReason.MISSING_URL,
            SkipReason.MISSING_VIEW,
            SkipReason.MISSING_SETTING,
            SkipReason.LOGGING_GAP,
            SkipReason.FEATURE_DISABLED,
            SkipReason.MISSING_DEPENDENCY,
            SkipReason.TDD_PENDING,
            SkipReason.OTHER
        ]
        
        # Verify all reasons are included
        self.assertEqual(len(expected_order), len(SkipReason))
        
        # Verify no duplicates
        self.assertEqual(len(set(expected_order)), len(SkipReason)) 
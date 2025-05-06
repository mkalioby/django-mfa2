from django.test import TestCase
from django.test.runner import DiscoverRunner
from django.test.utils import get_runner
from django.conf import settings
from .skip_registry import SkipRegistry, SkipReason

class MFATestRunner(DiscoverRunner):
    """Custom test runner for MFA tests that handles skip announcements."""

    def run_suite(self, suite, **kwargs):
        """Run the test suite and print skip announcements."""
        result = super().run_suite(suite, **kwargs)
        
        # Print skip announcements after all tests
        summary = SkipRegistry.get_skip_summary()
        if summary:
            print("\nSkip Announcements:")
            for reason, skips in summary.items():
                if skips:
                    print(f"\n{reason.get_category_name()}:")
                    for test_name, details in skips:
                        print(f"  - {test_name}: {details}")
        
        return result

def get_mfa_test_runner():
    """Get the MFA test runner instance."""
    return get_runner(settings, 'mfa.tests.utils.runners.MFATestRunner')

class TestMFATestRunner(TestCase):
    """Test suite for the MFA test runner.
    
    These tests verify that the custom test runner correctly handles test execution
    and skip announcements. They use standard Django testing methods since they
    are testing infrastructure code.
    """

    def test_runner_initialization(self):
        """Test that the runner initializes correctly."""
        runner = MFATestRunner()
        self.assertIsInstance(runner, DiscoverRunner)

    def test_skip_registry_integration(self):
        """Test integration with the skip registry."""
        # Clear any existing skips
        SkipRegistry.clear()
        
        # Add a test skip
        SkipRegistry.register_skip('test_name', SkipReason.MISSING_URL, 'test_reason')
        
        # Create and run a test suite
        runner = MFATestRunner()
        suite = runner.build_suite(['mfa.tests'])
        result = runner.run_suite(suite)
        
        # Verify skip was registered
        summary = SkipRegistry.get_skip_summary()
        self.assertTrue(len(summary) > 0)
        self.assertIn(SkipReason.MISSING_URL, summary)
        self.assertIn(('test_name', 'test_reason'), summary[SkipReason.MISSING_URL])

    def test_runner_getter(self):
        """Test the get_mfa_test_runner function."""
        runner = get_mfa_test_runner()
        self.assertIsInstance(runner, MFATestRunner) 
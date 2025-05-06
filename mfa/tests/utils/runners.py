from django.test.runner import DiscoverRunner
from django.test.utils import get_runner
from django.conf import settings
from .skip_registry import SkipRegistry

class MFATestRunner(DiscoverRunner):
    """Custom test runner for MFA tests that handles skip announcements."""

    def run_suite(self, suite, **kwargs):
        """Run the test suite and print skip announcements."""
        result = super().run_suite(suite, **kwargs)
        
        # Print skip announcements after all tests
        if SkipRegistry.has_skips():
            print("\nSkip Announcements:")
            for category, skips in SkipRegistry.get_skips().items():
                if skips:
                    print(f"\n{category}:")
                    for test_name, reason in skips.items():
                        print(f"  - {test_name}: {reason}")
        
        return result

def get_mfa_test_runner():
    """Get the MFA test runner instance."""
    return get_runner(settings, 'mfa.tests.utils.runners.MFATestRunner') 
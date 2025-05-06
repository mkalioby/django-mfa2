from typing import Dict, List, Tuple, Optional
from .skip_reasons import SkipReason

class SkipRegistry:
    """Central registry for tracking skipped tests and their reasons"""
    _registry: Dict[SkipReason, List[Tuple[str, Optional[str]]]] = {}
    
    @classmethod
    def register_skip(cls, test_name: str, reason: SkipReason, details: str = None) -> None:
        """Register a skipped test with its reason and optional details"""
        if reason not in cls._registry:
            cls._registry[reason] = []
        cls._registry[reason].append((test_name, details))
    
    @classmethod
    def get_skip_summary(cls) -> Dict[SkipReason, List[Tuple[str, Optional[str]]]]:
        """Get a summary of all skipped tests grouped by reason"""
        return {
            reason: sorted(tests) for reason, tests in cls._registry.items()
        }
    
    @classmethod
    def clear(cls) -> None:
        """Clear the registry (useful between test runs)"""
        cls._registry.clear()
    
    @classmethod
    def format_summary(cls) -> str:
        """Format a human-readable summary of skipped tests with implementation guidance"""
        if not cls._registry:
            return ""
            
        summary = []
        
        # Define priority order for skip reasons
        priority_order = {
            SkipReason.SECURITY_GAP: 1,
            SkipReason.MIDDLEWARE_DISABLED: 2,
            SkipReason.MISSING_URL: 3,
            SkipReason.MISSING_VIEW: 3,
            SkipReason.MISSING_SETTING: 4,
            SkipReason.LOGGING_GAP: 5,
            SkipReason.FEATURE_DISABLED: 6,
            SkipReason.MISSING_DEPENDENCY: 7,
            SkipReason.TDD_PENDING: 8,
            SkipReason.OTHER: 9
        }
        
        # Sort reasons by priority
        sorted_reasons = sorted(
            cls._registry.items(),
            key=lambda x: priority_order.get(x[0], 999)
        )
        
        # Track total skips
        total_skips = 0
        
        # Group by priority level
        current_priority = None
        for reason, tests in sorted_reasons:
            priority = priority_order.get(reason, 999)
            
            # Add priority header if it changes
            if priority != current_priority:
                current_priority = priority
                if priority == 1:
                    summary.append("\n=== CRITICAL: Security Features ===")
                elif priority == 2:
                    summary.append("\n=== HIGH: Core Functionality ===")
                elif priority == 3:
                    summary.append("\n=== HIGH: URL & View Implementation ===")
                elif priority == 4:
                    summary.append("\n=== MEDIUM: Configuration ===")
                elif priority == 5:
                    summary.append("\n=== MEDIUM: Monitoring & Logging ===")
                else:
                    summary.append("\n=== LOW: Additional Features ===")
            
            # Group tests by their details
            grouped_tests = {}
            for test_name, details in sorted(tests):
                if details not in grouped_tests:
                    grouped_tests[details] = []
                grouped_tests[details].append(test_name)
            
            # Add category header
            category_name = SkipReason.get_category_name(reason)
            summary.append(f"\n[{category_name}]")
            
            # Add tests grouped by their details
            for details, test_names in grouped_tests.items():
                if details:
                    summary.append(f"  {details}")
                for test_name in test_names:
                    summary.append(f"    - {test_name}")
            
            total_skips += len(tests)
        
        # Add implementation guidance
        summary.append("\n=== Implementation Guidance ===")
        summary.append("1. Start with security-critical features")
        summary.append("2. Enable and configure middleware")
        summary.append("3. Implement missing URLs and views")
        summary.append("4. Add required settings")
        summary.append("5. Implement logging and monitoring")
        
        # Add total count
        summary.append(f"\nFound {total_skips} test(s) requiring implementation.")
        
        return "\n".join(summary) 
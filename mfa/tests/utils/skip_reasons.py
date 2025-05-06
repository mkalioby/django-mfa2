from enum import Enum

class SkipReason(Enum):
    """Categories for test skips with standardized messages"""
    MISSING_URL = "URL endpoint not implemented"
    MISSING_VIEW = "View function not implemented"
    MISSING_SETTING = "Required setting not configured"
    MISSING_DEPENDENCY = "External dependency not available"
    FEATURE_DISABLED = "Feature explicitly disabled"
    TDD_PENDING = "Test-driven development pending implementation"
    SECURITY_GAP = "Security feature not implemented"
    LOGGING_GAP = "Logging feature not implemented"
    MIDDLEWARE_DISABLED = "Middleware functionality disabled"
    OTHER = "Other reason"

    def format_message(self, details: str = None) -> str:
        """Format a consistent skip message"""
        category_name = self.get_category_name(self)
        if details:
            return f"[{category_name}] {details}"
        return f"[{category_name}] {self.value}"

    @classmethod
    def get_category_name(cls, reason) -> str:
        """Get the display name for a skip category"""
        category_names = {
            cls.MISSING_URL: "SKIP URL",
            cls.MISSING_VIEW: "SKIP VIEW",
            cls.SECURITY_GAP: "SECURITY GAP",
            cls.LOGGING_GAP: "SKIP LOGGING",
            cls.MIDDLEWARE_DISABLED: "SKIP MIDDLEWARE",
            cls.MISSING_SETTING: "SKIP SETTING",
            cls.MISSING_DEPENDENCY: "SKIP DEPENDENCY",
            cls.FEATURE_DISABLED: "SKIP FEATURE",
            cls.TDD_PENDING: "SKIP TDD",
            cls.OTHER: "SKIP OTHER"
        }
        return category_names.get(reason, reason.name) 
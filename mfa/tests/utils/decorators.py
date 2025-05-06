from functools import wraps
from django.urls import reverse, NoReverseMatch
from django.core.exceptions import ImproperlyConfigured
from unittest import SkipTest
from .skip_reasons import SkipReason
from .skip_registry import SkipRegistry

def skip_if_url_missing(url_name: str):
    """Skip test if URL pattern is not found"""
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            try:
                reverse(url_name)
                return test_func(self, *args, **kwargs)
            except NoReverseMatch:
                SkipRegistry.register_skip(
                    test_func.__name__,
                    SkipReason.MISSING_URL,
                    f"URL '{url_name}' not found"
                )
                raise SkipTest(SkipReason.MISSING_URL.format_message(f"URL '{url_name}' not found"))
        return wrapper
    return decorator

def skip_if_view_missing(view_name: str):
    """Skip test if view function is not implemented"""
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            try:
                from mfa import views
                if not hasattr(views, view_name):
                    SkipRegistry.register_skip(
                        test_func.__name__,
                        SkipReason.MISSING_VIEW,
                        f"View '{view_name}' not found"
                    )
                    raise SkipTest(SkipReason.MISSING_VIEW.format_message(f"View '{view_name}' not found"))
                return test_func(self, *args, **kwargs)
            except ImportError:
                SkipRegistry.register_skip(
                    test_func.__name__,
                    SkipReason.MISSING_VIEW,
                    "Could not import views module"
                )
                raise SkipTest(SkipReason.MISSING_VIEW.format_message("Could not import views module"))
        return wrapper
    return decorator

def skip_if_setting_missing(setting_name: str):
    """Skip test if required setting is not configured"""
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            from django.conf import settings
            if not hasattr(settings, setting_name):
                SkipRegistry.register_skip(
                    test_func.__name__,
                    SkipReason.MISSING_SETTING,
                    f"Setting '{setting_name}' not configured"
                )
                raise SkipTest(SkipReason.MISSING_SETTING.format_message(f"Setting '{setting_name}' not configured"))
            return test_func(self, *args, **kwargs)
        return wrapper
    return decorator

def skip_if_feature_disabled(feature_name: str):
    """Skip test if feature is explicitly disabled"""
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            from django.conf import settings
            if getattr(settings, f'MFA_{feature_name.upper()}_ENABLED', False) is False:
                SkipRegistry.register_skip(
                    test_func.__name__,
                    SkipReason.FEATURE_DISABLED,
                    f"Feature '{feature_name}' is disabled"
                )
                raise SkipTest(SkipReason.FEATURE_DISABLED.format_message(f"Feature '{feature_name}' is disabled"))
            return test_func(self, *args, **kwargs)
        return wrapper
    return decorator

def skip_if_tdd_pending(reason: str = None):
    """Skip test that is part of TDD process"""
    def decorator(test_func):
        @wraps(test_func)
        def wrapper(self, *args, **kwargs):
            SkipRegistry.register_skip(
                test_func.__name__,
                SkipReason.TDD_PENDING,
                reason or "Test-driven development pending implementation"
            )
            raise SkipTest(SkipReason.TDD_PENDING.format_message(reason or "Test-driven development pending implementation"))
        return wrapper
    return decorator 
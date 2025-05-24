# MFA Testing Framework

This directory contains the test suite for the Django MFA application. The testing framework is built around the `MFATestCase` base class, which provides a comprehensive set of utilities and helpers for testing MFA functionality.

## Testing Philosophy

The testing framework follows these key principles:

1. **Setup**: Each test starts with a well-defined state including:
   - A test user with known credentials
   - Cleared cache
   - Controlled session state
   - Preserved and restorable settings

2. **Isolation**: Tests are designed to be independent and self-contained:
   - Each test resets to a known state
   - Original settings are restored after each test
   - Cache and session data are cleared
   - All MFA keys are removed between tests

3. **Flexibility**: The framework supports testing of:
   - Multiple MFA methods (TOTP, Recovery codes, etc.)
   - Both enabled and disabled states
   - Various session configurations
   - Different URL patterns (namespaced and non-namespaced)

## MFATestCase Features

The `MFATestCase` class provides several key features:

### User and Authentication Management
- Automatic test user creation
- Session management helpers
- MFA key creation utilities for different methods

### MFA State Verification
- Session state verification
- Key state checking
- Settings validation
- URL resolution testing

### Helper Methods
```python
# Create MFA keys
create_totp_key(enabled=True)
create_recovery_key(enabled=True)

# Session management
setup_mfa_session(method="TOTP", verified=True, id=1)
verify_mfa_session_state(expected_verified, expected_method, expected_id)

# TOTP testing
get_valid_totp_token()
get_invalid_totp_token()

# URL handling
get_mfa_url(url_name, *args, **kwargs)
verify_url_requires_mfa(url, method="get", data=None)
```

## Writing New Tests

When writing new tests:

1. **Inherit from MFATestCase**:
   ```python
   from .base import MFATestCase

   class TestYourFeature(MFATestCase):
       def test_your_functionality(self):
           # Your test code here
   ```

2. **Use the provided helpers**:
   - Use `create_totp_key()` or `create_recovery_key()` for key setup
   - Use `setup_mfa_session()` to configure the session state
   - Use verification methods to assert expected states

3. **Clean up properly**:
   - The base class handles most cleanup automatically
   - Add any additional cleanup in `tearDown()` if needed

4. **Test edge cases**:
   - Test both successful and failure scenarios
   - Verify behavior with different settings configurations
   - Test with various session states

## Configuration

The test framework supports various settings that can be overridden using `@override_settings`:

```python
@override_settings(
    MFA_REQUIRED=True,
    MFA_UNALLOWED_METHODS=(),
    MFA_HIDE_DISABLE=(),
    # ... other settings
)
def test_your_feature(self):
    # Test code
```

## Test Session Management

The testing framework includes a standalone `create_session()` function that simulates the MFA login process:

```python
def create_session(request, username):
    """Create a test session for MFA authentication."""
```

This function serves as a test implementation of the `MFA_LOGIN_CALLBACK` setting. It:
- Retrieves the user by username
- Sets up the authentication backend
- Logs the user in using Django's login system
- Redirects to the MFA home page

### Usage

1. **In Settings Override**:
   ```python
   @override_settings(
       MFA_LOGIN_CALLBACK='mfa.tests.base.create_session'
   )
   def test_your_feature(self):
       # Test code
   ```

2. **Purpose**:
   - Simulates the real-world login process in tests
   - Provides a reference implementation for custom login callbacks
   - Ensures consistent session creation across tests

This implementation mirrors the example from `example.auth.create_session`

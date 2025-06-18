# MFA Testing Framework

This directory contains a partial test suite built around the `MFATestCase` base class.

Currently, only infrastructure and totp prototype tests exist. Once the style of tests is agreed, the rest of the suite will be written.

## Quick Start

```python
from .base import MFATestCase

class TestYourFeature(MFATestCase):
    def test_your_functionality(self):
        # Create test keys
        key = self.create_totp_key(enabled=True)
        
        # Setup session
        self.setup_mfa_session(method="TOTP", verified=True, id=key.id)
        
        # Test your functionality
        response = self.client.get(self.get_mfa_url("mfa_home"))
        self.assertEqual(response.status_code, 200)
```

## Key Features

### Helper Methods
```python
# MFA Key Creation
create_totp_key(enabled=True)
create_recovery_key(enabled=True)
create_email_key(enabled=True)

# Session Management
setup_mfa_session(method="TOTP", verified=True, id=1)
assertMfaSessionVerified(method="TOTP", id=1)
assertMfaSessionUnverified()

# TOTP Testing
get_valid_totp_token()
get_invalid_totp_token()

# URL Handling
get_mfa_url("mfa_home")  # Handles namespaced/non-namespaced URLs
```

### Test Session Management
```python
@override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
def test_with_login_callback(self):
    # Test code here
```

### Logout URL Handling
The test framework includes a dummy logout URL to handle template rendering:
- **Purpose**: Templates may reference `{% url 'logout' %}` which doesn't exist in the MFA app
- **Solution**: `dummy_logout` view in `base.py` provides a placeholder response
- **Usage**: Automatically appended to test URL configurations (`test_base.py`, `test_urls.py`)
- **No action required**: Tests work transparently without template errors

## MFA Key Type System

### Database Storage Format (for creating keys)
- `"TOTP"` - Time-based One-Time Password
- `"Email"` - Email token authentication  
- `"U2F"` - Universal 2nd Factor security key
- `"FIDO2"` - FIDO2 security key/biometric
- `"Trusted Device"` - Device-based authentication (note the space)
- `"RECOVERY"` - Recovery codes

### Configuration Format (for settings)
- `"TOTP"`, `"Email"`, `"U2F"`, `"FIDO2"`, `"RECOVERY"`
- `"Trusted_Devices"` (note the underscore, different from storage)

### Example Usage
```python
# Creating keys - use database format
key = User_Keys.objects.create(key_type="Trusted Device", ...)

# Testing settings - use configuration format  
with override_settings(MFA_RENAME_METHODS={"Trusted_Devices": "Custom Name"}):
    ...
```

## Test Isolation

Each test automatically:
- Creates a fresh test user
- Clears cache and session data
- Removes all MFA keys
- Restores original settings after completion

## Configuration Override

```python
@override_settings(
    MFA_REQUIRED=True,
    MFA_UNALLOWED_METHODS=("TOTP",),
    MFA_HIDE_DISABLE=("RECOVERY",),
    MFA_RENAME_METHODS={"TOTP": "Authenticator App"}
)
def test_with_custom_settings(self):
    # Test code
```

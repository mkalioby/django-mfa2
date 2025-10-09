# MFA Testing Framework

## Quick Start

```python
from .mfatestcase import MFATestCase

class TestYourFeature(MFATestCase):
    def test_your_functionality(self):
        key = self.create_totp_key(enabled=True)
        self.setup_mfa_session(method="TOTP", verified=True, id=key.id)
        response = self.client.get(self.get_mfa_url("mfa_home"))
        self.assertEqual(response.status_code, 200)
```

## Architecture

### Base Class
`MFATestCase` extends Django's `TestCase` or `TransactionTestCase` (auto-selected based on database engine) to handle partial authentication states during MFA flows.

### Helper Methods
See `mfatestcase_usage_analysis.md` for complete reference.

### Key Creation
```python
# All MFA key types with proper properties
totp_key = self.create_totp_key(enabled=True)           # secret_key property
recovery_key = self.create_recovery_key(enabled=True)   # codes array
email_key = self.create_email_key(enabled=True)         # empty properties
fido2_key = self.create_fido2_key(enabled=True)         # device, type (binary)
trusted_device_key = self.create_trusted_device_key(enabled=True)  # user_agent, ip_address, key, status
```

### Session Management
```python
@override_settings(MFA_LOGIN_CALLBACK="mfa.tests.create_session")
def test_with_login_callback(self):
    # Test code here

# For recovery tests needing lastBackup flag:
self.setup_mfa_session(method="RECOVERY", verified=True, id=key.id)
session = self.client.session
session["mfa"]["lastBackup"] = True
session.save()
```

### Mock Helpers
- `create_mock_request()` - For functions expecting `request.user`
- `create_http_request_mock()` - For functions with `@never_cache` decorator

### Test Isolation
Each test automatically: creates fresh user, clears cache/session, removes MFA keys, restores settings.

## Username Resolution Architecture

MFA uses different username strategies based on operation context:

### Authentication Flows
Use `request.session["base_username"]` for:
- `*_auth()` functions (recovery.auth, totp.auth, email.auth, etc.)
- `*_recheck()` functions (recovery.recheck, totp.recheck, etc.)
- Any MFA verification operation

**Rationale**: Handles partial authentication states, custom user models, and timing issues.

### Management Operations
Use `request.user.username` for:
- `views.index()` - MFA key management page
- `recovery.delTokens()`, `recovery.genTokens()`, `recovery.getTokenLeft()`
- Any `@login_required` operation

**Rationale**: Requires full authentication, follows Django conventions.

### Custom User Model Integration
```python
# In your Django view
def login_view(request):
    username = request.user.get_username()  # Works with custom user models
    return verify(request, username)  # MFA stores in session["base_username"]
```

**Testing**: Use `setup_base_session()` or `setup_mfa_session()` for proper session setup.

## Configuration

```python
@override_settings(
    MFA_REQUIRED=True,
    MFA_UNALLOWED_METHODS=("TOTP",),
    MFA_HIDE_DISABLE=("RECOVERY",),
    MFA_RENAME_METHODS={"TOTP": "Authenticator App"}
)
def test_with_custom_settings(self):
    # Test code

# Debug email templates
@override_settings(EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend")
def test_email_template_output(self):
    # Email output appears in console
```

## Docstring Format

**Required Elements:**
- **Function Path**: `mfa.totp.verify_login()` - exact module and function
- **Code Path**: `with valid TOTP token` - scenario being tested
- **Step-by-Step Flow**: sequence of function calls and data flow
- **Mock Annotations**: append `(Mocked)` to mocked steps
- **Purpose**: business logic being verified

**Example:**
```python
def test_auth_with_mfa_recheck_settings(self):
    """Test mfa.totp.auth() with MFA_RECHECK settings enabled.

    Exercises the complete flow:
    1. auth() receives POST request with valid OTP token
    2. verify_login() validates token against user's TOTP keys
    3. mfa session is created with verified status and method
    4. set_next_recheck() calculates next recheck timestamp
    5. login() is called to complete authentication (Mocked)

    Purpose: Verify that TOTP authentication properly integrates with
    recheck mechanism, ensuring session security and user experience.
    """
```

## Best Practices

1. **Use `@override_settings`** for configuration-specific tests
2. **Use helper methods** from `MFATestCase` for common setup
3. **Write tests for new helper methods** - they are critical
4. **Base class tearDown()** is called automatically unless overridden (then call `super().tearDown()`)

## File Structure

### Base Class
- `mfatestcase.py` - MFATestCase base class and helpers
- `test_mfatestcase.py` - Base class tests
- `mfatestcase_usage_analysis.md` - Helper method reference
- `MFA_Methods_Diagrams.md` - Mermaid diagrams

### Test Modules
- `test_totp.py` - TOTP authentication
- `test_recovery.py` - Recovery code authentication
- `test_email.py` - Email token authentication
- `test_fido2.py` - FIDO2 authentication
- `test_trusteddevice.py` - TrustedDevice authentication
- `test_u2f.py` - U2F authentication
- `test_config.py` - Configuration tests
- `test_models.py` - Model tests
- `test_urls.py` - URL routing tests
- `test_views.py` - View integration tests
- `test_helpers.py` - Helper function tests

from django.conf import settings

# Ensure the MFA app is in INSTALLED_APPS
if 'mfa' not in settings.INSTALLED_APPS:
    settings.INSTALLED_APPS += ('mfa',)

# Configure URL namespaces
ROOT_URLCONF = 'mfa.tests.test_urls'

# MFA-specific settings
MFA_UNALLOWED_METHODS = ()
MFA_HIDE_DISABLE = ()
MFA_RENAME_METHODS = {}
TOKEN_ISSUER_NAME = 'Test Issuer'
MFA_ENFORCE_RECOVERY_METHOD = False

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
MFA_EMAIL_SUBJECT = 'Your verification code'
MFA_EMAIL_FROM = 'security@example.com'

# FIDO2 settings
FIDO_SERVER_ID = 'example.com'
FIDO_SERVER_NAME = 'Test Server'
FIDO_AUTHENTICATOR_ATTACHMENT = 'cross-platform'
FIDO_USER_VERIFICATION = 'preferred'
FIDO_AUTHENTICATION_TIMEOUT = 30000 
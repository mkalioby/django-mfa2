# MFA tests package

"""Test package for MFA application."""

# Import create_session function to make it available as tests.create_session
# This allows it to be used as MFA_LOGIN_CALLBACK in test settings
from .mfatestcase import create_session

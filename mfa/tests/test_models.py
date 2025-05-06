from django.test import override_settings
from jose import jwt
from django.conf import settings
import unittest

from mfa.models import User_Keys
from .base import MFATestCase, skip_if_setting_missing
from .utils import (
    skip_if_middleware_disabled,
    skip_if_security_gap,
    skip_if_logging_gap
)


class UserKeysModelTestCase(MFATestCase):
    """Test cases for the User_Keys model."""
    
    def test_user_keys_creation(self):
        """Test that a User_Keys object can be created correctly."""
        # Create a basic user key
        key = User_Keys.objects.create(
            username=self.username,
            key_type='TOTP',
            properties={'secret_key': 'test_secret'},
            enabled=True
        )
        
        # Verify the key was created with the expected values
        self.assertEqual(key.username, self.username)
        self.assertEqual(key.key_type, 'TOTP')
        self.assertEqual(key.properties['secret_key'], 'test_secret')
        self.assertTrue(key.enabled)
        self.assertIsNone(key.expires)
        self.assertIsNone(key.last_used)
    
    @skip_if_setting_missing('SECRET_KEY')
    def test_trusted_device_signature(self):
        """Test that a trusted device key generates a signature automatically."""
        # Create a trusted device key
        key = User_Keys.objects.create(
            username=self.username,
            key_type='Trusted Device',
            properties={'key': 'device_key'},
            enabled=True
        )
        
        # Verify the signature was generated
        self.assertIn('signature', key.properties)
        
        # Decode the signature and verify its contents
        decoded = jwt.decode(key.properties['signature'], settings.SECRET_KEY)
        self.assertEqual(decoded['username'], self.username)
        self.assertEqual(decoded['key'], 'device_key')
    
    def test_string_representation(self):
        """Test the string representation of a User_Keys object."""
        key = User_Keys.objects.create(
            username=self.username,
            key_type='TOTP',
            properties={'secret_key': 'test_secret'},
            enabled=True
        )
        
        expected_str = f"{self.username} -- TOTP"
        self.assertEqual(str(key), expected_str)
        self.assertEqual(key.__unicode__(), expected_str)
    
    def test_user_keys_update(self):
        """Test updating a User_Keys object."""
        # Create a key
        key = User_Keys.objects.create(
            username=self.username,
            key_type='TOTP',
            properties={'secret_key': 'old_secret'},
            enabled=True
        )
        
        # Update the key
        key.properties = {'secret_key': 'new_secret'}
        key.enabled = False
        key.save()
        
        # Refresh from database
        key.refresh_from_db()
        
        # Verify the updates
        self.assertEqual(key.properties['secret_key'], 'new_secret')
        self.assertFalse(key.enabled)

    @unittest.skip("[SECURITY GAP] Key validation not implemented: Missing validation checks")
    @skip_if_security_gap("Key validation not implemented")
    def test_key_validation(self):
        """Test key validation security."""
        pass

    @unittest.skip("[SKIP LOGGING] Model logging not implemented: Missing audit trail")
    @skip_if_logging_gap("Model logging not implemented")
    def test_model_logging(self):
        """Test model audit logging."""
        pass

    @unittest.skip("[SECURITY GAP] Key rotation not implemented: Missing rotation mechanism")
    @skip_if_security_gap("Key rotation not implemented")
    def test_key_rotation(self):
        """Test key rotation security."""
        pass 
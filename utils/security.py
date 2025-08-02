"""Security utility functions."""

import hashlib
import hmac
import secrets
import base64
from typing import Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.core.signing import Signer, BadSignature
from django.utils.encoding import force_bytes


class EncryptionManager:
    """Manager for encryption/decryption operations."""
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption manager.
        
        Args:
            key: Encryption key (if None, uses Django SECRET_KEY)
        """
        if key is None:
            key = self._derive_key_from_secret()
        self.fernet = Fernet(key)
    
    def _derive_key_from_secret(self) -> bytes:
        """Derive encryption key from Django SECRET_KEY."""
        password = force_bytes(settings.SECRET_KEY)
        salt = b'django-shared-libs'  # Use consistent salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data.
        
        Args:
            data: Data to encrypt
        
        Returns:
            Base64 encoded encrypted data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
        
        Returns:
            Decrypted data as string
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {e}")


def generate_salt(length: int = 32) -> str:
    """
    Generate a random salt.
    
    Args:
        length: Length of salt in bytes
    
    Returns:
        Base64 encoded salt
    """
    salt = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(salt).decode('utf-8')


def hash_password(password: str, salt: Optional[str] = None, iterations: int = 100000) -> tuple:
    """
    Hash password using PBKDF2.
    
    Args:
        password: Password to hash
        salt: Salt (if None, generates new one)
        iterations: Number of iterations
    
    Returns:
        Tuple of (hashed_password, salt)
    """
    if salt is None:
        salt = generate_salt()
    
    salt_bytes = base64.urlsafe_b64decode(salt.encode('utf-8'))
    password_bytes = password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=iterations,
    )
    
    key = kdf.derive(password_bytes)
    hashed = base64.urlsafe_b64encode(key).decode('utf-8')
    
    return hashed, salt


def verify_password(password: str, hashed_password: str, salt: str, iterations: int = 100000) -> bool:
    """
    Verify password against hash.
    
    Args:
        password: Password to verify
        hashed_password: Hashed password
        salt: Salt used for hashing
        iterations: Number of iterations used
    
    Returns
    """
    pass
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
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        computed_hash, _ = hash_password(password, salt, iterations)
        return hmac.compare_digest(computed_hash, hashed_password)
    except Exception:
        return False


def generate_api_key(length: int = 32) -> str:
    """
    Generate a secure API key.
    
    Args:
        length: Length of the key
    
    Returns:
        URL-safe API key
    """
    return secrets.token_urlsafe(length)


def generate_otp(length: int = 6) -> str:
    """
    Generate a numeric OTP.
    
    Args:
        length: Length of OTP
    
    Returns:
        Numeric OTP string
    """
    return ''.join(secrets.choice('0123456789') for _ in range(length))


def create_signature(data: str, secret: Optional[str] = None) -> str:
    """
    Create HMAC signature for data.
    
    Args:
        data: Data to sign
        secret: Secret key (if None, uses Django SECRET_KEY)
    
    Returns:
        Base64 encoded signature
    """
    if secret is None:
        secret = settings.SECRET_KEY
    
    signature = hmac.new(
        secret.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return base64.urlsafe_b64encode(signature).decode('utf-8')


def verify_signature(data: str, signature: str, secret: Optional[str] = None) -> bool:
    """
    Verify HMAC signature.
    
    Args:
        data: Original data
        signature: Signature to verify
        secret: Secret key (if None, uses Django SECRET_KEY)
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        expected_signature = create_signature(data, secret)
        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False


def sign_data(data: str, max_age: Optional[int] = None) -> str:
    """
    Sign data using Django's Signer.
    
    Args:
        data: Data to sign
        max_age: Maximum age in seconds
    
    Returns:
        Signed data
    """
    signer = Signer()
    return signer.sign(data)


def unsign_data(signed_data: str, max_age: Optional[int] = None) -> Optional[str]:
    """
    Unsign data using Django's Signer.
    
    Args:
        signed_data: Signed data
        max_age: Maximum age in seconds
    
    Returns:
        Original data or None if invalid
    """
    try:
        signer = Signer()
        return signer.unsign(signed_data, max_age=max_age)
    except BadSignature:
        return None


def mask_sensitive_data(data: str, visible_chars: int = 4, mask_char: str = '*') -> str:
    """
    Mask sensitive data showing only last few characters.
    
    Args:
        data: Data to mask
        visible_chars: Number of characters to show at the end
        mask_char: Character to use for masking
    
    Returns:
        Masked data
    """
    if len(data) <= visible_chars:
        return mask_char * len(data)
    
    masked_length = len(data) - visible_chars
    return mask_char * masked_length + data[-visible_chars:]


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return secrets.token_urlsafe(32)


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
    
    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a, b)


def sanitize_input(data: str, allowed_chars: Optional[str] = None) -> str:
    """
    Sanitize input by removing/replacing dangerous characters.
    
    Args:
        data: Input data to sanitize
        allowed_chars: Characters to allow (if None, uses alphanumeric + common safe chars)
    
    Returns:
        Sanitized data
    """
    if allowed_chars is None:
        allowed_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_@'
    
    return ''.join(char for char in data if char in allowed_chars)


def is_safe_url(url: str, allowed_hosts: Optional[list] = None) -> bool:
    """
    Check if URL is safe for redirect.
    
    Args:
        url: URL to check
        allowed_hosts: List of allowed hosts
    
    Returns:
        True if URL is safe, False otherwise
    """
    if not url:
        return False
    
    # Prevent javascript: and data: URLs
    if url.lower().startswith(('javascript:', 'data:', 'vbscript:')):
        return False
    
    # Allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return True
    
    # Check against allowed hosts if provided
    if allowed_hosts:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc in allowed_hosts
        except Exception:
            return False
    
    return False


# Global encryption manager instance
encryption_manager = EncryptionManager()

# Convenience functions
encrypt = encryption_manager.encrypt
decrypt = encryption_manager.decrypt
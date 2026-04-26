"""
Security utilities for password hashing, CSRF tokens, and validation.
"""
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta

class PasswordValidator:
    """Validate password strength."""
    
    MIN_LENGTH = 8
    
    @staticmethod
    def validate(password: str) -> tuple:
        """
        Validate password strength.
        Returns: (is_valid: bool, message: str)
        """
        if not password or len(password) < PasswordValidator.MIN_LENGTH:
            return False, f"密碼長度至少須 {PasswordValidator.MIN_LENGTH} 字符"
        
        return True, "密碼強度符合要求"


class PasswordHasher:
    """Secure password hashing using PBKDF2."""
    
    ITERATIONS = 100000
    HASH_ALGORITHM = 'sha256'
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> str:
        """
        Hash password using PBKDF2.
        Returns: salt$hash
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        pwd_hash = hashlib.pbkdf2_hmac(
            PasswordHasher.HASH_ALGORITHM,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            PasswordHasher.ITERATIONS
        )
        return f"{salt}${pwd_hash.hex()}"
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt, _ = stored_hash.split('$', 1)
            computed_hash = PasswordHasher.hash_password(password, salt)
            return hmac.compare_digest(computed_hash, stored_hash)
        except Exception:
            return False


class CSRFToken:
    """CSRF token generation and validation."""
    
    TOKEN_LENGTH = 32
    EXPIRY_HOURS = 24
    
    @staticmethod
    def generate_token() -> str:
        """Generate a new CSRF token."""
        return secrets.token_urlsafe(CSRFToken.TOKEN_LENGTH)
    
    @staticmethod
    def create_token_with_timestamp() -> tuple:
        """
        Create token with timestamp.
        Returns: (token, timestamp)
        """
        token = CSRFToken.generate_token()
        timestamp = datetime.utcnow().timestamp()
        return token, timestamp
    
    @staticmethod
    def verify_token_freshness(timestamp: float, max_age_hours: int = EXPIRY_HOURS) -> bool:
        """Verify token hasn't expired."""
        expiry_time = datetime.fromtimestamp(timestamp) + timedelta(hours=max_age_hours)
        return datetime.utcnow() < expiry_time

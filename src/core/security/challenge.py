import hashlib
import time
import hmac
from src.config.settings import settings

def get_challenge_token(ip: str, user_agent: str) -> str:
    """Generates a transient challenge token."""
    ts = int(time.time() // 3600)  # Valid for 1 hour window
    raw = f"{ip}|{user_agent}|{ts}"
    signature = hmac.new(
        settings.CHALLENGE_SECRET.encode(),
        raw.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{ts}|{signature}"

def verify_challenge_token(token: str, ip: str, user_agent: str) -> str:
    """Verifies the challenge token."""
    if not token:
        return 'missing'
    try:
        parts = token.split('|')
        if len(parts) != 2: return 'invalid'
        
        ts_str, signature = parts
        current_ts = int(time.time() // 3600)
        
        # Check time window (allow current or previous hour)
        if int(ts_str) not in (current_ts, current_ts - 1):
            return 'expired'
            
        expected = hmac.new(
            settings.CHALLENGE_SECRET.encode(),
            f"{ip}|{user_agent}|{ts_str}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        return 'valid' if hmac.compare_digest(expected, signature) else 'invalid'
    except Exception:
        return 'invalid'


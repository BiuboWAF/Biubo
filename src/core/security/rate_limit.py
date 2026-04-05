import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, Tuple
from src.config.settings import settings
from src.data.storage.manager import get_db

logger = logging.getLogger("WAF.RateLimit")

# _rate_data[ip] = deque of timestamps
_rate_data: Dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()

def _rate_gc_worker():
    while True:
        time.sleep(settings.RATE_GC_INTERVAL)
        now = time.time()
        with _rate_lock:
            empty_keys = [ip for ip, dq in _rate_data.items() if not dq or (now - dq[-1]) > 2]
            for ip in empty_keys: del _rate_data[ip]

threading.Thread(target=_rate_gc_worker, daemon=True).start()

def check_rate_limit(ip: str, host: str) -> Tuple[bool, str]:
    """
    Checks the request rate of an IP.
    Returns (blocked: bool, reason: str)
    """
    db = get_db(host)

    # 1. Blacklist check
    if db.is_banned(ip) and not db.is_temporary_banned(ip):
        return True, "banned"

    # 2. Sliding window count (1 second)
    now = time.time()
    window_start = now - 1.0

    with _rate_lock:
        dq = _rate_data[ip]
        while dq and dq[0] < window_start:
            dq.popleft()
        
        count = len(dq)
        if count >= settings.RATE_BAN_THRESHOLD:
            dq.clear()
            db.ban_ip(ip, reason="Rate limit exceeded (Ban)", expire_minutes=settings.RATE_BAN_DURATION_MIN)
            return True, "banned"

        dq.append(now)
        count += 1

    if count > settings.RATE_LIMIT_PER_SEC:
        logger.info(f"[RATE] {ip} rate limited ({count} req/s)")
        return True, "rate_limit"

    if db.is_temporary_banned(ip):
        return True, "temporary_banned"

    return False, ""

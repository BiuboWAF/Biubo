import re
import requests
import logging
from urllib.parse import urlparse, unquote
from pathlib import PurePosixPath
from typing import Dict, Any, List
from src.config.settings import settings
from geocode.geocode import Geocode

logger = logging.getLogger("WAF.HttpUtils")

gc = Geocode()
gc.load()

_WSGI_FORBIDDEN_HEADERS = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers',
    'transfer-encoding', 'upgrade', 'content-length',
})

STRIP_RESP_HEADERS = list(_WSGI_FORBIDDEN_HEADERS | {'content-encoding', 'server', 'x-powered-by'})

def get_client_ip(headers: dict, remote_addr: str) -> str:
    """Extract the real client IP address from headers or remote_addr."""
    if settings.GET_IP_FROM_HEADERS["state"]:
        for i in settings.GET_IP_FROM_HEADERS["order"]:
            val = headers.get(i)
            if not val:
                continue
            if i == "X-Forwarded-For":
                # Take the first IP if multiple exist
                return val.split(',')[0].strip()
            return val
    return remote_addr

def is_static_resource(url: str) -> bool:
    """
    Determine if the requested URL points to a static resource.
    Checks extension against whitelist and verifies lack of dynamic parameters.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Check extension
    suffix = PurePosixPath(path).suffix
    if suffix not in settings.STATIC_EXTENSIONS:
        return False
    
    # Anti-bypass: ensure the path actually ends with the static extension
    if not path.endswith(suffix):
        return False
        
    # Security check: check for potentially malicious parameters in static requests
    if parsed.query and any(c in unquote(parsed.query) for c in ("<", ">", "'", "\"", "(", ")")):
        return False

    return True

def detect_encoding(resp: requests.Response, raw_bytes: bytes) -> str:
    """Intelligently detect the encoding of the response content."""
    # 1. Try to find charset in HTML meta tags first
    meta_match = re.search(
        rb'<meta[^>]+charset\s*=\s*["\']?\s*([\w-]+)',
        raw_bytes[:2048], re.IGNORECASE
    )
    if meta_match:
        try:
            return meta_match.group(1).decode('ascii', errors='replace')
        except: pass

    # 2. Use requests' apparent_encoding fallback
    try:
        apparent = resp.apparent_encoding
        if apparent:
            return apparent
    except Exception:
        pass

    # 3. Check response headers (avoiding common ISO-8859-1 misdetections)
    header_enc = resp.encoding
    if header_enc and header_enc.lower() not in ('iso-8859-1', 'latin-1'):
        return header_enc

    return 'utf-8'

def get_ip_info(ip: str) -> dict:
    """Fetch geographical location information for an IP address."""
    try:
        url = getattr(settings, "IP_INFO_API", "https://biubo.zplb.org.cn/api/ip?ip={ip}").format(ip=ip)
        resp = requests.get(url, timeout=5)
        return resp.json()
    except Exception as e:
        logger.warning(f"get_ip_info failed for {ip}: {e}")
        return {}

def get_geo_info(city: str, country: str) -> dict:
    """Fetch geographical coordinates (lat/lon) for a city and country using local geocode."""
    try:
        query = f"{city}, {country}"
        results = gc.decode(query)

        if results and isinstance(results, list):
            for loc in results:
                if loc.get("location_type") == "city":
                    return {
                        "lat": float(loc.get("latitude", 0)),
                        "lon": float(loc.get("longitude", 0))
                    }

        return {}
    except Exception as e:
        logger.warning(f"get_geo_info failed for {city}, {country}: {e}")
        return {}

def get_ip_reputation(ip: str) -> bool:
    """Verify IP reputation against a blacklist/threat intelligence service."""
    try:
        url = getattr(settings, "IP_REPUTATION_API", "https://biubo.zplb.org.cn/api/ip/reputation?ip={ip}").format(ip=ip)
        resp = requests.get(url, timeout=5)
        return resp.json().get("safe", True)
    except Exception as e:
        logger.warning(f"get_ip_reputation failed for {ip}: {e}")
        return True

def verify_captcha(ticket: str) -> bool:
    """Verify the CAPTCHA ticket via external verification API."""
    try:
        url = getattr(settings, "CAPTCHA_VERIFY_API", "https://captcha.zplb.org.cn/api/verify")
        response = requests.post(
            url,
            json={"ticket": ticket},
            timeout=5
        )
        result = response.json()
        return result.get("success", False)
    except Exception as e:
        logger.error(f"Captcha verification failed: {e}")
        return False

def get_source_from_referer(referer: str) -> str:
    """Analyze traffic source type (direct, search, or social) from Referer header."""
    if not referer:
        return "direct"

    referer = referer.lower()

    SEARCH_ENGINES = [
        "google.", "bing.", "baidu.", "duckduckgo.", "yahoo.",
        "yandex.", "sogou.", "so.com", "360.cn", "naver.",
        "daum.", "ask.", "ecosia.", "brave.com/search",
    ]
    SOCIAL_NETWORKS = [
        "twitter.", "t.co", "x.com",
        "facebook.", "fb.com", "instagram.",
        "linkedin.", "weibo.", "wechat.", "wx.qq.com",
        "tiktok.", "douyin.", "youtube.", "youtu.be",
        "pinterest.", "reddit.", "telegram.", "whatsapp.",
        "line.", "discord.", "snapchat.",
    ]

    if any(s in referer for s in SEARCH_ENGINES):
        return "search"
    if any(s in referer for s in SOCIAL_NETWORKS):
        return "social"
    return "referral"


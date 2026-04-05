import requests
import logging
from urllib.parse import urlparse
from typing import Dict, Tuple, List, Optional
from src.utils.http_utils import STRIP_RESP_HEADERS, _WSGI_FORBIDDEN_HEADERS
from src.config.settings import settings

logger = logging.getLogger("WAF.Proxy")

_http_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=100)
_http_session.mount("http://", _adapter)
_http_session.mount("https://", _adapter)

def forward_request(
    target_base: str,
    path: str,
    method: str,
    headers: Dict[str, str],
    data: bytes,
    cookies: Dict[str, str],
    query_string: Optional[bytes] = None
) -> Tuple[bytes, int, List[Tuple[str, str]]]:
    """Forwards the request to the backend target server."""
    
    target_url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
    if query_string:
        target_url += f"?{query_string.decode()}"

    # Prepare outbound headers
    req_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in _WSGI_FORBIDDEN_HEADERS
    }
    if not settings.HOST_FORWARD:
        req_headers["Host"] = urlparse(target_base).netloc  #127.0.0.1
    req_headers["Accept-Encoding"] = "gzip, deflate, br"

    try:
        resp = _http_session.request(
            method=method,
            url=target_url,
            headers=req_headers,
            data=data,
            cookies=cookies,
            allow_redirects=False,
            timeout=(5, 30),
        )
        
        # Filter response headers
        resp_headers = [
            (k, v) for k, v in resp.headers.items()
            if k.lower() not in STRIP_RESP_HEADERS
        ]
        
        return resp.content, resp.status_code, resp_headers

    except Exception as e:
        logger.error(f"Proxy bridge failed to {target_url}: {e}")
        raise e

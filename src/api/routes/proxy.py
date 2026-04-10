import uuid
import datetime
import threading
import re
import os
import logging
from collections import Counter
from urllib.parse import unquote
from flask import Blueprint, request, Response, redirect
from src.config.settings import settings
from src.data.storage.manager import get_db
from src.utils.http_utils import (
    get_client_ip, is_static_resource,
    get_ip_reputation, verify_captcha
)
from src.core.security.rate_limit import check_rate_limit
from src.core.security.challenge import get_challenge_token, verify_challenge_token
from src.core.engine.waf_engine import detect_request
from src.core.session.manager import create_session, build_log_entry
from src.services.proxy.forwarder import forward_request

logger = logging.getLogger("WAF.Proxy")

proxy_bp = Blueprint('proxy', __name__)

# Memory-based strike counters for JS Challenge and Captcha
_challenge_strikes = Counter()
_challenge_lock = threading.Lock()

_captcha_strikes = Counter()
_captcha_lock = threading.Lock()

# Load static templates and error pages
def _load_asset(filename, fallback=""):
    path = os.path.join(settings.PAGE_ROOT, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return fallback

PAGE_400  = _load_asset("400.html", "<h1>400 Bad Request (Blocked by WAF)</h1>")
PAGE_403  = _load_asset("403.html", "<h1>403 Forbidden (IP Banned)</h1>")
PAGE_404  = _load_asset("404.html", "<h1>404 Not Found</h1>")
PAGE_429  = _load_asset("429.html", "<h1>429 Too Many Requests</h1>")
PAGE_500  = _load_asset("500.html", "<h1>500 Internal Server Error (WAF Engine Error)</h1>")
PAGE_CHALLENGE = _load_asset("challenge.html", "<h1>Security Challenge</h1>")
PAGE_CAPTCHA = _load_asset("captcha.html", "<h1>Security Captcha</h1>")
PAGE_LOADING = _load_asset("loading.html", "<h1>Security Loading</h1>")

def _normalize_path(path: str) -> str:
    """Normalize path to prevent bypasses (e.g., directory traversal)."""
    decoded = unquote(path)
    normalized = os.path.normpath("/" + decoded).replace("\\", "/")
    return normalized

@proxy_bp.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@proxy_bp.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def reverse_proxy(path: str):
    # Check for initialization
    if not settings.is_initialized():
        # Allow access to /init related paths for setup
        if not path.startswith("init") and not is_static_resource(request.url):
            return redirect("/init/")

    host = request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return PAGE_404, 404

    client_ip = get_client_ip(request.headers, request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    request_id = str(uuid.uuid4())
    db = get_db(host)
    proxy_status = db.ram.get("site", {}).get("status")

    if proxy_status not in ("on", "off", "pass", "log"):
        logger.error(f"Invalid site status for {host}")
        return PAGE_500, 500

    if proxy_status == "off":
        return PAGE_404, 404

    # 1. Rate Limiting & Ban Checking
    if proxy_status == "on" and not db.is_whitelisted(client_ip):
        blocked, block_reason = check_rate_limit(client_ip, host)

        # Check JS Challenge Cookie
        challenge_status = verify_challenge_token(request.cookies.get("bw_challenge"), client_ip, user_agent)

        if challenge_status == 'invalid':
            db.ban_ip(client_ip, "Forged Challenge Token")
            return Response(PAGE_403, status=403, mimetype="text/html")

        is_challenged = (challenge_status == 'valid')

        if blocked:
            if block_reason == "banned":
                return Response(PAGE_403, status=403, mimetype="text/html")
            elif block_reason == "temporary_banned":
                if not is_challenged and _captcha_strikes[client_ip] == 0:
                    db.ban_ip(client_ip, f"Verification failed.")
                    return Response(PAGE_403, status=403, mimetype="text/html")

                if is_challenged and _captcha_strikes[client_ip] == 0:
                    db.unban_ip(client_ip)
                elif is_challenged and _captcha_strikes[client_ip] > 0:
                    captcha_ticket = request.args.get("bw_captcha")
                    if not captcha_ticket:
                        with _captcha_lock:
                            _captcha_strikes[client_ip] += 1
                            strikes = _captcha_strikes[client_ip]
                        if strikes > 5:
                            db.ban_ip(client_ip, f"Ignored Captcha (Strikes: {strikes})")
                            with _captcha_lock: del _captcha_strikes[client_ip]
                            return Response(PAGE_403, status=403, mimetype="text/html")
                        body_html = PAGE_CAPTCHA.replace("{|<ri>|}", request_id)
                        return Response(body_html, status=200, mimetype="text/html")
                    else:
                        if verify_captcha(captcha_ticket):
                            db.unban_ip(client_ip)
                        else:
                            db.ban_ip(client_ip, "Captcha verification failed")

                with _challenge_lock: _challenge_strikes.pop(client_ip, None)
                with _captcha_lock: _captcha_strikes.pop(client_ip, None)

                return Response(
                    PAGE_LOADING.replace("{|<script>|}", """<script>setTimeout(() => {const u = new URL(window.location.href); u.searchParams.delete('bw_captcha'); window.location.replace(u.toString());}, 500);</script>"""),
                    status=200, mimetype="text/html"
                )

            # Rate limit triggered -> Challenge required
            if not is_challenged and not is_static_resource(request.url):
                db.ban_ip(client_ip, f"Challenge is required.", True)
                with _challenge_lock:
                    _challenge_strikes[client_ip] += 1
                    strikes = _challenge_strikes[client_ip]
                if strikes > 5:
                    db.ban_ip(client_ip, f"Ignored Challenge (Strikes: {strikes})")
                    with _challenge_lock: del _challenge_strikes[client_ip]
                    return Response(PAGE_403, status=403, mimetype="text/html")

                token = get_challenge_token(client_ip, user_agent)
                body_html = (PAGE_CHALLENGE
                            .replace("{{TOKEN}}", token)
                            .replace("{|<ri>|}", request_id)
                            .replace("{|<t>|}", datetime.datetime.now().isoformat()))
                return Response(body_html, status=200, mimetype="text/html")

            if is_challenged and not is_static_resource(request.url):
                db.ban_ip(client_ip, f"Captcha is required.", True)
                with _captcha_lock:
                    _captcha_strikes[client_ip] += 1
                    strikes = _captcha_strikes[client_ip]
                if strikes > 5:
                    db.ban_ip(client_ip, f"Ignored Captcha (Strikes: {strikes})")
                    with _captcha_lock: del _captcha_strikes[client_ip]
                    return Response(PAGE_403, status=403, mimetype="text/html")
                body_html = PAGE_CAPTCHA.replace("{|<ri>|}", request_id)
                return Response(body_html, status=200, mimetype="text/html")

            # Fallback 429
            resp = Response(PAGE_429, status=429, mimetype="text/html")
            resp.headers["Retry-After"] = "1"
            return resp

    # 2. WAF Detection & File Security
    body = request.get_data()
    args = dict(request.args)
    cookies = dict(request.cookies)
    snapshot = {
        "remote_addr": client_ip, "method": request.method, "url": request.url,
        "headers": dict(request.headers), "cookies": cookies,
        "args": args, "body": body
    }
    detection = {"type": "normal"}
    
    if proxy_status in ("on", "log"):
        # 2.1 IP Reputation Check
        if not get_ip_reputation(client_ip) and proxy_status == "on" and not db.is_whitelisted(client_ip):
            db.ban_ip(client_ip, "Malicious IP (Reputation Check)")
            _log_and_save_session(request_id, host, snapshot, {"type": "hacker", "attack_types": ["Malicious IP"]}, 403)
            return Response(PAGE_403, status=403, mimetype="text/html")

        # 2.2 File Security Check (Upload restricted extensions)
        if proxy_status == "on" and not db.is_whitelisted(client_ip):
            ok, f_reason = _check_file_security(body, snapshot["headers"], db)
            if not ok:
                detection = {"type": "hacker", "attack_types": [f"File Security Violation: {f_reason}"]}
            else:
                # 2.3 WAF Engine Detection (Regex + LLM)
                detection = detect_request(request, body, args, cookies, db)
        else:
            # log-only mode
            detection = detect_request(request, body, args, cookies, db)

        if detection["type"] == "hacker" and proxy_status == "on" and not db.is_whitelisted(client_ip):
            db.ban_ip(client_ip, f"Attack Detected: {', '.join(detection.get('attack_types', []))}")
            _log_and_save_session(request_id, host, snapshot, detection, 400)
            attack_str = ", ".join(detection.get("attack_types", []))
            body_html = (PAGE_400
                        .replace("{|<sa>|}", attack_str)
                        .replace("{|<ri>|}", request_id)
                        .replace("{|<t>|}", datetime.datetime.now().isoformat()))
            return Response(body_html, status=400, mimetype="text/html")

        if detection["type"] == "error":  # I will keep this, although it doesn't work...
            # If engine errored (should be caught in waf_engine, but just in case)
            return Response(PAGE_500, status=500, mimetype="text/html")

    # 3. Request Forwarding
    try:
        content, status, headers = forward_request(target_base, path, request.method, dict(request.headers),
                                                body, cookies, request.query_string)
        if proxy_status != "pass":
            content = _inject_beacon(content, headers, request_id)
            # Log session asynchronously to avoid delaying response
            threading.Thread(target=_log_and_save_session, args=(request_id, host, snapshot, detection, status), daemon=True).start()
        return Response(content, status=status, headers=headers)
    except Exception as e:
        logger.error(f"Proxy forwarding failed for {host}{path}: {e}")
        _log_and_save_session(request_id, host, snapshot, detection, 502)
        # Use 500/502 dedicated page for proxy errors
        return Response(PAGE_500, status=502, mimetype="text/html")

def _log_and_save_session(request_id, host, snapshot, detection, status_code=200):
    """Internal helper to build and store request logs."""
    log_entry = build_log_entry(request_id, snapshot, detection, status_code)
    create_session(request_id, host, log_entry)

def _check_file_security(body: bytes, headers: dict, db) -> tuple:
    """Check uploaded files against allowed extensions list."""
    content_type = headers.get("Content-Type", "")
    content_type_lower = content_type.lower() if content_type else ""
    if "multipart/form-data" not in content_type_lower:
        return True, ""
    
    if len(body) > settings.UPLOAD_MAX_SIZE:
        return False, f"Upload size exceeds limit"
        
    allowed_exts = [x.lower().strip() for x in settings.UPLOAD_ALLOWED_EXTENSIONS if x.strip()]
    if not allowed_exts: 
        return True, ""
        
    try:
        # Robust boundary extraction
        boundary_param = "boundary="
        idx = content_type_lower.find(boundary_param)
        if idx == -1:
            return True, ""
            
        boundary = content_type[idx + len(boundary_param):].split(";")[0].strip().encode()
        if not boundary:
            return True, ""
            
        # Split body by boundary to inspect parts
        for part in body.split(b"--" + boundary):
            if b"filename=" in part[:2048]:
                h_end = part.find(b"\r\n\r\n")
                if h_end != -1:
                    headers_part = part[:h_end].decode(errors="ignore")
                    # Match filename or filename* (RFC 6266)
                    m = re.search(r'filename\*?=["\']?(?:[A-Z0-9-]+[\'"][\'"])?([^"\'\r\n;]+)["\']?', headers_part, re.IGNORECASE)
                    if m:
                        fname = unquote(m.group(1)).lower()
                        ext = ""
                        if "." in fname:
                            ext = "." + fname.split('.')[-1]
                        
                        if ext not in allowed_exts:
                            return False, f"File extension {ext} is not allowed"
    except Exception as e:
        logger.error(f"Multipart parse error: {e}")
        return False, f"Malformed multipart data"
        
    return True, ""

def _inject_beacon(content, headers, request_id):
    """Inject tracking beacon script into HTML responses."""
    content_type = dict(headers).get('Content-Type', '').lower()
    if 'text/html' not in content_type: 
        return content
    try:
        html_text = content.decode('utf-8', errors='replace')
        # Simple heuristic to identify HTML documents
        if "<body" not in html_text.lower() or "<!doctypehtml>" not in html_text.lower().replace(" ", ''):
            return content
            
        script_tag = f'<script src="/biubo-cgi/scripts/biubo/beacon.js?ts={request_id}"></script>'
        if '</body>' in html_text:
            html_text = html_text.replace('</body>', f'{script_tag}</body>', 1)
        else:
            html_text += script_tag
        return html_text.encode('utf-8', errors='replace')
    except: 
        return content

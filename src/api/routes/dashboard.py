import os
import functools
import logging
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, Response, session, redirect, url_for, send_from_directory
from src.config.settings import settings
from src.utils.security import PasswordHasher, CSRFToken, PasswordValidator

logger = logging.getLogger("WAF.Dashboard")

dashboard_bp = Blueprint('dashboard', __name__)

# ── Auth config ──────────────────────────────────────────────
DASHBOARD_PASSWORD_HASH = getattr(settings, "DASHBOARD_PASSWORD_HASH", None)
SESSION_SECRET = secrets.token_hex(32) if not hasattr(settings, "SESSION_SECRET") else getattr(settings, "SESSION_SECRET", None)

# Login attempt tracking
_login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MIN = 15

def _check_login_lockout(ip_addr: str) -> tuple:
    """Check if IP is locked out. Returns (is_locked: bool, remaining_time_seconds: int)"""
    now = datetime.utcnow()
    # Clean old attempts
    _login_attempts[ip_addr] = [t for t in _login_attempts[ip_addr] if (now - t).total_seconds() < 3600]
    
    if len(_login_attempts[ip_addr]) >= MAX_LOGIN_ATTEMPTS:
        oldest_attempt = _login_attempts[ip_addr][0]
        lockout_expiry = oldest_attempt + timedelta(minutes=LOCKOUT_DURATION_MIN)
        if now < lockout_expiry:
            remaining = (lockout_expiry - now).total_seconds()
            return True, int(remaining)
    
    return False, 0

def _record_login_attempt(ip_addr: str):
    """Record a failed login attempt."""
    _login_attempts[ip_addr].append(datetime.utcnow())

def _reset_login_attempts(ip_addr: str):
    """Clear login attempts for IP."""
    _login_attempts.pop(ip_addr, None)

def _set_secret(app):
    app.secret_key = SESSION_SECRET

# Inject secret key lazily
@dashboard_bp.record_once
def on_register(state):
    state.app.secret_key = SESSION_SECRET

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("dashboard_authed"):
            # Redirect to login for page requests, return JSON error for API requests
            is_page = request.path.endswith(".html") or request.path.endswith("/dashboard") or request.path.endswith("/init")
            if is_page and "/api/" not in request.path and "/info/" not in request.path:
                return redirect(settings.DASHBOARD_PATH + "/dashboard/login")
            return jsonify({"status": "error", "msg": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def csrf_required(f):
    """CSRF token validation decorator."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                logger.warning(f"CSRF validation failed for {request.remote_addr}")
                return jsonify({"status": "error", "msg": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Pages ────────────────────────────────────────────────────
@dashboard_bp.route("/dashboard/login", methods=["GET"])
def login_page():
    # Generate CSRF token for this session
    if 'csrf_token' not in session:
        session['csrf_token'] = CSRFToken.generate_token()
    
    page_path = os.path.join(settings.PAGE_ROOT, "dashboard_login.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
            # Inject CSRF token into page
            content = content.replace("{{csrf_token}}", session['csrf_token'])
            return content
    except Exception as e:
        logger.error(f"Error loading login page: {e}")
        return "<h1>登錄頁面遺失</h1>", 404

@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_page():
    # Refresh CSRF token for each dashboard access
    session['csrf_token'] = CSRFToken.generate_token()
    
    page_path = os.path.join(settings.PAGE_ROOT, "dashboard.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error loading dashboard page: {e}")
        return "<h1>儀表板頁面遺失</h1>", 404

# ── Auth API ─────────────────────────────────────────────────
# Simplified login endpoint without complex validation
@dashboard_bp.route("/dashboard/api/simple-login", methods=["POST"])
def api_simple_login():
    """Simplified login endpoint for testing"""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    
    # Get stored password hash
    stored_hash = DASHBOARD_PASSWORD_HASH or settings.DASHBOARD_PASSWORD_HASH
    
    # If no hash exists (first login), use default password
    if not stored_hash:
        if password == settings.DEFAULT_PASSWORD:
            session["dashboard_authed"] = True
            session["force_password_change"] = True
            session['csrf_token'] = CSRFToken.generate_token()
            return jsonify({
                "status": "success",
                "force_password_change": True,
                "msg": "首次登入，請立即更改密碼"
            })
        else:
            return jsonify({"status": "error", "msg": "密碼不正確"}), 401
    
    # Verify password hash
    if PasswordHasher.verify_password(password, stored_hash):
        session["dashboard_authed"] = True
        session['csrf_token'] = CSRFToken.generate_token()
        session.pop("force_password_change", None)
        return jsonify({"status": "success"})
    
    return jsonify({"status": "error", "msg": "密碼不正確"}), 401

@dashboard_bp.route("/dashboard/api/login", methods=["POST"])
def api_login():
    # Get client IP
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    # Check login lockout
    is_locked, remaining_time = _check_login_lockout(client_ip)
    if is_locked:
        logger.warning(f"Login attempt from locked IP {client_ip}")
        return jsonify({
            "status": "error", 
            "msg": f"登入次數過多，請在 {remaining_time} 秒後重試"
        }), 429
    
    # CSRF validation - skip for login endpoint as it's the entry point
    # csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    # if not csrf_token or csrf_token != session.get('csrf_token'):
    #     logger.warning(f"CSRF validation failed for login from {client_ip}")
    #     _record_login_attempt(client_ip)
    #     return jsonify({"status": "error", "msg": "安全驗證失敗"}), 403
    
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    
    if not password:
        _record_login_attempt(client_ip)
        return jsonify({"status": "error", "msg": "請輸入密碼"}), 400
    
    # Get stored password hash
    stored_hash = DASHBOARD_PASSWORD_HASH or settings.DASHBOARD_PASSWORD_HASH
    
    # If no hash exists (first login), use default password from settings
    if not stored_hash:
        if password == settings.DEFAULT_PASSWORD:
            logger.warning("Default password used for login - user must change it")
            session["dashboard_authed"] = True
            session["force_password_change"] = True
            session['csrf_token'] = CSRFToken.generate_token()
            _reset_login_attempts(client_ip)
            return jsonify({
                "status": "success",
                "force_password_change": True,
                "msg": "首次登入，請立即更改密碼"
            })
        else:
            _record_login_attempt(client_ip)
            return jsonify({"status": "error", "msg": "密碼不正確"}), 401
    
    # Check if password change is forced (based on settings)
    force_change = settings.FORCE_PASSWORD_CHANGE and not stored_hash
    
    # Verify password hash
    if PasswordHasher.verify_password(password, stored_hash):
        session["dashboard_authed"] = True
        session['csrf_token'] = CSRFToken.generate_token()
        _reset_login_attempts(client_ip)
        logger.info(f"Successful login from {client_ip}")
        
        # Check if password change is still required
        if settings.FORCE_PASSWORD_CHANGE and not stored_hash:
            session["force_password_change"] = True
            return jsonify({
                "status": "success",
                "force_password_change": True,
                "msg": "請立即更改密碼"
            })
        
        session.pop("force_password_change", None)
        return jsonify({"status": "success"})
    
    _record_login_attempt(client_ip)
    logger.warning(f"Failed login attempt from {client_ip}")
    return jsonify({"status": "error", "msg": "密碼不正確"}), 401

@dashboard_bp.route("/dashboard/api/logout", methods=["POST"])
def api_logout():
    session.pop("dashboard_authed", None)
    session.pop("force_password_change", None)
    return jsonify({"status": "success"})

@dashboard_bp.route("/dashboard/api/check-auth", methods=["GET"])
@login_required
def check_auth():
    """Check if user is authenticated and if password change is required."""
    return jsonify({
        "status": "success",
        "force_password_change": session.get("force_password_change", False)
    })

@dashboard_bp.route("/dashboard/api/change-password", methods=["POST"])
@login_required
@csrf_required
def change_password():
    """Change dashboard password with validation."""
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")
    
    # Validate input
    if not old_password or not new_password:
        return jsonify({"status": "error", "msg": "請輸入所有必填字段"}), 400
    
    if new_password != confirm_password:
        return jsonify({"status": "error", "msg": "新密碼不符"}), 400
    
    # Check password strength
    is_valid, msg = PasswordValidator.validate(new_password)
    if not is_valid:
        return jsonify({"status": "error", "msg": msg}), 400
    
    # Verify old password (use default password if no hash exists)
    stored_hash = DASHBOARD_PASSWORD_HASH or settings.DASHBOARD_PASSWORD_HASH
    if stored_hash:
        # Existing password - verify normally
        if not PasswordHasher.verify_password(old_password, stored_hash):
            return jsonify({"status": "error", "msg": "舊密碼不正確"}), 401
    else:
        # No hash yet - verify against default password
        if old_password != settings.DEFAULT_PASSWORD:
            return jsonify({"status": "error", "msg": "默認密碼不正確"}), 401
    
    # Update password
    new_hash = PasswordHasher.hash_password(new_password)
    settings.DASHBOARD_PASSWORD_HASH = new_hash
    settings.DASHBOARD_PASSWORD = ""  # Clear plain text password
    settings.FORCE_PASSWORD_CHANGE = False  # Mark as password changed
    settings.save_config()
    
    # Clear forced password change flag
    session.pop("force_password_change", None)
    session['csrf_token'] = CSRFToken.generate_token()
    
    logger.info(f"Dashboard password changed by {request.remote_addr}")
    return jsonify({"status": "success", "msg": "密碼已成功更改"})

# ── Config API ───────────────────────────────────────────────
@dashboard_bp.route("/api/biubo/config", methods=["GET"])
@login_required
def get_config():
    # Return secure configuration subset (hide sensitive keys)
    return jsonify({
        "status": "success",
        "data": {
            "WAF_PORT": settings.WAF_PORT,
            "DASHBOARD_PATH": settings.DASHBOARD_PATH,
            "PROXY_MAP": settings.PROXY_MAP,
            "LLM_MODEL": settings.LLM_MODEL,
            "LLM_BASE_URL": settings.LLM_BASE_URL,
            # Never expose API_KEY to frontend
        }
    })

@dashboard_bp.route("/api/biubo/config", methods=["POST"])
@login_required
@csrf_required
def update_config():
    """Update WAF configuration with validation."""
    data = request.get_json(silent=True) or {}
    
    # Validate and update settings
    try:
        if "WAF_PORT" in data:
            port = int(data["WAF_PORT"])
            if not (1 <= port <= 65535):
                return jsonify({"status": "error", "msg": "無效的端口號"}), 400
            settings.WAF_PORT = port
        
        if "DASHBOARD_PASSWORD" in data and data["DASHBOARD_PASSWORD"]:
            new_pwd = data["DASHBOARD_PASSWORD"]
            is_valid, msg = PasswordValidator.validate(new_pwd)
            if not is_valid:
                return jsonify({"status": "error", "msg": msg}), 400
            settings.DASHBOARD_PASSWORD_HASH = PasswordHasher.hash_password(new_pwd)
        
        if "DASHBOARD_PATH" in data:
            path = data["DASHBOARD_PATH"]
            if not path.startswith("/") or ".." in path:
                return jsonify({"status": "error", "msg": "無效的儀表板路徑"}), 400
            settings.DASHBOARD_PATH = path
        
        if "PROXY_MAP" in data:
            if not isinstance(data["PROXY_MAP"], dict):
                return jsonify({"status": "error", "msg": "無效的代理映射"}), 400
            settings.PROXY_MAP = data["PROXY_MAP"]
        
        if "LLM_MODEL" in data:
            settings.LLM_MODEL = data["LLM_MODEL"]
        
        if "LLM_BASE_URL" in data:
            url = data["LLM_BASE_URL"]
            if not (url.startswith("http://") or url.startswith("https://")):
                return jsonify({"status": "error", "msg": "無效的 URL"}), 400
            settings.LLM_BASE_URL = url
        
        # Note: API_KEY updates should never be exposed via GET/POST without authentication
        if "API_KEY" in data and data["API_KEY"]:
            settings.API_KEY = data["API_KEY"]
        
        settings.save_config()
        session['csrf_token'] = CSRFToken.generate_token()
        logger.info(f"Configuration updated by {request.remote_addr}")
        return jsonify({"status": "success", "msg": "配置已更新"})
    
    except ValueError as e:
        return jsonify({"status": "error", "msg": f"無效的值: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Config update error: {e}")
        return jsonify({"status": "error", "msg": "配置更新失敗"}), 500

# ── Proxy-map (hosts list for UI) ────────────────────────────
@dashboard_bp.route("/api/biubo/dashboard/proxy-map")
@login_required
def proxy_map():
    return jsonify({"status": "success", "data": settings.PROXY_MAP})
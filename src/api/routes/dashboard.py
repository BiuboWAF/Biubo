import os
import functools
from flask import Blueprint, request, jsonify, Response, session, redirect, url_for, send_from_directory
from src.config.settings import settings

dashboard_bp = Blueprint('dashboard', __name__)

# ── Auth config ──────────────────────────────────────────────
DASHBOARD_PASSWORD = getattr(settings, "DASHBOARD_PASSWORD", "admin123")
SESSION_SECRET = getattr(settings, "SESSION_SECRET", "biubo_dashboard_secret_2026")

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

# ── Pages ────────────────────────────────────────────────────
@dashboard_bp.route("/dashboard/login", methods=["GET"])
def login_page():
    page_path = os.path.join(settings.PAGE_ROOT, "dashboard_login.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>Login page missing</h1>", 404

@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_page():
    page_path = os.path.join(settings.PAGE_ROOT, "dashboard.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>Dashboard page missing</h1>", 404

# ── Auth API ─────────────────────────────────────────────────
@dashboard_bp.route("/dashboard/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    if data.get("password") == settings.DASHBOARD_PASSWORD:
        session["dashboard_authed"] = True
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "msg": "Incorrect password"}), 401

@dashboard_bp.route("/dashboard/api/logout", methods=["POST"])
def api_logout():
    session.pop("dashboard_authed", None)
    return jsonify({"status": "success"})

# ── Config API ───────────────────────────────────────────────
@dashboard_bp.route("/api/biubo/config", methods=["GET"])
@login_required
def get_config():
    # Return secure configuration subset
    return jsonify({
        "status": "success",
        "data": {
            "WAF_PORT": settings.WAF_PORT,
            "DASHBOARD_PATH": settings.DASHBOARD_PATH,
            "PROXY_MAP": settings.PROXY_MAP,
            "API_KEY": settings.API_KEY,
            "LLM_MODEL": settings.LLM_MODEL,
            "LLM_BASE_URL": settings.LLM_BASE_URL
        }
    })

@dashboard_bp.route("/api/biubo/config", methods=["POST"])
@login_required
def update_config():
    data = request.get_json(silent=True) or {}
    
    # Update settings
    if "WAF_PORT" in data: settings.WAF_PORT = int(data["WAF_PORT"])
    if "DASHBOARD_PASSWORD" in data and data["DASHBOARD_PASSWORD"]: 
        settings.DASHBOARD_PASSWORD = data["DASHBOARD_PASSWORD"]
    if "DASHBOARD_PATH" in data: settings.DASHBOARD_PATH = data["DASHBOARD_PATH"]
    if "PROXY_MAP" in data: settings.PROXY_MAP = data["PROXY_MAP"]
    if "API_KEY" in data: settings.API_KEY = data["API_KEY"]
    if "LLM_MODEL" in data: settings.LLM_MODEL = data["LLM_MODEL"]
    if "LLM_BASE_URL" in data: settings.LLM_BASE_URL = data["LLM_BASE_URL"]
    
    settings.save_config()
    return jsonify({"status": "success"})

# ── Proxy-map (hosts list for UI) ────────────────────────────
@dashboard_bp.route("/api/biubo/dashboard/proxy-map")
@login_required
def proxy_map():
    return jsonify({"status": "success", "data": settings.PROXY_MAP})
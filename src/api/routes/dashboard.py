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
            if request.path.endswith(".html") or "." not in request.path.split("/")[-1]:
                return redirect("/biubo-cgi/dashboard/login")
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
    if data.get("password") == DASHBOARD_PASSWORD:
        session["dashboard_authed"] = True
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "msg": "Incorrect password"}), 401

@dashboard_bp.route("/dashboard/api/logout", methods=["POST"])
def api_logout():
    session.pop("dashboard_authed", None)
    return jsonify({"status": "success"})

# ── Proxy-map (hosts list) ───────────────────────────────────
@dashboard_bp.route("/api/biubo/dashboard/proxy-map")
@login_required
def proxy_map():
    return jsonify({"status": "success", "data": settings.PROXY_MAP})
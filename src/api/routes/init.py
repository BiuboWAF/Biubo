import os
import json
from flask import Blueprint, request, jsonify, redirect, url_for
from src.config.settings import settings

init_bp = Blueprint('init', __name__)

@init_bp.route("/", methods=["GET"])
def init_page():
    if settings.is_initialized():
        return redirect(settings.DASHBOARD_PATH + "/dashboard")
    
    page_path = os.path.join(settings.PAGE_ROOT, "init.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>Initialization page template missing</h1>", 404

@init_bp.route("/api/setup", methods=["POST"])
def api_setup():
    if settings.is_initialized():
        return jsonify({"status": "error", "msg": "System already initialized"}), 400
    
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    proxy_map = data.get("proxy_map")
    
    if not password or not proxy_map:
        return jsonify({"status": "error", "msg": "Password and proxy map are required"}), 400
    
    if not isinstance(proxy_map, dict) or len(proxy_map) == 0:
        return jsonify({"status": "error", "msg": "Invalid proxy map format"}), 400

    # Optional / Extended settings
    if "waf_port" in data:
        try:
            settings.WAF_PORT = int(data["waf_port"])
        except ValueError:
            pass
            
    if "api_key" in data: settings.API_KEY = data["api_key"]
    if "llm_base_url" in data: settings.LLM_BASE_URL = data["llm_base_url"]
    if "llm_model" in data: settings.LLM_MODEL = data["llm_model"]

    # Basic settings
    settings.DASHBOARD_PASSWORD = password
    settings.PROXY_MAP = proxy_map
    
    # Save to config.json
    settings.save_config()
    
    return jsonify({"status": "success", "dashboard_path": settings.DASHBOARD_PATH})

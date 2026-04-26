import os
import threading
from flask import Blueprint, request, Response, jsonify, current_app, send_from_directory
from src.config.settings import settings
from src.core.session.manager import update_session_log, update_rrweb_events
import platform
import psutil
from datetime import datetime
from flask import Blueprint, jsonify
from src.data.storage.manager import get_db, Database
from src.utils.compression import decompress_json
from src.utils.query_parser import parse, evaluate
import requests
from src.utils.http_utils import get_ip_info
from src.api.routes.dashboard import login_required
from src.utils.validators import validate_date_string, sanitize_filename, is_safe_path


internal_bp = Blueprint('internal', __name__)

START_TIME = datetime.now()

@internal_bp.route("/scripts/biubo/beacon.js")
def beacon():
    # Load beacon script from templates
    path = os.path.join(settings.TEMPLATE_ROOT, "beacon.js")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype="application/javascript")
    except Exception:
        return "console.error('Beacon JS missing')", 404

@internal_bp.route("/handle/biubo/greeting", methods=['POST'])
def greeting():
    data = request.get_json(silent=True) or {}
    request_id = data.get('ts')
    if not request_id:
        return jsonify({"status": "error", "msg": "missing request_id"}), 400

    host_key = request.host
    if host_key not in settings.PROXY_MAP:
        host_key = request.host.split(':')[0]

    # Capture request context data BEFORE spawning thread (Flask context will be gone in thread)
    fallback_ip = request.remote_addr
        
    if host_key in settings.PROXY_MAP:
        def _update_async():
            from src.utils.http_utils import get_ip_info
            # Data from legacy beacon.js: visitorId, ip, ts, browser_info
            client_ip = data.get('ip') or fallback_ip
            ip_info = get_ip_info(client_ip)
            # Legacy API returns varying formats - extract robustly
            country = ip_info.get("country") or ip_info.get("countryName") or ""
            city = ip_info.get("city") or ip_info.get("cityName") or ""
            
            updates = {
                "ip":           client_ip,
                "country":      country,
                "city":         city,
                "fingerprint":  data.get('visitorId', ''),
                "browser_info": data.get('browser_info', {}),
                "client_env":   data # Keep full payload for reference
            }
            update_session_log(request_id, host_key, updates)
            
        threading.Thread(target=_update_async, daemon=True).start()
    
    return jsonify({"status": "success"})


@internal_bp.route('/handle/biubo/screen', methods=['POST'])
def receive_screen_data():
    data = request.get_json(silent=True) or {}
    request_id = data.get('ts')
    events = data.get('events', [])
    if request_id:
        host_key = request.host
        if host_key not in settings.PROXY_MAP:
            host_key = request.host.split(':')[0]
        if host_key in settings.PROXY_MAP:
            update_rrweb_events(request_id, host_key, events)
    return jsonify({"status": "success"})

@internal_bp.route("/info/biubo/system")
@login_required
def system_info():
    """Returns system resource monitoring data."""
    now = datetime.now()
    uptime = str(now - START_TIME).split(".")[0]

    cpu_percent = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    cpu_data = {"percent": cpu_percent, "cores": psutil.cpu_count(logical=True)}
    mem_data = {
        "total_gb": round(memory.total / (1024 ** 3), 2),
        "used_gb": round(memory.used / (1024 ** 3), 2),
        "percent": memory.percent
    }
    disk_data = {
        "total_gb": round(disk.total / (1024 ** 3), 2),
        "used_gb": round(disk.used / (1024 ** 3), 2),
        "percent": disk.percent
    }

    return jsonify({
        "status": "success",
        "data": {
            "os": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
            "uptime": uptime,
            "cpu": cpu_data,
            "memory": mem_data,
            "disk": disk_data,
            "time": now.strftime("%Y-%m-%d %H:%M:%S")
        }
    })

@internal_bp.route("/info/biubo/waf")
@login_required
def waf_info():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    db = get_db(host)
    ram = db.ram._data
    return jsonify(ram)

@internal_bp.route("/info/biubo/setting", methods=['POST'])
@login_required
def waf_setting():
    host = request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    db = get_db(host)
    content = request.get_json()
    site_content = {
        "description": db.ram["site"]["description"],
        "domain": db.ram["site"]["domain"],
        "status": db.ram["site"]["status"],
        "created_at": db.ram["site"]["created_at"]
    }
    if content.get("description", None):
        site_content["description"] = content.get("description", None)
    if content.get("domain", None):
        site_content["domain"] = content.get("domain", None)
    if content.get("status", None):
        site_content["status"] = content.get("status", None)

    ram = db.ram.add("site", site_content)
    return jsonify(ram)

@internal_bp.route("/info/biubo/location")
@login_required
def server_location():
    """
    Get the WAF server's public location dynamically.
    Fetches public IP first, then geolocates it.
    """
    try:
        # 1. Fetch public IP from user's specified source
        resp = requests.get("https://ip.zplb.org.cn:7000", timeout=5)
        ip = resp.text.strip()
        
        # 2. Get geographical details for that IP
        location_data = get_ip_info(ip)
        
        if location_data:
            return jsonify({
                "status": "success",
                "data": location_data
            })
        return jsonify({"status": "error", "msg": "Could not resolve IP geodata"}), 500
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@internal_bp.route("/api/biubo/ipinfo")
@login_required
def ipinfo():
    """Proxy for get_ip_info utility."""
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"status": "error", "msg": "IP is required"}), 400
    try:
        return jsonify({"status": "success", "data": get_ip_info(ip)})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@internal_bp.route("/api/biubo/geocode")
@login_required
def geocode():
    """Proxy for Nominatim geocoding utility."""
    city = request.args.get("city", "")
    country = request.args.get("country", "")
    if not city and not country:
        return jsonify({"status": "error", "msg": "City or country required"}), 400
    try:
        from src.utils.http_utils import get_geo_info
        return jsonify({"status": "success", "data": get_geo_info(city, country)})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@internal_bp.route("/info/biubo/log", methods=['GET'])
@login_required
def waf_log():
    host = request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404

    host_dir = os.path.join(settings.DB_ROOT, host)
    if not os.path.exists(host_dir):
        return jsonify({})

    date = request.args.get("date")
    if not date or not validate_date_string(date):
        return jsonify({"status": "error", "msg": "Invalid date format"}), 400
    
    # Sanitize and validate path
    safe_date = sanitize_filename(date)
    new_path = os.path.join(host_dir, "logs", f"{safe_date}.msgpack")
    if not is_safe_path(new_path, settings.DB_ROOT):
        return jsonify({"status": "error", "msg": "Invalid path"}), 403
    if not os.path.exists(new_path):
        return jsonify({})
    db = Database(new_path, auto_backup=False)
    buffer = []
    for i in db.get("logs"):
        i["rrweb"] = ""
        buffer.append(i)
    return buffer

@internal_bp.route("/info/biubo/rrweb", methods=['GET'])
@login_required
def waf_rrweb():
    host = request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404

    host_dir = os.path.join(settings.DB_ROOT, host)
    if not os.path.exists(host_dir):
        return jsonify([])

    date = request.args.get("date")
    if not date or not validate_date_string(date):
        return jsonify({"status": "error", "msg": "Invalid date format"}), 400
    
    # Sanitize and validate path
    safe_date = sanitize_filename(date)
    new_path = os.path.join(host_dir, "logs", f"{safe_date}.msgpack")
    if not is_safe_path(new_path, settings.DB_ROOT):
        return jsonify({"status": "error", "msg": "Invalid path"}), 403
    if not os.path.exists(new_path):
        return jsonify([])

    request_id = request.args.get("id")

    if not request_id:
        return jsonify([])

    db = Database(new_path, auto_backup=False)
    for i in db.get("logs"):
        if i["request_id"] == request_id:
            rrweb = decompress_json(i["rrweb"])
            if rrweb:
                return jsonify(rrweb["events"])
            return jsonify([])
    return jsonify([])

@internal_bp.route("/info/biubo/search", methods=['GET'])
@login_required
def waf_search():
    host = request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404

    statement = request.args.get("statement")
    try:
        ast = parse(statement)
    except:
        return jsonify({"error": "Syntax error"})

    host_dir = os.path.join(settings.DB_ROOT, host)
    host_dir = os.path.join(host_dir, "logs")
    if not os.path.exists(host_dir):
        return jsonify([])
    msgpack_files = []
    for root, dirs, files in os.walk(host_dir):
        for file in files:
            if file.endswith(".msgpack"):
                msgpack_files.append(os.path.join(root, file))

    buffer = []

    for filepath in msgpack_files:
        date_str = os.path.splitext(os.path.basename(filepath))[0]
        db = Database(filepath, auto_backup=False)
        logs = db.get("logs")
        for r in logs:
            r["rrweb"] = ""
        try:
            for rec in logs:
                if evaluate(ast, rec):
                    rec["_date"] = date_str
                    buffer.append(rec)
        except:
            return jsonify(buffer)

    return jsonify(buffer)

@internal_bp.route("/info/biubo/blacklist")
@login_required
def waf_blacklist():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    db = get_db(host)
    blacklist = db.ram.get("security", {}).get("blacklist", {})
    return jsonify(blacklist)

@internal_bp.route("/info/biubo/unban")
@login_required
def waf_unban():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    ip = request.args.get("ip")
    if not ip:
        return jsonify({})
    db = get_db(host)
    db.unban_ip(ip)
    return jsonify({"status": "success"})

@internal_bp.route("/info/biubo/whitelist")
@login_required
def waf_whitelist():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    db = get_db(host)
    whitelist = db.ram.get("security", {}).get("whitelist", {})
    return jsonify(whitelist)

@internal_bp.route("/info/biubo/remove_whitelist")
@login_required
def waf_remove_whitelist():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    ip = request.args.get("ip")
    if not ip:
        return jsonify({})
    db = get_db(host)
    db.remove_whitelist(ip)
    return jsonify({"status": "success"})

@internal_bp.route("/info/biubo/add_whitelist", methods=["POST"])
@login_required
def add_whitelist():
    data = request.get_json(silent=True) or {}
    host = data.get("host") or request.host
    ip = data.get("ip", "").strip()
    note = data.get("note", "")
    if not ip:
        return jsonify({"status": "error", "msg": "IP required"}), 400
    db = get_db(host)
    db.add_whitelist(ip, note)  # note maps to remark param
    return jsonify({"status": "success"})

@internal_bp.route("/info/biubo/ban", methods=["POST"])
@login_required
def add_blacklist():
    host = request.args.get("host") or request.host
    target_base = settings.PROXY_MAP.get(host)
    if not target_base:
        return Response(current_app.config['ERR_PAGES']['404'], mimetype="text/html"), 404
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manual ban")
    if not ip:
        return jsonify({"status": "error", "msg": "IP required"}), 400
    db = get_db(host)
    db.ban_ip(ip, reason)
    return jsonify({"status": "success"})

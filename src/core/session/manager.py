import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from src.utils.compression import compress_json, decompress_json
from src.data.storage.manager import get_db
from src.config.settings import settings
from src.data.analytics.aggregator import update_analytics
from src.utils.http_utils import get_ip_info
from src.utils.query_parser import parse, evaluate
from src.data.storage.base import Database
import os


logger = logging.getLogger("WAF.Session")

# _sessions[rid] = {"timestamp": float, "host": str, "log": dict, "dirty": bool}
_sessions = {}
_sessions_lock = threading.Lock()

def create_session(request_id: str, host: str, log_entry: dict):
    """Initializes and persists the request log immediately, and retains the session for asynchronous beacon updates."""
    with _sessions_lock:
        _sessions[request_id] = {
            "timestamp": time.time(),
            "host":      host,
            "log":       log_entry,
            "dirty":     False,  # Will be set True when beacon updates arrive
        }
    # Write immediately so Access Logs are updated in real-time
    _flush_session(request_id, _sessions[request_id])

def update_session_log(request_id: str, host: str, updates: dict):
    """Updates the session log (Beacon asynchronous callback - IP/fingerprint/country)."""
    with _sessions_lock:
        session = _sessions.get(request_id)
        if session:
            session["log"].update(updates)
            session["timestamp"] = time.time()
            session["dirty"] = True  # Mark for re-flush with enriched data

def update_rrweb_events(request_id: str, host: str, events: list):
    """Appends rrweb recording event data real-time to DB to prevent memory blowup."""
    if not events: return
    
    with _sessions_lock:
        session = _sessions.get(request_id)
        if session:
            session["timestamp"] = time.time()
            if "rrweb" in session["log"] and isinstance(session["log"]["rrweb"], list):
                session["log"]["rrweb"] = b""  # Clear memory

    db = get_db(host)
    
    with db._lock:
        db._ensure_log_db()
        logs = db._log_db.get("logs", [])
        
        target_idx = -1
        for i, entry in enumerate(logs):
            if entry.get("request_id") == request_id:
                target_idx = i
                break
                
        if target_idx == -1: return
            
        target_entry = logs[target_idx]
        existing_events = []
        if target_entry.get("rrweb"):
            try:
                dec = decompress_json(target_entry["rrweb"])
                if dec and "events" in dec:
                    existing_events = dec["events"]
            except Exception:
                pass
                
        existing_events.extend(events)
        if existing_events:
            try:
                first_ts = existing_events[0].get("timestamp", 0)
                last_ts = existing_events[-1].get("timestamp", 0)
                target_entry["duration_sec"] = abs(last_ts - first_ts) // 1000
                target_entry["rrweb"] = compress_json({"events": existing_events})
            except Exception:
                pass
                
        logs[target_idx] = target_entry
        db._log_db["logs"] = logs
        db._log_db.flush()

def _flush_session(sid: str, session: dict):
    """Persists the session to the database for the corresponding host."""
    log   = session["log"]
    
    # Perform any network blocking tasks before preparing the final dictionary
    if not log.get("country"):
        country = get_ip_info(log.get("cdn_ip", ""))
        if country:
            log["country"] = country.get("country", "")
            log["city"] = country.get("city", "")
            
    db = get_db(session["host"])
    disk_rrweb = b""
    disk_duration = 0
    
    with db._lock:
        db._ensure_log_db()
        logs = db._log_db.get("logs", [])
        for entry in logs:
            if entry.get("request_id") == sid:
                disk_rrweb = entry.get("rrweb", b"")
                disk_duration = entry.get("duration_sec", 0)
                break

    if disk_rrweb:
        log["rrweb"] = disk_rrweb
        log["duration_sec"] = disk_duration
    else:
        rrweb = log.get("rrweb", [])
        if rrweb and isinstance(rrweb, list):
            try:
                first_ts = rrweb[0].get("timestamp", 0)
                last_ts  = rrweb[-1].get("timestamp", 0)
                log["duration_sec"] = abs(last_ts - first_ts) // 1000
                from src.utils.compression import compress_json
                log["rrweb"] = compress_json({"events": rrweb})
            except Exception:
                log["rrweb"] = b""
        else:
            if "rrweb" not in log or isinstance(log["rrweb"], list):
                log["rrweb"] = b""

    db = get_db(session["host"])
    db.write_log(log)
    logger.debug(f"Session flushed: {sid}")

def _session_gc_worker():
    """Cleans up expired sessions and re-flushes those with asynchronous updates (overwriting initial records)."""
    while True:
        time.sleep(settings.SESSION_GC_INTERVAL)
        now = time.time()
        to_flush = []
        with _sessions_lock:
            for sid in list(_sessions):
                s = _sessions[sid]
                if now - s["timestamp"] > settings.SESSION_TIMEOUT:
                    to_flush.append((sid, _sessions.pop(sid)))
        
        for sid, session in to_flush:
            try:
                db = get_db(session["host"])
                log = session["log"]
                
                # Fetch real-time duration from DB to replace the removed memory list duration
                with db._lock:
                    db._ensure_log_db()
                    for entry in db._log_db.get("logs", []):
                        if entry.get("request_id") == sid:
                            log["duration_sec"] = entry.get("duration_sec", 0)
                            break
                            
                update_analytics(db, session)
                if session.get("dirty"):
                    # Re-flush with enriched beacon data (fingerprint, country)
                    _flush_session(sid, session)
            except Exception as e:
                logger.error(f"Re-flush session {sid} failed: {e}")

# Start the garbage collection worker thread
threading.Thread(target=_session_gc_worker, daemon=True).start()

def _log_gc_worker():
    """Periodically cleans up old logs based on retention days and rules."""

    # Initial delay to wait for system startup
    time.sleep(15)
    
    while True:
        try:
            if settings.LOG_AUTO_DELETE:
                retain_asts = None
                if settings.LOG_RETAIN:
                    try:
                        retain_asts = parse(settings.LOG_RETAIN)
                    except Exception as e:
                        logger.error(f"Failed to parse retain rule '{settings.LOG_RETAIN}': {e}")

                cutoff_date = (datetime.now() - timedelta(days=settings.LOG_RETENTION_DAYS)).strftime('%Y-%m-%d')
                
                if os.path.exists(settings.DB_ROOT):
                    for host in os.listdir(settings.DB_ROOT):
                        host_dir = os.path.join(settings.DB_ROOT, host, "logs")
                        if not os.path.exists(host_dir): continue
                        
                        for file in os.listdir(host_dir):
                            if not file.endswith(".msgpack"): continue
                            
                            file_date = file.split(".msgpack")[0]
                            # Only delete older than cutoff date
                            if file_date < cutoff_date:
                                filepath = os.path.join(host_dir, file)
                                try:
                                    db = Database(filepath, auto_backup=False)
                                    logs = db.get("logs", [])
                                    
                                    retained_logs = []
                                    for rec in logs:
                                        keep = False
                                        if retain_asts:
                                            try:
                                                if evaluate(retain_asts, rec):
                                                    keep = True
                                            except Exception:
                                                pass
                                        if keep:
                                            retained_logs.append(rec)
                                            
                                    if not retained_logs:
                                        db.close()
                                        if os.path.exists(filepath):
                                            os.remove(filepath)
                                        logger.info(f"Deleted old log file completely: {file}")
                                    elif len(retained_logs) < len(logs):
                                        db["logs"] = retained_logs
                                        db.close()
                                        logger.info(f"Pruned {len(logs) - len(retained_logs)} logs from {file}, retained {len(retained_logs)}.")
                                    else:
                                        db.close()
                                        
                                except Exception as e:
                                    logger.error(f"Log GC error on {filepath}: {e}")
                                    
        except Exception as e:
            logger.error(f"Log GC worker error: {e}")
            
        # Run daily check
        time.sleep(3600 * 24)

# Start the log garbage collection worker thread
threading.Thread(target=_log_gc_worker, daemon=True).start()



def build_log_entry(request_id: str, snapshot: dict, detection: dict, status_code: int = 200) -> dict:
    """Constructs a standardized log entry structure."""
    return {
        "request_id":   request_id,
        "type":         detection.get("type", "normal"),
        "attack_types": detection.get("attack_types", []),
        "time":         datetime.now().isoformat(),
        "ip":           snapshot.get("remote_addr", ""),
        "cdn_ip":       snapshot.get("remote_addr", ""),
        "country":      "",
        "city":         "",
        "fingerprint":  "",
        "method":       snapshot.get("method", ""),
        "url":          snapshot.get("url", ""),
        "headers":      snapshot.get("headers", {}),
        "cookies":      snapshot.get("cookies", {}),
        "data": {
            "form": snapshot.get("form", {}),
            "json": snapshot.get("json", {}),
            "args": snapshot.get("args", {}),
        },
        "browser_info": {},
        "rrweb":        [],
        "duration_sec": 0,
        "status":       status_code,
    }


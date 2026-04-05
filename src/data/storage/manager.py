import os
import datetime
import threading
import logging
import json
from typing import Dict, Optional, List
from .base import Database
from src.config.settings import settings

logger = logging.getLogger("WAF.DBManager")

class ProxyDB:
    """Manages database state for a single host."""

    def __init__(self, host: str):
        self.host = host
        self._lock = threading.Lock()
        
        self.host_dir = os.path.join(settings.DB_ROOT, host)
        os.makedirs(os.path.join(self.host_dir, "logs"), exist_ok=True)

        # Initialize RAM (persistent state)
        self.ram = Database(os.path.join(self.host_dir, "RAM.msgpack"), auto_backup=False)
        self._init_ram_if_empty()

        self._log_path: str = ""
        self._log_db: Optional[Database] = None
        self._ensure_log_db()

    def _init_ram_if_empty(self):
        if len(self.ram) > 0:
            return
            
        template_path = os.path.join(settings.TEMPLATE_ROOT, "RAM.json")
        if os.path.exists(template_path):
            self._import_json_to_db(self.ram, template_path)

        # Set site info
        site_info = self.ram.get("site", {})
        site_info.update({
            "description": "This is a WAF proxy.",
            "domain": self.host,
            "created_at": datetime.datetime.now().strftime("%Y/%m/%d %H:%M"),
        })
        self.ram["site"] = site_info

    def _import_json_to_db(self, db: Database, json_path: str):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for k, v in data.items():
                    db[k] = v
        except Exception as e:
            logger.error(f"Failed to import template {json_path}: {e}")

    def _ensure_log_db(self):
        date_str = datetime.datetime.now().strftime('%Y-%m-%d')
        new_path = os.path.join(self.host_dir, "logs", f"{date_str}.msgpack")
        
        if new_path == self._log_path:
            return
            
        if self._log_db:
            self._log_db.flush()
            
        self._log_db = Database(new_path, auto_backup=False)
        if len(self._log_db) == 0:
            template_path = os.path.join(settings.TEMPLATE_ROOT, "log.json")
            if os.path.exists(template_path):
                self._import_json_to_db(self._log_db, template_path)
        
        if "logs" not in self._log_db:
            self._log_db["logs"] = []
        
        overview = self._log_db.get("overview", {})
        if "seen_ips_today" not in overview:
            overview["seen_ips_today"] = {}
        self._log_db["overview"] = overview
        self._log_path = new_path

    def write_log(self, entry: dict):
        with self._lock:
            self._ensure_log_db()
            logs = self._log_db.get("logs", [])
            # Upsert: update existing entry if request_id matches, otherwise append
            rid = entry.get("request_id")
            if rid:
                for i, existing in enumerate(logs):
                    if existing.get("request_id") == rid:
                        logs[i] = entry
                        self._log_db["logs"] = logs
                        return
            logs.append(entry)
            self._log_db["logs"] = logs


    def ban_ip(self, ip: str, reason: str, expire_minutes: Optional[int] = None):
        from src.utils.http_utils import get_ip_info
        info = get_ip_info(ip)
        # Legacy API returns varying formats - extract robustly
        country = info.get("country") or info.get("countryName") or ""
        city = info.get("city") or info.get("cityName") or ""
        record = {
            "reason": reason,
            "expire": expire_minutes,
            "added_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country": country,
            "city": city,
        }

        with self._lock:
            security = self.ram.get("security", {})
            blacklist = security.get("blacklist", {})
            blacklist[ip] = record
            security["blacklist"] = blacklist
            self.ram["security"] = security
            
            self._ensure_log_db()
            overview = self._log_db.get("overview", {})
            block_today = overview.get("block_today", [])
            block_today.append({ip: record})
            overview["block_today"] = block_today
            self._log_db["overview"] = overview
            self.ram.flush()
            self._log_db.flush()
            
        logger.warning(f"[BAN] {ip} banned — reason={reason} expire={expire_minutes}min")

    def unban_ip(self, ip: str) -> bool:
        with self._lock:
            security = self.ram.get("security", {})
            blacklist = security.get("blacklist", {})
            if ip in blacklist:
                blacklist.pop(ip)
                security["blacklist"] = blacklist
                self.ram["security"] = security
                self.ram.flush()
                logger.warning(f"[UNBAN] {ip} removed from blacklist")
                return True
        return False


    def is_banned(self, ip: str) -> bool:
        security = self.ram.get("security", {})
        blacklist = security.get("blacklist", {})
        record = blacklist.get(ip)
        
        if record is None: return False
            
        expire_min = record.get("expire")
        if expire_min is None or expire_min is True: return True
            
        added_at = datetime.datetime.strptime(
            record["added_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=datetime.timezone.utc)
        expire_at = added_at + datetime.timedelta(minutes=expire_min)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        if now_utc >= expire_at:
            self.unban_ip(ip)
            return False
        return True

    def is_temporary_banned(self, ip: str) -> bool:
        record = self.ram.get("security", {}).get("blacklist", {}).get(ip)
        return record is not None and record.get("expire") is True

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.ram.get("security", {}).get("whitelist", {})

    def add_whitelist(self, ip: str, remark: str = ""):
        with self._lock:
            security = self.ram.get("security", {})
            whitelist = security.get("whitelist", {})
            whitelist[ip] = {
                "remark": remark,
                "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            security["whitelist"] = whitelist
            self.ram["security"] = security
            self.ram.flush()

    def remove_whitelist(self, ip: str) -> bool:
        with self._lock:
            security = self.ram.get("security", {})
            whitelist = security.get("whitelist", {})
            if ip in whitelist:
                whitelist.pop(ip)
                security["whitelist"] = whitelist
                self.ram["security"] = security
                return True
        return False

# Global instance pool
_proxy_dbs: Dict[str, ProxyDB] = {}
_pool_lock = threading.Lock()

def get_db(host: str) -> ProxyDB:
    with _pool_lock:
        if host not in _proxy_dbs:
            _proxy_dbs[host] = ProxyDB(host)
        return _proxy_dbs[host]

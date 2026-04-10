import os
import json
import logging
from typing import Set, Dict, List
import secrets


class Settings:
    # ══════════════════════════════════════════════════════════════════════════════
    # Base Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    WAF_PORT: int = int(os.getenv("WAF_PORT", "80"))
    DASHBOARD_PASSWORD: str = os.getenv("WAF_DASHBOARD_PASSWORD", "admin123")
    CORS_ORIGINS: List[str] = json.loads(os.getenv("WAF_CORS_ORIGINS", '["http://ip.zplb.org.cn:7000"]'))

    HOST_FORWARD: bool = False
    PROXY_MAP: Dict[str, str] = {}

    # ══════════════════════════════════════════════════════════════════════════════
    # LLM & API Keys
    # ══════════════════════════════════════════════════════════════════════════════
    API_KEY: str      = os.getenv("WAF_API_KEY", "")
    LLM_MODEL: str    = os.getenv("WAF_LLM_MODEL", "qwen-plus")
    LLM_BASE_URL: str = os.getenv("WAF_LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

    # ══════════════════════════════════════════════════════════════════════════════
    # Timeout and Cycle Configuration (Seconds)
    # ══════════════════════════════════════════════════════════════════════════════
    SESSION_TIMEOUT: int     = int(os.getenv("WAF_SESSION_TIMEOUT", "20"))    # Idle timeout for rrweb sessions
    CACHE_TTL: int           = int(os.getenv("WAF_CACHE_TTL", "3600"))        # TTL for LLM detection cache
    SESSION_GC_INTERVAL: int = int(os.getenv("WAF_SESSION_GC_INTERVAL", "5")) # Session cleanup interval
    CACHE_GC_INTERVAL: int   = int(os.getenv("WAF_CACHE_GC_INTERVAL", "30"))  # Cache cleanup interval

    # ══════════════════════════════════════════════════════════════════════════════
    # IP Rate Limiting / Banning
    # ══════════════════════════════════════════════════════════════════════════════
    GET_IP_FROM_HEADERS: Dict = {
        "state": os.getenv("WAF_TRUST_HEADERS", "true").lower() == "true",
        "order": json.loads(os.getenv("WAF_IP_HEADER_ORDER", '["CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"]'))
    }
    RATE_LIMIT_PER_SEC: int    = int(os.getenv("WAF_RATE_LIMIT", "15"))       # Max requests per IP per second
    RATE_BAN_THRESHOLD: int    = int(os.getenv("WAF_BAN_THRESHOLD", "30"))    # Threshold for auto-banning
    RATE_BAN_DURATION_MIN: int = int(os.getenv("WAF_BAN_DURATION", "60"))     # Ban duration in minutes
    RATE_GC_INTERVAL: int      = int(os.getenv("WAF_RATE_GC_INTERVAL", "10")) # Rate limit cleanup interval

    # ══════════════════════════════════════════════════════════════════════════════
    # Resource Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    STATIC_EXTENSIONS: Set[str] = {
        '.js', '.css', '.png', '.jpg', '.jpeg',
        '.ico', '.woff', '.woff2', '.svg', '.gif', '.webp',
    }

    # ══════════════════════════════════════════════════════════════════════════════
    # Path Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    PROJECT_ROOT: str = os.getcwd()
    DB_ROOT: str = os.path.join(PROJECT_ROOT, "data")
    TEMPLATE_ROOT: str = os.path.join(PROJECT_ROOT, "templates")
    PAGE_ROOT: str = os.path.join(PROJECT_ROOT, "page")
    
    # ══════════════════════════════════════════════════════════════════════════════
    # JS Challenge Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    CHALLENGE_SECRET: str = os.getenv("WAF_CHALLENGE_SECRET", secrets.token_hex(32))
    CHALLENGE_EXPIRE: int = int(os.getenv("WAF_CHALLENGE_EXPIRE", "3600"))

    # ══════════════════════════════════════════════════════════════════════════════
    # File Upload Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    UPLOAD_MAX_SIZE: int = int(os.getenv("WAF_MAX_UPLOAD_SIZE", str(10 * 1024 * 1024))) # Default 10 MB
    UPLOAD_ALLOWED_EXTENSIONS: Set[str] = {
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.bmp', '.tiff',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.md', '.csv',
        # Archive
        '.zip', '.tar', '.gz', '.7z', '.rar',
        # Media
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm',
    }

    DASHBOARD_PATH: str = os.getenv("WAF_DASHBOARD_PATH", "/biubo-cgi")

    # ══════════════════════════════════════════════════════════════════════════════
    # Log Management Configuration
    # ══════════════════════════════════════════════════════════════════════════════
    LOG_AUTO_DELETE: bool     = os.getenv("WAF_LOG_AUTO_DELETE", "false").lower() == "true"
    LOG_RETENTION_DAYS: int   = int(os.getenv("WAF_LOG_RETENTION_DAYS", "30"))     # Delete logs older than this many days
    LOG_RETAIN: str = os.getenv("WAF_LOG_RETAIN_LIST", 'type:hacker') # Dates or rules of logs to permanently retain (e.g., ["type:hacker"])

    def __init__(self):
        self._load_config_file()

    def is_initialized(self) -> bool:
        """Checks if the WAF has been configured with at least one proxy site."""
        return len(self.PROXY_MAP) > 0

    def save_config(self):
        """Persists the current settings to config.json."""
        config_path = os.path.join(self.PROJECT_ROOT, "config.json")
        config_data = {
            "WAF_PORT": self.WAF_PORT,
            "DASHBOARD_PASSWORD": self.DASHBOARD_PASSWORD,
            "CORS_ORIGINS": self.CORS_ORIGINS,
            "PROXY_MAP": self.PROXY_MAP,
            "DASHBOARD_PATH": self.DASHBOARD_PATH,
            "API_KEY": self.API_KEY,
            "LLM_MODEL": self.LLM_MODEL,
            "LLM_BASE_URL": self.LLM_BASE_URL
        }
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logging.info(f"Configuration saved to {config_path}")
        except Exception as e:
            logging.error(f"Failed to save config.json: {e}")

    def _load_config_file(self):
        """Loads configuration from config.json if it exists."""
        config_path = os.path.join(self.PROJECT_ROOT, "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    for key, value in config.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
            except Exception as e:
                logging.error(f"Failed to load config.json: {e}")

settings = Settings()

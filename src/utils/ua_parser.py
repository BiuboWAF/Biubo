import re
from typing import Dict

def parse_user_agent(ua_string: str) -> Dict[str, str]:
    """A simple User-Agent parser for basic browser and OS identification."""
    res = {
        "browser": "Unknown",
        "os": "Unknown",
        "device": "PC"
    }
    
    if not ua_string:
        return res
        
    ua = ua_string.lower()
    
    # Detect Browser
    if "edg/" in ua: res["browser"] = "Edge"
    elif "chrome/" in ua: res["browser"] = "Chrome"
    elif "firefox/" in ua: res["browser"] = "Firefox"
    elif "safari/" in ua: res["browser"] = "Safari"
    elif "msie" in ua or "trident" in ua: res["browser"] = "IE"
    
    # Detect OS
    if "windows" in ua: res["os"] = "Windows"
    elif "mac os" in ua: res["os"] = "MacOS"
    elif "linux" in ua: res["os"] = "Linux"
    elif "android" in ua: 
        res["os"] = "Android"
        res["device"] = "Mobile"
    elif "iphone" in ua or "ipad" in ua: 
        res["os"] = "iOS"
        res["device"] = "Mobile"
        
    return res

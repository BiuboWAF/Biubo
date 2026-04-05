import logging
from src.utils.ua_parser import parse_user_agent
from src.utils.http_utils import get_source_from_referer
from src.data.storage.manager import ProxyDB
from urllib.parse import urlparse


logger = logging.getLogger("WAF.Analytics")

def extract_path(url):
    return urlparse(url).path

def update_analytics(db: ProxyDB, entry: dict):
    """Computes and updates traffic and security statistics."""
    analytics = db.ram.get("analytics", {})
    overview = db._log_db.get("overview", {})
    entry = entry.get("log", {})

    ip = entry.get("cdn_ip", "")
    fingerprint = entry.get("fingerprint", "")
    is_hacker = (entry.get("type") == "hacker")
    url = entry.get("url", "")
    url = extract_path(url)
    country = entry.get("country", "unknown") or "unknown"
    ua = entry.get("headers", {}).get("User-Agent", "unknown")
    duration_sec = entry.get("duration_sec", 0)

    def inc(d, key):
        d[key] = d.get(key, 0) + 1

    analytics["traffic"]["visitors"]["total"] += 1
    overview["visitors"]["total"] += 1

    if is_hacker:
        analytics["security"]["blocked_requests"] += 1
        overview["security"]["blocked_requests"] += 1

        if analytics["traffic"]["visitors"]["total"] == 0:
            analytics["security"]["block_rate"] = 1
            overview["security"]["block_rate"] = 1
        else:
            analytics["security"]["block_rate"] = analytics["security"]["blocked_requests"] / analytics["traffic"]["visitors"]["total"]
            overview["security"]["block_rate"] = overview["security"]["blocked_requests"] / overview["visitors"]["total"]

        for i in entry.get("attack_types", {}):
            inc(analytics["security"]["attack_types"], i)
            inc(overview["security"]["attack_types"], i)

        inc(analytics["security"]["top_attack_ips"], ip)
        inc(overview["security"]["top_attack_ips"], ip)

        inc(analytics["security"]["top_target_urls"], url)
        inc(overview["security"]["top_target_urls"], url)

        inc(analytics["security"]["geo"]["attackers_by_country"], country)
        inc(overview["security"]["geo"]["attackers_by_country"], country)

    if duration_sec != 0:
        inc(analytics["security"]["geo"]["visitors_by_country"], country)
        inc(overview["security"]["geo"]["visitors_by_country"], country)

        if fingerprint and fingerprint not in analytics["traffic"]["visitors"]["unique"]:
            analytics["traffic"]["visitors"]["unique"].append(fingerprint)
            overview["visitors"]["unique"].append(fingerprint)

        referer = entry.get("headers", {}).get("Referer", "")
        source_type = get_source_from_referer(referer)
        inc(analytics["traffic"]["sources"], source_type)
        inc(overview["sources"], source_type)

        analytics["traffic"]["engagement"]["total"] += 1
        overview["engagement"]["total"] += 1

        a_total = analytics["traffic"]["engagement"]["total"]
        o_total = overview["engagement"]["total"]

        if duration_sec <= 15:
            analytics["traffic"]["engagement"]["bounce_rate"] = (
                analytics["traffic"]["engagement"]["bounce_rate"] * (a_total - 1) + 1
            ) / a_total
            overview["engagement"]["bounce_rate"] = (
                overview["engagement"]["bounce_rate"] * (o_total - 1) + 1
            ) / o_total

        analytics["traffic"]["engagement"]["avg_session_duration"] = (
            analytics["traffic"]["engagement"]["avg_session_duration"] * (a_total - 1) + duration_sec
        ) / a_total
        overview["engagement"]["avg_session_duration"] = (
            overview["engagement"]["avg_session_duration"] * (o_total - 1) + duration_sec
        ) / o_total

        inc(analytics["trending_urls"], url)
        inc(overview["trending_urls"], url)

        ua_info = parse_user_agent(ua)

        inc(analytics["clients"]["browsers"], ua_info.get("browser", "Unknown"))
        inc(overview["clients"]["browsers"], ua_info.get("browser", "Unknown"))

        inc(analytics["clients"]["os"], ua_info.get("os", "Unknown"))
        inc(overview["clients"]["os"], ua_info.get("os", "Unknown"))

        inc(analytics["clients"]["devices"], ua_info.get("device", "PC"))
        inc(overview["clients"]["devices"], ua_info.get("device", "PC"))

        inc(analytics["clients"]["user_agents"], ua)
        inc(overview["clients"]["user_agents"], ua)

    db.ram["analytics"] = analytics
    db._log_db["overview"] = overview

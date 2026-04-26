"""
Input validation utilities for security hardening.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional


# Regex patterns for validation
_IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
_HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)

# Private/internal IP ranges that should not be accessible via external proxies
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ipaddress.ip_network('100.64.0.0/10'),   # Carrier-grade NAT
    ipaddress.ip_network('::1/128'),         # Loopback IPv6
    ipaddress.ip_network('fc00::/7'),       # Unique local IPv6
    ipaddress.ip_network('fe80::/10'),      # Link-local IPv6
]


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address (IPv4 or IPv6)."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_private_ip(ip: str) -> bool:
    """Check if IP is in a private/internal network range."""
    try:
        addr = ipaddress.ip_address(ip)
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                return True
        return False
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Check if string is a valid hostname."""
    if not hostname or len(hostname) > 253:
        return False
    return bool(_HOSTNAME_PATTERN.match(hostname))


def is_safe_url(url: str, allow_private: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Check if a URL is safe (not pointing to internal/private resources).
    
    Args:
        url: URL to validate
        allow_private: Whether to allow private IP addresses
        
    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)
        
        # Must have a scheme
        if not parsed.scheme or parsed.scheme not in ('http', 'https'):
            return False, "Invalid URL scheme"
        
        # Check for valid hostname/IP
        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname"
        
        # Check for private IPs
        if not allow_private:
            if is_private_ip(hostname):
                return False, "Private IP addresses not allowed"
            
            # Also check if hostname resolves to private IP
            # (This would require DNS resolution, skipping for now)
        
        # Check for localhost variants
        if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return False, "Localhost not allowed"
        
        # Check port is reasonable
        if parsed.port and (parsed.port < 1 or parsed.port > 65535):
            return False, "Invalid port number"
        
        return True, None
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    if not filename:
        return ""
    
    # Remove path traversal sequences
    sanitized = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Strip dangerous characters but keep common filename characters
    sanitized = re.sub(r'[<>:"|?*]', '', sanitized)
    
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized.strip()


def is_safe_path(path: str, base_path: str) -> bool:
    """
    Check if a path is safe (does not escape the base directory).
    
    Args:
        path: The path to check
        base_path: The base directory that must contain the path
        
    Returns:
        True if path is safe, False otherwise
    """
    import os
    try:
        # Normalize paths
        real_base = os.path.realpath(base_path)
        real_path = os.path.realpath(os.path.join(base_path, path))
        
        # Check if path starts with base
        return real_path.startswith(real_base)
    except Exception:
        return False


def validate_date_string(date_str: str) -> bool:
    """Validate a date string in YYYY-MM-DD format."""
    if not date_str:
        return False
    
    pattern = r'^\d{4}-\d{2}-\d{2}$'
    if not re.match(pattern, date_str):
        return False
    
    try:
        from datetime import datetime
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate a port number."""
    return isinstance(port, int) and 1 <= port <= 65535


def sanitize_log_query(query: str, max_length: int = 1000) -> str:
    """
    Sanitize a log search query to prevent injection attacks.
    
    Args:
        query: The search query
        max_length: Maximum allowed length
        
    Returns:
        Sanitized query
    """
    if not query:
        return ""
    
    # Limit length
    if len(query) > max_length:
        query = query[:max_length]
    
    # Remove null bytes
    query = query.replace('\x00', '')
    
    return query.strip()

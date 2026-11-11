"""
Small safety helpers for the benchmark harness.

  sanitize_url                 - strips userinfo, query and fragment before a URL is stored in a report
  is_loopback_host             - 127.0.0.0/8, ::1 and localhost
  enforce_https_for_credentials - refuse to send credential headers over cleartext HTTP to a
                                  non-loopback host (master plan 12.5: credentials never exposed)
"""

from __future__ import annotations

import ipaddress
from typing import Mapping, Optional
from urllib.parse import urlparse

from safety.policy import SafetyViolationError


def sanitize_url(url: str) -> str:
    """Return scheme://host[:port]/path with no userinfo, query string or fragment."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        if not parsed.scheme or not netloc:
            return "[invalid-url]"
        return f"{parsed.scheme}://{netloc}{parsed.path}"
    except ValueError:
        return "[invalid-url]"


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def enforce_https_for_credentials(
    url: str,
    headers: Optional[Mapping[str, str]],
    allow_insecure_http: bool = False,
) -> None:
    """
    Raise SafetyViolationError when credential-bearing headers would travel over
    cleartext HTTP to a non-loopback host. Loopback HTTP is always allowed.
    """
    if not headers or allow_insecure_http:
        return
    parsed = urlparse(url)
    if parsed.scheme.lower() == "https":
        return
    if is_loopback_host(parsed.hostname or ""):
        return
    raise SafetyViolationError(
        "Refusing to send credentials over cleartext HTTP to a non-loopback host "
        "(use HTTPS, or --allow-insecure-http for an isolated lab network)"
    )
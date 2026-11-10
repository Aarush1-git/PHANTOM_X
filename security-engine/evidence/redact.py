"""
Credential redaction for evidence artifacts.

Evidence (request/response dumps, proof data) is stored and shown to developers,
so credentials must never be persisted. Only credential-like values are removed;
business data (e.g. the victim's booking) is deliberately kept because it IS the proof.

Layers:
  * redact_headers  - structured headers: sensitive names -> [REDACTED]
  * redact_body     - JSON bodies: values under credential-like keys -> [REDACTED];
                      non-JSON bodies fall back to redact_text
  * redact_text     - regex pass for cookies, Bearer/Basic tokens, JWTs, key=value pairs
  * redact_obj      - recursive pass for dict/list proof data
  * build_response_dump - the single way evidence_response is built
"""

import json
import re
from typing import Any, Dict, Mapping

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token",
})

_KEY_WORDS = r"token|secret|passw(?:or)?d|passwd|api[_-]?key|authorization|session|jwt|cookie|credential|private[_-]?key|csrf"
_SENSITIVE_KEY = re.compile(_KEY_WORDS, re.IGNORECASE)

_COOKIE_HEADER = re.compile(r"""(?i)((?:set-)?cookie["']?\s*[:=]\s*["']?)[^"'\r\n]*""")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# Whole Authorization value (Bearer/Basic/Digest/...): quoted value in full, else to end of line.
_AUTH_HEADER = re.compile(
    r"""(?i)((?:proxy-)?authorization["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]*)"""
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
# Quoted values are redacted in full (spaces included); unquoted stop at a delimiter.
_KEY_VALUE = re.compile(
    r"""(?i)(["']?[\w-]*(?:""" + _KEY_WORDS + r""")[\w-]*["']?\s*[:=]\s*)"""
    r"""(?!\[REDACTED\])(?P<val>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,"'&;}\]]+)"""
)


def _redact_kv(m: "re.Match[str]") -> str:
    quote = m.group("val")[0] if m.group("val")[:1] in ("'", '"') else ""
    return m.group(1) + quote + REDACTED + quote


def redact_text(text: str) -> str:
    """Regex-based redaction for free text (dumps, non-JSON bodies)."""
    if not text:
        return text
    text = _COOKIE_HEADER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _JWT.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _KEY_VALUE.sub(_redact_kv, text)
    return text


def redact_headers(headers: Mapping[str, Any] | None) -> Dict[str, str]:
    """Return a copy of *headers* with credential header values replaced."""
    safe: Dict[str, str] = {}
    for name, value in (headers or {}).items():
        if name.lower() in SENSITIVE_HEADERS or _SENSITIVE_KEY.search(name):
            safe[name] = REDACTED
        else:
            safe[name] = redact_text(str(value))
    return safe


def redact_obj(obj: Any) -> Any:
    """Recursively redact a parsed JSON / proof-data structure."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEY.search(k) else redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def redact_body(body: str) -> str:
    """Redact a response body: JSON-aware first, regex fallback otherwise."""
    if not body:
        return body
    try:
        return json.dumps(redact_obj(json.loads(body)), ensure_ascii=False)
    except (ValueError, TypeError):
        return redact_text(body)


def build_response_dump(status_code: int, headers: Mapping[str, Any] | None, body: str, limit: int = 2000) -> str:
    """Build a safe evidence_response string (redact first, then truncate)."""
    return (
        f"HTTP {status_code}\n"
        f"Headers: {redact_headers(headers)}\n"
        f"Body: {redact_body(body)[:limit]}"
    )
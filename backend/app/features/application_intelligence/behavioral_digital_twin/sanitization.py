import re
import hashlib
from typing import Any, Dict, List, Optional, Set

# Regex pattern matching sensitive key names
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|auth|authorization|bearer|cookie|session|"
    r"api_?key|private_?key|credential|credit_?card|cvv|ssn|passphrase)"
)

# Regex matching actual JWT tokens (base64url encoded header.payload.signature starting with ey)
JWT_PATTERN = re.compile(r"^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+$")

# Sensitive header names to strictly strip or redact
SENSITIVE_HEADERS: Set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "apikey",
}


def hash_session_identifier(identifier: Optional[str]) -> Optional[str]:
    """
    Deterministically hash a session token or identifier using SHA-256.
    Returns a 64-character hexadecimal digest, or None if input is empty.
    Never stores or exposes the underlying session token.
    """
    if not identifier or not isinstance(identifier, str) or not identifier.strip():
        return None
    return hashlib.sha256(identifier.strip().encode("utf-8")).hexdigest()


def sanitize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Sanitize HTTP request/response headers by stripping sensitive credentials.
    """
    if not headers:
        return {}
    sanitized = {}
    for key, value in headers.items():
        lower_key = str(key).lower().strip()
        if lower_key in SENSITIVE_HEADERS or SENSITIVE_KEY_PATTERN.search(lower_key):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, str) and (JWT_PATTERN.match(value) or "bearer " in value.lower()):
            sanitized[key] = "[REDACTED]"
        else:
            # Store safe headers truncated if excessively long
            sanitized[key] = str(value)[:500]
    return sanitized


def sanitize_payload_recursively(
    payload: Any,
    max_depth: int = 10,
    current_depth: int = 0
) -> Any:
    """
    Recursively sanitize dictionaries, lists, and primitives.
    Replaces sensitive keys/values with '[REDACTED]' while preserving schema structure.
    Enforces depth limits to prevent unbounded recursion or denial of service.
    """
    if current_depth > max_depth:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(payload, dict):
        sanitized_dict = {}
        for key, value in payload.items():
            key_str = str(key)
            if SENSITIVE_KEY_PATTERN.search(key_str):
                sanitized_dict[key_str] = "[REDACTED]"
            else:
                sanitized_dict[key_str] = sanitize_payload_recursively(
                    value,
                    max_depth=max_depth,
                    current_depth=current_depth + 1
                )
        return sanitized_dict

    elif isinstance(payload, list):
        return [
            sanitize_payload_recursively(
                item,
                max_depth=max_depth,
                current_depth=current_depth + 1
            )
            for item in payload[:100]  # Cap list element inspection to prevent unbounded payloads
        ]

    elif isinstance(payload, str):
        if JWT_PATTERN.match(payload) or "bearer " in payload.lower():
            return "[REDACTED]"
        return payload[:1000]  # Cap string length

    elif isinstance(payload, (int, float, bool)) or payload is None:
        return payload

    return str(payload)[:200]


def extract_structural_schema(payload: Any, max_depth: int = 5, current_depth: int = 0) -> Dict[str, Any]:
    """
    Extract a safe structural metadata schema from a JSON payload (e.g. types, property names).
    Guarantees no actual business or sensitive customer data is preserved in structural schemas.
    """
    if current_depth > max_depth:
        return {"type": "object", "truncated": True}

    if isinstance(payload, dict):
        properties = {}
        for key, value in payload.items():
            key_str = str(key)
            is_sensitive = bool(SENSITIVE_KEY_PATTERN.search(key_str))
            properties[key_str] = {
                "type": type(value).__name__ if value is not None else "null",
                "sensitive": is_sensitive,
                "structure": extract_structural_schema(value, max_depth, current_depth + 1)
                if isinstance(value, (dict, list)) else None
            }
        return {"type": "object", "properties": properties}

    elif isinstance(payload, list):
        item_schema = None
        if payload:
            item_schema = extract_structural_schema(payload[0], max_depth, current_depth + 1)
        return {"type": "array", "length": len(payload), "items": item_schema}

    else:
        return {"type": type(payload).__name__ if payload is not None else "null"}

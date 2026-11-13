"""
PHANTOM-X - Feature 6: Role & Resource Relationship Mapping
Sanitization & Identity Privacy Utilities

Guarantees:
- Identities are correlated exclusively through SHA-256 hashes.
- Evidence references cannot expose passwords, bearer tokens, or raw session tokens.
- Payloads in evidence are recursively sanitized.
"""

import re
import hashlib
import uuid
from typing import Any, Dict, List, Union


SENSITIVE_FIELD_PATTERNS = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"auth(orization)?", re.IGNORECASE),
    re.compile(r"bearer", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"api[-_]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
]


def hash_identity_identifier(raw_identity: str) -> str:
    """Computes an irreversible SHA-256 hash of an identity or session string."""
    if not raw_identity:
        return ""
    return hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()


def is_sensitive_key(key: str) -> bool:
    """Checks if a field key matches common sensitive credential naming patterns."""
    return any(p.search(key) for p in SENSITIVE_FIELD_PATTERNS)


def sanitize_mapping_evidence(data: Any) -> Any:
    """
    Recursively redacts sensitive credential fields and token values from evidence.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if is_sensitive_key(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_mapping_evidence(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_mapping_evidence(item) for item in data]
    return data


def validate_evidence_reference(ref: str) -> bool:
    """Ensures an evidence reference is a valid UUID string and not a leaked token."""
    try:
        uuid.UUID(str(ref))
        return True
    except (ValueError, AttributeError):
        return False

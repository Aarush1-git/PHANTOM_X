import hashlib
import json
import re
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, asc

from app.models.audit import AuditLog
from app.features.security_operations.audit_logs.schemas import AuditIntegrityVerificationResponse

GENESIS_HASH = "GENESIS_0000000000000000000000000000000000000000000000000000000000000000"

SENSITIVE_KEY_PATTERNS = [
    r"(?i)password",
    r"(?i)passwd",
    r"(?i)pwd",
    r"(?i)secret",
    r"(?i)token",
    r"(?i)api[_-]?key",
    r"(?i)access[_-]?token",
    r"(?i)refresh[_-]?token",
    r"(?i)authorization",
    r"(?i)auth[_-]?header",
    r"(?i)cookie",
    r"(?i)session",
    r"(?i)private[_-]?key",
    r"(?i)credential",
    r"(?i)signature",
    r"(?i)client[_-]?secret",
    r"(?i)ssh[_-]?key",
]

JWT_PATTERN = r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
BEARER_PATTERN = r"(?i)bearer\s+[A-Za-z0-9_\-\.]+"
URL_SENSITIVE_PARAM_PATTERN = r'([?&](?:token|api[_-]?key|password|passwd|pwd|secret|access[_-]?token|refresh[_-]?token|auth|key|session|credential)=)([^&#\s]+)'
DB_URI_PASSWORD_PATTERN = r'((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:]+:)([^@]+)(@)'
PEM_PRIVATE_KEY_PATTERN = r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'


def scrub_secrets(data: Any) -> Any:
    """
    Recursively sanitize metadata payloads to ensure passwords, authentication tokens,
    session cookies, sensitive URL parameters, connection strings, and cryptographic
    private keys are never written to audit stores.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if any(re.search(pat, str(k)) for pat in SENSITIVE_KEY_PATTERNS):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = scrub_secrets(v)
        return cleaned
    elif isinstance(data, list):
        return [scrub_secrets(item) for item in data]
    elif isinstance(data, str):
        # 1. Scrub PEM private key blocks
        val = re.sub(PEM_PRIVATE_KEY_PATTERN, "[REDACTED_PRIVATE_KEY]", data)
        # 2. Scrub Database URI passwords (e.g. postgres://user:pw@host/db)
        val = re.sub(DB_URI_PASSWORD_PATTERN, r"\g<1>[REDACTED]\g<3>", val, flags=re.IGNORECASE)
        # 3. Scrub sensitive URL query parameters (?token=... or &api_key=...)
        val = re.sub(URL_SENSITIVE_PARAM_PATTERN, r"\g<1>[REDACTED]", val, flags=re.IGNORECASE)
        # 4. Scrub JWT strings
        val = re.sub(JWT_PATTERN, "[REDACTED_JWT]", val)
        # 5. Scrub Bearer tokens
        val = re.sub(BEARER_PATTERN, "Bearer [REDACTED_TOKEN]", val)
        # 6. Scrub Cookie headers
        val = re.sub(r'(?i)(cookie:\s*)([^\r\n]+)', r"\g<1>[REDACTED_COOKIE]", val)
        # 7. Scrub key-value secrets in JSON / query / header strings
        val = re.sub(
            r'(?i)(["\']?(?:password|passwd|pwd|secret|session[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key)["\']?\s*[:=]\s*["\']?)([^"\'\r\n,\}\s&;]+)(["\']?)',
            r"\g<1>[REDACTED]\g<3>",
            val
        )
        return val
    return data


def normalize_timestamp_str(ts: Any) -> str:
    """Normalize datetime or timestamp string to UTC seconds string without microsecond or timezone variance."""
    if not ts:
        return ""
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%dT%H:%M:%S")
    clean = str(ts).replace(" ", "T").split("+")[0].split("Z")[0]
    return clean.split(".")[0]


def compute_canonical_hash(
    event_id: str,
    org_id: str,
    timestamp_str: str,
    category: str,
    event_type: str,
    status: str,
    action: str,
    target_type: str,
    target_id: Optional[str],
    details: Dict[str, Any],
    prev_event_hash: str,
    sequence_number: Optional[int] = 1,
    legacy_format: bool = False
) -> str:
    """
    Calculate cryptographic SHA-256 hash across canonical event properties.
    By default, uses deterministic canonical JSON with stable sorted keys to prevent
    delimiter-collision ambiguities. Also supports legacy pipe-delimited strings
    for backwards compatibility.
    """
    clean_details = scrub_secrets(details)
    norm_ts = normalize_timestamp_str(timestamp_str)
    seq_num = int(sequence_number) if sequence_number is not None else 1

    if legacy_format:
        serialized_details = json.dumps(clean_details, sort_keys=True, separators=(',', ':'))
        canonical_payload = "|".join([
            str(event_id),
            str(org_id),
            str(seq_num),
            norm_ts,
            str(category).upper(),
            str(event_type).upper(),
            str(status).upper(),
            str(action).strip(),
            str(target_type).strip(),
            str(target_id or "").strip(),
            serialized_details,
            str(prev_event_hash)
        ])
        return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    canonical_dict = {
        "action": str(action).strip(),
        "category": str(category).upper(),
        "details": clean_details,
        "event_id": str(event_id),
        "event_type": str(event_type).upper(),
        "org_id": str(org_id),
        "prev_event_hash": str(prev_event_hash),
        "sequence_number": seq_num,
        "status": str(status).upper(),
        "target_id": str(target_id or "").strip(),
        "target_type": str(target_type).strip(),
        "timestamp": norm_ts,
    }
    canonical_payload = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


async def verify_chain_integrity(
    db: AsyncSession,
    org_id: uuid.UUID,
    expected_final_hash: Optional[str] = None,
    expected_final_sequence: Optional[int] = None
) -> AuditIntegrityVerificationResponse:
    """
    Traverse the organization's audit event log to mathematically verify
    cryptographic chain consistency, detect modified content, broken links,
    sequence gaps, reordered events, wiped hashes, or truncated latest events
    via an optional trusted checkpoint.
    """
    query = (
        select(AuditLog)
        .where(AuditLog.organization_id == org_id)
        .order_by(asc(AuditLog.sequence_number), asc(AuditLog.created_at), asc(AuditLog.id))
    )
    result = await db.execute(query)
    events: List[AuditLog] = list(result.scalars().all())

    if not events:
        if expected_final_sequence and expected_final_sequence > 0:
            return AuditIntegrityVerificationResponse(
                is_intact=False,
                records_checked=0,
                anomalies=[f"Audit log is completely empty; expected up to sequence #{expected_final_sequence}."],
                broken_event_ids=[],
                verified_at=datetime.now(timezone.utc)
            )
        return AuditIntegrityVerificationResponse(
            is_intact=True,
            records_checked=0,
            anomalies=[],
            broken_event_ids=[],
            verified_at=datetime.now(timezone.utc)
        )

    anomalies: List[str] = []
    broken_event_ids: List[str] = []
    expected_prev_hash = GENESIS_HASH
    expected_sequence = 1

    for idx, ev in enumerate(events):
        ev_id = str(ev.id)
        created_str = ev.created_at.isoformat() if ev.created_at else ""
        seq = ev.sequence_number if (ev.sequence_number is not None) else (idx + 1)

        # 1. Verify sequence continuity (detect deleted/missing events or reordering)
        if seq != expected_sequence:
            anomalies.append(
                f"Sequence gap or reordering at record {ev_id} (Index {idx}): "
                f"expected sequence {expected_sequence}, found {seq}."
            )
            if ev_id not in broken_event_ids:
                broken_event_ids.append(ev_id)

        # 2. Verify link to previous event
        if ev.prev_event_hash != expected_prev_hash:
            anomalies.append(
                f"Broken hash chain link at record {ev_id} (Index {idx}, Seq {seq}): "
                f"expected prev_hash '{expected_prev_hash}', found '{ev.prev_event_hash}'."
            )
            if ev_id not in broken_event_ids:
                broken_event_ids.append(ev_id)

        # 3. Recompute canonical event hash over content + sequence number
        # Validates against deterministic canonical JSON or backwards-compatible legacy format
        calculated_hash = compute_canonical_hash(
            event_id=ev_id,
            org_id=str(ev.organization_id),
            timestamp_str=created_str,
            category=ev.category,
            event_type=ev.event_type,
            status=ev.status,
            action=ev.action,
            target_type=ev.target_type,
            target_id=ev.target_id,
            details=ev.details,
            prev_event_hash=ev.prev_event_hash or expected_prev_hash,
            sequence_number=seq
        )

        calculated_legacy_hash = compute_canonical_hash(
            event_id=ev_id,
            org_id=str(ev.organization_id),
            timestamp_str=created_str,
            category=ev.category,
            event_type=ev.event_type,
            status=ev.status,
            action=ev.action,
            target_type=ev.target_type,
            target_id=ev.target_id,
            details=ev.details,
            prev_event_hash=ev.prev_event_hash or expected_prev_hash,
            sequence_number=seq,
            legacy_format=True
        )

        # 4. Strict hash check: catch mismatched content, legacy format transition, or null/empty hashes
        if not ev.event_hash or (ev.event_hash != calculated_hash and ev.event_hash != calculated_legacy_hash):
            anomalies.append(
                f"Content tampering detected at record {ev_id} (Seq {seq}): "
                f"stored hash '{ev.event_hash}' != recomputed hash '{calculated_hash}'."
            )
            if ev_id not in broken_event_ids:
                broken_event_ids.append(ev_id)

        # Advance expectations for next record
        expected_prev_hash = ev.event_hash or calculated_hash
        expected_sequence = seq + 1

    # 5. Checkpoint validation against trusted head (Check 2: Final event deletion detection)
    if expected_final_sequence is not None:
        last_seq = events[-1].sequence_number if events else 0
        if last_seq < expected_final_sequence:
            anomalies.append(
                f"Latest event deletion detected! Expected latest sequence #{expected_final_sequence}, but found #{last_seq}."
            )
            is_intact = False
    if expected_final_hash is not None:
        last_hash = events[-1].event_hash if events else None
        if last_hash != expected_final_hash:
            anomalies.append(
                f"Latest event deletion or rollback detected! Expected latest hash '{expected_final_hash}', but found '{last_hash}'."
            )
            is_intact = False

    is_intact = len(anomalies) == 0

    return AuditIntegrityVerificationResponse(
        is_intact=is_intact,
        records_checked=len(events),
        anomalies=anomalies,
        broken_event_ids=broken_event_ids,
        verified_at=datetime.now(timezone.utc),
        genesis_event_id=str(events[0].id) if events else None,
        latest_event_id=str(events[-1].id) if events else None,
        chain_head_hash=events[-1].event_hash if events else None
    )

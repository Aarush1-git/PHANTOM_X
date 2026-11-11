# Feature 25: Audit Logs & Execution History
## Member 4 — Security Operations & Intelligence

---

## 1. Executive Summary

In an autonomous dynamic application security testing (DAST) platform like **PHANTOM-X**, auditability, accountability, and operational visibility are foundational. When autonomous AI agents and automated testing engines explore, plan, and verify vulnerabilities, stakeholders require an indisputable, tamper-evident record of all operations.

**Feature 25 — Audit Logs & Execution History** provides an enterprise-grade governance backbone for PHANTOM-X:
1. **Structured Multi-Category Audit Trail**: Captures authentication, application management, authorization sign-offs, security testing operations, vulnerability findings, and platform governance events.
2. **Tamper-Evident SHA-256 Hash Chain**: Every recorded audit event computes a deterministic canonical SHA-256 hash linking to the preceding event in the organization's chain, enabling real-time verification of integrity, sequence, and immutability.
3. **Automated Secret Scrubbing**: Recursively scrubs passwords, bearer tokens, API keys, session cookies, private certificates, and Authorization headers prior to database insertion.
4. **Scan Execution Lifecycle History**: A dedicated lifecycle tracking engine (`scan_execution_records`) monitoring status transitions (`QUEUED`, `STARTED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`), duration, tests executed, tests blocked, and verified vulnerabilities.
5. **Seamless Feature 26 Integration**: Unifies scope configuration, authorization grants, suspensions, revocations, and blocked test executions directly into the audit stream without code duplication or credential leakage.
6. **Multi-Tenant Compliance & Audit UI**: Modern React/Tailwind frontend featuring live governance metrics, search and filtering, timeline visualization, JSON payload inspection, scan execution history, and one-click cryptographic chain verification.

---

## 2. Architecture & Design

```
+-----------------------------------------------------------------------------------------+
|                                    USER / CLIENT                                        |
|   +---------------------------------------------------------------------------------+   |
|   |                       Audit Logs & Execution History UI                         |   |
|   |  - Overview Compliance Metrics (Total, Success, Blocked, Critical, Categories)  |   |
|   |  - Chronological Timeline View         - Filterable & Searchable Event Table    |   |
|   |  - Scrubbed Event Details & Hash Modal - Scan Execution Lifecycle History       |   |
|   |  - One-Click SHA-256 Tamper-Evident Cryptographic Chain Verification Panel      |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
                                             | HTTP REST /api/v1/settings
                                             v
+-----------------------------------------------------------------------------------------+
|                                FASTAPI BACKEND SERVICE                                  |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   |             AuditEventRecorder (Per-Organization Serialized Locking)            |   |
|   |  * Automated Recursive Secret Scrubbing (Masks keys, tokens, credentials)       |   |
|   |  * Canonical JSON Normalization (Sorted keys, normalized UTC timestamps)        |   |
|   |  * SHA-256 Hash Chain Linking (Prev Hash -> Canonical Hash Computation)         |   |
|   |  * Domain Event Helpers (Auth, Scope/Authz, Scans, Vulnerabilities, Platform)   |   |
|   +---------------------------------------------------------------------------------+   |
|                                             |                                           |
|   +-----------------------------------------+---------------------------------------+   |
|   |                             AuditLogService Layer                               |   |
|   |  * Filtered Query Engine (Category, Status, Severity, App, User, Date Range)   |   |
|   |  * Compliance Overview & Category Breakdown Aggregator                          |   |
|   |  * Cryptographic Chain Verifier (Detects broken links, tampering, sequence gaps)|   |
|   |  * Scan Execution History Lifecycle Coordinator                                 |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                              DATABASE PERSISTENCE (SQLAlchemy 2)                        |
|                                                                                         |
|   [audit_logs]                                   [scan_execution_records]               |
|   - id (UUID), org_id, actor_id                  - id (UUID), scan_id, org_id           |
|   - category, event_type, status, severity       - application_id, status               |
|   - action, target_type, target_id               - started_at, completed_at, duration_s |
|   - metadata_json (scrubbed)                     - tests_executed, tests_blocked        |
|   - event_hash (SHA-256), prev_event_hash        - verified_findings, failure_reason    |
|   - correlation_id, timestamp (UTC)              - lifecycle_events (JSON array)        |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Cryptographic Tamper-Evident Hash Chaining

To ensure audit records cannot be silently altered, forged, deleted, or backdated, each organization maintains a forward-linked cryptographic hash chain.

### Canonical Hash Computation

1. **Previous Hash Reference**: The recorder fetches the most recent event's `event_hash` for the organization. If no previous events exist, the initial event links to `GENESIS_HASH`:
   ```
   GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
   ```
2. **Timestamp Normalization**: Timestamps are normalized to UTC seconds (`YYYY-MM-DDTHH:MM:SS`) to guarantee uniform string representation regardless of database engine formatting.
3. **Canonical Payload Construction**: The canonical string incorporates:
   ```
   canonical_string = f"{prev_hash}:{org_id}:{category}:{event_type}:{action}:{status}:{norm_timestamp}:{json.dumps(scrubbed_metadata, sort_keys=True)}"
   ```
4. **SHA-256 Generation**:
   ```
   event_hash = hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()
   ```

### Verification Algorithm (`verify_chain_integrity`)

When verification is invoked:
1. Records are queried in strictly ascending chronological order (`timestamp ASC, id ASC`).
2. For each event:
   - If it is the first event, its `prev_event_hash` must equal `GENESIS_HASH`.
   - If subsequent, its `prev_event_hash` must match the previous event's `event_hash`.
   - The canonical hash is independently recalculated from event fields and compared against `event_hash`.
3. If any hash mismatch, broken link, or sequence gap is detected:
   - Verification immediately flags `tamper_detected = True`.
   - The exact invalid event ID, expected hash, and actual hash are returned in the response.

---

## 4. Automated Secret Scrubbing

To comply with enterprise security standards (SOC 2, ISO 27001, HIPAA), the audit subsystem prevents credentials from entering persistent storage.

### Redacted Key Patterns

Any metadata key matching the following substrings is masked with `[REDACTED]`:
- `password`, `secret`, `token`, `key`, `credential`, `auth`
- `cookie`, `session`, `jwt`, `bearer`, `private`, `cert`

### Pattern-Based String Scanning

String values in metadata are inspected against regex patterns:
- Bearer tokens: `Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`
- JSON Web Tokens (JWT): `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`
- API keys: `(?:ghp|gho|xoxb|xoxp|sk_live|sk_test)_[A-Za-z0-9_]{16,}`

---

## 5. Structured Event Categories & Types

| Category | Typical Events | Description |
|---|---|---|
| `AUTHENTICATION` | `USER_LOGIN`, `LOGIN_FAILED`, `USER_LOGOUT`, `AUTHN_FAILED`, `PERMISSION_DENIED` | Authentication attempts, session lifecycle, and credential rejections. |
| `APPLICATION_MANAGEMENT` | `APP_CREATED`, `APP_UPDATED`, `APP_DELETED`, `APP_SCOPE_CONFIGURED` | Target application onboarding, scoping changes, and modifications. |
| `AUTHORIZATION` | `AUTHZ_GRANTED`, `AUTHZ_REVOKED`, `AUTHZ_SUSPENDED`, `PERMISSION_CHANGED` | Formal security testing authorization sign-offs and revocations. |
| `SECURITY_TESTING` | `SCAN_STARTED`, `SCAN_COMPLETED`, `SCAN_FAILED`, `TEST_EXECUTED`, `TEST_BLOCKED` | Scan execution lifecycle, probe executions, and safety violations. |
| `VULNERABILITY` | `FINDING_DETECTED`, `FINDING_CONFIRMED`, `SEVERITY_OVERRIDE`, `FALSE_POSITIVE_FLAGGED` | Discovery, confirmation, and status adjustments of vulnerabilities. |
| `PLATFORM` | `POLICY_CHANGED`, `INTEGRITY_VERIFIED`, `INTEGRITY_BREACH`, `CONFIG_EXPORTED` | System configurations, cryptographic verifications, and compliance exports. |

---

## 6. Database Schema Specifications

### Table: `audit_logs` (Expanded via Migration 003)

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | GUID | PRIMARY KEY | Unique event UUID |
| `organization_id` | GUID | FK `organizations.id` | Multi-tenant isolation |
| `actor_id` | GUID | FK `users.id`, NULLABLE | Acting user ID (NULL for system/agent actions) |
| `actor_email` | VARCHAR(255) | NULLABLE | Email address of acting user |
| `actor_role` | VARCHAR(100) | NULLABLE | Role (e.g. `SECURITY_ADMIN`, `SYSTEM_AGENT`) |
| `application_id` | GUID | FK `applications.id`, NULLABLE | Associated application |
| `scan_id` | GUID | FK `scans.id`, NULLABLE | Associated security scan |
| `category` | VARCHAR(50) | NOT NULL, INDEX | Event category (`AUTHENTICATION`, `SECURITY_TESTING`, etc.) |
| `event_type` | VARCHAR(100) | NOT NULL, INDEX | Granular event type (`USER_LOGIN`, `TEST_BLOCKED`, etc.) |
| `action` | VARCHAR(255) | NOT NULL | Human-readable action description |
| `status` | VARCHAR(50) | NOT NULL | `SUCCESS`, `FAILURE`, `BLOCKED`, `PENDING` |
| `severity` | VARCHAR(50) | NOT NULL | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `source_module` | VARCHAR(100) | NOT NULL | Originating subsystem (`SCOPE_SAFETY_ENGINE`, `AUTH_SERVICE`, etc.) |
| `target_type` | VARCHAR(100) | NULLABLE | Target entity (`APPLICATION`, `SCAN`, `VULNERABILITY`, etc.) |
| `target_id` | VARCHAR(255) | NULLABLE | ID of target entity |
| `metadata_json` | JSON | NOT NULL, DEFAULT `{}` | Scrubbed contextual details |
| `correlation_id` | VARCHAR(255) | NULLABLE | Distributed tracing ID |
| `event_hash` | VARCHAR(64) | NOT NULL | SHA-256 canonical hash |
| `prev_event_hash` | VARCHAR(64) | NOT NULL | SHA-256 hash of previous event |
| `timestamp` | DATETIME | NOT NULL, INDEX | UTC creation timestamp |

### Table: `scan_execution_records` (Created via Migration 003)

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | GUID | PRIMARY KEY | Unique execution record UUID |
| `scan_id` | GUID | FK `scans.id`, UNIQUE | Associated scan |
| `organization_id` | GUID | FK `organizations.id` | Multi-tenant isolation |
| `application_id` | GUID | FK `applications.id` | Target application |
| `status` | VARCHAR(50) | NOT NULL | Lifecycle state (`QUEUED`, `RUNNING`, `COMPLETED`, etc.) |
| `started_at` | DATETIME | NULLABLE | Scan start timestamp |
| `completed_at` | DATETIME | NULLABLE | Scan completion timestamp |
| `duration_seconds` | FLOAT | NULLABLE | Total scan duration |
| `tests_executed` | INTEGER | NOT NULL, DEFAULT 0 | Count of transmitted tests |
| `tests_blocked` | INTEGER | NOT NULL, DEFAULT 0 | Count of safety-blocked tests |
| `verified_findings` | INTEGER | NOT NULL, DEFAULT 0 | Count of verified vulnerabilities |
| `failure_reason` | TEXT | NULLABLE | Failure description if failed |
| `lifecycle_events` | JSON | NOT NULL, DEFAULT `[]` | Chronological transition events array |
| `created_at` | DATETIME | NOT NULL | Record creation timestamp |
| `updated_at` | DATETIME | NOT NULL | Last update timestamp |

---

## 7. API Reference

All audit log and execution history endpoints are scoped under `/api/v1/settings`:

### 1. List Audit Logs
- **Endpoint**: `GET /api/v1/settings/audit-logs`
- **Query Parameters**:
  - `category` (optional): Filter by category.
  - `status` (optional): Filter by status.
  - `severity` (optional): Filter by severity.
  - `application_id` (optional): Target application UUID.
  - `user_id` (optional): Actor UUID.
  - `search` (optional): Case-insensitive text search in action description.
  - `start_date` / `end_date` (optional): ISO timestamp bounds.
  - `skip` / `limit`: Pagination parameters.
- **Response**: `List[AuditLogResponse]`

### 2. Audit Overview Metrics
- **Endpoint**: `GET /api/v1/settings/audit-logs/overview`
- **Response**:
  ```json
  {
    "total_events": 142,
    "successful_events": 128,
    "failed_events": 6,
    "blocked_events": 8,
    "critical_events": 2,
    "events_by_category": {
      "AUTHENTICATION": 30,
      "APPLICATION_MANAGEMENT": 14,
      "AUTHORIZATION": 8,
      "SECURITY_TESTING": 72,
      "VULNERABILITY": 12,
      "PLATFORM": 6
    },
    "chain_status": "VALID",
    "last_event_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "last_event_timestamp": "2026-11-10T13:20:00Z"
  }
  ```

### 3. Cryptographic Chain Verification
- **Endpoint**: `POST /api/v1/settings/audit-logs/verify-integrity`
- **Response**:
  ```json
  {
    "total_events_checked": 142,
    "tamper_detected": false,
    "chain_valid": true,
    "verified_at": "2026-11-10T13:25:00Z",
    "first_event_hash": "a4f89...",
    "latest_event_hash": "e3b0c...",
    "broken_event_id": null,
    "details": "Audit log hash chain verified successfully. All 142 events are tamper-evident."
  }
  ```

### 4. Audit Log Export
- **Endpoint**: `GET /api/v1/settings/audit-logs/export?format=json|csv`
- **Response**: Downloadable file (`phantom_x_audit_export_*.json` or `.csv`).

### 5. Scan Execution History
- **Endpoint**: `GET /api/v1/settings/execution-history`
- **Query Parameters**: `application_id`, `status`, `skip`, `limit`
- **Response**: `List[ScanExecutionRecordResponse]`

---

## 8. Integration Instructions for Team Members

### How to Emit Audit Events in Backend Services

Import `AuditEventRecorder` from `backend.app.features.security_operations.audit_logs`:

```python
from backend.app.features.security_operations.audit_logs import AuditEventRecorder
from backend.app.schemas.audit_log import AuditCategory, AuditStatus, AuditSeverity

# Example 1: Security Testing Event
await AuditEventRecorder.record_event(
    db=db,
    organization_id=org_id,
    category=AuditCategory.SECURITY_TESTING,
    event_type="TEST_EXECUTED",
    action=f"Executed SQLi test probe against {target_path}",
    status=AuditStatus.SUCCESS,
    severity=AuditSeverity.INFO,
    source_module="VERIFICATION_RUNNER",
    application_id=app_id,
    scan_id=scan_id,
    target_type="ENDPOINT",
    target_id=target_path,
    metadata={
        "method": "GET",
        "payload_type": "BOOLEAN_BASED",
        "response_code": 200,
        "token": "secret_is_automatically_scrubbed" # Auto-scrubbed!
    }
)

# Example 2: Vulnerability Detection Event
await AuditEventRecorder.record_vulnerability_event(
    db=db,
    organization_id=org_id,
    event_type="FINDING_DETECTED",
    action="Identified high-severity Broken Object Level Authorization (BOLA)",
    finding_id=finding_uuid,
    title="BOLA on /api/v1/orders/{id}",
    severity_level="HIGH",
    application_id=app_id,
    scan_id=scan_id,
    cwe="CWE-639"
)
```

### Scan Execution Lifecycle Tracking

```python
from backend.app.features.security_operations.audit_logs.service import AuditLogService

# 1. Initialize record when scan is queued
record = await AuditLogService.record_scan_queued(db, scan_id, org_id, app_id)

# 2. Update when started
await AuditLogService.record_scan_started(db, scan_id)

# 3. Complete scan with stats
await AuditLogService.record_scan_completed(
    db=db,
    scan_id=scan_id,
    status="COMPLETED",
    tests_executed=150,
    tests_blocked=3,
    verified_findings=2
)
```

---

## 9. Security & Compliance Considerations

1. **Append-Only Immutability**: The audit subsystem does not expose any `UPDATE` or `DELETE` endpoints for audit records.
2. **Deterministic Canonicalization**: Hash generation relies on RFC 8785 compliant canonical sorting, preventing JSON formatting differences from invalidating hashes.
3. **Defense-in-Depth Secret Scrubbing**: Redaction happens in memory before the object is committed to SQLAlchemy, ensuring sensitive tokens are never written to write-ahead logs (WAL) or storage disks.
4. **Concurrency Thread-Safety**: Per-organization locks bound to the running event loop prevent race conditions when multiple concurrent asynchronous workers append events to the same organization's chain.


# Feature 26: Scope, Permission & Safety Management
## Member 4 — Security Operations & Intelligence

---

## 1. Executive Summary

In an autonomous Dynamic Application Security Testing (DAST) platform like **PHANTOM-X**, testing safety is paramount. Autonomous agents, LLM-based reasoning chains, fuzzers, and automated test runners must operate strictly within explicitly authorized boundaries.

**Feature 26 — Scope, Permission & Safety Management** establishes the authoritative governance and safety gate for PHANTOM-X. It ensures:
1. **Explicit Target Scoping**: Registration of authorized domains, API base URLs, permitted endpoint patterns (whitelist), and forbidden endpoint patterns (blacklist).
2. **Strict Permission Management**: Registration does not imply authorization. Every target requires formal sign-off (`authorized_by`, role, validity window, notes) with dynamic suspension and revocation controls.
3. **Conservative Testing Safety Controls**: Enforces rate limiting (RPS), max concurrency, scan duration limits, allowed HTTP methods, and destructive test restrictions.
4. **Unbypassable Pre-Execution Validation**: Validates all planned requests before packets leave the engine. LLM-generated attack plans cannot bypass these checks.
5. **Full Auditability**: Every blocked action is recorded with the violation category, reason, payload sample, source agent, and timestamp.

---

## 2. Architecture & Design

```
+---------------------------------------------------------------------------------+
|                                 USER / CLIENT                                   |
|   +-------------------------------------------------------------------------+   |
|   |         Settings & Scope Governance Interface (SettingsPage.tsx)        |   |
|   |  - Scope Policy List & Config Modal    - Formal Authorization Modal     |   |
|   |  - Live Safety Validation Simulator    - Blocked Execution History      |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
                                      | HTTP REST
                                      v
+---------------------------------------------------------------------------------+
|                       FASTAPI BACKEND (/api/v1/settings)                        |
|                                                                                 |
|   +-------------------------------------------------------------------------+   |
|   |                      ScopeSafetyService Layer                           |   |
|   |  * Scope Registration & Updates       * Formal Authorization Sign-Off   |   |
|   |  * Suspension & Revocation Gates      * Sliding-Window Rate Tracker     |   |
|   |  * Regex & Glob Path Evaluator        * Destructive Payload Scanner     |   |
|   |  * Blocked Execution Logger           * Audit Trail Integration         |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
         |                                           |
         v                                           v
+-----------------------+                 +---------------------------------------+
|   PostgreSQL / SQLite |                 |   EXECUTION ENGINES & AGENTS          |
|                       |                 |   * AI Attack Planner (LLM)           |
| - application_scope_  |                 |   * Security Test Runner (HTTPX)      |
|   policies            | <-------------  |   * Discovered Endpoints Scanner      |
| - blocked_execution_  | Pre-Execution   |   [Must query POST /validate-test     |
|   logs                | Safety Gate     |    before transmitting requests]      |
| - audit_logs          |                 +---------------------------------------+
+-----------------------+
```

### Safety Validation Flow (10 Criteria)

Whenever `POST /api/v1/settings/validate-test` is queried or `ScopeSafetyService.validate_test_execution` is called:
1. **Resolve Application Policy**: Matches target host and application ID against active records. If unmapped $\rightarrow$ **Blocked** (`UNREGISTERED_TARGET`).
2. **Domain Scope Verification**: Ensures the destination matches the authorized domain (or allowed wildcard suffix). If mismatched $\rightarrow$ **Blocked** (`UNAUTHORIZED_DOMAIN`).
3. **Scope Operational Status**: Checks if `scope_status` is `ACTIVE`. If `DRAFT` or `SUSPENDED` $\rightarrow$ **Blocked** (`SCOPE_NOT_ACTIVE`).
4. **Permission Status & Expiry**: Verifies `authorization_status` is `AUTHORIZED` and current UTC time $\le$ `valid_until`. If expired $\rightarrow$ **Blocked** (`AUTHORIZATION_EXPIRED`).
5. **Permitted HTTP Methods**: Verifies requested method is in `allowed_methods`. If not $\rightarrow$ **Blocked** (`PROHIBITED_METHOD`).
6. **Strict Excluded Paths (Blacklist)**: Evaluates requested path against `excluded_paths` (e.g. `/admin/*`, `/logout`). If matched $\rightarrow$ **Blocked** (`EXCLUDED_PATH`).
7. **Permitted Paths (Whitelist)**: Evaluates path against `permitted_paths`. If outside $\rightarrow$ **Blocked** (`PATH_NOT_PERMITTED`).
8. **Restricted Endpoint Protection**: Inspects path against `restricted_endpoint_patterns` (e.g. `*/delete-account*`). If matched and `allow_destructive=False` $\rightarrow$ **Blocked** (`RESTRICTED_ENDPOINT`).
9. **Destructive Payload Inspection**: Scans payloads and query strings for destructive SQL patterns (`DROP TABLE`, `TRUNCATE`, `GRANT DBA`), command injection (`rm -rf`, `mkfs`, fork bombs), and sensitive file disclosure. If matched and `allow_destructive=False` $\rightarrow$ **Blocked** (`DESTRUCTIVE_ACTION_PROHIBITED`).
10. **Sliding-Window Rate Limiting**: Evaluates per-second request frequency against `rate_limit_rps`. If exceeded $\rightarrow$ **Blocked** (`RATE_LIMIT_EXCEEDED`).

---

## 3. Database Schema Changes

### A. Table: `application_scope_policies`
Tracks testing scope, authorization validity, and safety controls for each registered application.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | GUID | PRIMARY KEY | Unique policy ID |
| `organization_id` | GUID | FK `organizations.id` ON DELETE CASCADE | Multi-tenant isolation |
| `application_id` | GUID | FK `applications.id` ON DELETE CASCADE, UNIQUE | Associated application |
| `target_domain` | VARCHAR(255) | NOT NULL | Hostname or domain (e.g. `api.staging.local`) |
| `base_url` | VARCHAR(500) | NOT NULL | Target API base URL |
| `permitted_paths` | JSON | NOT NULL, DEFAULT `["/*"]` | Permitted glob patterns |
| `excluded_paths` | JSON | NOT NULL | Strictly excluded paths (e.g. `/admin/*`, `/logout`) |
| `scope_status` | VARCHAR(50) | NOT NULL, DEFAULT `'DRAFT'` | `DRAFT`, `ACTIVE`, `SUSPENDED`, `EXPIRED` |
| `authorization_status` | VARCHAR(50) | NOT NULL, DEFAULT `'PENDING'` | `PENDING`, `AUTHORIZED`, `REVOKED`, `EXPIRED` |
| `authorized_by` | VARCHAR(255) | NULLABLE | Authorizer name and email |
| `authorizer_role` | VARCHAR(100) | NULLABLE | Role (e.g. "Application Security Lead") |
| `authorization_notes` | TEXT | NULLABLE | Audit reference or ticket number |
| `valid_from` | DATETIME | NULLABLE | Authorization start time |
| `valid_until` | DATETIME | NULLABLE | Authorization expiration time |
| `rate_limit_rps` | INTEGER | NOT NULL, DEFAULT 10 | Maximum requests per second |
| `max_concurrency` | INTEGER | NOT NULL, DEFAULT 2 | Maximum concurrent scans |
| `max_scan_duration_minutes` | INTEGER | NOT NULL, DEFAULT 60 | Maximum test duration |
| `allowed_methods` | JSON | NOT NULL | Allowed HTTP methods |
| `restricted_endpoint_patterns` | JSON | NOT NULL | Patterns requiring explicit destructive flag |
| `require_synthetic_auth` | BOOLEAN | NOT NULL, DEFAULT TRUE | Enforce synthetic non-prod credentials |
| `allow_destructive` | BOOLEAN | NOT NULL, DEFAULT FALSE | Allow destructive tests (default: False) |

### B. Table: `blocked_execution_logs`
Logs all prohibited execution attempts with reasons and payload metadata for security analysis.

| Column | Type | Description |
|---|---|---|
| `id` | GUID | PRIMARY KEY |
| `organization_id` | GUID | FK `organizations.id` |
| `application_id` | GUID | FK `applications.id` (NULLABLE) |
| `target_url` | VARCHAR(1000) | Destination URL attempted |
| `http_method` | VARCHAR(20) | HTTP method attempted |
| `violation_category` | VARCHAR(100) | Violation enum (e.g. `DESTRUCTIVE_ACTION_PROHIBITED`) |
| `blocked_reason` | VARCHAR(1000) | Human-readable explanation |
| `payload_sample` | TEXT | Sanitized/truncated payload sample |
| `source_agent` | VARCHAR(100) | Agent or runner that attempted execution |
| `client_ip` | VARCHAR(50) | Origin client IP address |
| `created_at` | DATETIME | Timestamp of blocked attempt |

---

## 4. API Endpoints

All endpoints are hosted under `/api/v1/settings` via `scope_safety_router`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/settings/scopes` | List all registered application scopes |
| `GET` | `/api/v1/settings/scopes/{app_id}` | Retrieve specific application scope policy |
| `POST` | `/api/v1/settings/scopes/{app_id}` | Register target scope (defaults to DRAFT / PENDING) |
| `PUT` | `/api/v1/settings/scopes/{app_id}` | Update scope paths, rate limits, or controls |
| `POST` | `/api/v1/settings/scopes/{app_id}/authorize` | Formally grant testing authorization |
| `POST` | `/api/v1/settings/scopes/{app_id}/suspend` | Suspend testing scope |
| `POST` | `/api/v1/settings/scopes/{app_id}/revoke` | Revoke testing authorization |
| `POST` | `/api/v1/settings/validate-test` | Pre-execution safety validation gate |
| `GET` | `/api/v1/settings/blocked-executions` | List audit log of blocked executions |

---

## 5. Integration Guide for Other Modules

Any test execution component (such as Member 2's AI Attack Planner or Member 3's Security Engine HTTP runner) can integrate with the safety policy in two ways:

### Option A: Via Python Service (Internal Backend / Engine)
```python
from app.services.scope_safety_service import ScopeSafetyService

verdict = await ScopeSafetyService.validate_test_execution(
    db=db_session,
    target_url=request_url,
    http_method=request_method,
    payload_sample=str(payload_data),
    application_id=app_id,
    source_agent="MEMBER_2_ATTACK_PLANNER"
)

if not verdict.is_allowed:
    logger.warning(f"Test blocked: {verdict.reason} ({verdict.violation_category})")
    return {"status": "BLOCKED", "reason": verdict.reason}
```

### Option B: Via HTTP REST Endpoint
```http
POST /api/v1/settings/validate-test
Content-Type: application/json

{
  "application_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "target_url": "https://api.banking-staging.local/v1/users",
  "http_method": "GET",
  "source_agent": "AUTONOMOUS_DAST_RUNNER"
}
```

---

## 6. Verification and Test Results

The feature test suite `backend/tests/test_feature_26_scope_safety.py` executes 10 scenarios:
1. `test_01_register_scope_unauthorized_by_default`: PASSED
2. `test_02_attempt_test_before_authorization_is_blocked`: PASSED
3. `test_03_authorize_target_and_validate_allowed`: PASSED
4. `test_04_reject_unregistered_or_unauthorized_domain`: PASSED
5. `test_05_reject_excluded_endpoint_path`: PASSED
6. `test_06_reject_prohibited_http_methods`: PASSED
7. `test_07_reject_expired_authorization`: PASSED
8. `test_08_suspend_and_revoke_scope_workflow`: PASSED
9. `test_09_reject_destructive_actions`: PASSED
10. `test_10_rate_limit_exceeded`: PASSED

**Result:** 10/10 automated backend tests passed.
Frontend component test suite `frontend/tests/ScopeSafety.test.tsx` (4 tests) and production Vite build: **PASSED**.


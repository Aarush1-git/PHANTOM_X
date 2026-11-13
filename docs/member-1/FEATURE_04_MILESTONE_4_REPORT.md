# PHANTOM-X — Feature 4: Behavioral Digital Twin
## Milestone 4 Implementation & Verification Report — REST API Endpoints & Router Registration

---

### 1. Executive Summary

Milestone 4 of **Feature 4 (Behavioral Digital Twin)** has been completed and verified.
All REST API endpoints for the Behavioral Digital Twin—spanning high-level overview metrics, single/batch/HAR observation ingestion, versioned baseline lifecycle management, anomaly querying/filtering/pagination, and drift evaluation/review workflows—have been implemented, registered on the FastAPI `api_router`, and verified with automated test suites.

All **48 targeted verification tests passed with exit code 0** (48 passed, 0 failed, 0 skipped in 149.10s).

---

### 2. Endpoints & Route Definitions

All endpoints are registered under prefix `/api/v1/behavioral-twin` with tag `Feature 4 — Behavioral Digital Twin`:

| Method | Endpoint Path | Summary | Minimum Role |
| :--- | :--- | :--- | :--- |
| `GET` | `/applications/{application_id}/overview` | High-level twin summary, active baseline metrics & anomalies | Any Authenticated |
| `GET` | `/overview` | Overview alias with query param `?application_id=...` | Any Authenticated |
| `POST` | `/observations` | Ingest a single sanitized API observation | Any Authenticated |
| `POST` | `/observations/batch` | Batch ingest up to 200 sanitized API observations | Any Authenticated |
| `POST` | `/observations/har` | Ingest interaction traces from raw HAR archive content | Any Authenticated |
| `GET` | `/observations` | List sanitized observations with bounded pagination | Any Authenticated |
| `GET` | `/baselines` | List all historical and current baselines for an application | Any Authenticated |
| `GET` | `/baselines/{baseline_id}` | Retrieve details and profiles of a specific baseline | Any Authenticated |
| `POST` | `/baselines/compile` | Compile observations into a new DRAFT baseline snapshot | `SECURITY_ENGINEER` / `DEVELOPER` |
| `POST` | `/baselines/{baseline_id}/activate` | Promote baseline to ACTIVE (superseding prior active baseline) | `SECURITY_ENGINEER` / `DEVELOPER` |
| `POST` | `/baselines/{baseline_id}/archive` | Archive an inactive or superseded baseline | `SECURITY_ENGINEER` / `DEVELOPER` |
| `GET` | `/anomalies` | Query detected anomalies with multi-criteria filters & pagination | Any Authenticated |
| `GET` | `/anomalies/{anomaly_id}` | Retrieve details and sanitized forensic evidence of an anomaly | Any Authenticated |
| `POST` | `/drift/evaluate` | Trigger drift evaluation against active baseline on demand | `SECURITY_ENGINEER` / `DEVELOPER` |
| `PATCH`| `/anomalies/{anomaly_id}/status` | Update anomaly review status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`)| `SECURITY_ENGINEER` / `DEVELOPER` |
| `POST` | `/anomalies/{anomaly_id}/acknowledge` | Shortcut to acknowledge an anomaly | `SECURITY_ENGINEER` / `DEVELOPER` |
| `POST` | `/anomalies/{anomaly_id}/resolve` | Shortcut to resolve an anomaly | `SECURITY_ENGINEER` / `DEVELOPER` |

---

### 3. Request & Response Examples

#### A. Behavioral Twin Overview (`GET /api/v1/behavioral-twin/applications/{app_id}/overview`)
* **Request**:
  ```http
  GET /api/v1/behavioral-twin/applications/768b0675-e48d-4786-9722-a4e5f82ff7df/overview HTTP/1.1
  Authorization: Bearer <valid_jwt_token>
  ```
* **Response** (`200 OK`):
  ```json
  {
    "application_id": "768b0675-e48d-4786-9722-a4e5f82ff7df",
    "organization_id": "6b784435-2f68-4a3f-97aa-a96ab82b874e",
    "total_observations": 128,
    "active_baseline_id": "e893365b-8d35-468b-88b7-78e7d9c8835b",
    "active_baseline_version": "v1.2",
    "active_baseline_confidence": 0.884,
    "total_transitions_tracked": 14,
    "open_anomalies_count": 2,
    "last_observed_at": "2026-11-12T19:20:00Z",
    "endpoint_profiles": {
      "POST:/api/v1/checkout": {
        "total_requests": 64,
        "status_code_distribution": {"200": 60, "400": 4},
        "latency_stats": {"min_ms": 45.0, "max_ms": 180.0, "avg_ms": 95.2, "p95_ms": 145.0},
        "confidence_score": 0.895
      }
    },
    "latest_anomalies": []
  }
  ```

#### B. Observation Ingestion (`POST /api/v1/behavioral-twin/observations`)
* **Request**:
  ```json
  {
    "application_id": "768b0675-e48d-4786-9722-a4e5f82ff7df",
    "method": "POST",
    "path": "/api/v1/checkout",
    "status_code": 200,
    "latency_ms": 115.5,
    "request_payload": {"amount": 250, "token": "sensitive_bearer_token"},
    "response_payload": {"order_id": "ORD-9912", "status": "CONFIRMED"},
    "session_identifier": "user_session_cookie_abc"
  }
  ```
* **Response** (`201 Created`):
  ```json
  {
    "id": "c1f7b022-7933-4f9e-a81d-488f2194a021",
    "organization_id": "6b784435-2f68-4a3f-97aa-a96ab82b874e",
    "application_id": "768b0675-e48d-4786-9722-a4e5f82ff7df",
    "endpoint_id": "3bb62c7e-8c31-419b-a010-ea988229bbf9",
    "method": "POST",
    "normalized_path": "/api/v1/checkout",
    "status_code": 200,
    "latency_ms": 115.5,
    "session_token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sanitized_request_schema": {
      "type": "object",
      "properties": {
        "amount": {"type": "integer"},
        "token": {"type": "string"}
      },
      "required": ["amount", "token"]
    },
    "sanitized_response_schema": {
      "type": "object",
      "properties": {
        "order_id": {"type": "string"},
        "status": {"type": "string"}
      },
      "required": ["order_id", "status"]
    },
    "observed_at": "2026-11-12T19:22:15Z",
    "created_at": "2026-11-12T19:22:15Z"
  }
  ```

#### C. Baseline Compilation (`POST /api/v1/behavioral-twin/baselines/compile`)
* **Request**:
  ```json
  {
    "application_id": "768b0675-e48d-4786-9722-a4e5f82ff7df",
    "version": "v1.0",
    "min_samples": 5
  }
  ```
* **Response** (`201 Created`):
  ```json
  {
    "id": "e893365b-8d35-468b-88b7-78e7d9c8835b",
    "organization_id": "6b784435-2f68-4a3f-97aa-a96ab82b874e",
    "application_id": "768b0675-e48d-4786-9722-a4e5f82ff7df",
    "version": "v1.0",
    "status": "DRAFT",
    "sample_count": 24,
    "confidence_score": 0.742,
    "endpoint_profiles": { ... },
    "transition_matrix": { ... },
    "created_at": "2026-11-12T19:23:00Z",
    "activated_at": null
  }
  ```

---

### 4. Security & Isolation Controls

1. **Mandatory Authentication & Identity Extraction**:
   - `get_current_user` extracts `user.organization_id` directly from verified JWT claims.
   - Client-supplied `organization_id` in request payloads is ignored in favor of the authenticated context.
2. **Role-Based Access Control (RBAC)**:
   - Read operations (`GET`) permit all authenticated roles belonging to the organization.
   - Mutating operations (baseline compile, baseline activate, archive, resolve anomaly, trigger drift evaluation) require `SECURITY_ENGINEER`, `DEVELOPER`, or `ADMIN` via `require_role(...)`.
   - `AUDITOR` accounts are blocked from mutating baselines or resolving anomalies with `403 Forbidden`.
3. **Application Ownership Enforcement**:
   - Every route verifies `ObservationIngestionService.validate_application_tenant(db, app_id, current_user.organization_id)`.
   - Mismatched tenant access returns `403 Forbidden` or `404 Not Found`.
4. **Credential & PII Redaction**:
   - Anomaly evidence payloads, request/response bodies, and session tokens are recursively stripped of secrets (`[REDACTED]`).
   - Session tokens are stored strictly as irreversible SHA-256 hashes (`session_token_hash`).
5. **Bounded Pagination & Denial-of-Service Defense**:
   - All listing endpoints enforce `page >= 1` and `1 <= limit <= 100`.
   - Ingestion payloads are bounded: max 200 items in batch ingest, max 15MB for HAR archives, max 200KB per JSON payload.

---

### 5. Verification Test Results

Targeted test execution:
```powershell
cd backend; python -m pytest tests/test_feature_04_behavioral_digital_twin.py -vv -s --tb=short -x --no-cov
```

**Output**:
```
============================= test session starts =============================
platform win32 -- Python 3.13.3, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Hrushikesh\Downloads\PHANTOM_X1.1\backend
configfile: pyproject.toml
plugins: asyncio-1.4.0, cov-7.1.0
collected 48 items

tests/test_feature_04_behavioral_digital_twin.py::test_observation_creation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_baseline_creation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_transition_creation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_anomaly_creation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_foreign_key_integrity PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_sensitive_header_sanitization PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_recursive_json_sanitization PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_session_token_hashing PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_pydantic_schema_validation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_schema_confidence_bounds PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_structural_schema_extraction PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_multi_tenant_isolation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_url_path_normalization PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_path_parameterization PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_structural_schema_inference_primitives PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_structural_schema_merging PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_behavior_profiler_and_latency PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_confidence_calculation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_markov_sequence_transition_learner PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_single_observation_ingestion PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_batch_observation_ingestion PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_nullable_endpoint_linking PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_baseline_compilation PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_baseline_version_incrementing PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_baseline_activation_and_supersession PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_insufficient_evidence_activation_rejection PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_historical_baseline_preservation_and_archiving PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_status_code_drift_detector PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_schema_drift_detector PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_sequence_drift_detector PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_latency_drift_detector PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_anomaly_deduplication PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_anomaly_lifecycle_review PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_cross_tenant_isolation_baseline_and_anomalies PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_sensitive_evidence_sanitization_in_anomalies PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_digital_twin_overview PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_unauthenticated_rejection PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_invalid_token_rejection PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_cross_tenant_rejection PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_observation_ingestion_single PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_observation_ingestion_batch PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_observation_ingestion_har PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_baseline_compilation_and_listing PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_baseline_activation_lifecycle PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_anomaly_filtering_and_pagination PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_anomaly_lifecycle_endpoints PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_sensitive_evidence_redaction PASSED
tests/test_feature_04_behavioral_digital_twin.py::test_api_rbac_restrictions PASSED

================= 48 passed, 3 warnings in 149.10s (0:02:29) ==================
```

---

### 6. Files Created & Modified

#### Created:
1. `backend/app/features/application_intelligence/behavioral_digital_twin/routes.py`
2. `docs/member-1/FEATURE_04_MILESTONE_4_REPORT.md`

#### Modified:
1. `backend/app/api/v1/api.py`: Mounted `behavioral_twin_router` into FastAPI `api_router`.
2. `backend/app/features/application_intelligence/behavioral_digital_twin/schemas.py`: Added REST API request and response schemas.
3. `backend/app/features/application_intelligence/behavioral_digital_twin/baseline_service.py`: Added `get_digital_twin_overview()` aggregator.
4. `backend/app/features/application_intelligence/behavioral_digital_twin/ingestion_service.py`: Added `ingest_batch()` and `ingest_from_har()` helper methods.
5. `backend/app/features/application_intelligence/behavioral_digital_twin/__init__.py`: Exported API `router`.
6. `backend/tests/test_feature_04_behavioral_digital_twin.py`: Seeded users/JWT tokens and added 13 REST API tests (Tests 36 through 48).

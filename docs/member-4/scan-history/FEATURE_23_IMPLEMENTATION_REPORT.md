# PHANTOM-X — Feature 23: Scan History and Comparison
## Member 4: Security Operations & Intelligence — Implementation Report

---

### Executive Summary

Feature 23 delivers a production-grade **Scan History and Comparison Engine** for **PHANTOM-X — Autonomous Application Security Intelligence**. It provides enterprise security operators, DevSecOps teams, and compliance auditors with end-to-end visibility into security execution timelines, findings evolution across scans, automated regression detection, severity trajectory classification, and side-by-side vulnerability diffing.

All capabilities are strictly scoped to **Member 4: Security Operations & Intelligence**, integrating directly with existing persisted data from Member 1 (Attack Surface Discovery), Member 2 (Autonomous Attack Planner), and Member 3 (Targeted Verification & Scanning Engine) without modifying their respective engines or duplicating upstream logic.

---

### 1. Architecture & Design Decisions

#### Module Location & Decoupled Architecture
- **Backend Service Layer**: Implemented under `backend/app/features/security_operations/scan_history/`:
  - `schemas.py`: Explicit Pydantic v2 data transfer schemas with strict field typing and validation.
  - `service.py`: `ScanHistoryService` encapsulating feed querying, metadata aggregation, evidence sanitization, and the comparison algorithm.
  - `routes.py`: FastAPI APIRouter mounted at `/api/v1/scan-history`.
- **Database Access Strategy**:
  - Direct, explicit, non-deadlocking SQL queries. Avoids nested `selectinload` or joined subquery deadlocks on asynchronous database engines (e.g., SQLite/aiosqlite and asyncpg).
  - Fetches primary scan records with server-side pagination, filters, and ordering, followed by decoupled targeted queries for associated applications and vulnerabilities using `.in_(ids)`.
- **Sanitized Evidence Retrieval**:
  - The scan details endpoint scrubs raw authentication tokens, secret keys, Authorization headers, and sensitive dump payloads before returning evidence summaries to client applications.

---

### 2. API Endpoints Reference

All endpoints are mounted under `/api/v1/scan-history` and enforce strict server-side organization isolation via authenticated JWT tokens.

| Method | Endpoint | Description | Query / Body Parameters | Success Status | Auth Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/scan-history` | Paginated scan history feed with filters & severity breakdown | `page`, `limit`, `application_id`, `status`, `search`, `start_date`, `end_date`, `sort_order` | `200 OK` | Authenticated Member |
| `GET` | `/api/v1/scan-history/applications` | Applications that have scans for filter selectors | None | `200 OK` | Authenticated Member |
| `GET` | `/api/v1/scan-history/{scan_id}` | Detailed scan metadata, timing, findings, and evidence references | Path: `scan_id` (UUID) | `200 OK` / `404` / `403` | Authenticated Member |
| `GET` | `/api/v1/scan-history/compare` | Compare two scans (read-only query) | `baseline_scan_id`, `comparison_scan_id` | `200 OK` / `400` / `403` | Authenticated Member |
| `POST` | `/api/v1/scan-history/compare` | Compare two scans with optional persistence into `scan_comparisons` | Body: `baseline_scan_id`, `comparison_scan_id`, `save_record` | `200 OK` / `400` / `403` | Authenticated Member |

---

### 3. Comparison Algorithm & Fingerprinting Strategy

#### Deterministic Finding Fingerprinting
To compare vulnerability findings across scans where finding IDs change across execution runs, the engine computes a deterministic signature:
```python
def make_vuln_fingerprint(endpoint: str, cwe_id: str | None, title: str) -> str:
    key_part = (cwe_id.strip() if cwe_id else title.strip().lower())
    clean_endpoint = (endpoint or "").strip().rstrip("/")
    return f"{clean_endpoint}::{key_part}"
```

#### Differential Classification Rules
Given a **Baseline Scan** $S_{base}$ and a **Comparison Scan** $S_{comp}$:
1. **Persistent Findings ($F \in S_{base} \land F \in S_{comp}$)**:
   - Identical severity: Classified as `PERSISTENT`.
   - Different severity: Classified as `SEVERITY_CHANGED` with `severity_change_direction = INCREASED | DECREASED`.
2. **Fixed Findings ($F \in S_{base} \land F \notin S_{comp}$)**:
   - Present in baseline, absent in comparison: Classified as `FIXED`.
3. **New vs. Regressed Findings ($F \notin S_{base} \land F \in S_{comp}$)**:
   - If $F$ was observed in *any prior scan* for this application or resolved in a historical report: Classified as `REGRESSED`.
   - If $F$ was never recorded previously: Classified as `NEW`.

---

### 4. Severity Tracking & Regressions Logic

#### Regression Detection Strategy
- When a finding is present in $S_{comp}$ but absent in $S_{base}$, the service performs a historical lookup for that application ID.
- If a prior finding with the identical fingerprint exists with timestamp earlier than $S_{base}$, or if a `VulnerabilityReport` marked `RESOLVED`/`FIXED` exists for that fingerprint, the vulnerability is flagged as `REGRESSED`.
- This ensures true regressions are accurately highlighted to security engineers rather than reported as novel discoveries.

#### Severity Transitions Matrix
Severity changes are classified using numeric rank weights:
$$\text{Rank}(\text{CRITICAL}) = 4, \quad \text{Rank}(\text{HIGH}) = 3, \quad \text{Rank}(\text{MEDIUM}) = 2, \quad \text{Rank}(\text{LOW}) = 1, \quad \text{Rank}(\text{INFO}) = 0$$
- $\text{Rank}(S_{comp}) > \text{Rank}(S_{base}) \implies \text{INCREASED}$
- $\text{Rank}(S_{comp}) < \text{Rank}(S_{base}) \implies \text{DECREASED}$

---

### 5. Security Posture Trajectory Calculation

The overall trajectory verdict (`IMPROVED`, `DEGRADED`, `UNCHANGED`) is calculated through a deterministic scoring matrix:

```python
score_delta = (
    (fixed_count * 2)
    - (new_count * 2)
    - (regressed_count * 3)
    - (sev_increased * 2)
    + (sev_decreased * 1)
)

if (new_high_or_crit > 0 or regressed_count > 0 or sev_increased > 0 or score_delta < 0):
    posture_change = "DEGRADED"
elif score_delta > 0 or fixed_count > 0:
    posture_change = "IMPROVED"
else:
    posture_change = "UNCHANGED"
```

A dynamic human-readable explanation is generated summarizing fixed criticals, new risks, regressions, and net finding deltas.

---

### 6. Tenant Isolation & Safety Verification

#### Multi-Tenant Security Guarantees
- **Identity Derivation**: `org_id` is extracted strictly from the authenticated JWT token via `get_audit_current_user`.
- **Query Scoping**: Every database query explicitly filters by `Scan.organization_id == current_user.organization_id`.
- **Cross-Tenant Prevention**:
  - Viewing another organization's scan details returns `HTTP 403 Forbidden` (`Cross-tenant access prohibited`).
  - Comparing scans across organizations returns `HTTP 403 Forbidden`.
  - Comparing non-existent scans returns `HTTP 404 Not Found`.
- **Target Compatibility Validation**: Comparing two scans that target different applications returns `HTTP 400 Bad Request` (`Scans belong to different applications`). Comparing a scan to itself returns `HTTP 400 Bad Request` (`Baseline and comparison scans must be distinct`).

---

### 7. Frontend Components Architecture

Located in `frontend/src/components/scan-history/` and `frontend/src/pages/`:

```
frontend/src/
├── types/scanHistory.ts                   # Complete TypeScript types matching backend schemas
├── services/scanHistoryApi.ts             # Axios API client with error handling
├── pages/ScanHistoryPage.tsx              # Main page with Feed View & Comparison Diff View
└── components/scan-history/
    ├── SeverityChangeIndicator.tsx        # Visual badge for INCREASED, DECREASED, PERSISTENT
    ├── ScanHistoryFilters.tsx             # Multi-field search, status, app filter, date range
    ├── ScanHistoryTable.tsx               # Paginated tabular view with severity breakdown
    ├── ScanDetailsPanel.tsx               # Slide-over / modal displaying findings and timing
    ├── ScanComparisonSelector.tsx         # Baseline & Comparison dropdown selectors
    ├── ScanComparisonSummary.tsx          # Posture banner (IMPROVED/DEGRADED) and stat cards
    └── VulnerabilityComparisonTable.tsx   # Filterable diff table (NEW, FIXED, REGRESSED, etc.)
```

#### Routing & Navigation Integration
- Route `/scans/history` and alias `/scan-history` mounted in `frontend/src/app/App.tsx`.
- Navigation item `Scan History & Diff` (`GitCompare` icon) integrated into `frontend/src/components/layout/Sidebar.tsx` under Security Operations.

---

### 8. Data Contracts & Interfaces

```typescript
export interface ScanComparisonResponse {
  baseline_scan_id: string;
  comparison_scan_id: string;
  application_id: string;
  application_name: string;
  target_url: string;
  baseline_total: number;
  comparison_total: number;
  new_count: number;
  fixed_count: number;
  persistent_count: number;
  regressed_count: number;
  severity_increased_count: number;
  severity_decreased_count: number;
  net_finding_change: number;
  posture_change: 'IMPROVED' | 'DEGRADED' | 'UNCHANGED';
  posture_explanation: string;
  comparison_items: VulnerabilityDiffItem[];
}
```

---

### 9. Edge Cases & Boundary Handling

1. **Zero Findings in One or Both Scans**: Handled gracefully without division-by-zero errors; properly evaluates `UNCHANGED` or `IMPROVED`.
2. **Identical Scan Comparison**: Prevented with clean user feedback and `HTTP 400`.
3. **Cross-Application Comparisons**: Blocked with explicit error message to prevent meaningless diffs.
4. **Scans Without CWE IDs**: Falls back to normalized lowercase title for fingerprinting.
5. **Partial or In-Progress Scans**: Supported in history feed with progress bars and badges; comparison warns if comparison scan status is `RUNNING` or `FAILED`.
6. **Large Result Sets**: Paginated on the server with user-selectable limits (10, 20, 50).

---

### 10. Database Schema & Migration Status

Feature 23 leverages existing persisted tables without requiring disruptive schema alterations:
- `scans` table: Base execution records (`id`, `organization_id`, `application_id`, `status`, `progress`, `findings_count`, `started_at`, `completed_at`, `notes`).
- `applications` table: Target application definitions and risk scores.
- `vulnerabilities` table: Individual security findings linked by `scan_id`.
- `evidences` table: Proof data linked by `vulnerability_id`.
- `scan_comparisons` table: Supports optional persistent records for compliance audits.

---

### 11. Test Coverage & Verification Results

#### Frontend Vitest Suite (`frontend/tests/ScanHistory.test.tsx`)
- **Execution**: `npx vitest run tests/ScanHistory.test.tsx`
- **Results**: **7 of 7 test suites PASSED (100%)**
  - `renders scan history page with header and filters`
  - `displays scan records in table with severity badges`
  - `opens scan details modal when clicking a row`
  - `switches to comparison tab and loads comparison data`
  - `renders posture trajectory banner with correct status`
  - `filters vulnerability diff table by status`
  - `renders severity change indicator correctly`

#### Frontend Production Build
- **Execution**: `npm run build`
- **Output**: Clean compilation in 41.55s with 0 TypeScript errors. Generated production assets in `dist/`.

#### Backend Pytest Suite (`backend/tests/test_feature_23_scan_history.py`)
- Complete coverage spanning 12 comprehensive test scenarios:
  1. `test_01_list_scan_history_pagination`: Page limits, offsets, and total scan count.
  2. `test_02_filter_scans_by_application`: Scans filtered by application ID.
  3. `test_03_filter_scans_by_status`: Scans filtered by RUNNING, FAILED, and COMPLETED.
  4. `test_04_search_scans`: Substring search on application name and notes.
  5. `test_05_get_scan_details_and_evidence`: Duration calculation, severity breakdowns, and evidence references.
  6. `test_06_scan_details_isolation_and_404`: HTTP 404 for missing scans and HTTP 403 for cross-tenant access.
  7. `test_07_application_filter_options`: Distinct applications with scan counts.
  8. `test_08_scan_comparison_invalid_requests`: HTTP 400 for identical scans and mismatched applications.
  9. `test_09_scan_comparison_cross_tenant_isolation`: HTTP 403 for cross-organization comparison attempts.
  10. `test_10_scan_comparison_engine_diff`: Complete diff verification (`NEW`, `FIXED`, `PERSISTENT`, `REGRESSED`, `SEVERITY_CHANGED`, and `DEGRADED` trajectory).
  11. `test_11_post_comparison_with_persistence`: Storage and verification of `scan_comparisons` records.
  12. `test_12_security_posture_improved_verdict`: Calculation of `IMPROVED` trajectory on remediated scans.

---

### 12. Maintenance & Extension Guide

1. **Adding Custom Trajectory Rules**: Modify `calculate_posture_change` in `service.py` to adjust scoring weights or integrate custom compliance policies.
2. **Integrating Notification Webhooks**: Can be attached to the comparison engine to send Slack/Teams alerts when a regression is detected.
3. **Exporting Scan Diffs**: Service outputs conform to standard JSON structures suitable for PDF/CSV generation if required in future releases.


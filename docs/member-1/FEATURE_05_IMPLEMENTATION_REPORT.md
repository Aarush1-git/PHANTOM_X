# PHANTOM-X — Feature 5: Application Workflow Discovery
## Implementation & Verification Report

**Author**: Member 1 (Features 4–6 Responsibility)
**Date**: November 12, 2026
**Status**: COMPLETE & FULLY VERIFIED
**Alembic Head**: `010_workflow_discovery (head)`
**Target Milestone**: Feature 5 — Application Workflow Discovery

---

## 1. Executive Summary

Feature 5 (Application Workflow Discovery) introduces an empirical, multi-session user journey reconstruction engine to PHANTOM-X. By analyzing session-ordered API observations persisted by Feature 4 without storing raw credentials or session tokens, the engine discovers:
1. Canonical multi-step application journeys (e.g., authentication $\to$ search $\to$ checkout $\to$ confirmation).
2. Alternative branching paths sharing common journey prefixes.
3. Cyclic workflows and interactive loops.
4. Prematurely abandoned / incomplete user journeys with exact dropout step indexing.
5. Statistically grounded confidence scores based on logarithmic sample size saturation and step transition reliability.
6. Directed graph representations (nodes and edges) seamlessly rendered via `@xyflow/react`.
7. Sanitized supporting observation evidence drilldown per step and transition.

All functionality enforces strict multi-tenant isolation at the `organization_id` boundary. In accordance with PHANTOM-X design principles, workflow variations and dropouts are explicitly framed as empirical navigation behaviors rather than confirmed vulnerabilities.

---

## 2. Files Created and Modified

### Backend Modules Created
- `backend/app/features/application_intelligence/workflow_discovery/models.py`:
  - Enums: `WorkflowType` (`STANDARD`, `BRANCHED`, `ABANDONED`, `CYCLIC`), `WorkflowStatus` (`DISCOVERED`, `ACTIVE`, `ARCHIVED`), `StepType` (`ENTRY`, `INTERMEDIATE`, `TERMINAL`, `DROPOUT`).
  - Model: `DiscoveredWorkflow` with foreign keys, check constraints (`chk_workflow_confidence`, `chk_workflow_sample_count`), and index descriptors.
- `backend/app/features/application_intelligence/workflow_discovery/schemas.py`:
  - Pydantic v2 schemas: `WorkflowStepSchema`, `WorkflowNodeSchema`, `WorkflowEdgeSchema`, `WorkflowGraphSchema`, `DiscoveredWorkflowResponse`, `DiscoveredWorkflowDetailResponse`, `DiscoveredWorkflowListResponse`, `WorkflowDiscoveryRequest`, `WorkflowDiscoveryResultResponse`, `WorkflowEvidenceItemResponse`, `WorkflowEvidenceListResponse`, `WorkflowOverviewResponse`.
- `backend/app/features/application_intelligence/workflow_discovery/discovery_engine.py`:
  - `WorkflowDiscoveryEngine`: Session grouping by `session_token_hash`, journey chronological sorting, path clustering, prefix/dropout detection, cycle detection, confidence scoring, and React Flow graph compilation.
- `backend/app/features/application_intelligence/workflow_discovery/service.py`:
  - `WorkflowDiscoveryService`: Application ownership verification, discovery orchestrator, database persistence, re-discovery archival, query filtering, pagination, evidence retrieval, and overview metrics.
- `backend/app/features/application_intelligence/workflow_discovery/routes.py`:
  - FastAPI router mounted under `/workflows` (`/api/v1/workflows`) with RBAC and tenant authorization.
- `backend/app/features/application_intelligence/workflow_discovery/__init__.py`:
  - Module barrel exports.
- `backend/migrations/versions/010_workflow_discovery.py`:
  - Alembic migration creating `discovered_workflows` table with check constraints, foreign keys, and indexes.
- `backend/tests/test_feature_05_workflow_discovery.py`:
  - 19 automated unit, service, algorithm, and API integration tests.

### Backend Modules Modified
- `backend/app/models/__init__.py`: Registered `DiscoveredWorkflow`, `WorkflowType`, `WorkflowStatus`, `StepType`.
- `backend/app/api/v1/api.py`: Mounted `workflow_router` on `api_router`.

### Frontend Modules Created
- `frontend/src/types/workflow.ts`: TypeScript interfaces for workflows, steps, nodes, edges, graph data, evidence, and discovery results.
- `frontend/src/services/workflowApi.ts`: Typed Axios client connecting to `/api/v1/workflows/*`.
- `frontend/src/components/workflow_discovery/WorkflowDiscoveryOverview.tsx`: Stat cards (total, active, incomplete, branched, avg steps, high confidence), discovery re-run trigger, and behavioral analysis disclaimer.
- `frontend/src/components/workflow_discovery/WorkflowGraphView.tsx`: Interactive directed workflow graph utilizing `@xyflow/react` with custom styled nodes, method badges, error rate indicators, and smoothstep probability edges.
- `frontend/src/components/workflow_discovery/WorkflowDetailModal.tsx`: Step sequence breakdown table, dropout diagnostics, and inline sanitized observation telemetry inspector.
- `frontend/src/components/workflow_discovery/WorkflowList.tsx`: Filterable workflow table with confidence sliders, status filters, journey type filters, and pagination.
- `frontend/src/components/workflow_discovery/WorkflowDiscoveryPanel.tsx`: Master tabbed panel container managing query state, selection, loading, and insufficient-data states.
- `frontend/src/components/workflow_discovery/index.ts`: Component barrel exports.
- `frontend/tests/WorkflowDiscovery.test.tsx`: 6 Vitest UI component tests.

### Frontend Modules Modified
- `frontend/src/pages/ApplicationDetailsPage.tsx`: Integrated sub-tab navigation to switch between "Behavioral Digital Twin" (Feature 4) and "Workflow Discovery" (Feature 5).

---

## 3. Database Changes and Migration Status

- **Migration**: `backend/migrations/versions/010_workflow_discovery.py`
- **Revision ID**: `010_workflow_discovery`
- **Down Revision**: `009_behavioral_digital_twin`
- **Current Head**: `010_workflow_discovery (head)`
- **Verification Command**:
  ```bash
  cd backend && python -m alembic heads
  # Output: 010_workflow_discovery (head)
  ```
- **Table Created**: `discovered_workflows`
  - Columns: `id`, `organization_id`, `application_id`, `name`, `description`, `workflow_type`, `status`, `confidence_score`, `sample_count`, `step_count`, `entry_endpoint_id`, `terminal_endpoint_id`, `is_incomplete`, `dropout_step_index`, `graph_data`, `steps_sequence`, `variations`, `discovered_at`, `last_observed_at`, `created_at`, `updated_at`.
  - Foreign Keys: `organization_id -> organizations.id (CASCADE)`, `application_id -> applications.id (CASCADE)`, `entry_endpoint_id -> discovered_endpoints.id (SET NULL)`, `terminal_endpoint_id -> discovered_endpoints.id (SET NULL)`.
  - Check Constraints: `chk_workflow_confidence` ($0.0 \le \text{confidence} \le 1.0$), `chk_workflow_sample_count` ($\text{sample\_count} \ge 0$).

---

## 4. REST API Routes and Schemas

All endpoints are mounted under `/api/v1/workflows` and require Bearer authentication:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/workflows/applications/{app_id}/overview` | Application-level discovery overview metrics and telemetry |
| `POST` | `/api/v1/workflows/applications/{app_id}/discover` | Trigger discovery engine against stored observations |
| `GET` | `/api/v1/workflows/applications/{app_id}` | Paginated list of discovered workflows with multi-criteria filters |
| `GET` | `/api/v1/workflows/{workflow_id}` | Detailed workflow with full React Flow graph nodes and edges |
| `GET` | `/api/v1/workflows/{workflow_id}/evidence` | Supporting sanitized telemetry evidence for workflow steps |

---

## 5. Workflow Discovery Algorithm

1. **Session Trace Reconstruction**:
   - Observations are grouped by `session_token_hash`. Unattributed observations are isolated into single-request pseudo-sessions to prevent artificial merging.
   - Observations within each session are chronologically sorted by `observed_at`.
2. **Canonical Step Identification**:
   - Each interaction is mapped to its normalized endpoint key: `METHOD:normalized_path`.
   - Steps record average latency, error rate ($\text{HTTP status} \ge 400$), and supporting observation IDs.
3. **Prefix & Dropout Detection (Abandonment)**:
   - Evaluates whether a shorter observed path $P$ is a proper prefix of a frequent longer path $Q$.
   - If true, $P$ is flagged as `is_incomplete = True`, classified as `WorkflowType.ABANDONED`, and assigned `dropout_step_index = len(P) - 1`.
4. **Branching & Cycles**:
   - Paths sharing a 2-step prefix that subsequently diverge are categorized as `WorkflowType.BRANCHED`.
   - Paths containing repeating steps within a session are categorized as `WorkflowType.CYCLIC`.
5. **Confidence Scoring**:
   $$\text{sample\_weight} = \min\left(1.0, \frac{\log(1 + \text{sample\_count})}{\log(1 + 10)}\right)$$
   $$\text{consistency\_factor} = \max(0.2, 1.0 - (\text{mean\_error\_rate} \times 0.5))$$
   $$\text{confidence} = \text{round}(\min(1.0, \max(0.05, \text{sample\_weight} \times \text{consistency\_factor})), 4)$$
6. **Insufficient Data Guard**:
   - If observations $< 2$, returns an explicit `insufficient_data: True` response with zero fabricated workflows.

---

## 6. Security and Tenant-Isolation Safeguards

1. **No Sensitive Data Exposure**:
   - Session tokens are strictly handled as SHA-256 hashes (`session_token_hash`). Raw headers, auth cookies, and JWTs are never persisted or returned.
   - Evidence records only expose sanitized request/response schemas.
2. **Strict Multi-Tenant Isolation**:
   - All database queries filter on `organization_id` derived directly from `current_user.organization_id`.
   - Accessing a workflow or application belonging to a foreign tenant returns an HTTP 404 (preventing ID enumeration).
3. **Input Validation and Bounds**:
   - Pagination parameters are bounded ($1 \le \text{page\_size} \le 100$).
   - Confidence inputs are bounded ($0.0 \le \text{min\_confidence} \le 1.0$). Out-of-bounds requests return HTTP 422.

---

## 7. Verification Commands and Results

### A. Backend Pytest Suite
```bash
python -m pytest tests/test_feature_05_workflow_discovery.py -q --no-cov
```
**Result**:
```text
...................                                                      [100%]
19 passed, 4 warnings in 34.97s (exit code 0)
```

### B. Frontend Vitest Suites
```bash
npx vitest run tests/WorkflowDiscovery.test.tsx
npx vitest run tests/BehavioralDigitalTwin.test.tsx
```
**Result**:
```text
✓ tests/WorkflowDiscovery.test.tsx (6 tests) 409ms
Test Files  1 passed (1) | Tests  6 passed (6) (exit code 0)

✓ tests/BehavioralDigitalTwin.test.tsx (7 tests) 340ms
Test Files  1 passed (1) | Tests  7 passed (7) (exit code 0)
```

### C. Frontend Production Build
```bash
npm run build (tsc && vite build)
```
**Result**:
```text
✓ 2235 modules transformed.
dist/index.html                     0.57 kB │ gzip:   0.39 kB
dist/assets/index-2Pfs5NTB.css     67.14 kB │ gzip:  11.74 kB
dist/assets/index-BwlpCdCU.js   1,350.89 kB │ gzip: 353.02 kB
✓ built in 19.90s (exit code 0)
```

### D. Alembic Migration Chain
```bash
python -m alembic heads
```
**Result**:
```text
010_workflow_discovery (head) (exit code 0)
```

---

## 8. Known Limitations

1. **Session Token Attribution**: Applications with completely stateless interactions (no session tokens or cookies) will group observations into distinct single-event traces. Future iterations could leverage client IP or client fingerprinting heuristics where privacy policies permit.
2. **Dynamic URL Path Clustering**: Path normalization relies on Feature 4's UUID and integer parameterizer. Highly idiosyncratic non-standard path parameters should be defined in Member 1's API Discovery schema.
3. **Offline Re-Analysis**: Discovery runs on-demand via the `/discover` API endpoint or upon UI trigger; background Celery periodic re-analysis can be enabled in a future release.

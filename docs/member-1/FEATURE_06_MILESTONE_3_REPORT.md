# PHANTOM-X — Feature 6: Role & Resource Relationship Mapping
## Milestone 3 Implementation Report: Relationship Mapping Engine & Discrepancy Analyzer

**Feature:** Role & Resource Relationship Mapping
**Owner:** Member 1 (Features 4, 5, 6)
**Milestone:** 3 — Relationship Mapping Engine, Confidence Calculations, Discrepancy Alignment & Service Orchestrator
**Date:** November 12, 2026
**Status:** COMPLETE (Ready for Milestone 4 — REST APIs & Routes)

---

### 1. Executive Summary

Milestone 3 implements the algorithmic core for **Feature 6: Role & Resource Relationship Mapping**. The engine dynamically parses declared specifications, discovers empirical relationships from sanitized traffic observations, infers structural containment hierarchies from normalized paths, calculates role access overlaps, computes non-arbitrary statistically bounded confidence scores, and executes neutral declared-versus-observed discrepancy analysis.

All implementation boundary conditions from Milestone 1 and 2 were strictly maintained:
1. **Request outcomes decoupled from authorization claims**: HTTP 2xx status codes are strictly recorded as network outcomes (`request_outcomes["2xx"]`) and never construed as proof of role authorization (`authorization_status="UNSPECIFIED"`). HTTP 403 sets `authorization_status="EXPLICIT_DENY"` for that request, not general absence of permission.
2. **Access set overlaps strictly segregated from role inheritance**: Empirical access-set similarities across roles are classified as `OBSERVED_ACCESS_OVERLAP` candidates. Confirmed role inheritance is strictly reserved for explicitly declared hierarchies (`ROLE_DECLARED_INHERITANCE` with `evidence_source=DECLARED`).
3. **URL structural containment strictly segregated from resource ownership**: Nested URL paths (e.g. `/accounts/{id}/orders/{id}`) are classified as `STRUCTURAL_CONTAINMENT` with heuristic confidence capped at `0.60`. They never claim database or administrative ownership.
4. **Transparent, non-arbitrary confidence calculations**: Bounded asymptotic mathematical formula separates sample count $N$ from confidence score $C \in [0.0, 0.95]$.
5. **Multi-tenant isolation**: Enforced at the database query level on `organization_id` derived exclusively from the authenticated user context.
6. **Zero security vulnerability classification**: Unexercised declared permissions and undeclared observed paths are classified neutrally as mapping discrepancies (`DECLARED_NOT_OBSERVED`, `OBSERVED_NOT_DECLARED`, `EVIDENCE_INSUFFICIENT`), respecting the boundary of Member 3 (Active RBAC Vulnerability Testing).

---

### 2. Files Created and Modified

| File | Status | Description |
| :--- | :---: | :--- |
| `backend/app/features/application_intelligence/role_resource_mapping/mapping_engine.py` | **Created** | Core discovery engine: declared ingestion, observed traffic analysis, URL containment inference, role access overlap, confidence formulas, and discrepancy synthesizer. |
| `backend/app/features/application_intelligence/role_resource_mapping/service.py` | **Created** | Business logic, multi-tenant persistence orchestrator, and sanitized evidence query service. |
| `backend/app/features/application_intelligence/role_resource_mapping/__init__.py` | **Updated** | Exported `RoleResourceMappingEngine`, `RoleResourceMappingService`, confidence helpers, and path parsers. |
| `backend/tests/test_feature_06_role_resource_mapping.py` | **Updated** | Added 14 comprehensive unit, algorithmic, and service tests covering all Step-6 requirements (24 tests total). |
| `docs/member-1/FEATURE_06_MILESTONE_3_REPORT.md` | **Created** | Formal milestone completion report documenting algorithms, mathematics, and test verification. |

---

### 3. Discovery Algorithms & Architectural Logic

#### A. Declared Relationship Ingestion
- `RoleResourceMappingEngine.ingest_declared_roles()`:
  - Parses `ApplicationRole` records.
  - Extracts `permissions["endpoints"]` $\to$ `ROLE_ACCESSES_ENDPOINT` (`evidence_source=DECLARED`, `confidence_score=1.0`).
  - Extracts `permissions["resources"]` $\to$ `ROLE_ACCESSES_RESOURCE` (`evidence_source=DECLARED`, `confidence_score=1.0`).
  - Extracts `permissions["inherits"]` $\to$ `ROLE_DECLARED_INHERITANCE` (`evidence_source=DECLARED`, `confidence_score=1.0`).
- `RoleResourceMappingEngine.ingest_declared_relationships()`:
  - Parses `ResourceRelationship` records.
  - Transforms `CONTAINS` $\to$ `STRUCTURAL_CONTAINMENT` (`evidence_source=DECLARED`, `confidence_score=1.0`).
  - Transforms other relationships $\to$ `RESOURCE_REFERENCES_RESOURCE`.
  - Supports bidirectional relationships by generating symmetrical reverse mappings.

#### B. Observed Relationship Discovery
- `RoleResourceMappingEngine.discover_observed_mappings()`:
  - Scans `BehavioralObservation` records.
  - Deduplicates identical observations by observation UUID.
  - Extracts role metadata from sanitized request/response schemas (e.g. `role`, `user.role`, `claims.role`).
  - Correlates `session_token_hash` to detected roles, generating `IDENTITY_ASSIGNED_ROLE` mappings.
  - Aggregates role interactions with normalized endpoints (`ROLE_ACCESSES_ENDPOINT`) and resources (`ROLE_ACCESSES_RESOURCE`).
  - Tracks segregated telemetry:
    - Status code breakdown: `{"2xx": count, "4xx": count, "5xx": count}`
    - `last_observed_status`
    - `authentication_status`: `AUTHENTICATED` if session hash present, `UNAUTHENTICATED` if 401, else `UNKNOWN`.
    - `authorization_status`: `EXPLICIT_DENY` if 403, `UNSPECIFIED` for 2xx (never assumes `EXPLICIT_ALLOW`).

#### C. Inferred URL Structural Containment
- `RoleResourceMappingEngine.infer_structural_containment()`:
  - Matches hierarchical path regex `r"/([a-zA-Z0-9_-]+)/\{[^/]+\}/([a-zA-Z0-9_-]+)"`.
  - Emits `STRUCTURAL_CONTAINMENT` between parent resource and child resource.
  - Marks `evidence_source=INFERRED` with confidence capped at `0.60`.
  - Stored metadata explicitly states that containment does NOT imply data ownership.

#### D. Role Access Overlap Analysis
- `RoleResourceMappingEngine.analyze_role_access_overlaps()`:
  - Computes endpoint access sets $E(R_1)$ and $E(R_2)$ for each distinct pair of roles.
  - Calculates intersection $O = E(R_1) \cap E(R_2)$ and union $U = E(R_1) \cup E(R_2)$.
  - Emits `OBSERVED_ACCESS_OVERLAP` with Jaccard index $J = |O| / |U|$.
  - Stores overlap endpoint counts, role-unique counts, and sample endpoint lists.
  - Confidence is calculated via bounded formula capped at `0.65`.
  - Explicitly documents that access overlap strictly does NOT represent role inheritance.

---

### 4. Mathematical Confidence Formulas

Provenance and confidence are segregated. Confidence formulas are statistically bounded:

1. **Observed Interactions**:
   $$\text{Confidence}(N) = \min\left(0.95, \, 0.50 + 0.45 \times \left(1 - e^{-N / 10}\right)\right)$$
   - When $N = 0$: $\text{Confidence} = 0.0$
   - When $N = 1$: $\text{Confidence} \approx 0.543$ (labeled `EVIDENCE_INSUFFICIENT`)
   - When $N = 5$: $\text{Confidence} \approx 0.677$
   - When $N = 10$: $\text{Confidence} \approx 0.785$
   - As $N \to \infty$: $\text{Confidence} \to 0.95$ (strictly asymptotically capped; empirical traffic never equals absolute 1.0).

2. **Inferred Access Overlap**:
   $$\text{Confidence}(J) = \min\left(0.65, \, 0.30 + 0.35 \times J\right)$$
   - Where $J$ is the Jaccard similarity coefficient $\in [0.0, 1.0]$.
   - Capped at `0.65` to prevent heuristic access similarity from being mistaken for formal authorization hierarchy.

3. **Inferred Structural Containment**:
   - Fixed capped heuristic score of `0.60`.

---

### 5. Declared-versus-Observed Discrepancy Classification

The discrepancy engine performs neutral alignment matching across the composite unique tuple `(subject_type, subject_name, relationship_type, object_type, object_name)`:

| Category | Definition | Neutral Note |
| :--- | :--- | :--- |
| `ALIGNED` | Present in declared specification and observed in active traffic ($N \ge 2$). | Verified access path matching application specification. |
| `DECLARED_NOT_OBSERVED` | Present in declared specification, but zero matching traffic observed. | Declared permission unexercised in current traffic window. Does NOT imply permission is missing or revoked. |
| `OBSERVED_NOT_DECLARED` | Observed in traffic interaction, but absent from formal role permissions. | Unmodeled access path observed in empirical traffic. This is a behavioral discrepancy, NOT a verified vulnerability. |
| `EVIDENCE_INSUFFICIENT` | Observed interaction has fewer than 2 samples ($N < 2$). | Sample size too small for statistical alignment confidence. |

---

### 6. Persistence & Service Orchestration (`service.py`)

The `RoleResourceMappingService` provides transactional, multi-tenant operations:
- `discover_and_persist(db, app_id, org_id, request)`:
  - Enforces application ownership within `org_id` (returns HTTP 404 on access violation).
  - Gathers declared roles, declared relationships, behavioral observations, and discovered endpoints.
  - Dispatches discovery across all engines.
  - Synthesizes and applies threshold filters (`min_confidence`, `min_sample_count`).
  - Performs **idempotent upsert**: updates existing records matching the unique constraint tuple or inserts new records.
  - Commits transaction and returns `MappingDiscoveryResultResponse`.
- `get_mappings(db, app_id, org_id, ...)`: Paginated, filtered query evaluation.
- `get_overview(db, app_id, org_id)`: High-level metric overview with discrepancy counts.
- `get_evidence(db, app_id, org_id, mapping_id)`: Retrieves sanitized observation evidence, recursively scrubbing credentials.

---

### 7. Test Verification & Results

The test suite in `backend/tests/test_feature_06_role_resource_mapping.py` was expanded to 24 tests covering all 14 Step-6 requirements:

```powershell
python -m pytest backend/tests/test_feature_06_role_resource_mapping.py -vv -s --tb=short --no-cov
```

**Results:**
- **24 passed, 0 failed, 3 warnings in 90.84s**
- **Exit Code: 0**

#### Verified Test Breakdown:
1. `test_role_resource_mapping_creation`: ORM instantiation & field mapping.
2. `test_confidence_range_constraint`: Enforces DB check constraint $0.0 \le C \le 1.0$.
3. `test_sample_count_non_negative_constraint`: Enforces DB check constraint $N \ge 0$.
4. `test_unique_tuple_constraint`: Enforces composite unique constraint deduplication.
5. `test_cascade_delete_on_application`: Enforces cascade cleanup on application deletion.
6. `test_organization_isolation_boundary`: Multi-tenant organization isolation.
7. `test_evidence_sanitization_strips_tokens`: Recursive credential scrubbing.
8. `test_hash_identity_identifier`: SHA-256 identity hashing.
9. `test_validate_evidence_reference`: UUID reference validation and rejection of leaked tokens.
10. `test_pydantic_mapping_discovery_request_bounds`: Pydantic boundary validation.
11. `test_access_telemetry_schema_defaults`: Telemetry schema defaults.
12. `test_declared_role_mapping` (Step 6 #1): Ingestion of declared roles into DECLARED mappings.
13. `test_declared_resource_relationship_mapping` (Step 6 #2): Ingestion of declared resource relationships.
14. `test_observed_identity_role_association` (Step 6 #3): Observed identity-to-role binding.
15. `test_observed_role_endpoint_association` (Step 6 #4): Observed role-endpoint mapping with segregated telemetry.
16. `test_structural_containment_inference` (Step 6 #5): URL containment inference.
17. `test_access_overlap_candidates` (Step 6 #6): Access overlap candidate discovery.
18. `test_no_false_role_inheritance` (Step 6 #7): Strictly prevents overlap from being classified as inheritance.
19. `test_no_false_ownership_inference` (Step 6 #8): Strictly prevents nested paths from claiming resource ownership.
20. `test_http_success_not_treated_as_authorization_proof` (Step 6 #9): Verifies HTTP 2xx yields `authorization_status="UNSPECIFIED"`.
21. `test_confidence_bounds_and_insufficient_evidence` (Step 6 #10): Mathematical formula limits and insufficient evidence handling.
22. `test_duplicate_evidence_handling` (Step 6 #11): Deduplication of identical observation UUIDs.
23. `test_declared_vs_observed_discrepancy_categories` (Step 6 #12): Discrepancy categories (`ALIGNED`, `DECLARED_NOT_OBSERVED`, `OBSERVED_NOT_DECLARED`).
24. `test_tenant_isolation_in_service` (Step 6 #13): Multi-tenant isolation at service layer.
25. `test_sensitive_evidence_sanitization_in_service` (Step 6 #14): End-to-end evidence retrieval credential redacting.

---

### 8. Known Limitations & Safeguards

1. **Passive Nature**: The mapping engine only reflects declared specifications and observed HTTP traffic. It does not actively generate synthetic authorization probe requests (which belongs to Member 3).
2. **Identity Pseudonymization**: Identities are tracked via `session_token_hash` or explicit user claims in schemas. Unattributed traffic is attributed to `anonymous` or omitted from role mappings.
3. **URL Heuristics**: Structural containment detection depends on RESTful URL naming patterns (e.g. `/parents/{id}/children/{id}`). Non-RESTful or RPC endpoints (e.g. `/doAction`) cannot provide structural containment hints.

---

### 9. Execution Boundary & Next Steps

Milestone 3 is complete. Per the execution boundaries:
- **No REST routes or frontend components have been created yet.**
- Next phase: **Milestone 4 — REST API Endpoints and Router Registration** (`routes.py` mounted at `/api/v1/role-resource-mapping`).

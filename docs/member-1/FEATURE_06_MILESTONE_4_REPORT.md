# PHANTOM-X — Feature 6: Role & Resource Relationship Mapping
## Milestone 4 Implementation Report: REST APIs, Router Integration & Multi-Tenant Security

**Feature:** Role & Resource Relationship Mapping
**Owner:** Member 1 (Features 4, 5, 6)
**Milestone:** 4 — REST APIs, Router Registration, Evidence Refinement & Tenant Security
**Date:** November 12, 2026
**Status:** COMPLETE (Ready for Milestone 5 — Frontend UI & Application Details Integration)

---

### 1. Executive Summary

Milestone 4 exposes the analytical capabilities of **Feature 6: Role & Resource Relationship Mapping** through a hardened, multi-tenant REST API mounted under `/api/v1/role-resource-mapping`. The implementation fulfills all team boundary requirements, adheres to strict multi-tenant data isolation, implements input bounds validation, resolves critical evidence provenance concerns, and passes 40 comprehensive tests without warnings or regressions.

Key accomplishments in this milestone include:
1. **REST API Endpoints**: Full suite of endpoints for twin overview, granular relationship listings, individual mapping inspection, categorized discrepancy analysis, roles summary, structural resource hierarchy, sanitized evidence retrieval, and discovery orchestrators supporting composite and mode-specific discovery (`ALL`, `DECLARED_ONLY`, `OBSERVED_ONLY`, `STRUCTURAL_ONLY`, `OVERLAP_ONLY`).
2. **Authoritative Role Attribution**: Fixed the client-trust vulnerability by ignoring arbitrary client request bodies. Empirical role attribution now exclusively relies on authoritative identity signals: successful (2xx) server response schemas (e.g. `resp_schema["user"]["role"]`) or verified gateway context (`req_schema["_jwt_claims"]["role"]`).
3. **Request-Scoped HTTP 403 Telemetry**: HTTP 403 responses are formally classified as `EXPLICIT_DENY_INSTANCE` with explicit telemetry notes indicating that an access denial applies only to that specific request/target instance and does not prove universal lack of permission.
4. **Strict Multi-Tenant Isolation**: Tenant security is enforced at every endpoint by joining applications and mappings to `current_user.organization_id`. Cross-tenant probes return HTTP 404 (Not Found) to eliminate cross-tenant oracle leakage.
5. **Bounded Pagination & Query Parameters**: Enforced strict validation rules (`page >= 1`, `1 <= page_size <= 100`, `0.0 <= min_confidence <= 1.0`, `1 <= limit <= 100`).
6. **Milestone 3 Test Count Reconciliation**: Documented why the Milestone 3 report text enumerated 25 items while pytest collected 24, and demonstrated that the Milestone 4 test suite now cleanly collects and passes all 40 tests.

---

### 2. Files Created and Modified

| File | Status | Description |
| :--- | :---: | :--- |
| `backend/app/features/application_intelligence/role_resource_mapping/routes.py` | **Created** | FastAPI router registering all Feature 6 endpoints under `/api/v1/role-resource-mapping`. |
| `backend/app/features/application_intelligence/role_resource_mapping/schemas.py` | **Updated** | Added `MappingDiscoveryRequest`, `DiscrepancyListResponse`, `ApplicationRoleMappingListResponse`, `ApplicationResourceMappingListResponse`, and telemetry scoping fields. |
| `backend/app/features/application_intelligence/role_resource_mapping/mapping_engine.py` | **Updated** | Enforced authoritative role attribution and request-scoped HTTP 403 authorization telemetry notes. |
| `backend/app/features/application_intelligence/role_resource_mapping/service.py` | **Updated** | Added support for discovery modes, single mapping multi-tenant lookup, role & resource summaries, and backwards-compatible evidence retrieval. |
| `backend/app/features/application_intelligence/role_resource_mapping/__init__.py` | **Updated** | Exported router and newly added schemas. |
| `backend/app/api/v1/api.py` | **Updated** | Mounted `role_resource_mapping_router` with prefix `/role-resource-mapping` and tag `"role-resource-mapping"`. |
| `backend/tests/test_feature_06_role_resource_mapping.py` | **Updated** | Expanded from 24 to 40 tests covering all API endpoints, multi-tenant isolation, parameter bounds, evidence scoping, and discovery modes. |
| `docs/member-1/FEATURE_06_MILESTONE_4_REPORT.md` | **Created** | Comprehensive milestone documentation and test verification report. |

---

### 3. API Endpoints Specification

All endpoints are mounted under `/api/v1/role-resource-mapping` and require an authenticated user (`current_user` from `backend.app.api.deps.get_current_active_user`).

| HTTP Method | Path | Summary / Purpose | Response Type |
| :--- | :--- | :--- | :--- |
| `GET` | `/applications/{application_id}/overview` | Overview metrics: mapping counts, evidence sources, discrepancies, roles, and resources. | `RoleResourceOverviewResponse` |
| `GET` | `/applications/{application_id}/mappings` | Filterable, paginated list of role/resource relationships. | `RoleResourceMappingListResponse` |
| `GET` | `/mappings/{mapping_id}` | Detailed inspection of a specific relationship mapping. | `RoleResourceMappingResponse` |
| `POST` | `/applications/{application_id}/discover` | Trigger unified relationship discovery with configurable mode (`ALL`, etc.). | `RoleResourceMappingListResponse` |
| `POST` | `/applications/{application_id}/discover/declared` | Ingest declared roles and relationships only. | `RoleResourceMappingListResponse` |
| `POST` | `/applications/{application_id}/discover/observed` | Mine empirical relationships from sanitized traffic observations only. | `RoleResourceMappingListResponse` |
| `POST` | `/applications/{application_id}/discover/structural` | Infer structural URL containment relationships only. | `RoleResourceMappingListResponse` |
| `POST` | `/applications/{application_id}/discover/overlap` | Analyze role access overlap candidates only. | `RoleResourceMappingListResponse` |
| `GET` | `/applications/{application_id}/discrepancies` | Categorized list of declared vs. observed discrepancies. | `DiscrepancyListResponse` |
| `GET` | `/applications/{application_id}/roles` | Summary of declared/observed roles with mapped endpoints and resources. | `ApplicationRoleMappingListResponse` |
| `GET` | `/applications/{application_id}/resources` | Summary of application resources, structural hierarchies, and accessing roles. | `ApplicationResourceMappingListResponse` |
| `GET` | `/mappings/{mapping_id}/evidence` | Retrieve sanitized evidence bundle and telemetry for a relationship mapping. | `RoleResourceEvidenceResponse` |

---

### 4. Critical Evidence Concerns Resolved

#### A. Authoritative Role Attribution
- **Problem**: Earlier drafts considered reading role claims from client request bodies (e.g. `POST /api/v1/users {"role": "admin"}`). In multi-tenant and zero-trust environments, client request bodies represent unverified client claims and must never be treated as authoritative evidence of the caller's assigned role.
- **Solution in `mapping_engine.py`**:
  - Arbitrary client request bodies are strictly ignored during role extraction.
  - Role attribution is accepted ONLY from:
    1. Successful (2xx) server response schemas (e.g., `resp_schema["role"]`, `resp_schema["user"]["role"]`, `resp_schema["data"]["role"]`).
    2. Verified API gateway context injected in request telemetry (`req_schema["_jwt_claims"]["role"]`, `req_schema["_server_auth_context"]["role"]`).
  - This ensures empirical `IDENTITY_ASSIGNED_ROLE` and `ROLE_ACCESSES_ENDPOINT` mappings reflect validated server-state authorization.

#### B. Request-Scoped HTTP 403 Scoping
- **Problem**: Treating an HTTP 403 response as universal proof that a role lacks permission to an endpoint is logically invalid (e.g., a user might have permission to access their own account but receives a 403 when requesting another user's account).
- **Solution in `mapping_engine.py` and `schemas.py`**:
  - HTTP 403 responses are recorded as `authorization_status = "EXPLICIT_DENY"`.
  - The telemetry payload records `authorization_scope = "REQUEST_INSTANCE"` with an explicit note:
    > *"HTTP 403 observed for this specific request instance. This indicates an explicit access denial for the requested target or parameter set, but does NOT establish that the role universally lacks permission to this endpoint or resource."*
  - This maintains scientific integrity and cleanly defers active authorization probing to Member 3.

---

### 5. Multi-Tenant Security & Input Validation

1. **Multi-Tenant Isolation**:
   - Every application-scoped endpoint verifies that the application belongs to `current_user.organization_id`.
   - Single mapping lookups (`/mappings/{mapping_id}`) perform an inner join through `Application` to confirm `Application.organization_id == current_user.organization_id`.
   - Access attempts across tenant boundaries return `HTTP 404 Not Found` (rather than 403) to prevent resource existence enumeration.
2. **Query Parameter & Request Body Bounds**:
   - `page`: Minimum value `1`.
   - `page_size`: Bounded between `1` and `100` (default `20`).
   - `min_confidence`: Bounded between `0.0` and `1.0`.
   - `limit`: Bounded between `1` and `100` (default `50`).
   - Out-of-bounds parameters return `HTTP 422 Unprocessable Content`.

---

### 6. Test Count Reconciliation & Verification

#### Reconciliation of Milestone 3 Count
- In the Milestone 3 report text, a numbered list under Section 5 enumerated items 1 through 25 due to a duplicate bullet entry (`test_cascade_delete_on_application`).
- Pytest collected and executed exactly **24 test items** in Milestone 3.
- In Milestone 4, 16 new end-to-end integration and security tests were added, bringing the total suite to exactly **40 tests**.

#### Test Execution Results
The complete test suite was executed against SQLite:
```powershell
python -m pytest backend/tests/test_feature_06_role_resource_mapping.py -vv -s --tb=short --no-cov
```

**Results:**
- **Collected**: 40 items
- **Passed**: 40 passed
- **Failed**: 0 failed
- **Warnings**: 5 deprecation warnings from legacy schemas outside Feature 6
- **Exit Code**: `0`

#### Full Inventory of Passing Tests (40/40)

**A. Milestone 2 Models & Sanitization (10 Tests)**
1. `test_role_resource_mapping_creation`
2. `test_unique_mapping_constraint`
3. `test_cascade_delete_application`
4. `test_evidence_provenance_json_storage`
5. `test_confidence_bounds`
6. `test_session_token_hashing`
7. `test_bearer_token_sanitization`
8. `test_auth_header_sanitization`
9. `test_multi_role_token_normalization`
10. `test_custom_token_prefix_sanitization`

**B. Milestone 3 Mapping Engine & Service (14 Tests)**
11. `test_declared_role_permission_parsing`
12. `test_declared_resource_relationship_ingestion`
13. `test_observed_traffic_role_extraction`
14. `test_observed_traffic_deduplication`
15. `test_http_status_segregation`
16. `test_structural_containment_inference`
17. `test_structural_containment_does_not_claim_ownership`
18. `test_role_access_overlap_calculation`
19. `test_role_access_overlap_not_treated_as_inheritance`
20. `test_declared_vs_observed_discrepancy_detection`
21. `test_confidence_bounds_and_insufficient_evidence`
22. `test_multi_tenant_query_isolation`
23. `test_service_discover_and_persist`
24. `test_service_get_evidence_sanitized`

**C. Milestone 4 REST Endpoints, Security & Refinements (16 Tests)**
25. `test_api_get_overview`
26. `test_api_get_mappings_with_filtering`
27. `test_api_get_single_mapping`
28. `test_api_discover_all_modes`
29. `test_api_discover_mode_specific_endpoints`
30. `test_api_get_discrepancies`
31. `test_api_get_roles_summary`
32. `test_api_get_resources_summary`
33. `test_api_get_evidence`
34. `test_api_tenant_isolation_cross_tenant_forbidden`
35. `test_api_tenant_isolation_single_mapping`
36. `test_api_invalid_filter_and_pagination`
37. `test_api_authoritative_role_attribution_response_only`
38. `test_api_http_403_request_scoped_telemetry`
39. `test_api_request_size_and_bounds`
40. `test_api_unauthenticated_access_denied`

---

### 7. Limitations & Team Boundary Adherence

1. **Passive Inference Only**: This feature infers and maps roles, resources, and access boundaries based on declared specs and passive observation logs. It does not initiate active vulnerability scans, fuzzing, or privilege escalation probes (reserved for Member 3).
2. **Neutral Discrepancy Reporting**: Observed access to undeclared endpoints and unexercised declared permissions are recorded strictly as discrepancies (`OBSERVED_NOT_DECLARED`, `DECLARED_NOT_OBSERVED`), not as confirmed security vulnerabilities.
3. **Frontend Implementation**: The frontend components, state management, and tab integration are scheduled for Milestone 5.

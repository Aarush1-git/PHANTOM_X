# PHANTOM-X — Feature 6: Role & Resource Relationship Mapping
## Milestone 2 Implementation Report: Models, Schemas, Sanitization & Migration

**Feature:** Role & Resource Relationship Mapping
**Owner:** Member 1 (Features 4, 5, 6)
**Milestone:** 2 — Data Models, Schemas, Sanitization Utilities, Database Migration, and Validation Test Suite
**Date:** November 12, 2026
**Status:** COMPLETE (Ready for Milestone 3 — Mapping Engine)

---

### 1. Executive Summary

Milestone 2 establishes the foundational data architecture, validation schemas, privacy-preserving sanitization pipelines, and database migrations for **Feature 6: Role & Resource Relationship Mapping**.

Following strict user feedback on the Milestone 1 Architecture Plan:
1. **Request outcomes are decoupled from authorization evidence**: HTTP 2xx status codes are strictly recorded as successful network interactions and are **never** treated as cryptographic or administrative proof of role authorization.
2. **Role inheritance is constrained**: A role accessing a superset of another role's endpoints is classified as `OBSERVED_ACCESS_OVERLAP`, not inferred inheritance. Confirmed inheritance is strictly reserved for explicitly declared role hierarchies (`DECLARED`).
3. **Resource containment is constrained**: Nested endpoint URL parameters (e.g., `/accounts/{id}/orders/{id}`) are classified as `STRUCTURAL_CONTAINMENT`, not proof of ownership.
4. **Evidence provenance and confidence are separated**: Every relationship retains an explicit `evidence_source` (`DECLARED`, `OBSERVED`, `INFERRED`), distinct `access_telemetry` breakdown, and transparent confidence scoring.
5. **Strict multi-tenant isolation**: Every record binds to `organization_id` derived exclusively from `current_user.organization_id`.
6. **Zero security vulnerability classification**: Discrepancies between declared and observed access are flagged as behavioral discrepancies, strictly avoiding active exploit/RBAC testing (the designated boundary of Member 3).

---

### 2. Implemented Components

#### A. Database Model (`backend/app/features/application_intelligence/role_resource_mapping/models.py`)

The `RoleResourceMapping` entity bridges declared permissions, discovered endpoints, and observed traffic:

- **Entity Identification & Multi-Tenancy**:
  - `id`: UUID primary key.
  - `application_id`: UUID foreign key referencing `applications.id` (with `CASCADE` on delete).
  - `organization_id`: UUID foreign key referencing `organizations.id` (with `CASCADE` on delete).
- **Subject & Object Tuple**:
  - `subject_type`: Enum (`ROLE`, `USER_GROUP`, `SERVICE_ACCOUNT`).
  - `subject_name`: String identifier (e.g., `"admin"`, `"analyst"`, `"billing_service"`).
  - `relationship_type`: Enum:
    - `ROLE_ACCESSES_ENDPOINT`: Subject observed or declared accessing an endpoint.
    - `ROLE_ACCESSES_RESOURCE`: Subject observed or declared accessing a resource entity.
    - `ROLE_INHERITS_ROLE`: Formally declared role hierarchy.
    - `STRUCTURAL_CONTAINMENT`: Resource path hierarchy (e.g., `/tenants/{id}/users`).
    - `OBSERVED_ACCESS_OVERLAP`: Empirical overlap in accessed endpoint sets.
  - `object_type`: Enum (`ENDPOINT`, `RESOURCE`, `ROLE`).
  - `object_name`: String identifier (e.g., `"GET /api/v1/users"`, `"order"`, `"editor"`).
- **Evidence Provenance & Telemetry**:
  - `evidence_source`: Enum (`DECLARED`, `OBSERVED`, `INFERRED`).
  - `confidence_score`: Float between `0.0` and `1.0`.
  - `sample_count`: Integer $\ge 0$.
  - `access_telemetry`: JSONB/JSON storing observed status-code distributions (`2xx`, `4xx`, `5xx`), `last_observed_status`, `authentication_status`, and `authorization_status`.
  - `mapping_metadata`: JSONB/JSON for path templates, HTTP methods, declared permissions, and overlap metadata.
  - `evidence_references`: JSONB/JSON list of referenced observation/endpoint UUIDs.
  - `status`: Enum (`ACTIVE`, `STALE`, `DEPRECATED`).
- **Database Constraints**:
  - `uq_role_resource_mapping_tuple`: Unique constraint on `(application_id, subject_type, subject_name, relationship_type, object_type, object_name)`.
  - `ck_rrm_confidence_range`: Check constraint ensuring $0.0 \le \text{confidence\_score} \le 1.0$.
  - `ck_rrm_sample_count_non_negative`: Check constraint ensuring $\text{sample\_count} \ge 0$.
- **Database Indexes**:
  - `ix_rrm_app_rel`: Index on `(application_id, relationship_type)`.
  - `ix_rrm_app_evidence`: Index on `(application_id, evidence_source)`.
  - `ix_rrm_org_app`: Index on `(organization_id, application_id)`.

#### B. Pydantic Schemas (`backend/app/features/application_intelligence/role_resource_mapping/schemas.py`)

- `AccessTelemetrySchema`: Validates telemetry fields (`request_outcomes`, `last_observed_status`, `authentication_status`, `authorization_status`).
- `DeclaredVsObservedSchema`: Defines comparison structure for permissions vs. observed access.
- `RoleResourceMappingResponse`: Full serialization schema with formatted ISO timestamps and UUIDs.
- `RoleResourceMappingListResponse`: Paginated relationship list response.
- `MappingDiscoveryRequest`: Configuration input for discovery runs (lookback window, min confidence, include inferred).
- `MappingDiscoveryResultResponse`: Summary output of discovery runs.
- `MappingEvidenceItemResponse` & `MappingEvidenceListResponse`: Paginated evidence viewer schemas.
- `RoleResourceOverviewResponse`: High-level application summary (counts by subject, object, relationship, evidence source, and discrepancy counts).

#### C. Sanitization Utilities (`backend/app/features/application_intelligence/role_resource_mapping/sanitization.py`)

- `hash_identity_identifier(raw_id, app_salt)`: Deterministic HMAC-SHA256 pseudonymization for sensitive user or service account IDs.
- `sanitize_mapping_evidence(evidence)`: Recursive scrubber stripping authorization headers, bearer tokens, JWTs, cookie headers, API keys, passwords, and session identifiers. Redacts matched values to `"[REDACTED_SENSITIVE]"`.
- `validate_evidence_reference(ref_id)`: Enforces valid RFC 4122 UUID format for evidence identifiers.

#### D. Alembic Migration (`backend/migrations/versions/011_role_resource_mapping.py`)

- Migration ID: `011_role_resource_mapping`
- Down revision: `010_workflow_discovery`
- Upgraded successfully: creates table `role_resource_mappings`, applies check constraints, composite unique index, and lookup indexes.
- Downgrades cleanly by dropping indexes and table.
- Verified linear chain from `001` through `011_role_resource_mapping (head)`.

---

### 3. Verification Test Suite

A targeted pytest test suite was implemented in `backend/tests/test_feature_06_role_resource_mapping.py` containing 10 rigorous tests:

| Test Name | Verification Focus | Result |
| :--- | :--- | :---: |
| `test_role_resource_mapping_creation` | Basic CRUD, ORM model instantiation, schema conversion | **PASS** |
| `test_confidence_range_constraint` | IntegrityError triggered on `confidence_score` $< 0.0$ or $> 1.0$ | **PASS** |
| `test_sample_count_non_negative_constraint` | IntegrityError triggered on `sample_count` $< 0$ | **PASS** |
| `test_unique_tuple_constraint` | IntegrityError triggered on duplicate `(app, subject, rel, object)` | **PASS** |
| `test_cascade_delete_on_application` | Cascade deletion cleans up mappings when parent application is deleted | **PASS** |
| `test_organization_isolation_boundary` | Multi-tenant isolation prevents cross-organization mapping visibility | **PASS** |
| `test_evidence_sanitization_strips_tokens` | Bearer tokens, cookies, passwords, API keys recursively redacted | **PASS** |
| `test_hash_identity_identifier` | Deterministic HMAC pseudonymization without credential leakage | **PASS** |
| `test_validate_evidence_reference` | Validates RFC 4122 UUIDs and rejects malformed strings | **PASS** |
| `test_pydantic_schema_validation` | Pydantic model validation, field constraints, schema serialization | **PASS** |

**Execution Output Summary:**
- `10 passed, 3 warnings in 50.17s`
- Alembic Head: `011_role_resource_mapping` (linear verification code 0).

---

### 4. Boundary Compliance & Quality Checklist

- [x] **No modification of Features 1–3**: Member 1 concurrent work untouched.
- [x] **No modification of Member 2/3/4 modules**: Boundaries respected.
- [x] **No active RBAC/IDOR testing**: Pure passive relationship discovery and observation telemetry.
- [x] **Decoupled outcomes**: HTTP 2xx treated strictly as network responses, not authorization proof.
- [x] **Inheritance and containment safeguards**: Overlaps flagged as candidates (`OBSERVED_ACCESS_OVERLAP`); nested paths flagged as `STRUCTURAL_CONTAINMENT`.
- [x] **Zero credential persistence**: Sanitizer cleanses all evidence structures before storage.
- [x] **Linear database migrations**: `010` $\to$ `011_role_resource_mapping`.

---

### 5. Transition to Milestone 3 (Mapping Engine)

Milestone 2 is formally complete and validated. Ready to begin **Milestone 3: Mapping Engine**, which will implement:
1. `mapping_engine.py` with multi-source ingestion (`ApplicationRole`, `ResourceRelationship`, `BehavioralObservation`).
2. Transparent confidence scoring calculator with sample size weighting.
3. Candidate access overlap analysis (`OBSERVED_ACCESS_OVERLAP`).
4. URL structural containment parser (`STRUCTURAL_CONTAINMENT`).
5. Declared vs. observed discrepancy detector.

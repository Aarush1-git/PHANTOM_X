# PHANTOM-X — Feature 6: Role & Resource Relationship Mapping
## Milestone 1: Architecture Inspection & Implementation Plan (Approved with Corrections)

**Feature:** Role & Resource Relationship Mapping
**Owner:** Member 1 (Features 4, 5, 6)
**Date:** November 12, 2026
**Status:** APPROVED WITH ARCHITECTURE CORRECTIONS — READY FOR MILESTONE 2
**Current Alembic Head:** `010_workflow_discovery`
**Target Migration:** `011_role_resource_mapping`

---

## 1. Existing Models and Their Fields

Inspection of the existing backend repository identifies the following relevant data models:

### A. `ApplicationRole` (`backend/app/models/application.py`)
- `id`: GUID (Primary Key)
- `created_at`: DateTime(timezone=True)
- `updated_at`: DateTime(timezone=True)
- `application_id`: GUID (Foreign Key `applications.id` ON DELETE CASCADE, Indexed)
- `name`: String(100) (e.g. `"admin"`, `"security_engineer"`, `"customer"`)
- `description`: Optional[String(500)]
- `permissions`: JSON (default `dict`, represents declared permissions or scopes)
- **Relationships**: `application -> Application`

### B. `ResourceRelationship` (`backend/app/models/application.py`)
- `id`: GUID (Primary Key)
- `created_at`: DateTime(timezone=True)
- `updated_at`: DateTime(timezone=True)
- `application_id`: GUID (Foreign Key `applications.id` ON DELETE CASCADE, Indexed)
- `source_resource`: String(100) (e.g. `"Organization"`, `"Account"`)
- `target_resource`: String(100) (e.g. `"User"`, `"Order"`)
- `relationship_type`: String(50) (e.g. `"OWNS"`, `"CONTAINS"`, `"REFERENCES"`)
- `is_bidirectional`: Boolean (default `False`)
- **Relationships**: `application -> Application`

### C. `DiscoveredEndpoint` (`backend/app/models/endpoint.py`)
- `id`: GUID (Primary Key)
- `application_id`: GUID (Foreign Key `applications.id` ON DELETE CASCADE, Indexed)
- `path`: String(500) (Indexed)
- `method`: HttpMethod Enum (`GET`, `POST`, `PUT`, `DELETE`, etc.)
- `auth_required`: Boolean (default `True`)
- `parameters`: JSON (list of path, query, header parameters)
- `response_codes`: JSON (list of observed/declared HTTP status codes)
- `risk_level`: EndpointRiskLevel Enum
- `raw_metadata`: JSON
- **Relationships**: `application -> Application`, `security_tests -> List[SecurityTest]`

### D. Feature 4: `BehavioralObservation` (`backend/app/features/application_intelligence/behavioral_digital_twin/models.py`)
- `id`: GUID (Primary Key)
- `organization_id`: GUID (Foreign Key `organizations.id` ON DELETE CASCADE, Indexed)
- `application_id`: GUID (Foreign Key `applications.id` ON DELETE CASCADE, Indexed)
- `endpoint_id`: Optional[GUID] (Foreign Key `discovered_endpoints.id` ON DELETE SET NULL, Indexed)
- `method`: String(20)
- `normalized_path`: String(500) (Indexed)
- `status_code`: Integer
- `sanitized_request_schema`: JSON
- `sanitized_response_schema`: JSON
- `latency_ms`: Float
- `session_token_hash`: Optional[String(64)] (Indexed)
- `observed_at`: DateTime(timezone=True)

### E. Feature 5: `DiscoveredWorkflow` (`backend/app/features/application_intelligence/workflow_discovery/models.py`)
- `id`: GUID (Primary Key)
- `organization_id`: GUID (Foreign Key `organizations.id` ON DELETE CASCADE)
- `application_id`: GUID (Foreign Key `applications.id` ON DELETE CASCADE)
- `name`: String(200)
- `workflow_type`: String(50) (`STANDARD`, `BRANCHED`, `ABANDONED`, `CYCLIC`)
- `status`: String(50) (`DISCOVERED`, `ACTIVE`, `ARCHIVED`)
- `confidence_score`: Float
- `sample_count`: Integer
- `steps_sequence`: JSON (ordered step telemetry)
- `graph_data`: JSON (nodes and directed edges)

---

## 2. Existing Services and Utilities That Can Be Reused

1. **Authentication & Multi-Tenant Authorization**:
   - `app.api.deps.get_current_user`: Resolves authenticated `User` from Bearer JWT.
   - `current_user.organization_id`: Authoritative tenant identifier; client-supplied tenant IDs are rejected.
   - `app.api.deps.require_role`: Role-based access control for administrative and security actions.
2. **Path Normalization & Entity Parameterization**:
   - `app.features.application_intelligence.behavioral_digital_twin.normalizer.parameterize_path`: Extracts resource templates and parameter positions (e.g. `/organizations/{org_id}/users/{user_id}` $\to$ identifies `Organization` and `User` resource candidates).
3. **Session & Identity Sanitization**:
   - `app.features.application_intelligence.behavioral_digital_twin.sanitization.hash_session_identifier`: Generates irreversible SHA-256 hashes for session identifiers and identity correlation without persisting raw credentials or tokens.
   - `app.features.application_intelligence.behavioral_digital_twin.sanitization.sanitize_payload_recursively`: Redacts passwords, tokens, API keys, and sensitive PII from request/response schemas.
4. **Endpoint Profiling & Markov Sequences**:
   - Observation aggregation from Feature 4 and journey reconstruction from Feature 5 ground role and resource interactions in empirical traffic.
5. **Frontend Graph Architecture**:
   - `@xyflow/react` is already installed and proven in Features 4 and 5 for rendering node-edge diagrams with custom styling, zoom controls, and mini-maps.

---

## 3. Gaps in the Current Architecture

While `ApplicationRole` and `ResourceRelationship` exist as basic tables in migration 001, critical architectural gaps prevent them from providing dynamic role and resource mapping:

1. **Lack of Role-to-Endpoint Binding**:
   - `ApplicationRole` only contains a generic `permissions: JSON` dictionary.
   - There is no mechanism to track which `DiscoveredEndpoint`s a role is observed accessing, nor the frequency, request outcome breakdown (HTTP 2xx vs 4xx), or declared vs. observed status.
2. **Lack of Role-to-Resource Access Tracking**:
   - No structure maps roles to specific application resource types (e.g., Role `Manager` observed accessing `Invoice` and `Report`, but never `PaymentCredential`).
3. **Lack of Evidence Provenance (Declared vs. Observed vs. Inferred)**:
   - `ResourceRelationship` is a static table without any notion of evidence source. It cannot differentiate between declared relationships (e.g., documentation/OpenAPI), observed interactions (e.g., observed nested path traversals), or inferred structural hierarchies.
4. **Separation of Provenance, Confidence, and Authorization**:
   - Existing tables lack explicit separation between request outcomes (e.g. HTTP 200), authentication status, authorization proof, evidence provenance, and confidence levels.
5. **No Identity Correlation Layer**:
   - No mechanism safely associates observed sanitized session identities (`session_token_hash`) with discovered application roles.
6. **No API or Service Layer**:
   - Neither `ApplicationRole` nor `ResourceRelationship` currently has dedicated services, routes, or frontend integration.

---

## 4. Proposed Mapping Data Model

To eliminate these gaps without duplicating `Application`, `DiscoveredEndpoint`, `ApplicationRole`, or `ResourceRelationship`, we propose adding a unified **`RoleResourceMapping`** model under:
`backend/app/features/application_intelligence/role_resource_mapping/models.py`.

### Minimum Schema Model: `RoleResourceMapping`
```python
class RoleResourceMapping(ModelBase):
    """
    Persistent mapping of access, structural relationship, and identity bindings
    between roles, endpoints, resources, and sanitized identities.
    Scoped strictly to organization_id and application_id with deterministic deduplication.
    """
    __tablename__ = "role_resource_mappings"
    __table_args__ = (
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="chk_mapping_confidence"),
        CheckConstraint("sample_count >= 0", name="chk_mapping_sample_count"),
        UniqueConstraint(
            "application_id",
            "subject_type",
            "subject_name",
            "relationship_type",
            "object_type",
            "object_name",
            name="uq_role_resource_mapping",
        ),
        Index("ix_rrm_app_type", "application_id", "relationship_type"),
        Index("ix_rrm_app_source", "application_id", "evidence_source"),
        Index("ix_rrm_app_confidence", "application_id", "confidence_score"),
        Index("ix_rrm_org_app", "organization_id", "application_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False
    )

    # Subject of relationship (ROLE, RESOURCE, or IDENTITY)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True) # UUID string if linked to entity
    subject_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Object of relationship (ENDPOINT, RESOURCE, or ROLE)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    object_name: Mapped[str] = mapped_column(String(200), nullable=False) # e.g. "GET:/api/v1/orders" or "Order"

    # Semantics of relationship (Enums validated by service and schema)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: ROLE_ACCESSES_ENDPOINT, ROLE_ACCESSES_RESOURCE, STRUCTURAL_CONTAINMENT,
    #        RESOURCE_REFERENCES_RESOURCE, ROLE_DECLARED_INHERITANCE,
    #        OBSERVED_ACCESS_OVERLAP, IDENTITY_ASSIGNED_ROLE

    # Evidence provenance (Origin of relationship claim)
    evidence_source: Mapped[str] = mapped_column(String(50), default="OBSERVED", nullable=False)
    # Sources: DECLARED, OBSERVED, INFERRED

    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Detailed access telemetry separating request outcomes from authorization claims
    # e.g.: {
    #   "request_outcomes": {"2xx": 12, "4xx": 1, "5xx": 0},
    #   "authentication_status": "AUTHENTICATED",  # AUTHENTICATED, UNAUTHENTICATED, UNKNOWN
    #   "authorization_status": "UNSPECIFIED",      # EXPLICIT_ALLOW, EXPLICIT_DENY, UNSPECIFIED
    #   "first_observed_at": "...",
    #   "last_observed_at": "..."
    # }
    access_telemetry: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Comparison of declared permissions vs observed reality
    # e.g.: {"declared_in_spec": true, "observed_in_traffic": true, "discrepancy_category": "NONE"}
    declared_vs_observed: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Supporting sanitized observation IDs (strictly sanitized, zero credentials)
    evidence_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    status: Mapped[str] = mapped_column(String(50), default="ACTIVE", nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
```

---

## 5. Relationship Types and Strict Provenance Boundaries

### A. Relationship Types & Architectural Corrections
| Relationship Type | Subject Type | Object Type | Semantic Meaning & Boundary Guard |
| :--- | :--- | :--- | :--- |
| `ROLE_ACCESSES_ENDPOINT` | `ROLE` | `ENDPOINT` | Role observed or declared sending requests to an endpoint. Request outcome (2xx vs 4xx) is tracked separately from authorization proof. |
| `ROLE_ACCESSES_RESOURCE` | `ROLE` | `RESOURCE` | Role observed interacting with an entity type (e.g., `Customer` accesses `Order`). |
| `STRUCTURAL_CONTAINMENT` | `RESOURCE` | `RESOURCE` | Path or schema structure suggests nested organization (e.g. `/accounts/{id}/orders/{id}`). **Correction: Does NOT establish ownership.** |
| `RESOURCE_REFERENCES_RESOURCE` | `RESOURCE` | `RESOURCE` | Entity references another entity via foreign reference. |
| `ROLE_DECLARED_INHERITANCE` | `ROLE` | `ROLE` | **Correction: Confirmed inheritance only when explicit configuration or metadata declares it.** |
| `OBSERVED_ACCESS_OVERLAP` | `ROLE` | `ROLE` | **Correction: Candidate relationship when Role A accesses a superset of Role B. Labeled as an access-set difference, NOT confirmed inheritance.** |
| `IDENTITY_ASSIGNED_ROLE` | `IDENTITY` | `ROLE` | Sanitized identity (`session_token_hash`) observed acting with a role. |

### B. Separation of Evidence Provenance from Confidence
- **`DECLARED`**: Explicitly configured in application specifications, `ApplicationRole.permissions`, or `ResourceRelationship`.
- **`OBSERVED`**: Captured in actual application interaction traffic (`BehavioralObservation`).
- **`INFERRED`**: Derived from structural patterns (such as parameterized path segments or schema references).

*Crucial rule*: `DECLARED`, `OBSERVED`, and `INFERRED` describe **where** the relationship came from. They are not confidence values. Confidence is derived transparently based on evidence weight and completeness.

---

## 6. Transparent Confidence Calculation Approach

Confidence must never be fabricated, nor can an arbitrary constant (e.g. 0.90) be assigned simply because an entry is declared.

### 1. Declared Relationships (`evidence_source = DECLARED`)
Confidence reflects the completeness and structural validity of the declaration metadata:
$$\text{confidence}_{\text{DECLARED}} = \begin{cases}
0.95 & \text{if declaration defines explicit method + path + matching active endpoint} \\
0.80 & \text{if declaration specifies valid scopes/permissions but general target} \\
0.50 & \text{if declaration is incomplete or partially defined}
\end{cases}$$
*Note*: A high declared confidence reflects confidence that the *declaration exists in configuration*, NOT proof that the application's authorization logic correctly enforces it.

### 2. Observed Relationships (`evidence_source = OBSERVED`)
Confidence reflects observation volume and interaction consistency:
$$\text{sample\_weight} = \min\left(1.0, \frac{\log(1 + \text{sample\_count})}{\log(1 + 10)}\right)$$
$$\text{consistency\_factor} = 1.0 - \left(\frac{\text{count}(\text{HTTP } 5xx)}{\text{sample\_count}} \times 0.5\right)$$
$$\text{confidence}_{\text{OBSERVED}} = \text{round}(\text{sample\_weight} \times \text{consistency\_factor}, 4)$$

**Separation of Request Outcome from Authorization**:
- If requests return HTTP 2xx: `request_outcome: SUCCESS`. This is recorded as *successful interaction*, NOT absolute proof of proper authorization.
- If requests return HTTP 401/403: `request_outcome: AUTH_REJECTED`. This is recorded as a failed request, NOT proof that the role has no permission in any other context.
- If $\text{sample\_count} < 2$: returns explicit `insufficient_evidence: True`.

### 3. Inferred Relationships (`evidence_source = INFERRED`)
Structural path containment (e.g. `/accounts/{acc_id}/orders/{order_id}`):
$$\text{confidence}_{\text{INFERRED}} = 0.60 \times \min\left(1.0, \frac{\text{distinct\_endpoints\_supporting}}{3}\right)$$
- Always capped at $\le 0.70$ because nested URL paths suggest structural hierarchy, but do not prove entity ownership or business containment.

---

## 7. Scope Boundaries — Strictly No Active RBAC/IDOR Testing

- **Strict Boundary**: This feature is strictly **Role & Resource Relationship Mapping** (observational and architectural telemetry).
- **Prohibited**:
  - Do NOT execute active attack payloads or unauthorized requests.
  - Do NOT attempt BOLA/IDOR cross-account access probes.
  - Do NOT claim security vulnerabilities (e.g. "Broken Object Level Authorization" or "Privilege Escalation").
  - All active vulnerability testing, attack simulation, and regression validation belong to **Member 3**.
- Discrepancies between declared permissions and observed traffic are classified strictly as **Behavioral Differences / Discrepancies** for security engineer review.

---

## 8. Proposed Backend Services and APIs

### A. Service Layer
- `RoleResourceService`:
  - `discover_and_persist_mappings()`: Runs the mapping engine, ingests declared roles/relationships, inspects observations, calculates confidence, and stores deduplicated mappings.
  - `list_mappings()`: Filter by role, resource, relationship type, evidence source, min confidence, and pagination.
  - `get_tripartite_graph()`: Compiles nodes (Roles, Resources, Endpoints, Identities) and edges for React Flow.
  - `get_mapping_evidence()`: Retrieves sanitized supporting observation schemas (passwords/tokens redacted).
  - `get_discrepancies()`: Lists access discrepancies (declared permissions unexercised vs undeclared observed access).
  - `get_overview()`: High-level mapping coverage statistics.

### B. REST API Endpoints (`/api/v1/role-resource-mapping/*`)
- `GET /applications/{app_id}/overview`: Application mapping overview.
- `POST /applications/{app_id}/discover`: Trigger mapping discovery.
- `GET /applications/{app_id}/graph`: Tripartite graph visualization data.
- `GET /applications/{app_id}/relationships`: Filterable relationships table.
- `GET /applications/{app_id}/discrepancies`: Declared vs observed discrepancy analysis.
- `GET /relationships/{mapping_id}/evidence`: Sanitized evidence references.

---

## 9. Proposed Frontend Components and Graph Structure

- Sub-tab 3 in `ApplicationDetailsPage.tsx`: **Role & Resource Mapping**.
- `@xyflow/react` directed graph with color-coded nodes:
  - Role: Violet/Purple
  - Endpoint: Cyan
  - Resource: Amber/Orange
  - Identity: Emerald
- Edges indicate provenance: Solid (`DECLARED`), Dashed (`OBSERVED`), Dotted (`INFERRED`).
- Discrepancy Inspector and Evidence Modal.

---

## 10. Proposed Alembic Migration 011

- **File**: `backend/migrations/versions/011_role_resource_mapping.py`
- **Revision ID**: `011_role_resource_mapping`
- **Down Revision**: `010_workflow_discovery`
- Creates `role_resource_mappings` table with check constraints, foreign keys, unique constraint, and indexes.

---

## 11. Milestone Execution Roadmap

- **Milestone 1**: Architecture Inspection & Plan (Updated with corrections). **[COMPLETED & APPROVED]**
- **Milestone 2**: Data Models (`RoleResourceMapping`), Schemas, Sanitization utilities, Alembic Migration 011, and verification tests. **[CURRENT]**
- **Milestone 3**: Mapping Engine (declared ingestion, observed access, candidate overlap, structural containment, discrepancy detector, confidence calculator).
- **Milestone 4**: Service Layer, REST APIs (`/api/v1/role-resource-mapping/*`), and backend integration test suite.
- **Milestone 5**: Frontend UI components (`RoleResourceMappingPanel`, React Flow tripartite graph, discrepancy explorer, evidence modal), `ApplicationDetailsPage.tsx` tab integration, and Vitest suite.
- **Milestone 6**: End-to-end verification and final implementation report (`FEATURE_06_IMPLEMENTATION_REPORT.md`).

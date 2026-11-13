"""
PHANTOM-X - Feature 6: Role & Resource Relationship Mapping
Milestone 2 Test Suite: Models, Schemas, Constraints, Sanitization & Tenant Isolation

Covers:
1. Model instantiation & persistence for RoleResourceMapping
2. Database check constraints (confidence score 0.0 to 1.0, sample_count >= 0)
3. Unique constraint enforcement (deterministic deduplication)
4. Foreign key cascades upon application/organization deletion
5. Multi-tenant boundary isolation
6. Pydantic v2 schema validations & boundary checks
7. Evidence sanitization & identity token hashing
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from httpx import AsyncClient, ASGITransport
import jwt

from app.main import app
from app.core.config import settings
from app.models.user import Organization, User
from app.models.application import Application, ApplicationRole, ResourceRelationship
from app.models.endpoint import DiscoveredEndpoint
from shared.enums.common import HttpMethod, EndpointRiskLevel, UserRole
from tests.conftest import TestingSessionLocal

from app.features.application_intelligence.role_resource_mapping.models import (
    RoleResourceMapping,
    SubjectType,
    ObjectType,
    RelationshipType,
    EvidenceSource,
    MappingStatus,
)
from app.features.application_intelligence.role_resource_mapping.schemas import (
    RoleResourceMappingResponse,
    AccessTelemetrySchema,
    DeclaredVsObservedSchema,
    MappingDiscoveryRequest,
)
from app.features.application_intelligence.role_resource_mapping.sanitization import (
    hash_identity_identifier,
    sanitize_mapping_evidence,
    validate_evidence_reference,
)


@pytest.fixture
async def role_resource_test_setup():
    """Seeds test organizations, applications, and endpoints."""
    async with TestingSessionLocal() as db:
        # Organization 1
        org_1 = Organization(name="Mapping Org 1", slug="mapping-org-1")
        # Organization 2 (for tenant isolation)
        org_2 = Organization(name="Mapping Org 2", slug="mapping-org-2")
        db.add_all([org_1, org_2])
        await db.flush()

        # Application 1 (under Org 1)
        app_1 = Application(
            organization_id=org_1.id,
            name="Core Banking App",
            target_url="https://api.banking.local",
            risk_score=20.0,
            status="ACTIVE",
        )
        # Application 2 (under Org 2)
        app_2 = Application(
            organization_id=org_2.id,
            name="HR Portal",
            target_url="https://api.hr.local",
            risk_score=10.0,
            status="ACTIVE",
        )
        db.add_all([app_1, app_2])
        await db.flush()

        # Existing ApplicationRole and ResourceRelationship from migration 001
        role_admin = ApplicationRole(
            application_id=app_1.id,
            name="admin",
            description="System administrator",
            permissions={"accounts:read": True, "accounts:write": True},
        )
        role_auditor = ApplicationRole(
            application_id=app_1.id,
            name="auditor",
            description="External auditor",
            permissions={"accounts:read": True},
        )
        res_rel = ResourceRelationship(
            application_id=app_1.id,
            source_resource="Organization",
            target_resource="Account",
            relationship_type="CONTAINS",
            is_bidirectional=False,
        )
        db.add_all([role_admin, role_auditor, res_rel])

        # DiscoveredEndpoint
        ep_accounts = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/accounts",
            method=HttpMethod.GET,
            auth_required=True,
            parameters=[],
            response_codes=[200],
            risk_level=EndpointRiskLevel.LOW,
            raw_metadata={},
        )
        db.add(ep_accounts)

        # Users
        user_1 = User(
            organization_id=org_1.id,
            email="secops@mapping-org-1.local",
            hashed_password="pw_test_hash",
            full_name="Alice Security",
            role=UserRole.ADMIN,
            is_active=True,
        )
        user_2 = User(
            organization_id=org_2.id,
            email="secops@mapping-org-2.local",
            hashed_password="pw_test_hash",
            full_name="Bob Rival",
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([user_1, user_2])
        await db.flush()

        # Seed initial observations for App 1
        from app.features.application_intelligence.behavioral_digital_twin.models import BehavioralObservation
        obs_1 = BehavioralObservation(
            organization_id=org_1.id,
            application_id=app_1.id,
            endpoint_id=ep_accounts.id,
            method="GET",
            normalized_path="/api/v1/accounts",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={"role": "admin", "data": "accounts_data"},
            latency_ms=35.0,
            session_token_hash="sess_hash_admin_org1",
        )
        obs_2 = BehavioralObservation(
            organization_id=org_1.id,
            application_id=app_1.id,
            endpoint_id=None,
            method="GET",
            normalized_path="/accounts/{id}/orders/{id}",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={"role": "admin", "order": "details"},
            latency_ms=45.0,
            session_token_hash="sess_hash_admin_org1",
        )
        db.add_all([obs_1, obs_2])
        await db.commit()

        def make_token(user_id: uuid.UUID) -> str:
            return jwt.encode(
                {"sub": str(user_id), "exp": datetime.now(timezone.utc) + timedelta(hours=2)},
                settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM,
            )

        return {
            "org_1": org_1,
            "org_2": org_2,
            "app_1": app_1,
            "app_2": app_2,
            "role_admin": role_admin,
            "role_auditor": role_auditor,
            "res_rel": res_rel,
            "ep_accounts": ep_accounts,
            "obs_1": obs_1,
            "obs_2": obs_2,
            "user_1": user_1,
            "user_2": user_2,
            "token_1": make_token(user_1.id),
            "token_2": make_token(user_2.id),
        }


# ==============================================================================
# 1. MODEL INSTANTIATION & PERSISTENCE
# ==============================================================================

@pytest.mark.asyncio
async def test_role_resource_mapping_creation(role_resource_test_setup):
    """Verifies valid RoleResourceMapping persistence and relationship loading."""
    setup = role_resource_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        mapping = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.ENDPOINT.value,
            object_name="GET:/api/v1/accounts",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            evidence_source=EvidenceSource.OBSERVED.value,
            confidence_score=0.85,
            sample_count=12,
            access_telemetry={
                "request_outcomes": {"2xx": 12, "4xx": 0, "5xx": 0},
                "authentication_status": "AUTHENTICATED",
                "authorization_status": "UNSPECIFIED",
            },
            declared_vs_observed={
                "declared_in_spec": True,
                "observed_in_traffic": True,
                "discrepancy_category": "NONE",
            },
            evidence_references=[str(uuid.uuid4())],
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping)

        assert mapping.id is not None
        assert mapping.confidence_score == 0.85
        assert mapping.sample_count == 12
        assert mapping.access_telemetry["request_outcomes"]["2xx"] == 12
        assert mapping.status == MappingStatus.ACTIVE.value


# ==============================================================================
# 2. DATABASE CONSTRAINTS & DEDUPLICATION
# ==============================================================================

@pytest.mark.asyncio
async def test_confidence_score_check_constraint(role_resource_test_setup):
    """CheckConstraint rejects confidence_score outside [0.0, 1.0]."""
    setup = role_resource_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        # Invalid confidence > 1.0
        m_high = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.ENDPOINT.value,
            object_name="POST:/api/v1/test_high",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            confidence_score=1.5,
            sample_count=5,
        )
        db.add(m_high)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()

        # Invalid confidence < 0.0
        m_low = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.ENDPOINT.value,
            object_name="POST:/api/v1/test_low",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            confidence_score=-0.2,
            sample_count=5,
        )
        db.add(m_low)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.asyncio
async def test_sample_count_check_constraint(role_resource_test_setup):
    """CheckConstraint rejects negative sample_count."""
    setup = role_resource_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        m_neg = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.ENDPOINT.value,
            object_name="GET:/api/v1/test_neg",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            confidence_score=0.5,
            sample_count=-1,
        )
        db.add(m_neg)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.asyncio
async def test_unique_constraint_deduplication(role_resource_test_setup):
    """UniqueConstraint prevents duplicate mapping tuples for an application."""
    setup = role_resource_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        m1 = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="auditor",
            object_type=ObjectType.RESOURCE.value,
            object_name="Report",
            relationship_type=RelationshipType.ROLE_ACCESSES_RESOURCE.value,
            confidence_score=0.8,
            sample_count=4,
        )
        db.add(m1)
        await db.commit()

        # Duplicate tuple
        m2 = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="auditor",
            object_type=ObjectType.RESOURCE.value,
            object_name="Report",
            relationship_type=RelationshipType.ROLE_ACCESSES_RESOURCE.value,
            confidence_score=0.9,
            sample_count=8,
        )
        db.add(m2)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


# ==============================================================================
# 3. TENANT ISOLATION & FOREIGN KEY CASCADES
# ==============================================================================

@pytest.mark.asyncio
async def test_tenant_isolation_boundary(role_resource_test_setup):
    """Mappings belonging to Org 1 are isolated from Org 2."""
    setup = role_resource_test_setup
    app_1 = setup["app_1"]
    app_2 = setup["app_2"]
    org_1 = setup["org_1"]
    org_2 = setup["org_2"]

    async with TestingSessionLocal() as db:
        m1 = RoleResourceMapping(
            organization_id=org_1.id,
            application_id=app_1.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.RESOURCE.value,
            object_name="Account",
            relationship_type=RelationshipType.ROLE_ACCESSES_RESOURCE.value,
            confidence_score=0.7,
            sample_count=5,
        )
        m2 = RoleResourceMapping(
            organization_id=org_2.id,
            application_id=app_2.id,
            subject_type=SubjectType.ROLE.value,
            subject_name="admin",
            object_type=ObjectType.RESOURCE.value,
            object_name="EmployeeRecord",
            relationship_type=RelationshipType.ROLE_ACCESSES_RESOURCE.value,
            confidence_score=0.9,
            sample_count=10,
        )
        db.add_all([m1, m2])
        await db.commit()

        # Query Org 1
        res_org1 = await db.execute(
            select(RoleResourceMapping).where(RoleResourceMapping.organization_id == org_1.id)
        )
        items_org1 = res_org1.scalars().all()
        assert len(items_org1) == 1
        assert items_org1[0].object_name == "Account"

        # Query Org 2
        res_org2 = await db.execute(
            select(RoleResourceMapping).where(RoleResourceMapping.organization_id == org_2.id)
        )
        items_org2 = res_org2.scalars().all()
        assert len(items_org2) == 1
        assert items_org2[0].object_name == "EmployeeRecord"


# ==============================================================================
# 4. SANITIZATION & PRIVACY UTILITIES
# ==============================================================================

def test_hash_identity_identifier_consistency():
    """Validates deterministic SHA-256 identity hashing."""
    raw_token = "bearer-secret-token-12345"
    h1 = hash_identity_identifier(raw_token)
    h2 = hash_identity_identifier(raw_token)
    assert h1 == h2
    assert len(h1) == 64
    assert raw_token not in h1


def test_sanitize_mapping_evidence_recursive():
    """Recursively redacts sensitive token and credential fields from evidence."""
    sensitive_payload = {
        "user": {
            "name": "Alice",
            "password": "SuperSecretPassword123!",
            "auth_token": "jwt.header.payload.signature",
            "session_id": "sess_raw_cookie_abc",
        },
        "api_key": "sk-phantom-live-key",
        "orders": [{"id": 1, "amount": 100.5}],
    }

    sanitized = sanitize_mapping_evidence(sensitive_payload)
    assert sanitized["user"]["name"] == "Alice"
    assert sanitized["user"]["password"] == "[REDACTED]"
    assert sanitized["user"]["auth_token"] == "[REDACTED]"
    assert sanitized["user"]["session_id"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["orders"][0]["amount"] == 100.5


def test_validate_evidence_reference():
    """Validates UUID strings and rejects raw credentials/tokens."""
    valid_uuid = str(uuid.uuid4())
    assert validate_evidence_reference(valid_uuid) is True

    # Leaked credentials or raw strings rejected
    assert validate_evidence_reference("Bearer eyJhbGciOi...") is False
    assert validate_evidence_reference("raw_session_id") is False
    assert validate_evidence_reference("12345") is False


# ==============================================================================
# 5. PYDANTIC V2 SCHEMA VALIDATIONS
# ==============================================================================

def test_pydantic_mapping_discovery_request_bounds():
    """Pydantic rejects invalid confidence and sample count bounds."""
    # Valid
    req = MappingDiscoveryRequest(min_confidence=0.7, min_sample_count=2)
    assert req.min_confidence == 0.7

    # Invalid confidence > 1.0
    with pytest.raises(ValidationError):
        MappingDiscoveryRequest(min_confidence=1.5)

    # Invalid confidence < 0.0
    with pytest.raises(ValidationError):
        MappingDiscoveryRequest(min_confidence=-0.1)

    # Invalid sample count < 1
    with pytest.raises(ValidationError):
        MappingDiscoveryRequest(min_sample_count=0)


def test_access_telemetry_schema_defaults():
    """Validates AccessTelemetrySchema separating outcomes from auth status."""
    telemetry = AccessTelemetrySchema()
    assert telemetry.request_outcomes == {"2xx": 0, "4xx": 0, "5xx": 0}
    assert telemetry.authentication_status == "UNKNOWN"
    assert telemetry.authorization_status == "UNSPECIFIED"



# ==============================================================================
# 6. MILESTONE 3: ENGINE & SERVICE TESTS (14 STEP-6 REQUIREMENTS)
# ==============================================================================

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
)
from app.features.application_intelligence.role_resource_mapping.mapping_engine import (
    RoleResourceMappingEngine,
    calculate_observed_confidence,
    calculate_inferred_overlap_confidence,
)
from app.features.application_intelligence.role_resource_mapping.service import (
    RoleResourceMappingService,
)


@pytest.mark.asyncio
async def test_declared_role_mapping(role_resource_test_setup):
    """1. Ingestion of declared role permissions into DECLARED mappings."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        role = ApplicationRole(
            application_id=setup["app_1"].id,
            name="editor",
            description="Content Editor",
            permissions={
                "endpoints": ["POST /api/v1/articles", "GET /api/v1/articles"],
                "resources": ["articles"],
                "inherits": ["viewer"],
            },
        )
        db.add(role)
        await db.commit()
        await db.refresh(role)

        mappings = RoleResourceMappingEngine.ingest_declared_roles(
            roles=[role],
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
        )

        assert len(mappings) == 4  # 2 endpoints + 1 resource + 1 inheritance
        ep_mappings = [m for m in mappings if m["relationship_type"] == RelationshipType.ROLE_ACCESSES_ENDPOINT.value]
        res_mappings = [m for m in mappings if m["relationship_type"] == RelationshipType.ROLE_ACCESSES_RESOURCE.value]
        inh_mappings = [m for m in mappings if m["relationship_type"] == RelationshipType.ROLE_DECLARED_INHERITANCE.value]

        assert len(ep_mappings) == 2
        assert len(res_mappings) == 1
        assert len(inh_mappings) == 1

        assert ep_mappings[0]["evidence_source"] == EvidenceSource.DECLARED.value
        assert ep_mappings[0]["confidence_score"] == 1.0
        assert inh_mappings[0]["object_name"] == "viewer"
        assert inh_mappings[0]["subject_name"] == "editor"


@pytest.mark.asyncio
async def test_declared_resource_relationship_mapping(role_resource_test_setup):
    """2. Ingestion of declared resource relationships into DECLARED mappings."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        res_rel = ResourceRelationship(
            application_id=setup["app_1"].id,
            source_resource="Invoice",
            target_resource="LineItem",
            relationship_type="CONTAINS",
            is_bidirectional=True,
        )
        db.add(res_rel)
        await db.commit()
        await db.refresh(res_rel)

        mappings = RoleResourceMappingEngine.ingest_declared_relationships(
            relationships=[res_rel],
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
        )

        # Bidirectional CONTAINS generates forward and reverse mappings
        assert len(mappings) == 2
        for m in mappings:
            assert m["evidence_source"] == EvidenceSource.DECLARED.value
            assert m["relationship_type"] == RelationshipType.STRUCTURAL_CONTAINMENT.value
            assert m["confidence_score"] == 1.0


@pytest.mark.asyncio
async def test_observed_identity_role_association(role_resource_test_setup):
    """3. Observed identity-to-role binding from session activity."""
    setup = role_resource_test_setup
    obs_id = uuid.uuid4()
    session_hash = "f" * 64

    obs = BehavioralObservation(
        id=obs_id,
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
        method="POST",
        normalized_path="/api/v1/orders",
        status_code=200,
        sanitized_request_schema={},
        sanitized_response_schema={"status": "created", "user": {"role": "merchant"}},
        latency_ms=45.0,
        session_token_hash=session_hash,
    )

    discovered = RoleResourceMappingEngine.discover_observed_mappings(
        observations=[obs],
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
    )

    id_role_mappings = [
        m for m in discovered if m["relationship_type"] == RelationshipType.IDENTITY_ASSIGNED_ROLE.value
    ]
    assert len(id_role_mappings) == 1
    assert id_role_mappings[0]["subject_type"] == SubjectType.IDENTITY.value
    assert id_role_mappings[0]["subject_id"] == session_hash
    assert id_role_mappings[0]["object_name"] == "merchant"
    assert id_role_mappings[0]["evidence_source"] == EvidenceSource.OBSERVED.value


@pytest.mark.asyncio
async def test_observed_role_endpoint_association(role_resource_test_setup):
    """4. Observed role-endpoint association with segregated telemetry."""
    setup = role_resource_test_setup
    observations = [
        BehavioralObservation(
            id=uuid.uuid4(),
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            method="GET",
            normalized_path="/api/v1/reports",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={"role": "analyst"},
            latency_ms=30.0,
            session_token_hash="a" * 64,
        ),
        BehavioralObservation(
            id=uuid.uuid4(),
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            method="GET",
            normalized_path="/api/v1/reports",
            status_code=403,
            sanitized_request_schema={"_jwt_claims": {"role": "analyst"}},
            sanitized_response_schema={},
            latency_ms=15.0,
            session_token_hash="a" * 64,
        ),
    ]

    discovered = RoleResourceMappingEngine.discover_observed_mappings(
        observations=observations,
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
    )

    role_ep = [
        m for m in discovered if m["relationship_type"] == RelationshipType.ROLE_ACCESSES_ENDPOINT.value
    ]
    assert len(role_ep) == 1
    mapping = role_ep[0]
    assert mapping["subject_name"] == "analyst"
    assert mapping["object_name"] == "GET /api/v1/reports"
    assert mapping["sample_count"] == 2
    # Verify segregated telemetry
    assert mapping["access_telemetry"]["request_outcomes"]["2xx"] == 1
    assert mapping["access_telemetry"]["request_outcomes"]["4xx"] == 1
    assert mapping["access_telemetry"]["authorization_status"] == "EXPLICIT_DENY"


def test_structural_containment_inference():
    """5. Structural containment inference from nested URL paths."""
    org_id = uuid.uuid4()
    app_id = uuid.uuid4()
    paths = [
        "/accounts/{account_id}/orders/{order_id}",
        "/accounts/{account_id}/invoices/{invoice_id}",
        "/users/{user_id}/profile",
    ]

    inferred = RoleResourceMappingEngine.infer_structural_containment(
        normalized_paths=paths,
        organization_id=org_id,
        application_id=app_id,
    )

    assert len(inferred) == 3
    for m in inferred:
        assert m["evidence_source"] == EvidenceSource.INFERRED.value
        assert m["relationship_type"] == RelationshipType.STRUCTURAL_CONTAINMENT.value
        assert m["confidence_score"] <= 0.60  # Capped heuristic confidence
        assert m["declared_vs_observed"]["ownership_claimed"] is False


def test_access_overlap_candidates():
    """6. Access overlap candidate discovery across role endpoint sets."""
    org_id = uuid.uuid4()
    app_id = uuid.uuid4()

    role_endpoints = {
        "admin": {"GET /api/v1/users", "POST /api/v1/users", "GET /api/v1/reports"},
        "auditor": {"GET /api/v1/users", "GET /api/v1/reports"},
        "guest": {"GET /api/v1/public"},
    }

    overlaps = RoleResourceMappingEngine.analyze_role_access_overlaps(
        observed_role_endpoints=role_endpoints,
        organization_id=org_id,
        application_id=app_id,
    )

    # admin & auditor overlap; guest has no overlap
    assert len(overlaps) == 1
    ov = overlaps[0]
    assert ov["relationship_type"] == RelationshipType.OBSERVED_ACCESS_OVERLAP.value
    assert ov["evidence_source"] == EvidenceSource.INFERRED.value
    assert ov["access_telemetry"]["overlap_endpoint_count"] == 2
    assert ov["confidence_score"] <= 0.65  # Strictly capped


def test_no_false_role_inheritance():
    """7. Guarantees access set overlap is NEVER classified as role inheritance."""
    org_id = uuid.uuid4()
    app_id = uuid.uuid4()

    # Even if admin accesses a strict superset of auditor
    role_endpoints = {
        "admin": {"GET /a", "GET /b", "GET /c"},
        "auditor": {"GET /a", "GET /b"},
    }

    overlaps = RoleResourceMappingEngine.analyze_role_access_overlaps(
        observed_role_endpoints=role_endpoints,
        organization_id=org_id,
        application_id=app_id,
    )

    for m in overlaps:
        assert m["relationship_type"] != RelationshipType.ROLE_DECLARED_INHERITANCE.value
        assert m["relationship_type"] == RelationshipType.OBSERVED_ACCESS_OVERLAP.value
        assert m["declared_vs_observed"]["is_inheritance"] is False


def test_no_false_ownership_inference():
    """8. Guarantees nested paths are NEVER classified as resource ownership."""
    org_id = uuid.uuid4()
    app_id = uuid.uuid4()
    paths = ["/tenants/{tenant_id}/databases/{db_id}"]

    inferred = RoleResourceMappingEngine.infer_structural_containment(
        normalized_paths=paths,
        organization_id=org_id,
        application_id=app_id,
    )

    for m in inferred:
        assert m["relationship_type"] == RelationshipType.STRUCTURAL_CONTAINMENT.value
        assert m["declared_vs_observed"]["ownership_claimed"] is False
        assert "ownership" not in m["relationship_type"].lower()


@pytest.mark.asyncio
async def test_http_success_not_treated_as_authorization_proof(role_resource_test_setup):
    """9. HTTP 2xx response must NEVER be classified as EXPLICIT_ALLOW authorization."""
    setup = role_resource_test_setup
    observations = [
        BehavioralObservation(
            id=uuid.uuid4(),
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            method="GET",
            normalized_path="/api/v1/public-data",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={"role": "anonymous", "data": "sample"},
            latency_ms=25.0,
            session_token_hash=None,
        )
    ]

    discovered = RoleResourceMappingEngine.discover_observed_mappings(
        observations=observations,
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
    )

    for m in discovered:
        # Crucial check: 2xx recorded in request outcomes, but authorization is UNSPECIFIED
        assert m["access_telemetry"]["request_outcomes"]["2xx"] == 1
        assert m["access_telemetry"]["authorization_status"] == "UNSPECIFIED"
        assert m["access_telemetry"]["authorization_status"] != "EXPLICIT_ALLOW"


def test_confidence_bounds_and_insufficient_evidence():
    """10. Mathematical confidence bounds and explicit insufficient evidence handling."""
    # Confidence formula tests
    c0 = calculate_observed_confidence(0)
    assert c0 == 0.0

    c1 = calculate_observed_confidence(1)
    assert 0.50 <= c1 <= 0.60

    c10 = calculate_observed_confidence(10)
    assert 0.70 <= c10 <= 0.85

    c1000 = calculate_observed_confidence(1000)
    # Strictly bounded by upper cap 0.95
    assert c1000 == 0.95

    # Overlap confidence capped at 0.65
    ov_c = calculate_inferred_overlap_confidence(1.0)
    assert ov_c == 0.65


@pytest.mark.asyncio
async def test_duplicate_evidence_handling(role_resource_test_setup):
    """11. Duplicate observation IDs are not counted repeatedly."""
    setup = role_resource_test_setup
    obs_id = uuid.uuid4()
    # Same observation passed twice
    obs_1 = BehavioralObservation(
        id=obs_id,
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
        method="GET",
        normalized_path="/api/v1/config",
        status_code=200,
        sanitized_request_schema={},
        sanitized_response_schema={"role": "admin"},
        latency_ms=10.0,
        session_token_hash="abc",
    )
    obs_2 = BehavioralObservation(
        id=obs_id,
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
        method="GET",
        normalized_path="/api/v1/config",
        status_code=200,
        sanitized_request_schema={},
        sanitized_response_schema={"role": "admin"},
        latency_ms=10.0,
        session_token_hash="abc",
    )

    discovered = RoleResourceMappingEngine.discover_observed_mappings(
        observations=[obs_1, obs_2],
        organization_id=setup["org_1"].id,
        application_id=setup["app_1"].id,
    )

    ep_mapping = next(m for m in discovered if m["relationship_type"] == RelationshipType.ROLE_ACCESSES_ENDPOINT.value)
    # Deduplication ensures sample_count is 1, not 2
    assert ep_mapping["sample_count"] == 1
    assert len(ep_mapping["evidence_references"]) == 1


def test_declared_vs_observed_discrepancy_categories():
    """12. Neutral discrepancy categorizations (ALIGNED, DECLARED_NOT_OBSERVED, OBSERVED_NOT_DECLARED, EVIDENCE_INSUFFICIENT)."""
    org_id = uuid.uuid4()
    app_id = uuid.uuid4()

    declared = [
        {
            "organization_id": org_id,
            "application_id": app_id,
            "subject_type": SubjectType.ROLE.value,
            "subject_id": None,
            "subject_name": "billing_user",
            "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            "object_type": ObjectType.ENDPOINT.value,
            "object_id": None,
            "object_name": "POST /api/v1/payments",
            "evidence_source": EvidenceSource.DECLARED.value,
            "confidence_score": 1.0,
            "sample_count": 1,
            "access_telemetry": {},
            "declared_vs_observed": {},
            "evidence_references": [],
            "status": MappingStatus.ACTIVE.value,
        },
        {
            "organization_id": org_id,
            "application_id": app_id,
            "subject_type": SubjectType.ROLE.value,
            "subject_id": None,
            "subject_name": "billing_user",
            "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            "object_type": ObjectType.ENDPOINT.value,
            "object_id": None,
            "object_name": "GET /api/v1/invoices",
            "evidence_source": EvidenceSource.DECLARED.value,
            "confidence_score": 1.0,
            "sample_count": 1,
            "access_telemetry": {},
            "declared_vs_observed": {},
            "evidence_references": [],
            "status": MappingStatus.ACTIVE.value,
        },
    ]

    observed = [
        # Matches POST /api/v1/payments with 3 samples -> ALIGNED
        {
            "organization_id": org_id,
            "application_id": app_id,
            "subject_type": SubjectType.ROLE.value,
            "subject_id": None,
            "subject_name": "billing_user",
            "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            "object_type": ObjectType.ENDPOINT.value,
            "object_id": None,
            "object_name": "POST /api/v1/payments",
            "evidence_source": EvidenceSource.OBSERVED.value,
            "confidence_score": 0.85,
            "sample_count": 3,
            "access_telemetry": {},
            "declared_vs_observed": {},
            "evidence_references": [str(uuid.uuid4())],
            "status": MappingStatus.ACTIVE.value,
        },
        # Not declared -> OBSERVED_NOT_DECLARED
        {
            "organization_id": org_id,
            "application_id": app_id,
            "subject_type": SubjectType.ROLE.value,
            "subject_id": None,
            "subject_name": "billing_user",
            "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            "object_type": ObjectType.ENDPOINT.value,
            "object_id": None,
            "object_name": "DELETE /api/v1/records",
            "evidence_source": EvidenceSource.OBSERVED.value,
            "confidence_score": 0.70,
            "sample_count": 2,
            "access_telemetry": {},
            "declared_vs_observed": {},
            "evidence_references": [str(uuid.uuid4())],
            "status": MappingStatus.ACTIVE.value,
        },
    ]

    unified, summary = RoleResourceMappingEngine.synthesize_and_align_mappings(
        declared_mappings=declared,
        observed_mappings=observed,
        inferred_mappings=[],
    )

    breakdown = summary["discrepancy_breakdown"]
    assert breakdown["ALIGNED"] == 1
    assert breakdown["DECLARED_NOT_OBSERVED"] == 1  # GET /api/v1/invoices
    assert breakdown["OBSERVED_NOT_DECLARED"] == 1  # DELETE /api/v1/records


@pytest.mark.asyncio
async def test_tenant_isolation_in_service(role_resource_test_setup):
    """13. Multi-tenant isolation prevents accessing or mutating mappings from another organization."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        req = MappingDiscoveryRequest()
        # Attempting to run discovery on app_1 with org_2 credentials must raise 404
        with pytest.raises(Exception) as exc_info:
            await RoleResourceMappingService.discover_and_persist(
                db=db,
                application_id=setup["app_1"].id,
                organization_id=setup["org_2"].id,  # Wrong org!
                request=req,
            )
        assert "404" in str(exc_info.value) or "denied" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_sensitive_evidence_sanitization_in_service(role_resource_test_setup):
    """14. End-to-end evidence retrieval scrubs passwords, bearer tokens, and session identifiers."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        obs_id = uuid.uuid4()
        obs = BehavioralObservation(
            id=obs_id,
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            method="POST",
            normalized_path="/api/v1/checkout",
            status_code=201,
            sanitized_request_schema={
                "card_token": "tok_secret_123",
                "auth_header": "Bearer secret_jwt",
                "amount": 500,
            },
            sanitized_response_schema={
                "confirmation": "conf_xyz",
                "cookie": "sess_leak",
            },
            latency_ms=100.0,
            session_token_hash="s" * 64,
        )
        db.add(obs)

        # Create mapping pointing to this observation
        mapping = RoleResourceMapping(
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            subject_type=SubjectType.ROLE.value,
            subject_name="shopper",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            object_type=ObjectType.ENDPOINT.value,
            object_name="POST /api/v1/checkout",
            evidence_source=EvidenceSource.OBSERVED.value,
            confidence_score=0.8,
            sample_count=1,
            evidence_references=[str(obs_id)],
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping)

        # Retrieve evidence via service
        evidence_resp = await RoleResourceMappingService.get_evidence(
            db=db,
            application_id=setup["app_1"].id,
            organization_id=setup["org_1"].id,
            mapping_id=mapping.id,
        )

        assert evidence_resp.total_evidence == 1
        item = evidence_resp.items[0]
        # Sensitive keys must be redacted
        assert item.sanitized_request_schema["card_token"] == "[REDACTED]"
        assert item.sanitized_request_schema["auth_header"] == "[REDACTED]"
        assert item.sanitized_request_schema["amount"] == 500
        assert item.sanitized_response_schema["cookie"] == "[REDACTED]"
        assert item.sanitized_response_schema["confirmation"] == "conf_xyz"


# ==============================================================================
# 7. MILESTONE 4: REST API & SECURITY TESTS (16 STEP-6 REQUIREMENTS)
# ==============================================================================

@pytest.mark.asyncio
async def test_api_overview(role_resource_test_setup):
    """1. Overview API returns summary metrics, counts, and insufficient evidence flag."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/overview",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_roles" in data
        assert "total_resources" in data
        assert "total_mappings" in data
        assert "declared_count" in data
        assert "observed_count" in data
        assert "inferred_count" in data
        assert "discrepancies_count" in data


@pytest.mark.asyncio
async def test_api_mapping_list_and_pagination(role_resource_test_setup):
    """2. Mapping listing with page and page_size bounds."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First trigger discovery so mappings exist
        await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )

        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/mappings?page=1&page_size=5",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert len(data["items"]) <= 5
        assert data["page"] == 1
        assert data["page_size"] == 5


@pytest.mark.asyncio
async def test_api_mapping_filters(role_resource_test_setup):
    """3. Mapping filters by subject_type, object_type, relationship_type, provenance."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )

        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/mappings?relationship_type=STRUCTURAL_CONTAINMENT&evidence_source=DECLARED",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["relationship_type"] == "STRUCTURAL_CONTAINMENT"
            assert item["evidence_source"] == "DECLARED"


@pytest.mark.asyncio
async def test_api_individual_mapping_details(role_resource_test_setup):
    """4. Retrieve individual mapping details by UUID."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Trigger discovery
        disc = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        mappings = disc.json()["mappings"]
        assert len(mappings) > 0
        target_id = mappings[0]["id"]

        resp = await ac.get(
            f"/api/v1/role-resource-mapping/mappings/{target_id}",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["id"] == target_id
        assert "access_telemetry" in detail
        assert "declared_vs_observed" in detail


@pytest.mark.asyncio
async def test_api_declared_discovery_endpoint(role_resource_test_setup):
    """5. POST /discover/declared triggers declared ingestion only."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover/declared",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["declared_mappings_count"] > 0
        assert data["observed_mappings_count"] == 0


@pytest.mark.asyncio
async def test_api_observed_discovery_endpoint(role_resource_test_setup):
    """6. POST /discover/observed triggers behavioral traffic analysis only."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover/observed",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["observed_mappings_count"] > 0
        assert data["declared_mappings_count"] == 0


@pytest.mark.asyncio
async def test_api_structural_inference_endpoint(role_resource_test_setup):
    """7. POST /discover/structural infers URL containment candidates only."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover/structural",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["inferred_mappings_count"] > 0


@pytest.mark.asyncio
async def test_api_access_overlap_endpoint(role_resource_test_setup):
    """8. POST /discover/overlap analyzes role access set overlaps."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover/overlap",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "discovered_mappings_count" in data


@pytest.mark.asyncio
async def test_api_discrepancy_endpoint(role_resource_test_setup):
    """9. Discrepancy API returns neutral categories and limitation notes."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )

        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discrepancies",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "breakdown" in data
        assert "evidence_limitations_note" in data
        # Check neutral wording in notes
        assert "NOT constitute verified security vulnerabilities" in data["evidence_limitations_note"]


@pytest.mark.asyncio
async def test_api_evidence_sanitization(role_resource_test_setup):
    """10. Evidence retrieval endpoint returns sanitized schemas with redacted secrets."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        obs_id = uuid.uuid4()
        obs = BehavioralObservation(
            id=obs_id,
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            method="POST",
            normalized_path="/api/v1/secure-op",
            status_code=200,
            sanitized_request_schema={"password": "raw_pass", "bearer_token": "raw_jwt"},
            sanitized_response_schema={"session_id": "sess_leak", "status": "ok"},
            latency_ms=20.0,
        )
        db.add(obs)
        mapping = RoleResourceMapping(
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            subject_type=SubjectType.ROLE.value,
            subject_name="tester",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            object_type=ObjectType.ENDPOINT.value,
            object_name="POST /api/v1/secure-op",
            evidence_source=EvidenceSource.OBSERVED.value,
            confidence_score=0.7,
            sample_count=1,
            evidence_references=[str(obs_id)],
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping)
        map_id = mapping.id

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/mappings/{map_id}/evidence",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["sanitized_request_schema"]["password"] == "[REDACTED]"
        assert items[0]["sanitized_request_schema"]["bearer_token"] == "[REDACTED]"
        assert items[0]["sanitized_response_schema"]["session_id"] == "[REDACTED]"
        assert items[0]["sanitized_response_schema"]["status"] == "ok"


@pytest.mark.asyncio
async def test_api_invalid_filter_and_pagination(role_resource_test_setup):
    """11. Rejects invalid pagination (page=0) and invalid confidence bounds (> 1.0)."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Invalid page=0
        resp_p0 = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/mappings?page=0",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp_p0.status_code == 422

        # Invalid min_confidence > 1.0
        resp_c2 = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/mappings?min_confidence=1.5",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp_c2.status_code == 422


@pytest.mark.asyncio
async def test_api_unauthorized_access(role_resource_test_setup):
    """12. Unauthenticated requests return 401 Unauthorized."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/overview"
            # No Authorization header
        )
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_cross_tenant_application_access(role_resource_test_setup):
    """13. Cross-tenant application access is strictly forbidden (returns 404)."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User 2 (org 2) attempting to query App 1 (org 1)
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/overview",
            headers={"Authorization": f"Bearer {setup['token_2']}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_cross_tenant_mapping_access(role_resource_test_setup):
    """14. Cross-tenant mapping access returns 404 without leaking resource existence."""
    setup = role_resource_test_setup
    async with TestingSessionLocal() as db:
        mapping = RoleResourceMapping(
            organization_id=setup["org_1"].id,
            application_id=setup["app_1"].id,
            subject_type=SubjectType.ROLE.value,
            subject_name="org1_role",
            relationship_type=RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
            object_type=ObjectType.ENDPOINT.value,
            object_name="GET /org1/private",
            evidence_source=EvidenceSource.DECLARED.value,
            confidence_score=1.0,
            sample_count=1,
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping)
        m_id = mapping.id

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User 2 (org 2) calling mapping under org 1
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/mappings/{m_id}",
            headers={"Authorization": f"Bearer {setup['token_2']}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_duplicate_discovery_idempotence(role_resource_test_setup):
    """15. Repeated discovery triggers are idempotent and do not duplicate mappings."""
    setup = role_resource_test_setup
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Trigger 1
        res1 = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert res1.status_code == 200
        count1 = res1.json()["discovered_mappings_count"]

        # Trigger 2
        res2 = await ac.post(
            f"/api/v1/role-resource-mapping/applications/{setup['app_1'].id}/discover",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert res2.status_code == 200
        count2 = res2.json()["discovered_mappings_count"]

        # Counts must match identically (no duplicate rows created)
        assert count1 == count2


@pytest.mark.asyncio
async def test_api_request_size_and_bounds(role_resource_test_setup):
    """16. Request size bounds check: rejects evidence limit > 100."""
    setup = role_resource_test_setup
    valid_uuid = uuid.uuid4()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/role-resource-mapping/mappings/{valid_uuid}/evidence?limit=500",
            headers={"Authorization": f"Bearer {setup['token_1']}"},
        )
        assert resp.status_code == 422

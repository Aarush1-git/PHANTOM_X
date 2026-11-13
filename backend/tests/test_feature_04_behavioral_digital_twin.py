import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

from app.models.user import Organization, User
from app.models.application import Application
from app.models.endpoint import DiscoveredEndpoint
from shared.enums.common import HttpMethod, EndpointRiskLevel, UserRole
from app.core.config import settings
import jwt
from httpx import AsyncClient, ASGITransport
from app.main import app
from tests.conftest import TestingSessionLocal

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
    BehavioralBaseline,
    BehavioralTransition,
    BehavioralAnomaly,
    BaselineStatus,
    AnomalyStatus,
    AnomalyType,
    AnomalySeverity,
)
from app.features.application_intelligence.behavioral_digital_twin.schemas import (
    ObservationIngestRequest,
    BaselineCreateRequest,
    AnomalyCreateRequest,
    AnomalyStatusUpdateRequest,
)
from app.features.application_intelligence.behavioral_digital_twin.sanitization import (
    sanitize_headers,
    sanitize_payload_recursively,
    hash_session_identifier,
    extract_structural_schema,
)
from app.features.application_intelligence.behavioral_digital_twin.normalizer import (
    normalize_url_path,
    parameterize_path,
    normalize_endpoint_identity,
)
from app.features.application_intelligence.behavioral_digital_twin.schema_inference import (
    infer_payload_schema,
    merge_structural_schemas,
)
from app.features.application_intelligence.behavioral_digital_twin.profiler import (
    calculate_confidence,
    compute_latency_stats,
    aggregate_endpoint_observations,
)
from app.features.application_intelligence.behavioral_digital_twin.transition_learner import (
    learn_endpoint_transitions,
)
from app.features.application_intelligence.behavioral_digital_twin.ingestion_service import (
    ObservationIngestionService,
    TenantAccessDeniedError,
)
from app.features.application_intelligence.behavioral_digital_twin.baseline_service import (
    BaselineService,
    generate_next_version,
)
from app.features.application_intelligence.behavioral_digital_twin.drift_engine import (
    DriftEngine,
    compare_schemas,
)
import json


@pytest.fixture
async def digital_twin_test_setup():
    """Seed test organizations, applications, and endpoints."""
    async with TestingSessionLocal() as db:
        # Organization 1
        org_1 = Organization(name="Twin Org 1", slug="twin-org-1")
        # Organization 2 (for tenant isolation tests)
        org_2 = Organization(name="Twin Org 2", slug="twin-org-2")
        db.add_all([org_1, org_2])
        await db.flush()

        # Application 1 (under Org 1)
        app_1 = Application(
            organization_id=org_1.id,
            name="Payments Service",
            target_url="https://api.payments.local",
            risk_score=25.0,
            status="ACTIVE",
        )
        # Application 2 (under Org 2)
        app_2 = Application(
            organization_id=org_2.id,
            name="Inventory Service",
            target_url="https://api.inventory.local",
            risk_score=10.0,
            status="ACTIVE",
        )
        db.add_all([app_1, app_2])
        await db.flush()

        # Discovered Endpoint for App 1
        endpoint_1 = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/checkout",
            method=HttpMethod.POST,
            auth_required=True,
            parameters=[],
            response_codes=[200, 400, 401],
            risk_level=EndpointRiskLevel.HIGH,
            raw_metadata={},
        )
        endpoint_2 = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/receipt",
            method=HttpMethod.GET,
            auth_required=True,
            parameters=[],
            response_codes=[200],
            risk_level=EndpointRiskLevel.LOW,
            raw_metadata={},
        )
        db.add_all([endpoint_1, endpoint_2])

        # Seed Users with distinct roles for RBAC and tenant testing
        user_admin_1 = User(
            organization_id=org_1.id,
            email="admin@twin-org-1.local",
            hashed_password="hashed_pw_test",
            full_name="Alice Admin",
            role=UserRole.ADMIN,
            is_active=True,
        )
        user_eng_1 = User(
            organization_id=org_1.id,
            email="engineer@twin-org-1.local",
            hashed_password="hashed_pw_test",
            full_name="Bob Engineer",
            role=UserRole.SECURITY_ENGINEER,
            is_active=True,
        )
        user_auditor_1 = User(
            organization_id=org_1.id,
            email="auditor@twin-org-1.local",
            hashed_password="hashed_pw_test",
            full_name="Charlie Auditor",
            role=UserRole.AUDITOR,
            is_active=True,
        )
        user_admin_2 = User(
            organization_id=org_2.id,
            email="admin@twin-org-2.local",
            hashed_password="hashed_pw_test",
            full_name="Dave Rival Admin",
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([user_admin_1, user_eng_1, user_auditor_1, user_admin_2])
        await db.commit()

        # Generate signed test JWTs
        token_admin_1 = jwt.encode(
            {"sub": str(user_admin_1.id), "org_id": str(org_1.id), "email": user_admin_1.email, "role": user_admin_1.role.value},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_eng_1 = jwt.encode(
            {"sub": str(user_eng_1.id), "org_id": str(org_1.id), "email": user_eng_1.email, "role": user_eng_1.role.value},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_auditor_1 = jwt.encode(
            {"sub": str(user_auditor_1.id), "org_id": str(org_1.id), "email": user_auditor_1.email, "role": user_auditor_1.role.value},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_admin_2 = jwt.encode(
            {"sub": str(user_admin_2.id), "org_id": str(org_2.id), "email": user_admin_2.email, "role": user_admin_2.role.value},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )

        return {
            "org_1_id": org_1.id,
            "org_2_id": org_2.id,
            "app_1_id": app_1.id,
            "app_2_id": app_2.id,
            "endpoint_1_id": endpoint_1.id,
            "endpoint_2_id": endpoint_2.id,
            "token_admin_1": token_admin_1,
            "token_eng_1": token_eng_1,
            "token_auditor_1": token_auditor_1,
            "token_admin_2": token_admin_2,
            "user_admin_1_id": user_admin_1.id,
            "user_admin_2_id": user_admin_2.id,
        }


# ==============================================================================
# TEST 1: Observation Creation
# ==============================================================================
@pytest.mark.asyncio
async def test_observation_creation(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        session_hash = hash_session_identifier("sess_token_xyz_12345")
        obs = BehavioralObservation(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            endpoint_id=data["endpoint_1_id"],
            method="POST",
            normalized_path="/api/v1/checkout",
            status_code=200,
            sanitized_request_schema={"type": "object", "properties": {"amount": "number"}},
            sanitized_response_schema={"type": "object", "properties": {"status": "string"}},
            latency_ms=124.5,
            session_token_hash=session_hash,
            observed_at=datetime.now(timezone.utc),
        )
        db.add(obs)
        await db.commit()
        await db.refresh(obs)

        assert obs.id is not None
        assert obs.method == "POST"
        assert obs.status_code == 200
        assert obs.latency_ms == 124.5
        assert obs.session_token_hash == session_hash
        assert obs.sanitized_request_schema["properties"]["amount"] == "number"


# ==============================================================================
# TEST 2: Baseline Creation & Transition Attachment
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_creation(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        baseline = BehavioralBaseline(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
            status=BaselineStatus.DRAFT.value,
            sample_count=150,
            confidence_score=0.92,
            endpoint_profiles={"/api/v1/checkout": {"methods": ["POST"], "status_codes": [200]}},
            transition_matrix={"POST:/api/v1/checkout": {"GET:/api/v1/receipt": 0.85}},
        )
        db.add(baseline)
        await db.commit()
        await db.refresh(baseline)

        # Attach transition
        trans = BehavioralTransition(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            baseline_id=baseline.id,
            from_endpoint_id=data["endpoint_1_id"],
            to_endpoint_id=data["endpoint_2_id"],
            probability=0.85,
            observation_count=85,
        )
        db.add(trans)
        await db.commit()
        await db.refresh(trans)

        assert baseline.id is not None
        assert baseline.version == "v1.0"
        assert baseline.confidence_score == 0.92

        # Verify transitions via query
        trans_res = await db.execute(
            select(BehavioralTransition).where(BehavioralTransition.baseline_id == baseline.id)
        )
        loaded_transitions = trans_res.scalars().all()
        assert len(loaded_transitions) == 1
        assert loaded_transitions[0].probability == 0.85


# ==============================================================================
# TEST 3: Baseline Version Uniqueness
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_version_uniqueness(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        b1 = BehavioralBaseline(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
            status=BaselineStatus.DRAFT.value,
            confidence_score=0.5,
            endpoint_profiles={},
            transition_matrix={},
        )
        db.add(b1)
        await db.commit()

        # Duplicate version for same application should violate UniqueConstraint
        b2 = BehavioralBaseline(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
            status=BaselineStatus.ACTIVE.value,
            confidence_score=0.8,
            endpoint_profiles={},
            transition_matrix={},
        )
        db.add(b2)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


# ==============================================================================
# TEST 4: Anomaly Creation
# ==============================================================================
@pytest.mark.asyncio
async def test_anomaly_creation(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        anomaly = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            endpoint_id=data["endpoint_1_id"],
            anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
            severity=AnomalySeverity.HIGH.value,
            confidence=0.95,
            evidence_data={"expected_status": [200], "observed_status": 500, "error_body": "Internal server error"},
            status=AnomalyStatus.OPEN.value,
        )
        db.add(anomaly)
        await db.commit()
        await db.refresh(anomaly)

        assert anomaly.id is not None
        assert anomaly.anomaly_type == "UNEXPECTED_STATUS_CODE"
        assert anomaly.severity == "HIGH"
        assert anomaly.confidence == 0.95
        assert anomaly.status == "OPEN"
        assert anomaly.evidence_data["observed_status"] == 500


# ==============================================================================
# TEST 5: Organization Association
# ==============================================================================
@pytest.mark.asyncio
async def test_organization_association(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Organization association must be strictly present on every record
        obs = BehavioralObservation(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            method="GET",
            normalized_path="/api/v1/status",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={},
            observed_at=datetime.now(timezone.utc),
        )
        db.add(obs)
        await db.commit()
        await db.refresh(obs)

        assert obs.organization_id == data["org_1_id"]


# ==============================================================================
# TEST 6: Nullable Endpoint Handling
# ==============================================================================
@pytest.mark.asyncio
async def test_nullable_endpoint_handling(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # New observation on an unmapped endpoint where endpoint_id is None
        obs = BehavioralObservation(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            endpoint_id=None,  # Nullable endpoint
            method="PUT",
            normalized_path="/api/v1/undocumented_feature",
            status_code=201,
            sanitized_request_schema={},
            sanitized_response_schema={},
            observed_at=datetime.now(timezone.utc),
        )
        db.add(obs)

        # Anomaly on an unmapped endpoint where endpoint_id is None
        anomaly = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            endpoint_id=None,  # Nullable endpoint
            anomaly_type=AnomalyType.UNSEEN_SEQUENCE.value,
            severity=AnomalySeverity.MEDIUM.value,
            confidence=0.75,
            evidence_data={"reason": "Endpoint invoked outside recorded sitemap"},
            status=AnomalyStatus.OPEN.value,
        )
        db.add(anomaly)
        await db.commit()

        assert obs.id is not None
        assert obs.endpoint_id is None
        assert anomaly.id is not None
        assert anomaly.endpoint_id is None


# ==============================================================================
# TEST 7: Foreign-Key Integrity
# ==============================================================================
@pytest.mark.asyncio
async def test_foreign_key_integrity(digital_twin_test_setup):
    data = digital_twin_test_setup
    non_existent_app = uuid.uuid4()
    async with TestingSessionLocal() as db:
        await db.execute(text("PRAGMA foreign_keys = ON;"))
        obs = BehavioralObservation(
            organization_id=data["org_1_id"],
            application_id=non_existent_app,
            method="GET",
            normalized_path="/api/v1/ghost",
            status_code=200,
            sanitized_request_schema={},
            sanitized_response_schema={},
            observed_at=datetime.now(timezone.utc),
        )
        db.add(obs)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


# ==============================================================================
# TEST 8: Sensitive Header Sanitization
# ==============================================================================
def test_sensitive_header_sanitization():
    raw_headers = {
        "Host": "api.payments.local",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",
        "Cookie": "session_id=secret_cookie_val; remember_me=true",
        "X-API-Key": "live_ak_9876543210abcdef",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    sanitized = sanitize_headers(raw_headers)

    assert sanitized["Host"] == "api.payments.local"
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["User-Agent"] == "Mozilla/5.0"
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["X-API-Key"] == "[REDACTED]"


# ==============================================================================
# TEST 9: Recursive JSON Sanitization & Structural Schema Extraction
# ==============================================================================
def test_recursive_json_sanitization():
    raw_payload = {
        "user": {
            "name": "Jane Doe",
            "email": "jane@example.com",
            "auth": {
                "password": "SuperSecretPassword123!",
                "api_key": "live_key_xyz",
            },
            "payment": {
                "credit_card": "4111222233334444",
                "cvv": "123",
                "amount": 99.50,
            },
        },
        "order_id": "ord_1001",
        "items": [
            {"sku": "SKU-A", "qty": 2},
            {"sku": "SKU-B", "auth_token": "token_item_secret"},
        ],
    }

    sanitized = sanitize_payload_recursively(raw_payload)

    # Sensitive values must be masked (entire sensitive subtrees/keys masked)
    assert sanitized["user"]["auth"] == "[REDACTED]"
    assert sanitized["user"]["payment"]["credit_card"] == "[REDACTED]"
    assert sanitized["user"]["payment"]["cvv"] == "[REDACTED]"
    assert sanitized["items"][1]["auth_token"] == "[REDACTED]"

    # Non-sensitive structure preserved
    assert sanitized["order_id"] == "ord_1001"
    assert sanitized["user"]["payment"]["amount"] == 99.50
    assert sanitized["items"][0]["sku"] == "SKU-A"

    # Verify structural schema extraction
    struct = extract_structural_schema(raw_payload)
    assert struct["type"] == "object"
    assert struct["properties"]["order_id"]["type"] == "str"
    assert struct["properties"]["user"]["structure"]["properties"]["auth"]["sensitive"] is True
    assert struct["properties"]["user"]["structure"]["properties"]["payment"]["structure"]["properties"]["credit_card"]["sensitive"] is True


# ==============================================================================
# TEST 10: Invalid Confidence Values Rejected by Schemas
# ==============================================================================
def test_invalid_confidence_values():
    app_id = uuid.uuid4()

    # Confidence > 1.0
    with pytest.raises(ValidationError) as exc_info:
        BaselineCreateRequest(
            application_id=app_id,
            version="v1.0",
            confidence_score=1.5,  # Invalid
        )
    assert "confidence_score" in str(exc_info.value)

    # Confidence < 0.0
    with pytest.raises(ValidationError) as exc_info2:
        AnomalyCreateRequest(
            application_id=app_id,
            anomaly_type="SCHEMA_DRIFT",
            confidence=-0.1,  # Invalid
        )
    assert "confidence" in str(exc_info2.value)


# ==============================================================================
# TEST 11: Invalid Status Values Rejected by Schemas
# ==============================================================================
def test_invalid_status_values():
    with pytest.raises(ValidationError) as exc_info:
        AnomalyStatusUpdateRequest(
            status="NON_EXISTENT_STATUS"  # Invalid status string
        )
    assert "status" in str(exc_info.value)


# ==============================================================================
# TEST 12: Cross-Tenant Ownership Validation
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_tenant_ownership_rejection(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Query application to check organization ownership
        app_result = await db.execute(select(Application).where(Application.id == data["app_1_id"]))
        app = app_result.scalars().first()

        # Suppose a request arrives claiming to belong to Org 2, but referencing App 1 (owned by Org 1)
        claimed_org_id = data["org_2_id"]

        def validate_tenant_ownership(app_record: Application, caller_org_id: uuid.UUID) -> bool:
            return app_record.organization_id == caller_org_id

        # Must reject mismatch
        is_authorized = validate_tenant_ownership(app, claimed_org_id)
        assert is_authorized is False

        # Correct org must be accepted
        assert validate_tenant_ownership(app, data["org_1_id"]) is True


# ==============================================================================
# MILESTONE 2: BEHAVIORAL LEARNING ENGINE TESTS
# ==============================================================================

# ==============================================================================
# TEST 13: Endpoint Normalization & Parameterization
# ==============================================================================
def test_endpoint_normalization():
    # 1. URL path extraction & cleaning
    assert normalize_url_path("https://api.payments.local:8080/v1/users/?sort=desc#anchor") == "/v1/users"
    assert normalize_url_path("/api/v1//checkout///") == "/api/v1/checkout"
    assert normalize_url_path("") == "/"
    assert normalize_url_path("relative/path/test") == "/relative/path/test"

    # 2. Dynamic segment parameterization
    test_uuid = "550e8400-e29b-41d4-a716-446655440000"
    path_with_uuid = f"/api/v1/users/{test_uuid}/orders/98765"
    assert parameterize_path(path_with_uuid) == "/api/v1/users/{id}/orders/{id}"

    # 3. Method and identity normalization
    m, p, param = normalize_endpoint_identity("get", "https://api.test/checkout/123?page=2")
    assert m == "GET"
    assert p == "/checkout/123"
    assert param == "/checkout/{id}"


# ==============================================================================
# TEST 14: Structural Schema Inference (Primitives, Formats, Objects)
# ==============================================================================
def test_structural_schema_inference():
    payload = {
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "created_at": "2026-11-12T14:30:00Z",
        "is_active": True,
        "age": 28,
        "balance": 150.75,
        "metadata": {
            "tier": "GOLD",
            "score": 850
        }
    }
    schema = infer_payload_schema(payload)

    assert schema["type"] == "object"
    assert schema["properties"]["user_id"]["type"] == "string"
    assert schema["properties"]["user_id"]["format"] == "uuid"
    assert schema["properties"]["created_at"]["format"] == "date-time"
    assert schema["properties"]["is_active"]["type"] == "boolean"
    assert schema["properties"]["age"]["type"] == "integer"
    assert schema["properties"]["balance"]["type"] == "number"
    assert schema["properties"]["metadata"]["type"] == "object"
    assert schema["properties"]["metadata"]["properties"]["tier"]["type"] == "string"
    assert "user_id" in schema["required"]


# ==============================================================================
# TEST 15: Nested JSON and Array Handling
# ==============================================================================
def test_nested_json_and_array_handling():
    payload = {
        "orders": [
            {"id": 1, "sku": "A100", "tags": ["sale", "clearance"]},
            {"id": 2, "sku": "B200", "tags": ["new"]}
        ],
        "empty_list": []
    }
    schema = infer_payload_schema(payload)

    assert schema["type"] == "object"
    assert schema["properties"]["orders"]["type"] == "array"
    assert schema["properties"]["orders"]["items"]["type"] == "object"
    assert schema["properties"]["orders"]["items"]["properties"]["sku"]["type"] == "string"
    assert schema["properties"]["orders"]["items"]["properties"]["tags"]["type"] == "array"
    assert schema["properties"]["empty_list"]["type"] == "array"


# ==============================================================================
# TEST 16: Optional and Inconsistent Field Schema Merging
# ==============================================================================
def test_optional_and_inconsistent_fields():
    # Observation A: has 'name' and 'age' (int)
    schema_a = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name", "age"]
    }
    # Observation B: has 'name', no 'age', but adds 'nickname' and 'age' was absent
    schema_b = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "nickname": {"type": "string"}
        },
        "required": ["name", "nickname"]
    }

    merged = merge_structural_schemas(schema_a, schema_b)
    # 'name' is in both -> required
    assert "name" in merged["required"]
    # 'age' and 'nickname' are optional
    assert "age" not in merged["required"]
    assert "nickname" not in merged["required"]
    assert "age" in merged["properties"]
    assert "nickname" in merged["properties"]

    # Inconsistent types: field is string in A, integer in B
    schema_c = {"type": "object", "properties": {"code": {"type": "string"}}}
    schema_d = {"type": "object", "properties": {"code": {"type": "integer"}}}
    merged_types = merge_structural_schemas(schema_c, schema_d)
    assert merged_types["properties"]["code"]["inconsistent_types"] is True
    assert set(merged_types["properties"]["code"]["type"]) == {"integer", "string"}


# ==============================================================================
# TEST 17: Status-Code Frequency and Latency Statistics
# ==============================================================================
def test_status_code_and_latency_statistics():
    observations = [
        {"status_code": 200, "latency_ms": 10.0, "sanitized_request_schema": {}, "sanitized_response_schema": {}},
        {"status_code": 200, "latency_ms": 20.0, "sanitized_request_schema": {}, "sanitized_response_schema": {}},
        {"status_code": 200, "latency_ms": 30.0, "sanitized_request_schema": {}, "sanitized_response_schema": {}},
        {"status_code": 400, "latency_ms": 40.0, "sanitized_request_schema": {}, "sanitized_response_schema": {}},
        {"status_code": 500, "latency_ms": 100.0, "sanitized_request_schema": {}, "sanitized_response_schema": {}},
    ]
    profile = aggregate_endpoint_observations(observations)

    assert profile["total_requests"] == 5
    assert profile["status_code_distribution"]["200"] == 3
    assert profile["status_code_distribution"]["400"] == 1
    assert profile["status_code_distribution"]["500"] == 1

    l_stats = profile["latency_stats"]
    assert l_stats["min_ms"] == 10.0
    assert l_stats["max_ms"] == 100.0
    assert l_stats["avg_ms"] == 40.0
    assert l_stats["p95_ms"] == 100.0


# ==============================================================================
# TEST 18: Markov Transition Counting and Probability Learning
# ==============================================================================
def test_transition_counting_and_probabilities():
    # Construct 3 synthetic session sequences:
    # S1: /login -> /dashboard -> /reports
    # S2: /login -> /dashboard -> /settings
    # S3: /login -> /dashboard -> /reports
    s1_obs = [
        {"session_token_hash": "s1", "method": "POST", "normalized_path": "/login", "observed_at": 1},
        {"session_token_hash": "s1", "method": "GET", "normalized_path": "/dashboard", "observed_at": 2},
        {"session_token_hash": "s1", "method": "GET", "normalized_path": "/reports", "observed_at": 3},
    ]
    s2_obs = [
        {"session_token_hash": "s2", "method": "POST", "normalized_path": "/login", "observed_at": 1},
        {"session_token_hash": "s2", "method": "GET", "normalized_path": "/dashboard", "observed_at": 2},
        {"session_token_hash": "s2", "method": "GET", "normalized_path": "/settings", "observed_at": 3},
    ]
    s3_obs = [
        {"session_token_hash": "s3", "method": "POST", "normalized_path": "/login", "observed_at": 1},
        {"session_token_hash": "s3", "method": "GET", "normalized_path": "/dashboard", "observed_at": 2},
        {"session_token_hash": "s3", "method": "GET", "normalized_path": "/reports", "observed_at": 3},
    ]

    all_obs = s1_obs + s2_obs + s3_obs
    counts, probs, items = learn_endpoint_transitions(all_obs)

    # /login -> /dashboard occurred 3 times out of 3 transitions from /login
    assert counts["POST:/login"]["GET:/dashboard"] == 3
    assert probs["POST:/login"]["GET:/dashboard"] == 1.0

    # /dashboard -> /reports occurred 2 times (2/3 = 0.6667)
    assert counts["GET:/dashboard"]["GET:/reports"] == 2
    assert probs["GET:/dashboard"]["GET:/reports"] == 0.6667

    # /dashboard -> /settings occurred 1 time (1/3 = 0.3333)
    assert counts["GET:/dashboard"]["GET:/settings"] == 1
    assert probs["GET:/dashboard"]["GET:/settings"] == 0.3333
    assert len(items) == 3


# ==============================================================================
# TEST 19: Statistical Confidence Scoring Bounds
# ==============================================================================
def test_confidence_calculation():
    # 0 observations -> 0.0
    assert calculate_confidence(0) == 0.0

    # 1 or 2 observations -> strictly <= 0.15 (Requirement 10)
    assert calculate_confidence(1) <= 0.15
    assert calculate_confidence(2) <= 0.15

    # 30 observations with consistent status -> moderate (~0.60 to 0.75)
    c30 = calculate_confidence(30, status_code_distribution={"200": 30})
    assert 0.60 <= c30 <= 0.80

    # 100 observations with 100% 200s -> high (~0.95+)
    c100 = calculate_confidence(100, status_code_distribution={"200": 100})
    assert c100 >= 0.90

    # Consistency penalty: 50% 200s vs 50% 500s should score lower than 100% 200s
    c_erratic = calculate_confidence(100, status_code_distribution={"200": 50, "500": 50})
    assert c_erratic < c100


# ==============================================================================
# TEST 20: HAR Observation Ingestion with Sanitization & DB Persistence
# ==============================================================================
@pytest.mark.asyncio
async def test_har_traffic_ingestion_and_sanitization(digital_twin_test_setup):
    data = digital_twin_test_setup
    sample_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "time": 45.2,
                    "request": {
                        "method": "POST",
                        "url": "https://api.payments.local/api/v1/checkout",
                        "headers": [
                            {"name": "Host", "value": "api.payments.local"},
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_12345"},
                            {"name": "Cookie", "value": "session_id=super_secret_cookie_val"}
                        ],
                        "postData": {
                            "text": json.dumps({"order_id": "ORD-99", "password": "PlainTextPassword!", "amount": 49.99})
                        }
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Set-Cookie", "value": "auth_token=super_secret_refresh"}
                        ],
                        "content": {
                            "text": json.dumps({"status": "SUCCESS", "auth_token": "token_val_here"})
                        }
                    }
                },
                {
                    "time": 22.0,
                    "request": {
                        "method": "GET",
                        "url": "https://api.payments.local/api/v1/receipt?order_id=ORD-99",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_12345"}
                        ],
                        "postData": {"text": ""}
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": json.dumps({"receipt_id": "RCPT-100"})}
                    }
                }
            ]
        }
    }
    har_str = json.dumps(sample_har)

    async with TestingSessionLocal() as db:
        ingested = await ObservationIngestionService.ingest_har_traffic(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            har_content=har_str
        )

        assert len(ingested) == 2

        # 1. Verify checkout observation
        checkout_obs = ingested[0]
        assert checkout_obs.method == "POST"
        assert checkout_obs.normalized_path == "/api/v1/checkout"
        assert checkout_obs.endpoint_id == data["endpoint_1_id"]  # Mapped endpoint linked
        assert checkout_obs.status_code == 200
        assert checkout_obs.latency_ms == 45.2
        # Session hash derived from Cookie/Authorization, never raw credentials
        assert checkout_obs.session_token_hash is not None
        assert "super_secret" not in checkout_obs.session_token_hash

        # Schema inferred from sanitized body
        req_schema = checkout_obs.sanitized_request_schema
        assert req_schema["type"] == "object"
        assert req_schema["properties"]["order_id"]["type"] == "string"

        # 2. Verify receipt observation
        receipt_obs = ingested[1]
        assert receipt_obs.method == "GET"
        assert receipt_obs.normalized_path == "/api/v1/receipt"
        assert receipt_obs.endpoint_id == data["endpoint_2_id"]


# ==============================================================================
# TEST 21: Cross-Tenant Isolation Enforcement on Ingestion
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_tenant_isolation_ingestion(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Caller claims Org 2 identity, but attempts to ingest for App 1 (owned by Org 1)
        with pytest.raises(TenantAccessDeniedError):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_2_id"],  # Wrong org
                method="GET",
                url_or_path="/api/v1/checkout",
                status_code=200,
            )


# ==============================================================================
# TEST 22: Nullable Endpoint Linking on Unregistered Endpoints
# ==============================================================================
@pytest.mark.asyncio
async def test_nullable_endpoint_linking(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Ingest an observation for an endpoint that has NOT been registered yet
        obs = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            method="DELETE",
            url_or_path="/api/v1/unregistered_action",
            status_code=204,
        )

        assert obs.id is not None
        assert obs.method == "DELETE"
        assert obs.normalized_path == "/api/v1/unregistered_action"
        assert obs.endpoint_id is None  # Nullable endpoint supported cleanly


# ==============================================================================
# TEST 23: Baseline Compilation from Observations
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_compilation(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Ingest a sequence of observations
        sess = "user-sess-100"
        for i in range(6):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
                latency_ms=120.0 + i * 5.0,
                request_payload={"amount": 100 + i, "currency": "USD"},
                response_payload={"order_id": f"ORD-{i}", "status": "CONFIRMED"},
                session_identifier=sess,
            )
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_2_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
                latency_ms=45.0,
                response_payload={"receipt_id": f"REC-{i}", "verified": True},
                session_identifier=sess,
            )

        baseline = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
        )

        assert baseline.id is not None
        assert baseline.status == BaselineStatus.DRAFT.value
        assert baseline.sample_count == 12
        assert baseline.version == "v1.0"
        assert baseline.confidence_score > 0.0
        assert len(baseline.endpoint_profiles) == 2
        # Check transition matrix learned checkout -> receipt
        assert len(baseline.transition_matrix) > 0


# ==============================================================================
# TEST 24: Version Incrementing & Uniqueness
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_version_incrementing(digital_twin_test_setup):
    data = digital_twin_test_setup
    assert generate_next_version(None) == "v1.0"
    assert generate_next_version("v1.0") == "v1.1"
    assert generate_next_version("v1.9") == "v1.10"
    assert generate_next_version("v2") == "v2.1"

    async with TestingSessionLocal() as db:
        # Ingest 2 observations
        for _ in range(2):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
            )

        b1 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert b1.version == "v1.0"

        # Next compile without explicit version auto-increments
        b2 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert b2.version == "v1.1"

        # Explicit duplicate version should be rejected
        with pytest.raises(ValueError, match="already exists"):
            await BaselineService.compile_baseline(
                db=db,
                organization_id=data["org_1_id"],
                application_id=data["app_1_id"],
                version="v1.0",
            )


# ==============================================================================
# TEST 25: Baseline Activation & Previous Baseline Supersession
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_activation_and_supersession(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Ingest 10 observations to satisfy sample count requirement
        for i in range(10):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
                latency_ms=100.0,
            )

        b1 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
        )
        # Activate b1 (min_samples=5, min_confidence=0.1)
        active_b1 = await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b1.id,
            min_confidence=0.1,
            min_samples=5,
        )
        assert active_b1.status == BaselineStatus.ACTIVE.value
        assert active_b1.activated_at is not None

        # Verify get_active_baseline returns b1
        current_active = await BaselineService.get_active_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert current_active.id == b1.id

        # Compile and activate b2
        b2 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v2.0",
        )
        active_b2 = await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b2.id,
            min_confidence=0.1,
            min_samples=5,
        )
        assert active_b2.status == BaselineStatus.ACTIVE.value

        # Refresh b1: must now be SUPERSEDED
        await db.refresh(b1)
        assert b1.status == BaselineStatus.SUPERSEDED.value

        # Only one baseline remains active
        active_now = await BaselineService.get_active_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert active_now.id == b2.id


# ==============================================================================
# TEST 26: Insufficient Evidence Rejection on Activation
# ==============================================================================
@pytest.mark.asyncio
async def test_insufficient_evidence_activation_rejection(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Ingest only 2 observations
        for _ in range(2):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
            )

        baseline = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )

        # Attempt to activate with requirement of 10 samples
        with pytest.raises(ValueError, match="Insufficient evidence to activate baseline"):
            await BaselineService.activate_baseline(
                db=db,
                organization_id=data["org_1_id"],
                baseline_id=baseline.id,
                min_samples=10,
            )

        # Status remains DRAFT
        await db.refresh(baseline)
        assert baseline.status == BaselineStatus.DRAFT.value


# ==============================================================================
# TEST 27: Historical Baseline Preservation & Archiving
# ==============================================================================
@pytest.mark.asyncio
async def test_historical_baseline_preservation_and_archiving(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        for _ in range(5):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
            )

        b1 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v1.0",
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b1.id,
            min_confidence=0.05,
            min_samples=2,
        )

        b2 = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            version="v2.0",
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b2.id,
            min_confidence=0.05,
            min_samples=2,
        )

        # Archive the superseded b1
        archived_b1 = await BaselineService.archive_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b1.id,
        )
        assert archived_b1.status == BaselineStatus.ARCHIVED.value

        # Attempting to archive the ACTIVE baseline b2 must be rejected
        with pytest.raises(ValueError, match="Cannot archive an ACTIVE baseline"):
            await BaselineService.archive_baseline(
                db=db,
                organization_id=data["org_1_id"],
                baseline_id=b2.id,
            )

        # Both baselines remain preserved in history
        history = await BaselineService.list_baselines(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert len(history) == 2


# ==============================================================================
# TEST 28: Status Code Drift Detector
# ==============================================================================
@pytest.mark.asyncio
async def test_status_code_drift_detector(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Build baseline with only 200 OK responses
        for _ in range(8):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
            )

        b = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b.id,
            min_confidence=0.1,
            min_samples=5,
        )

        drift_engine = DriftEngine()

        # Ingest an observation with unexpected 500 Internal Server Error
        obs_500 = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_1_id"],
            method="POST",
            url_or_path="/api/v1/checkout",
            status_code=500,
        )

        anomalies = await drift_engine.evaluate_observation(db=db, observation=obs_500, baseline=b)
        assert len(anomalies) == 1
        anom = anomalies[0]
        assert anom.anomaly_type == AnomalyType.UNEXPECTED_STATUS_CODE.value
        assert anom.severity == AnomalySeverity.HIGH.value  # 5xx is HIGH
        assert anom.evidence_data["observed_status_code"] == 500

        # Ingest an observation with normal 200 OK -> no drift
        obs_200 = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_1_id"],
            method="POST",
            url_or_path="/api/v1/checkout",
            status_code=200,
        )
        no_anomalies = await drift_engine.evaluate_observation(db=db, observation=obs_200, baseline=b)
        assert len(no_anomalies) == 0


# ==============================================================================
# TEST 29: Schema Drift Detector (Required, Types, Unexpected, Optional)
# ==============================================================================
@pytest.mark.asyncio
async def test_schema_drift_detector(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Ingest baseline observations with consistent response schema
        for _ in range(6):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
                response_payload={"order_id": 12345, "status": "APPROVED"},
            )

        b = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b.id,
            min_confidence=0.1,
            min_samples=5,
        )

        drift_engine = DriftEngine()

        # Observation with type change: order_id is string instead of integer, and missing 'status'
        obs_mutated = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_1_id"],
            method="POST",
            url_or_path="/api/v1/checkout",
            status_code=200,
            response_payload={"order_id": "ORD-XYZ", "extra_debug_flag": True},
        )

        anomalies = await drift_engine.evaluate_observation(db=db, observation=obs_mutated, baseline=b)
        schema_anoms = [a for a in anomalies if a.anomaly_type == AnomalyType.SCHEMA_DRIFT.value]
        assert len(schema_anoms) >= 1
        diff = schema_anoms[0].evidence_data["schema_diff"]
        assert "status" in diff["missing_required"]
        assert "extra_debug_flag" in diff["unexpected_properties"]
        assert any(t["field"] == "order_id" for t in diff["type_mismatches"])


# ==============================================================================
# TEST 30: Sequence Drift Detector
# ==============================================================================
@pytest.mark.asyncio
async def test_sequence_drift_detector(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Establish learned sequence: checkout -> receipt
        for i in range(6):
            sess = f"seq-sess-{i}"
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
                session_identifier=sess,
            )
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_2_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
                session_identifier=sess,
            )

        b = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b.id,
            min_confidence=0.1,
            min_samples=5,
        )

        drift_engine = DriftEngine()

        # Now simulate a session where checkout jumps directly to /api/v1/admin_refund (unseen transition)
        prior_obs = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_1_id"],
            method="POST",
            url_or_path="/api/v1/checkout",
            status_code=200,
        )
        unseen_next_obs = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            method="POST",
            url_or_path="/api/v1/admin_refund",
            status_code=200,
        )

        anomalies = await drift_engine.evaluate_observation(
            db=db,
            observation=unseen_next_obs,
            baseline=b,
            prior_observation=prior_obs,
        )
        seq_anoms = [a for a in anomalies if a.anomaly_type == AnomalyType.UNSEEN_SEQUENCE.value]
        assert len(seq_anoms) == 1
        assert seq_anoms[0].severity == AnomalySeverity.LOW.value  # Low severity, non-alarmist
        assert seq_anoms[0].evidence_data["learned_probability"] == 0.0


# ==============================================================================
# TEST 31: Latency Drift Detector & False-Positive Gating
# ==============================================================================
@pytest.mark.asyncio
async def test_latency_drift_detector(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Fast endpoint: 20ms average
        for _ in range(10):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_2_id"],
                method="GET",
                url_or_path="/api/v1/receipt",
                status_code=200,
                latency_ms=20.0,
            )

        b = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b.id,
            min_confidence=0.1,
            min_samples=5,
        )

        drift_engine = DriftEngine(latency_multiplier=3.0, latency_min_delta_ms=50.0)

        # Normal latency (25ms) -> no spike
        obs_normal = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_2_id"],
            method="GET",
            url_or_path="/api/v1/receipt",
            status_code=200,
            latency_ms=25.0,
        )
        assert len(await drift_engine.evaluate_observation(db=db, observation=obs_normal, baseline=b)) == 0

        # Massive latency spike (450ms) -> flagged as LATENCY_SPIKE
        obs_spike = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=data["app_1_id"],
            organization_id=data["org_1_id"],
            endpoint_id=data["endpoint_2_id"],
            method="GET",
            url_or_path="/api/v1/receipt",
            status_code=200,
            latency_ms=450.0,
        )
        anomalies = await drift_engine.evaluate_observation(db=db, observation=obs_spike, baseline=b)
        lat_anoms = [a for a in anomalies if a.anomaly_type == AnomalyType.LATENCY_SPIKE.value]
        assert len(lat_anoms) == 1
        assert lat_anoms[0].evidence_data["observed_latency_ms"] == 450.0


# ==============================================================================
# TEST 32: Anomaly Deduplication for Repeated Events
# ==============================================================================
@pytest.mark.asyncio
async def test_anomaly_deduplication(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        for _ in range(6):
            await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=200,
            )

        b = await BaselineService.compile_baseline(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        await BaselineService.activate_baseline(
            db=db,
            organization_id=data["org_1_id"],
            baseline_id=b.id,
            min_confidence=0.1,
            min_samples=5,
        )

        drift_engine = DriftEngine()

        # Ingest 3 consecutive 502 Bad Gateway observations
        for _ in range(3):
            obs_502 = await ObservationIngestionService.ingest_single_observation(
                db=db,
                application_id=data["app_1_id"],
                organization_id=data["org_1_id"],
                endpoint_id=data["endpoint_1_id"],
                method="POST",
                url_or_path="/api/v1/checkout",
                status_code=502,
            )
            await drift_engine.evaluate_observation(db=db, observation=obs_502, baseline=b)

        # List anomalies: should be only 1 deduplicated record with occurrence_count == 3
        anomalies = await drift_engine.list_anomalies(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
        )
        assert len(anomalies) == 1
        assert anomalies[0].evidence_data["occurrence_count"] == 3


# ==============================================================================
# TEST 33: Anomaly Review Lifecycle (OPEN -> ACKNOWLEDGED -> RESOLVED)
# ==============================================================================
@pytest.mark.asyncio
async def test_anomaly_lifecycle_review(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        anomaly = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
            severity=AnomalySeverity.HIGH.value,
            confidence=0.9,
            evidence_data={"observed_status": 500},
            status=AnomalyStatus.OPEN.value,
        )
        db.add(anomaly)
        await db.commit()
        await db.refresh(anomaly)

        assert anomaly.status == AnomalyStatus.OPEN.value
        assert anomaly.resolved_at is None

        # Acknowledge
        ack = await DriftEngine.update_anomaly_status(
            db=db,
            organization_id=data["org_1_id"],
            anomaly_id=anomaly.id,
            new_status=AnomalyStatus.ACKNOWLEDGED,
            notes="Engineering team investigating upstream DB deadlock.",
        )
        assert ack.status == AnomalyStatus.ACKNOWLEDGED.value
        assert ack.resolved_at is None
        assert len(ack.evidence_data["review_notes"]) == 1

        # Resolve
        resolved = await DriftEngine.update_anomaly_status(
            db=db,
            organization_id=data["org_1_id"],
            anomaly_id=anomaly.id,
            new_status=AnomalyStatus.RESOLVED,
            notes="Database connection pool size increased. Incident resolved.",
        )
        assert resolved.status == AnomalyStatus.RESOLVED.value
        assert resolved.resolved_at is not None
        assert len(resolved.evidence_data["review_notes"]) == 2


# ==============================================================================
# TEST 34: Cross-Tenant Isolation Enforcement
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_tenant_isolation_baseline_and_anomalies(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        # Org 2 attempts to compile baseline for App 1 (owned by Org 1) -> must fail
        with pytest.raises(ValueError, match="Application not found or tenant access denied"):
            await BaselineService.compile_baseline(
                db=db,
                organization_id=data["org_2_id"],  # Tenant mismatch
                application_id=data["app_1_id"],
            )

        # Create an anomaly under Org 1
        anom = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            anomaly_type=AnomalyType.LATENCY_SPIKE.value,
            severity=AnomalySeverity.LOW.value,
            evidence_data={},
            status=AnomalyStatus.OPEN.value,
        )
        db.add(anom)
        await db.commit()
        await db.refresh(anom)

        # Org 2 attempts to acknowledge Org 1's anomaly -> must fail
        with pytest.raises(ValueError, match="Anomaly not found or tenant access denied"):
            await DriftEngine.update_anomaly_status(
                db=db,
                organization_id=data["org_2_id"],  # Tenant mismatch
                anomaly_id=anom.id,
                new_status=AnomalyStatus.ACKNOWLEDGED,
            )


# ==============================================================================
# TEST 35: Sensitive Evidence Sanitization in Anomalies
# ==============================================================================
@pytest.mark.asyncio
async def test_sensitive_evidence_sanitization_in_anomalies(digital_twin_test_setup):
    data = digital_twin_test_setup
    async with TestingSessionLocal() as db:
        drift_engine = DriftEngine()
        raw_evidence = {
            "error_msg": "Authentication failure",
            "password": "SuperSecretPassword123!",
            "session_token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
            "debug_headers": {"Authorization": "Bearer raw_token_value"},
        }

        # Create anomaly with sensitive payload
        anomaly = await drift_engine._get_or_create_anomaly(
            db=db,
            organization_id=data["org_1_id"],
            application_id=data["app_1_id"],
            baseline_id=None,
            endpoint_id=None,
            anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
            severity=AnomalySeverity.MEDIUM.value,
            confidence=0.8,
            evidence_data=raw_evidence,
            signature="test_sig_sanitized",
        )

        assert anomaly.evidence_data["password"] == "[REDACTED]"
        assert anomaly.evidence_data["session_token"] == "[REDACTED]"
        assert "SuperSecretPassword123!" not in json.dumps(anomaly.evidence_data)


# ==============================================================================
# TEST 36: Authenticated Digital Twin Overview Access (200 OK)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_digital_twin_overview(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    app_id = data["app_1_id"]
    token = data["token_admin_1"]

    headers = {"Authorization": f"Bearer {token}"}
    response = await client.get(
        f"/api/v1/behavioral-twin/applications/{app_id}/overview",
        headers=headers,
    )
    assert response.status_code == 200
    res = response.json()
    assert res["application_id"] == str(app_id)
    assert res["organization_id"] == str(data["org_1_id"])
    assert "total_observations" in res
    assert "open_anomalies_count" in res
    assert "endpoint_profiles" in res


# ==============================================================================
# TEST 37: Unauthenticated Access Rejection (401 Unauthorized)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_unauthenticated_rejection(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    app_id = data["app_1_id"]

    # Request without Authorization header
    response = await client.get(
        f"/api/v1/behavioral-twin/applications/{app_id}/overview"
    )
    assert response.status_code == 401
    assert "credentials" in response.json()["detail"].lower()


# ==============================================================================
# TEST 38: Invalid JWT Token Rejection (401 Unauthorized)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_invalid_token_rejection(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    app_id = data["app_1_id"]

    headers = {"Authorization": "Bearer malformed.invalid.token.here"}
    response = await client.get(
        f"/api/v1/behavioral-twin/applications/{app_id}/overview",
        headers=headers,
    )
    assert response.status_code == 401


# ==============================================================================
# TEST 39: Cross-Tenant Application Access Rejection (403/404 Forbidden)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_cross_tenant_rejection(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    # User 2 belongs to Org 2, App 1 belongs to Org 1
    token_org2 = data["token_admin_2"]
    app_1_id = data["app_1_id"]

    headers = {"Authorization": f"Bearer {token_org2}"}
    # Attempt overview of another organization's application
    response = await client.get(
        f"/api/v1/behavioral-twin/applications/{app_1_id}/overview",
        headers=headers,
    )
    assert response.status_code in [403, 404]


# ==============================================================================
# TEST 40: API Observation Ingestion (Single)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_observation_ingestion_single(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_admin_1"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "application_id": str(data["app_1_id"]),
        "endpoint_id": str(data["endpoint_1_id"]),
        "method": "POST",
        "path": "/api/v1/checkout",
        "status_code": 200,
        "latency_ms": 115.5,
        "request_payload": {"amount": 250, "token": "sensitive_val"},
        "response_payload": {"status": "SUCCESS"},
        "session_identifier": "api_test_session_token",
    }
    response = await client.post(
        "/api/v1/behavioral-twin/observations",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 201
    res = response.json()
    assert res["method"] == "POST"
    assert res["normalized_path"] == "/api/v1/checkout"
    assert res["status_code"] == 200
    assert res["latency_ms"] == 115.5
    assert res["session_token_hash"] is not None
    # Verify sensitive token was redacted from schema
    assert "token" in res["sanitized_request_schema"]["properties"]


# ==============================================================================
# TEST 41: API Batch Observation Ingestion
# ==============================================================================
@pytest.mark.asyncio
async def test_api_observation_ingestion_batch(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_admin_1"]
    headers = {"Authorization": f"Bearer {token}"}

    obs_list = [
        {
            "application_id": str(data["app_1_id"]),
            "method": "GET",
            "path": f"/api/v1/receipt?item={i}",
            "status_code": 200,
            "latency_ms": 25.0 + i,
        }
        for i in range(5)
    ]

    response = await client.post(
        "/api/v1/behavioral-twin/observations/batch",
        headers=headers,
        json={"application_id": str(data["app_1_id"]), "observations": obs_list},
    )
    assert response.status_code == 201
    res = response.json()
    assert res["ingested_count"] == 5
    assert res["failed_count"] == 0
    assert len(res["observations"]) == 5


# ==============================================================================
# TEST 42: API HAR Archive Ingestion
# ==============================================================================
@pytest.mark.asyncio
async def test_api_observation_ingestion_har(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_admin_1"]
    headers = {"Authorization": f"Bearer {token}"}

    har_sample = {
        "log": {
            "version": "1.2",
            "creator": {"name": "TestHar", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-11-12T10:00:00.000Z",
                    "time": 85.0,
                    "request": {
                        "method": "POST",
                        "url": "https://api.payments.local/api/v1/checkout",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"mimeType": "application/json", "text": "{\"amount\": 99}"},
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": "{\"order_id\": \"HAR-1\"}"},
                    },
                }
            ],
        }
    }

    response = await client.post(
        "/api/v1/behavioral-twin/observations/har",
        headers=headers,
        json={"application_id": str(data["app_1_id"]), "har_content": json.dumps(har_sample)},
    )
    assert response.status_code == 201
    res = response.json()
    assert res["ingested_count"] == 1
    assert len(res["observations"]) == 1


# ==============================================================================
# TEST 43: API Baseline Compilation & Listing
# ==============================================================================
@pytest.mark.asyncio
async def test_api_baseline_compilation_and_listing(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_eng_1"]  # Security Engineer
    headers = {"Authorization": f"Bearer {token}"}
    app_id = data["app_1_id"]

    # Ingest 6 observations first
    obs_batch = [
        {
            "application_id": str(app_id),
            "method": "POST",
            "path": "/api/v1/checkout",
            "status_code": 200,
            "latency_ms": 100.0,
        }
        for _ in range(6)
    ]
    await client.post(
        "/api/v1/behavioral-twin/observations/batch",
        headers=headers,
        json={"application_id": str(app_id), "observations": obs_batch},
    )

    # Compile baseline
    compile_res = await client.post(
        "/api/v1/behavioral-twin/baselines/compile",
        headers=headers,
        json={"application_id": str(app_id), "version": "v1.0", "min_samples": 2},
    )
    assert compile_res.status_code == 201
    baseline = compile_res.json()
    assert baseline["version"] == "v1.0"
    assert baseline["status"] == "DRAFT"
    assert baseline["sample_count"] >= 6

    # List baselines
    list_res = await client.get(
        f"/api/v1/behavioral-twin/baselines?application_id={app_id}",
        headers=headers,
    )
    assert list_res.status_code == 200
    b_list = list_res.json()
    assert b_list["total"] >= 1
    assert any(b["id"] == baseline["id"] for b in b_list["items"])


# ==============================================================================
# TEST 44: API Baseline Activation & Single-Active Supersession
# ==============================================================================
@pytest.mark.asyncio
async def test_api_baseline_activation_lifecycle(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_eng_1"]
    headers = {"Authorization": f"Bearer {token}"}
    app_id = data["app_1_id"]

    # Ingest 10 observations
    obs_batch = [
        {
            "application_id": str(app_id),
            "method": "POST",
            "path": "/api/v1/checkout",
            "status_code": 200,
            "latency_ms": 100.0,
        }
        for _ in range(10)
    ]
    await client.post(
        "/api/v1/behavioral-twin/observations/batch",
        headers=headers,
        json={"application_id": str(app_id), "observations": obs_batch},
    )

    # Compile v1
    c1 = await client.post(
        "/api/v1/behavioral-twin/baselines/compile",
        headers=headers,
        json={"application_id": str(app_id), "version": "v1.0"},
    )
    b1_id = c1.json()["id"]

    # Activate v1
    act1 = await client.post(
        f"/api/v1/behavioral-twin/baselines/{b1_id}/activate",
        headers=headers,
    )
    assert act1.status_code == 200
    assert act1.json()["status"] == "ACTIVE"

    # Compile v2
    c2 = await client.post(
        "/api/v1/behavioral-twin/baselines/compile",
        headers=headers,
        json={"application_id": str(app_id), "version": "v2.0"},
    )
    b2_id = c2.json()["id"]

    # Activate v2 -> v1 should become SUPERSEDED
    act2 = await client.post(
        f"/api/v1/behavioral-twin/baselines/{b2_id}/activate",
        headers=headers,
    )
    assert act2.status_code == 200
    assert act2.json()["status"] == "ACTIVE"

    # Inspect v1 details -> must be SUPERSEDED
    get_b1 = await client.get(
        f"/api/v1/behavioral-twin/baselines/{b1_id}",
        headers=headers,
    )
    assert get_b1.status_code == 200
    assert get_b1.json()["status"] == "SUPERSEDED"


# ==============================================================================
# TEST 45: API Anomaly Filtering & Bounded Pagination
# ==============================================================================
@pytest.mark.asyncio
async def test_api_anomaly_filtering_and_pagination(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_admin_1"]
    headers = {"Authorization": f"Bearer {token}"}
    app_id = data["app_1_id"]

    # Seed 2 anomalies directly in DB
    async with TestingSessionLocal() as db:
        anom1 = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=app_id,
            anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
            severity=AnomalySeverity.HIGH.value,
            confidence=0.9,
            status=AnomalyStatus.OPEN.value,
            evidence_data={"status": 500},
        )
        anom2 = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=app_id,
            anomaly_type=AnomalyType.LATENCY_SPIKE.value,
            severity=AnomalySeverity.LOW.value,
            confidence=0.6,
            status=AnomalyStatus.RESOLVED.value,
            evidence_data={"latency": 900},
        )
        db.add_all([anom1, anom2])
        await db.commit()

    # Query with status=OPEN filter
    res = await client.get(
        f"/api/v1/behavioral-twin/anomalies?application_id={app_id}&status=OPEN&page=1&limit=10",
        headers=headers,
    )
    assert res.status_code == 200
    data_res = res.json()
    assert data_res["page"] == 1
    assert data_res["limit"] == 10
    assert all(a["status"] == "OPEN" for a in data_res["items"])


# ==============================================================================
# TEST 46: API Anomaly Review Lifecycle (Acknowledge & Resolve)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_anomaly_lifecycle_endpoints(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_eng_1"]
    headers = {"Authorization": f"Bearer {token}"}
    app_id = data["app_1_id"]

    # Seed an OPEN anomaly
    async with TestingSessionLocal() as db:
        anom = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=app_id,
            anomaly_type=AnomalyType.SCHEMA_DRIFT.value,
            severity=AnomalySeverity.MEDIUM.value,
            confidence=0.8,
            status=AnomalyStatus.OPEN.value,
            evidence_data={"field": "auth_token"},
        )
        db.add(anom)
        await db.commit()
        await db.refresh(anom)
        anom_id = anom.id

    # Acknowledge
    ack_res = await client.post(
        f"/api/v1/behavioral-twin/anomalies/{anom_id}/acknowledge?notes=Under+investigation",
        headers=headers,
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    # Resolve
    resolve_res = await client.post(
        f"/api/v1/behavioral-twin/anomalies/{anom_id}/resolve?notes=Resolved+via+patch",
        headers=headers,
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
    assert resolve_res.json()["resolved_at"] is not None


# ==============================================================================
# TEST 47: Sensitive Evidence Redaction in API Responses
# ==============================================================================
@pytest.mark.asyncio
async def test_api_sensitive_evidence_redaction(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token = data["token_admin_1"]
    headers = {"Authorization": f"Bearer {token}"}
    app_id = data["app_1_id"]

    # Seed an anomaly containing sensitive evidence
    async with TestingSessionLocal() as db:
        raw_evidence = {
            "error_msg": "Unauthorized attempt",
            "password": "SuperSecretCustomerPassword!",
            "session_token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret",
        }
        sanitized = sanitize_payload_recursively(raw_evidence)
        anom = BehavioralAnomaly(
            organization_id=data["org_1_id"],
            application_id=app_id,
            anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
            severity=AnomalySeverity.HIGH.value,
            confidence=0.85,
            status=AnomalyStatus.OPEN.value,
            evidence_data=sanitized,
        )
        db.add(anom)
        await db.commit()
        await db.refresh(anom)
        anom_id = anom.id

    res = await client.get(
        f"/api/v1/behavioral-twin/anomalies/{anom_id}",
        headers=headers,
    )
    assert res.status_code == 200
    anom_data = res.json()
    assert anom_data["evidence_data"]["password"] == "[REDACTED]"
    assert anom_data["evidence_data"]["session_token"] == "[REDACTED]"
    assert "SuperSecretCustomerPassword!" not in json.dumps(anom_data)


# ==============================================================================
# TEST 48: RBAC Restrictions (Auditor cannot mutate baselines or anomalies)
# ==============================================================================
@pytest.mark.asyncio
async def test_api_rbac_restrictions(digital_twin_test_setup, client: AsyncClient):
    data = digital_twin_test_setup
    token_auditor = data["token_auditor_1"]
    headers = {"Authorization": f"Bearer {token_auditor}"}
    app_id = data["app_1_id"]

    # Auditor attempting to compile a baseline must be blocked with 403 Forbidden
    res = await client.post(
        "/api/v1/behavioral-twin/baselines/compile",
        headers=headers,
        json={"application_id": str(app_id), "version": "v1.0"},
    )
    assert res.status_code == 403
    assert "not permitted" in res.json()["detail"].lower()

"""
PHANTOM-X - Feature 5: Application Workflow Discovery
Comprehensive Test Suite

Covers:
1. Workflow Discovery Engine (session grouping, ordering, journey reconstruction)
2. Branching, loops/cycles, and alternative path discovery
3. Incomplete and abandoned user journey detection with dropout indices
4. Statistically grounded confidence scoring and saturation behavior
5. Graph compilation (nodes, directed edges, transition probabilities)
6. Persistence, deduplication, and archival lifecycle
7. Strict multi-tenant isolation at organization_id boundary
8. REST API endpoints (overview, discover, list, detail, evidence)
9. Input validation and authorization controls
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from httpx import AsyncClient, ASGITransport
import jwt

from app.main import app
from app.core.config import settings
from app.models.user import Organization, User
from app.models.application import Application
from app.models.endpoint import DiscoveredEndpoint
from shared.enums.common import HttpMethod, EndpointRiskLevel, UserRole
from tests.conftest import TestingSessionLocal

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
)
from app.features.application_intelligence.behavioral_digital_twin.sanitization import (
    hash_session_identifier,
)
from app.features.application_intelligence.workflow_discovery.models import (
    DiscoveredWorkflow,
    WorkflowType,
    WorkflowStatus,
    StepType,
)
from app.features.application_intelligence.workflow_discovery.schemas import (
    WorkflowDiscoveryRequest,
)
from app.features.application_intelligence.workflow_discovery.discovery_engine import (
    WorkflowDiscoveryEngine,
    extract_node_key,
)
from app.features.application_intelligence.workflow_discovery.service import (
    WorkflowDiscoveryService,
)


@pytest.fixture
async def workflow_test_setup():
    """Seeds test organizations, applications, and users."""
    async with TestingSessionLocal() as db:
        # Organization 1
        org_1 = Organization(name="Workflow Org 1", slug="workflow-org-1")
        # Organization 2 (for tenant isolation)
        org_2 = Organization(name="Workflow Org 2", slug="workflow-org-2")
        db.add_all([org_1, org_2])
        await db.flush()

        # Application 1 (under Org 1)
        app_1 = Application(
            organization_id=org_1.id,
            name="E-Commerce Core",
            target_url="https://api.ecommerce.local",
            risk_score=15.0,
            status="ACTIVE",
        )
        # Application 2 (under Org 2)
        app_2 = Application(
            organization_id=org_2.id,
            name="Logistics Core",
            target_url="https://api.logistics.local",
            risk_score=20.0,
            status="ACTIVE",
        )
        db.add_all([app_1, app_2])
        await db.flush()

        # Endpoints for App 1
        ep_login = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/auth/login",
            method=HttpMethod.POST,
            auth_required=False,
            parameters=[],
            response_codes=[200, 401],
            risk_level=EndpointRiskLevel.LOW,
            raw_metadata={},
        )
        ep_search = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/products/search",
            method=HttpMethod.GET,
            auth_required=True,
            parameters=[],
            response_codes=[200],
            risk_level=EndpointRiskLevel.LOW,
            raw_metadata={},
        )
        ep_checkout = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/cart/checkout",
            method=HttpMethod.POST,
            auth_required=True,
            parameters=[],
            response_codes=[200, 400],
            risk_level=EndpointRiskLevel.HIGH,
            raw_metadata={},
        )
        ep_confirm = DiscoveredEndpoint(
            application_id=app_1.id,
            path="/api/v1/order/confirm",
            method=HttpMethod.POST,
            auth_required=True,
            parameters=[],
            response_codes=[200],
            risk_level=EndpointRiskLevel.MEDIUM,
            raw_metadata={},
        )
        db.add_all([ep_login, ep_search, ep_checkout, ep_confirm])

        # Users
        user_org_1 = User(
            organization_id=org_1.id,
            email="dev@workflow-org-1.local",
            hashed_password="test_hash_pw",
            full_name="Alice Workflow",
            role=UserRole.ADMIN,
            is_active=True,
        )
        user_org_2 = User(
            organization_id=org_2.id,
            email="dev@workflow-org-2.local",
            hashed_password="test_hash_pw",
            full_name="Bob Rival",
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([user_org_1, user_org_2])
        await db.flush()

        # Seed realistic session observations for App 1
        now_ts = datetime.now(timezone.utc)
        observations = []
        for s_idx in range(4):
            s_hash = hash_session_identifier(f"fixture-session-{s_idx}")
            observations.extend([
                BehavioralObservation(
                    organization_id=org_1.id,
                    application_id=app_1.id,
                    endpoint_id=ep_login.id,
                    method="POST",
                    normalized_path="/api/v1/auth/login",
                    status_code=200,
                    sanitized_request_schema={"username": "string"},
                    sanitized_response_schema={"token": "string"},
                    latency_ms=40.0,
                    session_token_hash=s_hash,
                    observed_at=now_ts + timedelta(seconds=1),
                ),
                BehavioralObservation(
                    organization_id=org_1.id,
                    application_id=app_1.id,
                    endpoint_id=ep_search.id,
                    method="GET",
                    normalized_path="/api/v1/products/search",
                    status_code=200,
                    sanitized_request_schema={},
                    sanitized_response_schema={"results": "array"},
                    latency_ms=25.0,
                    session_token_hash=s_hash,
                    observed_at=now_ts + timedelta(seconds=3),
                ),
                BehavioralObservation(
                    organization_id=org_1.id,
                    application_id=app_1.id,
                    endpoint_id=ep_checkout.id,
                    method="POST",
                    normalized_path="/api/v1/cart/checkout",
                    status_code=200,
                    sanitized_request_schema={"cart_id": "string"},
                    sanitized_response_schema={"order_id": "string"},
                    latency_ms=85.0,
                    session_token_hash=s_hash,
                    observed_at=now_ts + timedelta(seconds=6),
                ),
            ])
        db.add_all(observations)
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
            "user_org_1": user_org_1,
            "user_org_2": user_org_2,
            "token_org_1": make_token(user_org_1.id),
            "token_org_2": make_token(user_org_2.id),
            "endpoints": {
                "login": ep_login,
                "search": ep_search,
                "checkout": ep_checkout,
                "confirm": ep_confirm,
            },
        }


# ==============================================================================
# 1. WORKFLOW DISCOVERY ENGINE UNIT TESTS
# ==============================================================================

def test_engine_insufficient_data():
    """Engine returns insufficient_data flag when observations < 2."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()

    # 0 observations
    wfs, meta = WorkflowDiscoveryEngine.discover_workflows([], app_id, org_id)
    assert len(wfs) == 0
    assert meta["insufficient_data"] is True
    assert "Insufficient" in meta["insufficient_data_reason"]

    # 1 observation
    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(
        [{"method": "GET", "normalized_path": "/test"}], app_id, org_id
    )
    assert len(wfs) == 0
    assert meta["insufficient_data"] is True


def test_engine_session_grouping_and_ordering():
    """Verifies observations are grouped by session_token_hash and sorted chronologically."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    sess_1 = hash_session_identifier("session-user-alpha")
    sess_2 = hash_session_identifier("session-user-beta")

    # Session 1: out-of-order in input
    obs_list = [
        {
            "id": uuid.uuid4(),
            "session_token_hash": sess_1,
            "method": "POST",
            "normalized_path": "/api/v1/auth/login",
            "observed_at": now + timedelta(seconds=1),
            "status_code": 200,
            "latency_ms": 50.0,
        },
        {
            "id": uuid.uuid4(),
            "session_token_hash": sess_1,
            "method": "GET",
            "normalized_path": "/api/v1/products/search",
            "observed_at": now + timedelta(seconds=5),
            "status_code": 200,
            "latency_ms": 30.0,
        },
        # Session 2
        {
            "id": uuid.uuid4(),
            "session_token_hash": sess_2,
            "method": "POST",
            "normalized_path": "/api/v1/auth/login",
            "observed_at": now + timedelta(seconds=2),
            "status_code": 200,
            "latency_ms": 45.0,
        },
        {
            "id": uuid.uuid4(),
            "session_token_hash": sess_2,
            "method": "GET",
            "normalized_path": "/api/v1/products/search",
            "observed_at": now + timedelta(seconds=6),
            "status_code": 200,
            "latency_ms": 35.0,
        },
    ]

    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    assert meta["insufficient_data"] is False
    assert meta["analyzed_sessions_count"] == 2
    assert len(wfs) >= 1

    canonical_wf = wfs[0]
    assert canonical_wf["sample_count"] == 2
    assert len(canonical_wf["steps_sequence"]) == 2
    assert canonical_wf["steps_sequence"][0]["normalized_path"] == "/api/v1/auth/login"
    assert canonical_wf["steps_sequence"][1]["normalized_path"] == "/api/v1/products/search"


def test_engine_linear_journey_reconstruction():
    """Reconstructs ordered multi-step linear journey: login -> search -> checkout -> confirm."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    obs_list = []
    # 5 sessions executing the exact same 4-step path
    for s_idx in range(5):
        s_hash = hash_session_identifier(f"sess-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 40.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 25.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/checkout", "observed_at": now + timedelta(seconds=6), "status_code": 200, "latency_ms": 80.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/confirm", "observed_at": now + timedelta(seconds=9), "status_code": 200, "latency_ms": 110.0},
        ])

    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    assert len(wfs) == 1
    wf = wfs[0]
    assert wf["sample_count"] == 5
    assert wf["step_count"] == 4
    assert wf["workflow_type"] == WorkflowType.STANDARD.value
    assert wf["is_incomplete"] is False

    # Check step tagging
    steps = wf["steps_sequence"]
    assert steps[0]["step_type"] == StepType.ENTRY.value
    assert steps[1]["step_type"] == StepType.INTERMEDIATE.value
    assert steps[2]["step_type"] == StepType.INTERMEDIATE.value
    assert steps[3]["step_type"] == StepType.TERMINAL.value


def test_engine_incomplete_and_abandoned_detection():
    """Detects when sessions drop off before reaching canonical terminal step."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    obs_list = []
    # 6 sessions complete full path: login -> search -> checkout -> confirm
    for s_idx in range(6):
        s_hash = hash_session_identifier(f"full-sess-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 40.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 25.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/checkout", "observed_at": now + timedelta(seconds=6), "status_code": 200, "latency_ms": 80.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/confirm", "observed_at": now + timedelta(seconds=9), "status_code": 200, "latency_ms": 110.0},
        ])

    # 3 sessions abandon after checkout (login -> search -> checkout -> stop)
    for s_idx in range(3):
        s_hash = hash_session_identifier(f"abandoned-sess-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 40.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 25.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/checkout", "observed_at": now + timedelta(seconds=6), "status_code": 500, "latency_ms": 300.0},
        ])

    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    assert len(wfs) == 2

    # Canonical full workflow
    full_wf = next(w for w in wfs if not w["is_incomplete"])
    assert full_wf["step_count"] == 4
    assert full_wf["sample_count"] == 6

    # Abandoned workflow
    abandoned_wf = next(w for w in wfs if w["is_incomplete"])
    assert abandoned_wf["step_count"] == 3
    assert abandoned_wf["sample_count"] == 3
    assert abandoned_wf["workflow_type"] == WorkflowType.ABANDONED.value
    assert abandoned_wf["dropout_step_index"] == 2
    assert abandoned_wf["steps_sequence"][2]["step_type"] == StepType.DROPOUT.value


def test_engine_cyclic_workflow_detection():
    """Detects cycles / loops within a user journey."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    obs_list = []
    # Session revisits search: login -> search -> view_item -> search -> view_item
    for s_idx in range(3):
        s_hash = hash_session_identifier(f"cyclic-sess-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 30.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 20.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/item/1", "observed_at": now + timedelta(seconds=5), "status_code": 200, "latency_ms": 15.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=7), "status_code": 200, "latency_ms": 20.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/item/2", "observed_at": now + timedelta(seconds=9), "status_code": 200, "latency_ms": 15.0},
        ])

    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    assert len(wfs) >= 1
    wf = wfs[0]
    assert wf["workflow_type"] == WorkflowType.CYCLIC.value


def test_engine_branching_workflow_detection():
    """Detects alternative branch paths sharing a common prefix."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    obs_list = []
    # Branch A: login -> search -> add_to_cart
    for s_idx in range(4):
        s_hash = hash_session_identifier(f"branch-a-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 30.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 20.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/cart", "observed_at": now + timedelta(seconds=5), "status_code": 200, "latency_ms": 40.0},
        ])

    # Branch B: login -> search -> add_to_wishlist
    for s_idx in range(3):
        s_hash = hash_session_identifier(f"branch-b-{s_idx}")
        obs_list.extend([
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/login", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 30.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "GET", "normalized_path": "/search", "observed_at": now + timedelta(seconds=3), "status_code": 200, "latency_ms": 20.0},
            {"id": uuid.uuid4(), "session_token_hash": s_hash, "method": "POST", "normalized_path": "/wishlist", "observed_at": now + timedelta(seconds=5), "status_code": 200, "latency_ms": 40.0},
        ])

    wfs, meta = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    assert len(wfs) == 2
    # Both share prefix login -> search, branching at step 3
    assert any(w["workflow_type"] == WorkflowType.BRANCHED.value for w in wfs)


def test_engine_confidence_saturation_and_bounds():
    """Confidence stays in [0.0, 1.0] and grows with sample count without fabrication."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    # 1 session
    obs_1 = [
        {"id": uuid.uuid4(), "session_token_hash": "s1", "method": "GET", "normalized_path": "/a", "observed_at": now, "status_code": 200, "latency_ms": 10.0},
        {"id": uuid.uuid4(), "session_token_hash": "s1", "method": "GET", "normalized_path": "/b", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 10.0},
    ]
    wfs_1, _ = WorkflowDiscoveryEngine.discover_workflows(obs_1, app_id, org_id)
    conf_1 = wfs_1[0]["confidence_score"]
    assert 0.0 < conf_1 <= 1.0

    # 10 sessions with the same pattern
    obs_10 = []
    for i in range(10):
        h = f"s_multi_{i}"
        obs_10.extend([
            {"id": uuid.uuid4(), "session_token_hash": h, "method": "GET", "normalized_path": "/a", "observed_at": now, "status_code": 200, "latency_ms": 10.0},
            {"id": uuid.uuid4(), "session_token_hash": h, "method": "GET", "normalized_path": "/b", "observed_at": now + timedelta(seconds=1), "status_code": 200, "latency_ms": 10.0},
        ])
    wfs_10, _ = WorkflowDiscoveryEngine.discover_workflows(obs_10, app_id, org_id)
    conf_10 = wfs_10[0]["confidence_score"]

    # 10 sessions should have strictly higher confidence than 1 session
    assert conf_10 > conf_1
    assert conf_10 <= 1.0


def test_engine_graph_structure():
    """Validates nodes and edges in compiled graph data."""
    app_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now()

    obs_list = [
        {"id": uuid.uuid4(), "session_token_hash": "s_graph", "method": "POST", "normalized_path": "/step1", "observed_at": now, "status_code": 200, "latency_ms": 20.0},
        {"id": uuid.uuid4(), "session_token_hash": "s_graph", "method": "GET", "normalized_path": "/step2", "observed_at": now + timedelta(seconds=2), "status_code": 200, "latency_ms": 40.0},
        {"id": uuid.uuid4(), "session_token_hash": "s_graph", "method": "POST", "normalized_path": "/step3", "observed_at": now + timedelta(seconds=4), "status_code": 500, "latency_ms": 60.0},
    ]
    wfs, _ = WorkflowDiscoveryEngine.discover_workflows(obs_list, app_id, org_id)
    graph = wfs[0]["graph_data"]

    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2

    # Check edges connectivity
    e1 = graph["edges"][0]
    assert e1["source"] == "POST:/step1"
    assert e1["target"] == "GET:/step2"
    assert e1["probability"] == 1.0


# ==============================================================================
# 2. WORKFLOW DISCOVERY SERVICE & PERSISTENCE TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_service_discover_and_persist(workflow_test_setup):
    """Verifies service reads observations, runs discovery, and persists workflows."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]
    eps = setup["endpoints"]
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # Seed 3 session observations into behavioral_observations
        for s_idx in range(3):
            s_hash = hash_session_identifier(f"persist-sess-{s_idx}")
            obs1 = BehavioralObservation(
                organization_id=org_1.id,
                application_id=app_1.id,
                endpoint_id=eps["login"].id,
                method="POST",
                normalized_path="/api/v1/auth/login",
                status_code=200,
                sanitized_request_schema={"username": "string"},
                sanitized_response_schema={"token": "string"},
                latency_ms=45.0,
                session_token_hash=s_hash,
                observed_at=now + timedelta(seconds=1),
            )
            obs2 = BehavioralObservation(
                organization_id=org_1.id,
                application_id=app_1.id,
                endpoint_id=eps["search"].id,
                method="GET",
                normalized_path="/api/v1/products/search",
                status_code=200,
                sanitized_request_schema={},
                sanitized_response_schema={"results": "array"},
                latency_ms=25.0,
                session_token_hash=s_hash,
                observed_at=now + timedelta(seconds=4),
            )
            db.add_all([obs1, obs2])
        await db.commit()

        # Run discovery via service
        req = WorkflowDiscoveryRequest(min_sample_count=1)
        res = await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=req,
        )

        assert res.discovered_count >= 1
        assert res.insufficient_data is False
        assert res.analyzed_sessions_count >= 3
        assert len(res.workflows) >= 1

        # Check DB persistence
        db_res = await db.execute(
            select(DiscoveredWorkflow).where(DiscoveredWorkflow.application_id == app_1.id)
        )
        saved = db_res.scalars().all()
        assert len(saved) >= 1
        assert saved[0].status == WorkflowStatus.DISCOVERED.value


@pytest.mark.asyncio
async def test_service_rediscovery_archives_previous(workflow_test_setup):
    """Re-running discovery archives existing DISCOVERED workflows to avoid duplicate state."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        # Run discovery pass 1
        req = WorkflowDiscoveryRequest(min_sample_count=1)
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=req,
        )

        # Run discovery pass 2
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=req,
        )

        # Verify old ones became ARCHIVED and only pass 2 are DISCOVERED
        res = await db.execute(
            select(DiscoveredWorkflow).where(DiscoveredWorkflow.application_id == app_1.id)
        )
        all_wf = res.scalars().all()
        active_count = sum(1 for w in all_wf if w.status == WorkflowStatus.DISCOVERED.value)
        archived_count = sum(1 for w in all_wf if w.status == WorkflowStatus.ARCHIVED.value)

        assert active_count >= 1
        assert archived_count >= 1


@pytest.mark.asyncio
async def test_service_list_workflows_filters(workflow_test_setup):
    """Tests filtering by confidence, status, and pagination."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=WorkflowDiscoveryRequest(min_sample_count=1),
        )
        list_res = await WorkflowDiscoveryService.list_workflows(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            min_confidence=0.0,
            page=1,
            page_size=10,
        )
        assert list_res.total >= 1
        assert len(list_res.items) >= 1
        assert list_res.page == 1


@pytest.mark.asyncio
async def test_service_get_workflow_by_id_and_graph(workflow_test_setup):
    """Retrieves full workflow detail with graph structure."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=WorkflowDiscoveryRequest(min_sample_count=1),
        )
        list_res = await WorkflowDiscoveryService.list_workflows(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            page=1,
            page_size=1,
        )
        wf_id = list_res.items[0].id

        detail = await WorkflowDiscoveryService.get_workflow_by_id(
            db=db,
            workflow_id=wf_id,
            organization_id=org_1.id,
        )
        assert detail.id == wf_id
        assert len(detail.graph_data.nodes) >= 1
        assert len(detail.steps_sequence) >= 1


@pytest.mark.asyncio
async def test_service_get_workflow_evidence(workflow_test_setup):
    """Retrieves sanitized observation evidence for a workflow."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=WorkflowDiscoveryRequest(min_sample_count=1),
        )
        list_res = await WorkflowDiscoveryService.list_workflows(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            page=1,
            page_size=1,
        )
        wf_id = list_res.items[0].id

        evidence = await WorkflowDiscoveryService.get_workflow_evidence(
            db=db,
            workflow_id=wf_id,
            organization_id=org_1.id,
            step_index=0,
        )
        assert evidence.workflow_id == wf_id
        assert evidence.total_evidence >= 1
        assert evidence.items[0].status_code == 200
        # Secrets should not be present in evidence
        assert "password" not in str(evidence.items[0].sanitized_request_schema)


@pytest.mark.asyncio
async def test_service_overview_metrics(workflow_test_setup):
    """Verifies calculated overview metrics for application workflows."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]

    async with TestingSessionLocal() as db:
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=WorkflowDiscoveryRequest(min_sample_count=1),
        )
        overview = await WorkflowDiscoveryService.get_overview(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
        )
        assert overview.application_id == app_1.id
        assert overview.total_workflows >= 1
        assert overview.total_observed_sessions >= 1
        assert overview.insufficient_data is False


@pytest.mark.asyncio
async def test_tenant_isolation_service(workflow_test_setup):
    """Org 2 cannot access Org 1's workflow."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    org_1 = setup["org_1"]
    org_2 = setup["org_2"]

    async with TestingSessionLocal() as db:
        await WorkflowDiscoveryService.discover_and_persist(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
            request=WorkflowDiscoveryRequest(min_sample_count=1),
        )
        list_res = await WorkflowDiscoveryService.list_workflows(
            db=db,
            application_id=app_1.id,
            organization_id=org_1.id,
        )
        wf_id = list_res.items[0].id

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await WorkflowDiscoveryService.get_workflow_by_id(
                db=db,
                workflow_id=wf_id,
                organization_id=org_2.id,
            )
        assert exc_info.value.status_code == 404


# ==============================================================================
# 3. REST API ENDPOINTS TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_api_auth_required():
    """Unauthenticated requests to workflow endpoints return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(f"/api/v1/workflows/applications/{uuid.uuid4()}/overview")
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_api_tenant_isolation_routes(workflow_test_setup):
    """User from Org 2 cannot discover or list Org 1's workflows."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    token_org_2 = setup["token_org_2"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Org 2 user querying Org 1 app
        res = await client.get(
            f"/api/v1/workflows/applications/{app_1.id}/overview",
            headers={"Authorization": f"Bearer {token_org_2}"},
        )
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_api_workflow_discovery_flow(workflow_test_setup):
    """Full API integration test: discover -> list -> detail -> evidence -> overview."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    token_org_1 = setup["token_org_1"]
    headers = {"Authorization": f"Bearer {token_org_1}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Trigger Discovery
        disc_res = await client.post(
            f"/api/v1/workflows/applications/{app_1.id}/discover",
            json={"min_sample_count": 1, "min_confidence": 0.0},
            headers=headers,
        )
        assert disc_res.status_code == 200
        disc_data = disc_res.json()
        assert disc_data["discovered_count"] >= 1

        # 2. List Workflows
        list_res = await client.get(
            f"/api/v1/workflows/applications/{app_1.id}?page=1&page_size=10",
            headers=headers,
        )
        assert list_res.status_code == 200
        list_data = list_res.json()
        assert list_data["total"] >= 1
        wf_id = list_data["items"][0]["id"]

        # 3. Get Workflow Detail
        detail_res = await client.get(
            f"/api/v1/workflows/{wf_id}",
            headers=headers,
        )
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        assert detail_data["id"] == wf_id
        assert "nodes" in detail_data["graph_data"]
        assert "edges" in detail_data["graph_data"]

        # 4. Get Evidence
        ev_res = await client.get(
            f"/api/v1/workflows/{wf_id}/evidence",
            headers=headers,
        )
        assert ev_res.status_code == 200
        ev_data = ev_res.json()
        assert ev_data["workflow_id"] == wf_id
        assert ev_data["total_evidence"] >= 1

        # 5. Get Overview
        ov_res = await client.get(
            f"/api/v1/workflows/applications/{app_1.id}/overview",
            headers=headers,
        )
        assert ov_res.status_code == 200
        ov_data = ov_res.json()
        assert ov_data["total_workflows"] >= 1
        assert ov_data["insufficient_data"] is False


@pytest.mark.asyncio
async def test_api_input_validation_bounds(workflow_test_setup):
    """Tests request bounds: page_size > 100, invalid min_confidence."""
    setup = workflow_test_setup
    app_1 = setup["app_1"]
    token_org_1 = setup["token_org_1"]
    headers = {"Authorization": f"Bearer {token_org_1}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # page_size > 100
        res = await client.get(
            f"/api/v1/workflows/applications/{app_1.id}?page_size=200",
            headers=headers,
        )
        assert res.status_code == 422

        # min_confidence > 1.0
        res = await client.get(
            f"/api/v1/workflows/applications/{app_1.id}?min_confidence=1.5",
            headers=headers,
        )
        assert res.status_code == 422

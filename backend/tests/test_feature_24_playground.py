import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import jwt

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scope_safety import ApplicationScopePolicy
from app.models.playground import (
    PlaygroundSession,
    SessionStatus,
    SecurityResultClassification,
    TargetType,
)
from app.models.audit import AuditLog
from app.core.config import settings


@pytest.fixture
async def playground_test_setup():
    """Seed comprehensive test data for Playground testing."""
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # Organization A
        org_a = Organization(name="FinTech Alpha Org", slug="fintech-alpha-org")
        # Organization B (Tenant Isolation testing)
        org_b = Organization(name="Rival Vanguard Org", slug="rival-vanguard-org")
        db.add_all([org_a, org_b])
        await db.flush()

        # Users
        user_a = User(
            organization_id=org_a.id,
            email="secops@fintech-alpha.local",
            hashed_password="test_hashed_password",
            full_name="Alice SecOps",
            role="SECURITY_ENGINEER",
        )
        user_b = User(
            organization_id=org_b.id,
            email="auditor@rival-vanguard.local",
            hashed_password="test_hashed_password",
            full_name="Bob Rival",
            role="ADMIN",
        )
        db.add_all([user_a, user_b])
        await db.flush()

        # Application Target for Org A
        app_a = Application(
            organization_id=org_a.id,
            name="Alpha Core Banking API",
            target_url="https://banking.fintech-alpha.local",
            risk_score=8.2,
            status="ACTIVE",
        )
        # Application Target for Org B
        app_b = Application(
            organization_id=org_b.id,
            name="Rival Core API",
            target_url="https://rival.local",
            risk_score=5.0,
            status="ACTIVE",
        )
        db.add_all([app_a, app_b])
        await db.flush()

        # Scope Policies
        policy_a = ApplicationScopePolicy(
            organization_id=org_a.id,
            application_id=app_a.id,
            target_domain="banking.fintech-alpha.local",
            base_url="https://banking.fintech-alpha.local",
            permitted_paths=["/*"],
            excluded_paths=["/admin/delete", "/system/reset"],
            scope_status="ACTIVE",
            authorization_status="AUTHORIZED",
            rate_limit_rps=60,
            max_concurrency=2,
            allow_destructive=False,
            valid_until=now + timedelta(days=30),
        )
        policy_b = ApplicationScopePolicy(
            organization_id=org_b.id,
            application_id=app_b.id,
            target_domain="rival.local",
            base_url="https://rival.local",
            permitted_paths=["/*"],
            excluded_paths=[],
            scope_status="ACTIVE",
            authorization_status="AUTHORIZED",
            rate_limit_rps=60,
            max_concurrency=2,
            allow_destructive=False,
            valid_until=now + timedelta(days=30),
        )
        db.add_all([policy_a, policy_b])
        await db.commit()

        # Generate JWT tokens
        token_a = jwt.encode(
            {"sub": str(user_a.id), "org_id": str(org_a.id), "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_b = jwt.encode(
            {"sub": str(user_b.id), "org_id": str(org_b.id), "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )

        return {
            "org_a": org_a,
            "org_b": org_b,
            "user_a": user_a,
            "user_b": user_b,
            "app_a": app_a,
            "app_b": app_b,
            "policy_a": policy_a,
            "token_a": token_a,
            "token_b": token_b,
        }


@pytest.mark.asyncio
async def test_01_scenario_library_listing(client: AsyncClient, playground_test_setup):
    """Test 1: List scenarios organizes library by category, contains >= 8 categories."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    resp = await client.get("/api/v1/playground/scenarios", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "scenarios" in data
    assert "categories" in data
    assert len(data["categories"]) >= 8
    assert data["total"] >= 10

    # Test category filtering
    cat = data["categories"][0]
    cat_resp = await client.get(f"/api/v1/playground/scenarios?category={cat}", headers=headers)
    assert cat_resp.status_code == 200
    filtered_data = cat_resp.json()
    assert all(s["category"] == cat for s in filtered_data["scenarios"])


@pytest.mark.asyncio
async def test_02_scenario_detail_retrieval(client: AsyncClient, playground_test_setup):
    """Test 2: Retrieve full scenario details with constraints and payload preview."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    resp = await client.get("/api/v1/playground/scenarios/auth-01", headers=headers)
    assert resp.status_code == 200
    sc = resp.json()

    assert sc["id"] == "auth-01"
    assert sc["risk_level"] == "CRITICAL"
    assert "JWT" in sc["name"]
    assert len(sc["preconditions"]) > 0
    assert sc["expected_secure_behavior"] is not None
    assert sc["execution_constraints"]["rate_limit_rps"] == 2


@pytest.mark.asyncio
async def test_03_authorized_target_listing(client: AsyncClient, playground_test_setup):
    """Test 3: List targets automatically provisions synthetic target."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    resp = await client.get("/api/v1/playground/targets", headers=headers)
    assert resp.status_code == 200
    targets = resp.json()

    assert len(targets) >= 2  # synthetic + real app
    synthetic = next((t for t in targets if t["is_synthetic"]), None)
    assert synthetic is not None
    assert synthetic["target_type"] == TargetType.SYNTHETIC_TARGET.value
    assert synthetic["target_url"] == "synthetic://phantom-sandbox.local"


@pytest.mark.asyncio
async def test_04_session_creation(client: AsyncClient, playground_test_setup):
    """Test 4: Create session generates execution plan awaiting authorization."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    # List targets to obtain synthetic target ID
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    payload = {
        "application_id": synthetic["id"],
        "scenario_id": "idor-01",
        "notes": "Regression simulation on IDOR",
    }
    resp = await client.post("/api/v1/playground/sessions", json=payload, headers=headers)
    assert resp.status_code == 201
    sess = resp.json()

    assert sess["scenario_id"] == "idor-01"
    assert sess["status"] == SessionStatus.AWAITING_AUTHORIZATION.value
    assert sess["is_authorized"] is False
    assert "execution_plan" in sess
    assert sess["execution_plan"]["is_synthetic"] is True


@pytest.mark.asyncio
async def test_05_unauthorized_target_selection_rejection(client: AsyncClient, playground_test_setup):
    """Test 5: Create session with non-existent or cross-tenant target rejected."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}

    # Non-existent app
    bad_payload = {
        "application_id": str(uuid.uuid4()),
        "scenario_id": "auth-01",
    }
    resp = await client.post("/api/v1/playground/sessions", json=bad_payload, headers=headers)
    assert resp.status_code == 404

    # Cross-tenant app (app_b belongs to org_b)
    cross_payload = {
        "application_id": str(playground_test_setup["app_b"].id),
        "scenario_id": "auth-01",
    }
    resp2 = await client.post("/api/v1/playground/sessions", json=cross_payload, headers=headers)
    assert resp2.status_code == 403


@pytest.mark.asyncio
async def test_06_execution_without_authorization_blocked(client: AsyncClient, playground_test_setup):
    """Test 6: Execution without prior explicit authorization returns HTTP 400."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    # Attempt to execute directly without authorizing
    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 400
    assert "Explicit authorization required" in exec_resp.json()["detail"]


@pytest.mark.asyncio
async def test_07_expired_scope_execution_blocked(client: AsyncClient, playground_test_setup):
    """Test 7: Execution against expired scope policy is blocked by Feature 26."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import update

    # Set scope policy to EXPIRED
    async with TestingSessionLocal() as db:
        await db.execute(
            update(ApplicationScopePolicy)
            .where(ApplicationScopePolicy.application_id == playground_test_setup["app_a"].id)
            .values(authorization_status="EXPIRED", valid_until=datetime.now(timezone.utc) - timedelta(days=1))
        )
        await db.commit()

    # Create session
    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": str(playground_test_setup["app_a"].id), "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    # Authorize session
    auth_resp = await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize",
        json={"notes": "Authorized by tester"},
        headers=headers,
    )
    assert auth_resp.status_code == 200

    # Execute session -> should be BLOCKED by safety engine
    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    res = exec_resp.json()

    assert res["execution_status"] == SessionStatus.BLOCKED.value
    assert res["security_result"] == SecurityResultClassification.BLOCKED_BY_POLICY.value
    assert res["safety_decisions"]["allowed"] is False
    assert "EXPIRED" in res["safety_decisions"]["violation_category"] or "EXPIRED" in res["safety_decisions"]["reason"]


@pytest.mark.asyncio
async def test_08_suspended_scope_execution_blocked(client: AsyncClient, playground_test_setup):
    """Test 8: Execution against suspended scope policy is blocked by Feature 26."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import update

    # Set scope policy to SUSPENDED
    async with TestingSessionLocal() as db:
        await db.execute(
            update(ApplicationScopePolicy)
            .where(ApplicationScopePolicy.application_id == playground_test_setup["app_a"].id)
            .values(scope_status="SUSPENDED", authorization_status="AUTHORIZED")
        )
        await db.commit()

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": str(playground_test_setup["app_a"].id), "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize",
        json={"notes": "Test auth"},
        headers=headers,
    )

    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    res = exec_resp.json()
    assert res["security_result"] == SecurityResultClassification.BLOCKED_BY_POLICY.value
    assert "SUSPENDED" in str(res["safety_decisions"])


@pytest.mark.asyncio
async def test_09_destructive_execution_attempts_blocked(client: AsyncClient, playground_test_setup):
    """Test 9: Destructive operations permanently disallowed by safety engine."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import update

    # Restore active policy with excluded path
    async with TestingSessionLocal() as db:
        await db.execute(
            update(ApplicationScopePolicy)
            .where(ApplicationScopePolicy.application_id == playground_test_setup["app_a"].id)
            .values(
                scope_status="ACTIVE",
                authorization_status="AUTHORIZED",
                valid_until=datetime.now(timezone.utc) + timedelta(days=30),
                excluded_paths=["/admin/delete", "/system/reset"],
            )
        )
        await db.commit()

    # Create session and manually inject excluded endpoint into execution plan
    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": str(playground_test_setup["app_a"].id), "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    async with TestingSessionLocal() as db:
        sess = await db.get(PlaygroundSession, uuid.UUID(sess_id))
        plan = dict(sess.execution_plan)
        plan["endpoint"] = "/admin/delete"
        plan["target_url"] = "https://banking.fintech-alpha.local/admin/delete"
        sess.execution_plan = plan
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(sess, "execution_plan")
        await db.commit()

    await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize",
        json={"notes": "Authorize probe"},
        headers=headers,
    )

    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    res = exec_resp.json()
    assert res["security_result"] == SecurityResultClassification.BLOCKED_BY_POLICY.value
    assert "EXCLUDED_PATH" in str(res["safety_decisions"]) or "PROHIBITED" in str(res["safety_decisions"])


@pytest.mark.asyncio
async def test_10_execution_passes_through_controlled_runner(client: AsyncClient, playground_test_setup):
    """Test 10: Valid in-scope execution passes safely to controlled runner."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import update

    async with TestingSessionLocal() as db:
        await db.execute(
            update(ApplicationScopePolicy)
            .where(ApplicationScopePolicy.application_id == playground_test_setup["app_a"].id)
            .values(
                scope_status="ACTIVE",
                authorization_status="AUTHORIZED",
                valid_until=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        await db.commit()

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": str(playground_test_setup["app_a"].id), "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize",
        json={"notes": "Cleared for testing"},
        headers=headers,
    )

    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    res = exec_resp.json()
    assert res["execution_status"] == SessionStatus.COMPLETED.value
    assert res["security_result"] == SecurityResultClassification.SECURE_BEHAVIOR_CONFIRMED.value
    assert "403" in res["observed_behavior"]


@pytest.mark.asyncio
async def test_11_synthetic_target_execution_remains_isolated(client: AsyncClient, playground_test_setup):
    """Test 11: Synthetic simulation executes isolated testbed with realistic proof."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "idor-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize",
        json={"notes": "Authorize synthetic IDOR test"},
        headers=headers,
    )

    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    res = exec_resp.json()

    assert res["is_synthetic"] is True
    assert res["security_result"] == SecurityResultClassification.VULNERABILITY_CONFIRMED.value
    assert "Bob Corp" in res["evidence_references"]["response_dump"]
    assert "alice" in res["evidence_references"]["request_dump"].lower()


@pytest.mark.asyncio
async def test_12_results_persisted_correctly(client: AsyncClient, playground_test_setup):
    """Test 12: Session status and execution metrics persisted accurately."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(f"/api/v1/playground/sessions/{sess_id}/authorize", json={}, headers=headers)
    await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)

    # Retrieve session
    sess_get = await client.get(f"/api/v1/playground/sessions/{sess_id}", headers=headers)
    assert sess_get.status_code == 200
    s_data = sess_get.json()
    assert s_data["status"] == SessionStatus.COMPLETED.value
    assert s_data["security_result"] == SecurityResultClassification.VULNERABILITY_CONFIRMED.value
    assert s_data["duration_seconds"] > 0


@pytest.mark.asyncio
async def test_13_evidence_references_returned_safely(client: AsyncClient, playground_test_setup):
    """Test 13: Results endpoint returns evidence dumps without raw secret leakage."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "tenant-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(f"/api/v1/playground/sessions/{sess_id}/authorize", json={}, headers=headers)
    await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)

    res_resp = await client.get(f"/api/v1/playground/sessions/{sess_id}/results", headers=headers)
    assert res_resp.status_code == 200
    r_data = res_resp.json()
    assert "evidence_references" in r_data
    assert "request_dump" in r_data["evidence_references"]
    assert "response_dump" in r_data["evidence_references"]


@pytest.mark.asyncio
async def test_14_cross_tenant_session_access_rejected(client: AsyncClient, playground_test_setup):
    """Test 14: Tenant isolation strictly enforced on session endpoints."""
    headers_a = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    headers_b = {"Authorization": f"Bearer {playground_test_setup['token_b']}"}

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": str(playground_test_setup["app_a"].id), "scenario_id": "auth-01"},
        headers=headers_a,
    )
    sess_id = create_resp.json()["id"]

    # User B (Org B) attempts to read Org A's session -> 403 Forbidden
    get_resp = await client.get(f"/api/v1/playground/sessions/{sess_id}", headers=headers_b)
    assert get_resp.status_code == 403

    # User B attempts to authorize Org A's session -> 403 Forbidden
    auth_resp = await client.post(
        f"/api/v1/playground/sessions/{sess_id}/authorize", json={}, headers=headers_b
    )
    assert auth_resp.status_code == 403

    # User B attempts to execute Org A's session -> 403 Forbidden
    exec_resp = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers_b)
    assert exec_resp.status_code == 403


@pytest.mark.asyncio
async def test_15_replay_requires_fresh_authorization(client: AsyncClient, playground_test_setup):
    """Test 15: Replaying a scenario creates a linked child session requiring fresh authorization."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    # 1. Create and complete parent session
    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "auth-01"},
        headers=headers,
    )
    parent_id = create_resp.json()["id"]
    await client.post(f"/api/v1/playground/sessions/{parent_id}/authorize", json={}, headers=headers)
    await client.post(f"/api/v1/playground/sessions/{parent_id}/execute", headers=headers)

    # 2. Trigger Replay
    replay_resp = await client.post(f"/api/v1/playground/sessions/{parent_id}/replay", headers=headers)
    assert replay_resp.status_code == 200
    child = replay_resp.json()

    assert child["parent_session_id"] == parent_id
    assert child["status"] == SessionStatus.AWAITING_AUTHORIZATION.value
    assert child["is_authorized"] is False  # Must NOT inherit parent authorization!

    # 3. Attempting to execute child directly must be rejected
    exec_fail = await client.post(f"/api/v1/playground/sessions/{child['id']}/execute", headers=headers)
    assert exec_fail.status_code == 400


@pytest.mark.asyncio
async def test_16_duplicate_execution_handling(client: AsyncClient, playground_test_setup):
    """Test 16: Executing an already completed session safely returns existing results."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "auth-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(f"/api/v1/playground/sessions/{sess_id}/authorize", json={}, headers=headers)
    res1 = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert res1.status_code == 200

    # Repeat execution call
    res2 = await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)
    assert res2.status_code == 200
    assert res2.json()["session_id"] == sess_id


@pytest.mark.asyncio
async def test_17_audit_events_recorded_in_feature_25(client: AsyncClient, playground_test_setup):
    """Test 17: Lifecycle actions create corresponding Feature 25 audit log entries."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select

    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}
    targets_resp = await client.get("/api/v1/playground/targets", headers=headers)
    synthetic = next(t for t in targets_resp.json() if t["is_synthetic"])

    create_resp = await client.post(
        "/api/v1/playground/sessions",
        json={"application_id": synthetic["id"], "scenario_id": "rate-01"},
        headers=headers,
    )
    sess_id = create_resp.json()["id"]

    await client.post(f"/api/v1/playground/sessions/{sess_id}/authorize", json={}, headers=headers)
    await client.post(f"/api/v1/playground/sessions/{sess_id}/execute", headers=headers)

    async with TestingSessionLocal() as db:
        q = select(AuditLog).where(
            AuditLog.organization_id == playground_test_setup["org_a"].id
        )
        res = await db.execute(q)
        events = res.scalars().all()
        actions = [e.action for e in events]

        assert any("Playground Session Created" in a for a in actions)
        assert any("Playground Session Authorized" in a for a in actions)
        assert any("Playground Execution Completed" in a for a in actions)


@pytest.mark.asyncio
async def test_18_empty_states_and_404_handling(client: AsyncClient, playground_test_setup):
    """Test 18: Non-existent resources return clean 404 responses."""
    headers = {"Authorization": f"Bearer {playground_test_setup['token_a']}"}

    # Scenario not found
    bad_sc = await client.get("/api/v1/playground/scenarios/non-existent-xyz", headers=headers)
    assert bad_sc.status_code == 404

    # Session not found
    bad_sess = await client.get(f"/api/v1/playground/sessions/{uuid.uuid4()}", headers=headers)
    assert bad_sess.status_code == 404

    # List sessions empty query
    sess_list = await client.get(
        f"/api/v1/playground/sessions?scenario_id=non-existent-sc", headers=headers
    )
    assert sess_list.status_code == 200
    assert sess_list.json()["total"] == 0

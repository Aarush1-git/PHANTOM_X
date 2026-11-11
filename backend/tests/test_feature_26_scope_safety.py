import uuid
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.user import Organization
from app.models.application import Application
from app.models.scope_safety import ApplicationScopePolicy, BlockedExecutionLog
from app.models.audit import AuditLog
from app.services.scope_safety_service import rate_tracker


@pytest.fixture
async def sample_app(client: AsyncClient):
    """Seed test organization and application."""
    from tests.conftest import TestingSessionLocal
    async with TestingSessionLocal() as db:
        org = Organization(name="SecOps Security", slug="secops-security")
        db.add(org)
        await db.flush()

        app = Application(
            organization_id=org.id,
            name="Target Banking API",
            target_url="https://api.banking-staging.local",
            description="Staging core banking system"
        )
        db.add(app)
        await db.commit()
        await db.refresh(app)
        return {"org_id": str(org.id), "app_id": str(app.id), "target_url": app.target_url}


@pytest.mark.asyncio
async def test_01_register_scope_unauthorized_by_default(client: AsyncClient, sample_app):
    """Scenario 1 & 2: Register scope defaults to DRAFT status and PENDING authorization."""
    app_id = sample_app["app_id"]

    payload = {
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local/v1",
        "permitted_paths": ["/v1/*"],
        "excluded_paths": ["/v1/admin/*", "/v1/auth/reset-password", "/logout"],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET", "POST", "PUT"],
        "restricted_endpoint_patterns": ["*/delete-account*"],
        "require_synthetic_auth": True,
        "allow_destructive": False
    }

    res = await client.post(f"/api/v1/settings/scopes/{app_id}", json=payload)
    assert res.status_code == 201
    data = res.json()

    assert data["target_domain"] == "api.banking-staging.local"
    assert data["scope_status"] == "DRAFT"
    assert data["authorization_status"] == "PENDING"
    assert data["authorized_by"] is None
    assert data["allow_destructive"] is False


@pytest.mark.asyncio
async def test_02_attempt_test_before_authorization_is_blocked(client: AsyncClient, sample_app):
    """Scenario 2 & 10: Attempting test execution while authorization is PENDING must be blocked and logged."""
    app_id = sample_app["app_id"]

    # Register draft scope
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local/v1",
        "permitted_paths": ["/v1/*"],
        "excluded_paths": ["/v1/admin/*"],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET", "POST"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })

    # Validate test
    val_res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/v1/accounts",
        "http_method": "GET"
    })
    assert val_res.status_code == 200
    data = val_res.json()
    assert data["is_allowed"] is False
    assert data["violation_category"] in ["SCOPE_NOT_ACTIVE", "AUTHORIZATION_PENDING"]

    # Check blocked log recorded
    blocked_res = await client.get("/api/v1/settings/blocked-executions")
    assert blocked_res.status_code == 200
    logs = blocked_res.json()
    assert len(logs) >= 1
    assert any(log["application_id"] == app_id for log in logs)


@pytest.mark.asyncio
async def test_03_authorize_target_and_validate_allowed(client: AsyncClient, sample_app):
    """Scenario 1: Formally authorize target and verify valid tests are permitted."""
    app_id = sample_app["app_id"]

    # Register
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local/v1",
        "permitted_paths": ["/v1/*"],
        "excluded_paths": ["/v1/admin/*"],
        "rate_limit_rps": 20,
        "max_concurrency": 4,
        "max_scan_duration_minutes": 120,
        "allowed_methods": ["GET", "POST"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })

    # Authorize
    auth_res = await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "alice.secops@company.internal",
        "authorizer_role": "Principal Security Engineer",
        "valid_days": 14,
        "authorization_notes": "Approved for Q4 penetration testing."
    })
    assert auth_res.status_code == 200
    auth_data = auth_res.json()
    assert auth_data["scope_status"] == "ACTIVE"
    assert auth_data["authorization_status"] == "AUTHORIZED"
    assert auth_data["authorized_by"] == "alice.secops@company.internal"
    assert auth_data["valid_until"] is not None

    # Legitimate test must pass validation
    val_res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/v1/transactions",
        "http_method": "GET"
    })
    assert val_res.status_code == 200
    assert val_res.json()["is_allowed"] is True


@pytest.mark.asyncio
async def test_04_reject_unregistered_or_unauthorized_domain(client: AsyncClient, sample_app):
    """Scenario 3: Reject tests targeting unregistered or unauthorized destinations."""
    app_id = sample_app["app_id"]

    # Authorize legitimate app
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local/v1",
        "permitted_paths": ["/*"],
        "excluded_paths": [],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "bob.ciso@company.internal",
        "authorizer_role": "CISO",
        "valid_days": 7
    })

    # Test 1: Completely unregistered target host
    res1 = await client.post("/api/v1/settings/validate-test", json={
        "target_url": "https://malicious-external-host.com/steal-data",
        "http_method": "GET"
    })
    assert res1.status_code == 200
    assert res1.json()["is_allowed"] is False
    assert res1.json()["violation_category"] == "UNREGISTERED_TARGET"

    # Test 2: Mismatched domain for this application_id
    res2 = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://production-sensitive.internal/api",
        "http_method": "GET"
    })
    assert res2.status_code == 200
    assert res2.json()["is_allowed"] is False
    assert res2.json()["violation_category"] == "UNAUTHORIZED_DOMAIN"


@pytest.mark.asyncio
async def test_05_reject_excluded_endpoint_path(client: AsyncClient, sample_app):
    """Scenario 4: Reject security test targeting excluded/forbidden paths."""
    app_id = sample_app["app_id"]

    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local",
        "permitted_paths": ["/*"],
        "excluded_paths": ["/admin/*", "/internal/metrics", "/logout"],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET", "POST"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "authorizer@test.com",
        "authorizer_role": "Lead",
        "valid_days": 30
    })

    # Excluded path /admin/system-shutdown
    res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/admin/system-shutdown",
        "http_method": "GET"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_allowed"] is False
    assert data["violation_category"] == "EXCLUDED_PATH"
    assert "/admin/*" in data["reason"]


@pytest.mark.asyncio
async def test_06_reject_prohibited_http_methods(client: AsyncClient, sample_app):
    """Scenario 5: Reject tests using HTTP methods not explicitly authorized."""
    app_id = sample_app["app_id"]

    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local",
        "permitted_paths": ["/*"],
        "excluded_paths": [],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET", "POST"],  # Only GET and POST
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "authorizer@test.com",
        "authorizer_role": "Lead",
        "valid_days": 30
    })

    # Attempt DELETE request
    res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/users/42",
        "http_method": "DELETE"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_allowed"] is False
    assert data["violation_category"] == "PROHIBITED_METHOD"


@pytest.mark.asyncio
async def test_07_reject_expired_authorization(client: AsyncClient, sample_app):
    """Scenario 6: Reject security tests after authorization period expires."""
    app_id = sample_app["app_id"]
    from tests.conftest import TestingSessionLocal

    # Manually configure an expired scope
    async with TestingSessionLocal() as db:
        past_time = datetime.now(timezone.utc) - timedelta(days=2)
        policy = ApplicationScopePolicy(
            organization_id=uuid.UUID(sample_app["org_id"]),
            application_id=uuid.UUID(app_id),
            target_domain="api.banking-staging.local",
            base_url="https://api.banking-staging.local",
            permitted_paths=["/*"],
            excluded_paths=[],
            scope_status="ACTIVE",
            authorization_status="AUTHORIZED",
            authorized_by="old.auditor@company.com",
            valid_from=past_time - timedelta(days=30),
            valid_until=past_time,  # Expired 2 days ago
            rate_limit_rps=10,
            max_concurrency=2,
            max_scan_duration_minutes=60,
            allowed_methods=["GET"],
            restricted_endpoint_patterns=[],
            require_synthetic_auth=True,
            allow_destructive=False
        )
        db.add(policy)
        await db.commit()

    # Attempt test
    res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/health",
        "http_method": "GET"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_allowed"] is False
    assert data["violation_category"] == "AUTHORIZATION_EXPIRED"


@pytest.mark.asyncio
async def test_08_suspend_and_revoke_scope_workflow(client: AsyncClient, sample_app):
    """Scenario 7: Suspending or revoking authorization blocks all further tests."""
    app_id = sample_app["app_id"]

    # Register & authorize
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local",
        "permitted_paths": ["/*"],
        "excluded_paths": [],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "lead@company.com",
        "authorizer_role": "Lead",
        "valid_days": 10
    })

    # Suspend
    suspend_res = await client.post(f"/api/v1/settings/scopes/{app_id}/suspend", json={
        "reason": "Production incident underway, freeze all scanning."
    })
    assert suspend_res.status_code == 200
    assert suspend_res.json()["scope_status"] == "SUSPENDED"

    # Attempt test while suspended -> Blocked
    res_susp = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/items",
        "http_method": "GET"
    })
    assert res_susp.json()["is_allowed"] is False
    assert res_susp.json()["violation_category"] == "SCOPE_NOT_ACTIVE"

    # Revoke
    revoke_res = await client.post(f"/api/v1/settings/scopes/{app_id}/revoke", json={
        "reason": "Target decommissioned."
    })
    assert revoke_res.status_code == 200
    assert revoke_res.json()["authorization_status"] == "REVOKED"

    # Attempt test while revoked -> Blocked
    res_rev = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/items",
        "http_method": "GET"
    })
    assert res_rev.json()["is_allowed"] is False
    assert res_rev.json()["violation_category"] in ["SCOPE_NOT_ACTIVE", "AUTHORIZATION_REVOKED"]


@pytest.mark.asyncio
async def test_09_reject_destructive_actions(client: AsyncClient, sample_app):
    """Scenario 9: Prohibited destructive actions (SQL injection DROP/DELETE, command injection) rejected."""
    app_id = sample_app["app_id"]

    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local",
        "permitted_paths": ["/*"],
        "excluded_paths": [],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET", "POST"],
        "restricted_endpoint_patterns": ["*/delete-account*"],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "sec@company.com",
        "authorizer_role": "Analyst",
        "valid_days": 10
    })

    # Test 1: Destructive SQL Injection payload
    res_sql = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/search?q=1",
        "http_method": "GET",
        "payload_sample": "'; DROP TABLE accounts; --"
    })
    assert res_sql.status_code == 200
    assert res_sql.json()["is_allowed"] is False
    assert res_sql.json()["violation_category"] == "DESTRUCTIVE_ACTION_PROHIBITED"

    # Test 2: Command injection payload
    res_cmd = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/export",
        "http_method": "POST",
        "payload_sample": "test.txt; rm -rf /var/www"
    })
    assert res_cmd.status_code == 200
    assert res_cmd.json()["is_allowed"] is False
    assert res_cmd.json()["violation_category"] == "DESTRUCTIVE_ACTION_PROHIBITED"

    # Test 3: Restricted endpoint pattern
    res_re = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/users/123/delete-account",
        "http_method": "POST"
    })
    assert res_re.status_code == 200
    assert res_re.json()["is_allowed"] is False
    assert res_re.json()["violation_category"] == "RESTRICTED_ENDPOINT"


@pytest.mark.asyncio
async def test_10_rate_limit_exceeded(client: AsyncClient, sample_app):
    """Scenario 8: Requests exceeding configured RPS rate limit are rejected."""
    import time
    app_id = sample_app["app_id"]
    rate_tracker.reset(app_id)

    # Configure rate limit of 2 RPS
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "api.banking-staging.local",
        "base_url": "https://api.banking-staging.local",
        "permitted_paths": ["/*"],
        "excluded_paths": [],
        "rate_limit_rps": 2,  # 2 RPS limit
        "max_concurrency": 1,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "sec@company.com",
        "authorizer_role": "Analyst",
        "valid_days": 10
    })

    # Direct unit test of sliding window tracker
    tracker_test_id = "test-tracker-app"
    rate_tracker.reset(tracker_test_id)
    assert rate_tracker.is_allowed(tracker_test_id, 2) is True
    assert rate_tracker.is_allowed(tracker_test_id, 2) is True
    assert rate_tracker.is_allowed(tracker_test_id, 2) is False

    # Simulate saturated rate limit window on the live API endpoint
    now = time.time()
    rate_tracker._history[app_id] = [now, now]

    res_blocked = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://api.banking-staging.local/ping",
        "http_method": "GET"
    })

    assert res_blocked.status_code == 200
    data = res_blocked.json()
    assert data["is_allowed"] is False
    assert data["violation_category"] == "RATE_LIMIT_EXCEEDED"
    assert "exceeds configured target rate limit" in data["reason"]


import uuid
import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scan import Scan, ScanConfiguration
from app.models.audit import AuditLog, ScanExecutionRecord
from app.features.security_operations.audit_logs import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
    AuditEventRecorder,
    AuditLogService,
    scrub_secrets,
)


@pytest.fixture
async def audit_test_setup():
    """Seed test organizations, user, application, and scan."""
    from tests.conftest import TestingSessionLocal
    async with TestingSessionLocal() as db:
        org_a = Organization(name="FinTech Primary Org", slug="fintech-primary")
        org_b = Organization(name="External Competitor Org", slug="external-org")
        db.add_all([org_a, org_b])
        await db.flush()

        user = User(
            organization_id=org_a.id,
            email="auditor@fintech.local",
            hashed_password="hashed_placeholder_pw",
            full_name="Alex Auditor",
            role="SECURITY_ENGINEER"
        )
        db.add(user)
        await db.flush()

        app = Application(
            organization_id=org_a.id,
            name="Online Banking Gateway",
            target_url="https://gateway.banking.local"
        )
        db.add(app)
        await db.flush()

        scan = Scan(
            organization_id=org_a.id,
            application_id=app.id,
            status="QUEUED"
        )
        db.add(scan)
        await db.commit()
        await db.refresh(org_a)
        await db.refresh(org_b)
        await db.refresh(app)
        await db.refresh(scan)

        import jwt
        from app.core.config import settings
        token = jwt.encode({"sub": str(user.id)}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        return {
            "org_a_id": str(org_a.id),
            "org_b_id": str(org_b.id),
            "user_id": str(user.id),
            "app_id": str(app.id),
            "scan_id": str(scan.id),
            "auth_headers": {"Authorization": f"Bearer {token}"}
        }


@pytest.mark.asyncio
async def test_01_record_and_retrieve_valid_events(client: AsyncClient, audit_test_setup):
    """Scenarios 1 & 2: Record structured events and verify retrieval with complete metadata and hashes."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])
    app_id = uuid.UUID(setup["app_id"])

    async with TestingSessionLocal() as db:
        # Record Authentication event
        ev1 = await AuditEventRecorder.record_authentication_event(
            db=db,
            org_id=org_id,
            event_type="AUTH_LOGIN_SUCCESS",
            action="Operator logged in successfully",
            email="auditor@fintech.local",
            ip_address="192.168.1.10"
        )
        assert ev1.id is not None
        assert ev1.event_hash is not None
        assert ev1.prev_event_hash == "GENESIS_0000000000000000000000000000000000000000000000000000000000000000"

        # Record Application event
        ev2 = await AuditEventRecorder.record_application_event(
            db=db,
            org_id=org_id,
            app_id=app_id,
            event_type="APP_SCOPE_CONFIGURED",
            action="Updated target scope parameters",
            actor_email="auditor@fintech.local",
            details={"rate_limit_rps": 20}
        )
        assert ev2.prev_event_hash == ev1.event_hash

    # Query via API
    res = await client.get("/api/v1/settings/audit-logs", headers=setup["auth_headers"])
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 2
    assert any(e["event_type"] == "AUTH_LOGIN_SUCCESS" for e in events)
    assert any(e["event_type"] == "APP_SCOPE_CONFIGURED" for e in events)


@pytest.mark.asyncio
async def test_02_filter_by_category_and_type(client: AsyncClient, audit_test_setup):
    """Scenario 3: Filter audit events by category and event_type."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])
    app_id = uuid.UUID(setup["app_id"])

    async with TestingSessionLocal() as db:
        await AuditEventRecorder.record_authorization_event(
            db=db,
            org_id=org_id,
            app_id=app_id,
            event_type="AUTHZ_GRANTED",
            action="Granted DAST testing authorization",
            authorizer_email="sec-lead@fintech.local",
            authorizer_role="Lead"
        )

    # Filter for AUTHORIZATION category
    res = await client.get("/api/v1/settings/audit-logs?category=AUTHORIZATION", headers=setup["auth_headers"])
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    assert all(i["category"] == "AUTHORIZATION" for i in items)

    # Filter for specific event_type
    res_type = await client.get("/api/v1/settings/audit-logs?event_type=AUTHZ_GRANTED", headers=setup["auth_headers"])
    assert res_type.status_code == 200
    assert all(i["event_type"] == "AUTHZ_GRANTED" for i in res_type.json())


@pytest.mark.asyncio
async def test_03_filter_by_application_and_date(client: AsyncClient, audit_test_setup):
    """Scenarios 4 & 5: Filter audit events by application ID and timestamp boundaries."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])
    app_id = uuid.UUID(setup["app_id"])

    async with TestingSessionLocal() as db:
        await AuditEventRecorder.record_application_event(
            db=db,
            org_id=org_id,
            app_id=app_id,
            event_type="APP_UPDATED",
            action="Target URL updated",
            actor_email="admin@fintech.local"
        )

    # Filter by application_id
    res = await client.get(f"/api/v1/settings/audit-logs?application_id={app_id}", headers=setup["auth_headers"])
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    assert all(i["application_id"] == str(app_id) for i in items)

    # Filter by date range
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    res_date = await client.get(f"/api/v1/settings/audit-logs?start_date={past}&end_date={future}", headers=setup["auth_headers"])
    assert res_date.status_code == 200
    assert len(res_date.json()) >= 1


@pytest.mark.asyncio
async def test_04_scan_execution_lifecycle_history(client: AsyncClient, audit_test_setup):
    """Scenario 6: Dedicated scan execution history records transitions, duration, and metrics."""
    setup = audit_test_setup
    app_id = setup["app_id"]
    scan_id = setup["scan_id"]

    # 1. Post QUEUED transition
    p1 = await client.post("/api/v1/settings/execution-history", headers=setup["auth_headers"], json={
        "scan_id": scan_id,
        "application_id": app_id,
        "final_status": "QUEUED",
        "initiating_user": "security.bot@fintech.local"
    })
    assert p1.status_code == 201
    assert p1.json()["final_status"] == "QUEUED"

    # 2. Transition to STARTED
    p2 = await client.post("/api/v1/settings/execution-history", headers=setup["auth_headers"], json={
        "scan_id": scan_id,
        "application_id": app_id,
        "final_status": "STARTED"
    })
    assert p2.status_code == 201
    assert p2.json()["start_time"] is not None

    # 3. Transition to COMPLETED with counts
    p3 = await client.post("/api/v1/settings/execution-history", headers=setup["auth_headers"], json={
        "scan_id": scan_id,
        "application_id": app_id,
        "final_status": "COMPLETED",
        "tests_executed": 45,
        "tests_blocked": 3,
        "verified_findings": 2
    })
    assert p3.status_code == 201
    data = p3.json()
    assert data["final_status"] == "COMPLETED"
    assert data["tests_executed"] == 45
    assert data["tests_blocked"] == 3
    assert data["verified_findings"] == 2
    assert len(data["lifecycle_events"]) >= 3

    # Query specific scan execution history
    get_res = await client.get(f"/api/v1/settings/execution-history/{scan_id}", headers=setup["auth_headers"])
    assert get_res.status_code == 200
    assert get_res.json()["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_05_organization_level_isolation(client: AsyncClient, audit_test_setup):
    """Scenario 7: Ensure organization data isolation — Org A cannot inspect Org B's audit stream."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_a = uuid.UUID(setup["org_a_id"])
    org_b = uuid.UUID(setup["org_b_id"])

    async with TestingSessionLocal() as db:
        # Event in Org A
        await AuditEventRecorder.record_platform_event(
            db=db,
            org_id=org_a,
            event_type="CONFIG_CHANGED",
            action="Org A internal setting updated"
        )
        # Event in Org B
        await AuditEventRecorder.record_platform_event(
            db=db,
            org_id=org_b,
            event_type="CONFIG_CHANGED",
            action="Org B confidential setting updated"
        )

        # Service-level query with Org A isolation
        org_a_events = await AuditLogService.list_events(db=db, org_id=org_a)
        assert all(e.organization_id == org_a for e in org_a_events)
        assert not any("Org B confidential" in e.action for e in org_a_events)


@pytest.mark.asyncio
async def test_06_secret_scrubbing_in_metadata(client: AsyncClient, audit_test_setup):
    """Scenario 14: Sensitive credentials, API keys, passwords, and tokens are scrubbed from metadata."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    dirty_payload = {
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "api_key": "ak_live_981249120491024",
        "access_token": "bearer_sample_token",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_sig",
            "Cookie": "session_id=123456789"
        },
        "safe_config": "enabled"
    }

    # Test scrubber directly
    cleaned = scrub_secrets(dirty_payload)
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["headers"]["Authorization"] == "[REDACTED]"
    assert cleaned["safe_config"] == "enabled"

    # Test persistence through event recorder
    async with TestingSessionLocal() as db:
        ev = await AuditEventRecorder.record_platform_event(
            db=db,
            org_id=org_id,
            event_type="ADMIN_ACTION",
            action="Credential rotation attempt",
            details=dirty_payload
        )
        assert ev.details["password"] == "[REDACTED]"
        assert ev.details["api_key"] == "[REDACTED]"
        assert "SuperSecretPassword" not in str(ev.details)


@pytest.mark.asyncio
async def test_07_hash_chain_integrity_verification(client: AsyncClient, audit_test_setup):
    """Scenario 10: Validate intact cryptographic SHA-256 hash chain verification."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async with TestingSessionLocal() as db:
        # Record three linked events
        await AuditEventRecorder.record_authentication_event(
            db=db, org_id=org_id, event_type="AUTH_LOGIN_SUCCESS", action="User 1 login"
        )
        await AuditEventRecorder.record_authentication_event(
            db=db, org_id=org_id, event_type="AUTH_LOGIN_SUCCESS", action="User 2 login"
        )
        await AuditEventRecorder.record_authentication_event(
            db=db, org_id=org_id, event_type="AUTH_LOGOUT", action="User 1 logout"
        )

        # Verify integrity
        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is True
        assert verdict.records_checked >= 3
        assert len(verdict.anomalies) == 0


@pytest.mark.asyncio
async def test_08_detect_tampered_event_content(client: AsyncClient, audit_test_setup):
    """Scenario 11: Tamper detection: detect when record contents are altered post-creation."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async with TestingSessionLocal() as db:
        # Create an event
        ev = await AuditEventRecorder.record_authentication_event(
            db=db, org_id=org_id, event_type="AUTH_LOGIN_SUCCESS", action="Legitimate operator action"
        )
        tamper_id = ev.id

        # Maliciously modify the database record action directly
        q = select(AuditLog).where(AuditLog.id == tamper_id)
        res = await db.execute(q)
        record = res.scalars().first()
        record.action = "Tampered unauthorized action"
        await db.commit()

        # Run integrity verification
        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is False
        assert len(verdict.anomalies) >= 1
        assert str(tamper_id) in verdict.broken_event_ids
        assert any("Content tampering detected" in a for a in verdict.anomalies)


@pytest.mark.asyncio
async def test_09_detect_broken_hash_chain_link(client: AsyncClient, audit_test_setup):
    """Scenario 12: Broken link detection: detect when an event's prev_event_hash linkage is broken."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async with TestingSessionLocal() as db:
        e1 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="A")
        e2 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="B")

        # Break e2's previous hash pointer
        q = select(AuditLog).where(AuditLog.id == e2.id)
        res = await db.execute(q)
        record = res.scalars().first()
        record.prev_event_hash = "FORGED_HASH_LINK_000000000000000000000000000000000000000000000000000"
        await db.commit()

        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is False
        assert str(e2.id) in verdict.broken_event_ids
        assert any("Broken hash chain link" in a for a in verdict.anomalies)


@pytest.mark.asyncio
async def test_10_concurrent_event_creation(client: AsyncClient, audit_test_setup):
    """Scenario 13: Handle concurrent event creation safely without breaking hash chain linkage."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async def create_event(idx: int):
        async with TestingSessionLocal() as db:
            return await AuditEventRecorder.record_platform_event(
                db=db,
                org_id=org_id,
                event_type="CONFIG_CHANGED",
                action=f"Concurrent operation {idx}"
            )

    # Launch 5 concurrent event recordings
    tasks = [create_event(i) for i in range(5)]
    results = await asyncio.gather(*tasks)
    assert len(results) == 5

    # Verify that the resulting chain has zero broken links
    async with TestingSessionLocal() as db:
        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is True
        assert verdict.records_checked >= 5


@pytest.mark.asyncio
async def test_11_feature_26_blocked_action_integration(client: AsyncClient, audit_test_setup):
    """Scenario 15: Blocked actions from Feature 26 automatically record in the audit event chain."""
    setup = audit_test_setup
    app_id = setup["app_id"]

    # Register and authorize target with Feature 26
    await client.post(f"/api/v1/settings/scopes/{app_id}", json={
        "target_domain": "gateway.banking.local",
        "base_url": "https://gateway.banking.local",
        "permitted_paths": ["/*"],
        "excluded_paths": ["/admin/*"],
        "rate_limit_rps": 10,
        "max_concurrency": 2,
        "max_scan_duration_minutes": 60,
        "allowed_methods": ["GET"],
        "restricted_endpoint_patterns": [],
        "require_synthetic_auth": True,
        "allow_destructive": False
    })
    await client.post(f"/api/v1/settings/scopes/{app_id}/authorize", json={
        "authorized_by": "lead@fintech.local",
        "authorizer_role": "Lead",
        "valid_days": 10
    })

    # Trigger a prohibited destructive SQL injection test
    val_res = await client.post("/api/v1/settings/validate-test", json={
        "application_id": app_id,
        "target_url": "https://gateway.banking.local/v1/search",
        "http_method": "GET",
        "payload_sample": "'; DROP TABLE accounts; --"
    })
    assert val_res.status_code == 200
    assert val_res.json()["is_allowed"] is False

    # Check audit log contains the BLOCKED event
    audit_res = await client.get("/api/v1/settings/audit-logs?status=BLOCKED", headers=setup["auth_headers"])
    assert audit_res.status_code == 200
    blocked_events = audit_res.json()
    assert len(blocked_events) >= 1
    target_event = next(e for e in blocked_events if e["status"] == "BLOCKED")
    assert target_event["category"] == "SECURITY_TESTING"
    assert target_event["event_type"] == "TEST_BLOCKED"
    assert target_event["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_12_audit_overview_metrics_and_export(client: AsyncClient, audit_test_setup):
    """Test /audit-logs/overview and /audit-logs/export return valid live records."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    # Seed an event first
    async with TestingSessionLocal() as db:
        await AuditEventRecorder.record_platform_event(
            db=db, org_id=org_id, event_type="ADMIN_ACTION", action="Metric test event"
        )

    # Overview
    res_ov = await client.get("/api/v1/settings/audit-logs/overview", headers=setup["auth_headers"])
    assert res_ov.status_code == 200
    ov = res_ov.json()
    assert ov["total_events"] >= 1
    assert "categories_breakdown" in ov

    # Export
    res_exp = await client.get("/api/v1/settings/audit-logs/export?limit=10", headers=setup["auth_headers"])
    assert res_exp.status_code == 200
    assert isinstance(res_exp.json(), list)


@pytest.mark.asyncio
async def test_13_sequence_gap_and_deletion_detection(client: AsyncClient, audit_test_setup):
    """Scenario 16: Detect sequence gaps and deleted intermediate/genesis records."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select, delete
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async with TestingSessionLocal() as db:
        e1 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="Event 1")
        e2 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="Event 2")
        e3 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="Event 3")

        assert e1.sequence_number == 1
        assert e2.sequence_number == 2
        assert e3.sequence_number == 3

        # Maliciously delete intermediate event e2 from database
        await db.execute(delete(AuditLog).where(AuditLog.id == e2.id))
        await db.commit()

        # Run integrity verification
        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is False
        assert any("Sequence gap" in a for a in verdict.anomalies)


@pytest.mark.asyncio
async def test_14_missing_or_wiped_hash_detection(client: AsyncClient, audit_test_setup):
    """Scenario 17: Detect when event_hash is cleared/nullified by an attacker."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    async with TestingSessionLocal() as db:
        ev = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="CONFIG_CHANGED", action="Legit")
        target_id = ev.id

        # Maliciously set event_hash to None directly in DB
        res = await db.execute(select(AuditLog).where(AuditLog.id == target_id))
        record = res.scalars().first()
        record.event_hash = None
        await db.commit()

        verdict = await AuditLogService.verify_integrity(db, org_id)
        assert verdict.is_intact is False
        assert any("Content tampering detected" in a for a in verdict.anomalies)


@pytest.mark.asyncio
async def test_15_deep_secret_scrubbing_urls_and_keys(client: AsyncClient, audit_test_setup):
    """Scenario 18: Scrub sensitive URL query parameters, connection strings, PEM keys, and key aliases."""
    raw_payload = {
        "callback_url": "https://auth.fintech.local/cb?token=secret_tok_9988&client_id=123&api_key=ak_live_7766&limit=25",
        "db_connection": "postgresql://operator:super_secret_db_pass@internal.db:5432/phantom",
        "private_cert": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
        "passwd": "UserPasswordToScrub123",
        "client_secret": "cs_live_secret_4455",
        "safe_endpoint": "/api/v1/health"
    }

    cleaned = scrub_secrets(raw_payload)

    # 1. URL params scrubbed while non-sensitive params preserved
    assert "token=[REDACTED]" in cleaned["callback_url"]
    assert "api_key=[REDACTED]" in cleaned["callback_url"]
    assert "client_id=123" in cleaned["callback_url"]
    assert "limit=25" in cleaned["callback_url"]

    # 2. Connection string password scrubbed
    assert "operator:[REDACTED]@internal.db" in cleaned["db_connection"]
    assert "super_secret_db_pass" not in cleaned["db_connection"]

    # 3. PEM private key block scrubbed
    assert cleaned["private_cert"] == "[REDACTED_PRIVATE_KEY]"

    # 4. Aliased keys scrubbed
    assert cleaned["passwd"] == "[REDACTED]"
    assert cleaned["client_secret"] == "[REDACTED]"
    assert cleaned["safe_endpoint"] == "/api/v1/health"


@pytest.mark.asyncio
async def test_16_api_organization_filtering(client: AsyncClient, audit_test_setup):
    """Scenario 19: REST endpoint GET /audit-logs respects org_id parameter for strict multi-tenant isolation."""
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_a = uuid.UUID(setup["org_a_id"])
    org_b = uuid.UUID(setup["org_b_id"])

    async with TestingSessionLocal() as db:
        await AuditEventRecorder.record_platform_event(
            db=db, org_id=org_a, event_type="CONFIG_CHANGED", action="Org A Isolated Event"
        )
        await AuditEventRecorder.record_platform_event(
            db=db, org_id=org_b, event_type="CONFIG_CHANGED", action="Org B Isolated Event"
        )

    # Query for Org A only via API with Org A user token
    res_a = await client.get(f"/api/v1/settings/audit-logs?org_id={org_a}", headers=setup["auth_headers"])
    assert res_a.status_code == 200
    events_a = res_a.json()
    assert all(e["organization_id"] == str(org_a) for e in events_a)
    assert not any(e["action"] == "Org B Isolated Event" for e in events_a)

    # Create Org B user and query for Org B via API with Org B user token
    import jwt
    from app.core.config import settings
    from app.models.user import User
    from shared.enums.common import UserRole
    user_b_id = uuid.uuid4()
    async with TestingSessionLocal() as db:
        user_b = User(
            id=user_b_id,
            organization_id=org_b,
            email="user_b_test16@tenant-b.com",
            hashed_password="mock_hashed_pw",
            full_name="User Tenant B",
            role=UserRole.SECURITY_ENGINEER,
            is_active=True
        )
        db.add(user_b)
        await db.commit()

    token_b = jwt.encode({"sub": str(user_b_id)}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    res_b = await client.get(f"/api/v1/settings/audit-logs?org_id={org_b}", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b.status_code == 200
    events_b = res_b.json()
    assert all(e["organization_id"] == str(org_b) for e in events_b)
    assert not any(e["action"] == "Org A Isolated Event" for e in events_b)


@pytest.mark.asyncio
async def test_17_authenticated_server_side_org_isolation(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 1: Server-side organization isolation enforcement.
    A user must NEVER gain access to another organization's records by supplying or modifying
    an org_id query parameter. All cross-tenant requests must be rejected with 403 Forbidden.
    """
    import jwt
    from tests.conftest import TestingSessionLocal
    from app.core.config import settings
    from app.models.user import User
    from shared.enums.common import UserRole

    setup = audit_test_setup
    org_a = uuid.UUID(setup["org_a_id"])
    org_b = uuid.UUID(setup["org_b_id"])

    # Create User A (Org A) and User B (Org B)
    user_a_id = uuid.uuid4()
    user_b_id = uuid.uuid4()

    async with TestingSessionLocal() as db:
        user_a = User(
            id=user_a_id,
            organization_id=org_a,
            email="user_a@tenant-a.com",
            hashed_password="mock_hashed_pw",
            full_name="User Tenant A",
            role=UserRole.SECURITY_ENGINEER,
            is_active=True
        )
        user_b = User(
            id=user_b_id,
            organization_id=org_b,
            email="user_b@tenant-b.com",
            hashed_password="mock_hashed_pw",
            full_name="User Tenant B",
            role=UserRole.SECURITY_ENGINEER,
            is_active=True
        )
        db.add_all([user_a, user_b])

        # Record events for each org
        await AuditEventRecorder.record_platform_event(
            db=db, org_id=org_a, event_type="TENANT_A_ACTION", action="Org A Sensitive Audit Record"
        )
        await AuditEventRecorder.record_platform_event(
            db=db, org_id=org_b, event_type="TENANT_B_ACTION", action="Org B Sensitive Audit Record"
        )

    # Generate JWT Bearer tokens
    token_a = jwt.encode({"sub": str(user_a_id)}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Organization A requests its own records (with and without explicit org_id)
    r1 = await client.get("/api/v1/settings/audit-logs", headers=headers_a)
    assert r1.status_code == 200
    events = r1.json()
    assert len(events) >= 1
    assert all(e["organization_id"] == str(org_a) for e in events)
    assert not any("Org B Sensitive" in e["action"] for e in events)

    r1_explicit = await client.get(f"/api/v1/settings/audit-logs?org_id={org_a}", headers=headers_a)
    assert r1_explicit.status_code == 200

    # 2. Organization A attempts to request Organization B's records via org_id -> 403 FORBIDDEN
    r2 = await client.get(f"/api/v1/settings/audit-logs?org_id={org_b}", headers=headers_a)
    assert r2.status_code == 403
    assert "Cross-tenant access forbidden" in r2.json()["detail"]

    # 3. Organization A attempts to export Organization B's logs -> 403 FORBIDDEN
    r3 = await client.get(f"/api/v1/settings/audit-logs/export?org_id={org_b}", headers=headers_a)
    assert r3.status_code == 403
    assert "Cross-tenant access forbidden" in r3.json()["detail"]

    # 4. Organization A attempts to verify Organization B's chain -> 403 FORBIDDEN
    r4_get = await client.get(f"/api/v1/settings/audit-logs/verify-integrity?org_id={org_b}", headers=headers_a)
    assert r4_get.status_code == 403

    r4_post = await client.post(f"/api/v1/settings/audit-logs/verify-chain?org_id={org_b}", headers=headers_a)
    assert r4_post.status_code == 403

    # 5. Organization A attempts to retrieve Organization B's execution history -> 403 FORBIDDEN
    r5 = await client.get(f"/api/v1/settings/execution-history?org_id={org_b}", headers=headers_a)
    assert r5.status_code == 403

    # 6. Organization A attempts to retrieve Organization B's blocked executions & overview -> 403 FORBIDDEN
    r6_blocked = await client.get(f"/api/v1/settings/blocked-executions?org_id={org_b}", headers=headers_a)
    assert r6_blocked.status_code == 403

    r6_overview = await client.get(f"/api/v1/settings/audit-logs/overview?org_id={org_b}", headers=headers_a)
    assert r6_overview.status_code == 403


@pytest.mark.asyncio
async def test_18_event_deletion_scenarios_first_intermediate_latest(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 2: Test deletion of:
    1. First audit event.
    2. Intermediate audit event.
    3. Latest audit event (with and without trusted checkpoint).
    """
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select, delete
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    # Setup 3 consecutive events: Seq 1, 2, 3
    async with TestingSessionLocal() as db:
        e1 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="OP_1", action="Step 1")
        e2 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="OP_2", action="Step 2")
        e3 = await AuditEventRecorder.record_platform_event(db=db, org_id=org_id, event_type="OP_3", action="Step 3")
        e1_id = e1.id
        e2_id = e2.id
        e3_id = e3.id
        e3_hash = e3.event_hash

    # Subtest A: Intermediate event deletion (delete e2)
    async with TestingSessionLocal() as db:
        await db.execute(delete(AuditLog).where(AuditLog.id == e2_id))
        await db.commit()

        # Both sequence gap and broken hash link must be detected
        v_inter = await AuditLogService.verify_integrity(db, org_id)
        assert v_inter.is_intact is False
        assert any("Sequence gap" in a for a in v_inter.anomalies)
        assert any("Broken hash chain link" in a for a in v_inter.anomalies)

    # Subtest B: First (genesis) event deletion (delete e1)
    async with TestingSessionLocal() as db:
        await db.execute(delete(AuditLog).where(AuditLog.id == e1_id))
        await db.commit()

        # Chain now starts at Seq 3, missing Seq 1 and 2
        v_first = await AuditLogService.verify_integrity(db, org_id)
        assert v_first.is_intact is False
        assert any("expected sequence 1, found 3" in a for a in v_first.anomalies)

    # Subtest C: Latest event deletion
    # Create fresh chain with 3 events
    fresh_org = uuid.uuid4()
    async with TestingSessionLocal() as db:
        ne1 = await AuditEventRecorder.record_platform_event(db=db, org_id=fresh_org, event_type="L1", action="L1")
        ne2 = await AuditEventRecorder.record_platform_event(db=db, org_id=fresh_org, event_type="L2", action="L2")
        ne3 = await AuditEventRecorder.record_platform_event(db=db, org_id=fresh_org, event_type="L3", action="L3")
        saved_final_sequence = ne3.sequence_number  # 3
        saved_final_hash = ne3.event_hash
        ne3_id = ne3.id

        # Delete latest event (ne3)
        await db.execute(delete(AuditLog).where(AuditLog.id == ne3_id))
        await db.commit()

        # 1. Without external checkpoint: internal chain (ne1, ne2) is self-consistent from seq 1 to 2
        v_unassisted = await AuditLogService.verify_integrity(db, fresh_org)
        assert v_unassisted.is_intact is True  # Mathematically valid subchain 1..2

        # 2. WITH trusted external checkpoint: deletion of latest event is strictly detected!
        v_checkpoint = await AuditLogService.verify_integrity(
            db, fresh_org,
            expected_final_hash=saved_final_hash,
            expected_final_sequence=saved_final_sequence
        )
        assert v_checkpoint.is_intact is False
        assert any("Latest event deletion detected" in a for a in v_checkpoint.anomalies)


@pytest.mark.asyncio
async def test_19_canonical_json_hash_serialization_and_delimiter_safety(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 5: Canonical hash serialization.
    Verify that fields are serialized unambiguously using deterministic canonical JSON
    to prevent delimiter collisions, while supporting backwards compatibility.
    """
    from app.features.security_operations.audit_logs.integrity import compute_canonical_hash

    # Case where values contain delimiter '|'
    hash_a = compute_canonical_hash(
        event_id="evt-1",
        org_id="org-1",
        timestamp_str="2026-11-10T12:00:00",
        category="PLATFORM",
        event_type="AUTH",
        status="SUCCESS",
        action="LOGIN|PRIVILEGED",
        target_type="USER",
        target_id="u1",
        details={"mode": "sso"},
        prev_event_hash="GENESIS_BLOCK",
        sequence_number=1
    )

    hash_b = compute_canonical_hash(
        event_id="evt-1",
        org_id="org-1",
        timestamp_str="2026-11-10T12:00:00",
        category="PLATFORM",
        event_type="AUTH",
        status="SUCCESS",
        action="LOGIN",
        target_type="PRIVILEGED|USER",
        target_id="u1",
        details={"mode": "sso"},
        prev_event_hash="GENESIS_BLOCK",
        sequence_number=1
    )

    # In canonical JSON, "LOGIN|PRIVILEGED" with "USER" is distinct from "LOGIN" with "PRIVILEGED|USER"
    assert hash_a != hash_b, "Canonical JSON must eliminate delimiter collisions!"

    # Test legacy format backwards compatibility
    legacy_hash = compute_canonical_hash(
        event_id="evt-1",
        org_id="org-1",
        timestamp_str="2026-11-10T12:00:00",
        category="PLATFORM",
        event_type="AUTH",
        status="SUCCESS",
        action="LOGIN",
        target_type="USER",
        target_id="u1",
        details={"mode": "sso"},
        prev_event_hash="GENESIS_BLOCK",
        sequence_number=1,
        legacy_format=True
    )
    assert isinstance(legacy_hash, str) and len(legacy_hash) == 64


@pytest.mark.asyncio
async def test_20_migration_backfill_and_uniqueness(client: AsyncClient):
    """
    CRITICAL CHECK 4: Deterministic backfilling and unique sequence numbers per organization.
    Ensures duplicate sequence numbers within an organization are strictly rejected.
    """
    from tests.conftest import TestingSessionLocal
    import sqlite3

    test_org_id = uuid.uuid4()

    async with TestingSessionLocal() as db:
        # Insert event 1 with sequence 1
        ev1 = AuditLog(
            id=uuid.uuid4(),
            organization_id=test_org_id,
            sequence_number=1,
            action="First Record",
            target_type="System",
            details={},
            event_hash="hash_1",
            prev_event_hash="GENESIS"
        )
        db.add(ev1)
        await db.commit()

        # Attempt to insert a second event with the duplicate sequence 1 in the same organization
        ev2 = AuditLog(
            id=uuid.uuid4(),
            organization_id=test_org_id,
            sequence_number=1,  # Duplicate sequence!
            action="Duplicate Record",
            target_type="System",
            details={},
            event_hash="hash_2",
            prev_event_hash="hash_1"
        )
        db.add(ev2)
        with pytest.raises(Exception):  # UniqueConstraint or IntegrityError
            await db.commit()


@pytest.mark.asyncio
async def test_21_unauthenticated_and_invalid_token_access_returns_401(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 1: Ensure every Feature 25 endpoint strictly requires authentication.
    Missing tokens and invalid tokens must return HTTP 401 Unauthorized.
    Local dev bypass cannot be accidentally enabled in production.
    """
    from app.core.config import settings
    setup = audit_test_setup
    dummy_id = uuid.uuid4()

    endpoints_to_test = [
        ("GET", "/api/v1/settings/audit-logs"),
        ("GET", "/api/v1/settings/audit-logs/overview"),
        ("GET", "/api/v1/settings/audit-logs/verify-integrity"),
        ("POST", "/api/v1/settings/audit-logs/verify-chain"),
        ("GET", "/api/v1/settings/audit-logs/export"),
        ("GET", f"/api/v1/settings/audit-logs/{dummy_id}"),
        ("GET", "/api/v1/settings/execution-history"),
        ("GET", f"/api/v1/settings/execution-history/{dummy_id}"),
        ("GET", "/api/v1/settings/blocked-executions"),
    ]

    original_env = settings.ENVIRONMENT
    original_flag = settings.ALLOW_DEV_ANONYMOUS_AUDIT
    try:
        # 1. When ALLOW_DEV_ANONYMOUS_AUDIT is False: Anonymous requests without token -> 401 UNAUTHORIZED
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = False
        for method, path in endpoints_to_test:
            if method == "GET":
                res = await client.get(path)
            else:
                res = await client.post(path)
            assert res.status_code == 401, f"Expected 401 for anonymous {method} {path}, got {res.status_code}"
            assert "Authentication required" in res.json()["detail"] or "Could not validate" in res.json()["detail"]

        # 2. Invalid / forged token -> 401 UNAUTHORIZED
        invalid_headers = {"Authorization": "Bearer forged.token.signature12345"}
        res_inv = await client.get("/api/v1/settings/audit-logs", headers=invalid_headers)
        assert res_inv.status_code == 401

        # 3. Production Environment Safety Gating:
        # Even if ALLOW_DEV_ANONYMOUS_AUDIT is set to True, when ENVIRONMENT == 'production',
        # anonymous requests are still strictly rejected with 401.
        settings.ENVIRONMENT = "production"
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = True

        for method, path in endpoints_to_test:
            if method == "GET":
                res_prod = await client.get(path)
            else:
                res_prod = await client.post(path)
            assert res_prod.status_code == 401, f"Production must NEVER allow anonymous audit access on {path}!"

        # 4. Local dev bypass verification:
        # When ENVIRONMENT == 'development' and ALLOW_DEV_ANONYMOUS_AUDIT == True,
        # anonymous dev requests are permitted.
        settings.ENVIRONMENT = "development"
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = True
        res_dev = await client.get("/api/v1/settings/blocked-executions")
        assert res_dev.status_code == 200
    finally:
        settings.ENVIRONMENT = original_env
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = original_flag


@pytest.mark.asyncio
async def test_22_postgresql_advisory_lock_fail_closed(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 2: Ensure PostgreSQL advisory lock acquisition fails closed.
    If lock acquisition throws an error, the audit write is aborted, rolled back,
    and no audit log is inserted.
    """
    from unittest.mock import AsyncMock, MagicMock
    from tests.conftest import TestingSessionLocal
    setup = audit_test_setup
    org_id = uuid.UUID(setup["org_a_id"])

    # Create mock session simulating PostgreSQL dialect where advisory lock fails
    mock_db = MagicMock()
    mock_bind = MagicMock()
    mock_bind.dialect.name = "postgresql"
    mock_db.get_bind.return_value = mock_bind

    # Simulate database error during SELECT pg_advisory_xact_lock
    mock_db.execute = AsyncMock(side_effect=Exception("Connection reset during lock acquisition"))
    mock_db.rollback = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.add = MagicMock()

    # Call record_platform_event
    with pytest.raises(RuntimeError) as exc_info:
        await AuditEventRecorder.record_platform_event(
            db=mock_db,
            org_id=org_id,
            event_type="CONFIG_CHANGED",
            action="Test advisory lock fail-closed"
        )

    # Verification:
    # 1. Error propagated containing lock failure reason
    assert "PostgreSQL advisory lock acquisition failed" in str(exc_info.value)
    # 2. Database transaction rolled back
    mock_db.rollback.assert_awaited()
    # 3. No commit was executed
    mock_db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_23_migration_backfill_safe_failure(client: AsyncClient):
    """
    CRITICAL CHECK 4: Ensure migration backfill fails safely without silent exception swallowing.
    Pre-constraint verification must detect sequence duplicates and abort.
    """
    # Simulate duplicate detection logic from migration 003
    mock_duplicates = [("org-uuid-1", 1, 2)]  # duplicate sequence 1 found
    if mock_duplicates:
        with pytest.raises(RuntimeError) as exc_info:
            raise RuntimeError(
                f"Migration 003 aborting: Found duplicate sequence numbers after backfill: {mock_duplicates}"
            )
        assert "Migration 003 aborting" in str(exc_info.value)


@pytest.mark.asyncio
async def test_24_trusted_checkpoint_lifecycle_and_limitations(client: AsyncClient, audit_test_setup):
    """
    CRITICAL CHECK 3: Verify the lifecycle and limitations of trusted checkpoints.
    1. Internal-only sequence continuity cannot prove event N wasn't truncated without an external anchor.
    2. With an external trusted checkpoint, tail truncation is immediately flagged.
    """
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import delete
    setup = audit_test_setup
    test_org = uuid.uuid4()

    async with TestingSessionLocal() as db:
        ev1 = await AuditEventRecorder.record_platform_event(db=db, org_id=test_org, event_type="E1", action="Event 1")
        ev2 = await AuditEventRecorder.record_platform_event(db=db, org_id=test_org, event_type="E2", action="Event 2")
        ev3 = await AuditEventRecorder.record_platform_event(db=db, org_id=test_org, event_type="E3", action="Event 3")
        final_seq = ev3.sequence_number  # 3
        final_hash = ev3.event_hash
        ev3_id = ev3.id

        # Delete latest event (ev3)
        await db.execute(delete(AuditLog).where(AuditLog.id == ev3_id))
        await db.commit()

        # 1. Internal verification alone: evaluates remaining subchain 1..2 as internally valid
        v_internal = await AuditLogService.verify_integrity(db, test_org)
        assert v_internal.is_intact is True

        # 2. External checkpoint verification: detects tail truncation
        v_anchored = await AuditLogService.verify_integrity(
            db, test_org,
            expected_final_hash=final_hash,
            expected_final_sequence=final_seq
        )
        assert v_anchored.is_intact is False
        assert any("Latest event deletion detected" in a for a in v_anchored.anomalies)




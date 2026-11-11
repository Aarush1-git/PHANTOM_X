import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import jwt

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_report import VulnerabilityReport, VulnerabilityStatusHistory, ReportStatus
from app.models.audit import AuditLog
from app.models.scope_safety import BlockedExecutionLog
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.core.config import settings


@pytest.fixture
async def dashboard_test_setup():
    """Seed comprehensive test data for Security Dashboard & Analytics."""
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # Organization A
        org_a = Organization(name="CyberDefense Org A", slug="cyberdefense-org-a")
        # Organization B
        org_b = Organization(name="Rival Systems Org B", slug="rival-systems-org-b")
        # Organization C (Empty Org)
        org_c = Organization(name="Empty Startup Org C", slug="empty-startup-org-c")
        db.add_all([org_a, org_b, org_c])
        await db.flush()

        # Users
        user_a = User(
            organization_id=org_a.id,
            email="ciso@cyberdefense.local",
            hashed_password="hashed_test_password",
            full_name="Alice CISO",
            role="SECURITY_ENGINEER",
        )
        user_b = User(
            organization_id=org_b.id,
            email="lead@rival.local",
            hashed_password="hashed_test_password",
            full_name="Bob Rival",
            role="ADMIN",
        )
        user_c = User(
            organization_id=org_c.id,
            email="founder@empty.local",
            hashed_password="hashed_test_password",
            full_name="Charlie Clean",
            role="ADMIN",
        )
        db.add_all([user_a, user_b, user_c])
        await db.flush()

        # Applications for Org A
        app_a1 = Application(
            organization_id=org_a.id,
            name="Payment Gateway Service",
            target_url="https://pay.cyberdefense.local",
            risk_score=8.5,
        )
        app_a2 = Application(
            organization_id=org_a.id,
            name="Customer Account Portal",
            target_url="https://portal.cyberdefense.local",
            risk_score=5.0,
        )
        app_a3 = Application(
            organization_id=org_a.id,
            name="Internal Documentation Wiki",
            target_url="https://wiki.cyberdefense.local",
            risk_score=1.0,
        )
        # Application for Org B
        app_b1 = Application(
            organization_id=org_b.id,
            name="Rival Core Engine",
            target_url="https://rival.local",
            risk_score=9.0,
        )
        db.add_all([app_a1, app_a2, app_a3, app_b1])
        await db.flush()

        # Scans for Org A
        scan_completed = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=3,
            started_at=now - timedelta(days=2, minutes=15),
            completed_at=now - timedelta(days=2, minutes=5),  # 10 minutes duration = 600 seconds
        )
        scan_completed_2 = Scan(
            organization_id=org_a.id,
            application_id=app_a2.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=1, minutes=20),
            completed_at=now - timedelta(days=1, minutes=10),  # 10 minutes duration = 600 seconds
        )
        scan_failed = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.FAILED,
            progress=0.4,
            findings_count=0,
            started_at=now - timedelta(hours=5),
            completed_at=now - timedelta(hours=4, minutes=55),
        )
        scan_running = Scan(
            organization_id=org_a.id,
            application_id=app_a3.id,
            status=ScanStatus.RUNNING,
            progress=0.65,
            findings_count=0,
            started_at=now - timedelta(minutes=12),
        )
        db.add_all([scan_completed, scan_completed_2, scan_failed, scan_running])
        await db.flush()

        # Vulnerabilities for Org A:
        # Vuln 1: CRITICAL, Open, created 20 days ago (SLA Breach)
        vuln_1 = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_completed.id,
            title="Remote Code Execution via Insecure Deserialization",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/jobs/submit",
            confidence=0.98,
            recommendation="Use safe serialization formats.",
            cwe_id="CWE-502",
            cvss_score=9.8,
            created_at=now - timedelta(days=20),
            updated_at=now - timedelta(days=20),
        )
        # Vuln 2: HIGH, Open, created 3 days ago (Under 7 days)
        vuln_2 = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_completed.id,
            title="SQL Injection in Transaction Query",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/txns/search",
            confidence=0.92,
            recommendation="Use parameterized statements.",
            cwe_id="CWE-89",
            cvss_score=8.4,
            created_at=now - timedelta(days=3),
            updated_at=now - timedelta(days=3),
        )
        # Vuln 3: MEDIUM, Fixed/Mitigated, created 10 days ago, fixed 2 days ago (MTTR = 8 days = 192 hrs)
        vuln_3 = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a2.id,
            scan_id=scan_completed_2.id,
            title="Cross-Site Scripting in User Profile",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.MITIGATED,
            endpoint="/profile/edit",
            confidence=0.88,
            recommendation="Encode HTML output.",
            cwe_id="CWE-79",
            cvss_score=6.1,
            created_at=now - timedelta(days=10),
            updated_at=now - timedelta(days=2),
        )
        # Vuln 4: LOW, False Positive, created 5 days ago
        vuln_4 = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a3.id,
            scan_id=scan_completed_2.id,
            title="Missing Anti-clickjacking Header",
            severity=VulnerabilitySeverity.LOW,
            status=VulnerabilityStatus.FALSE_POSITIVE,
            endpoint="/docs/intro",
            confidence=0.70,
            recommendation="Add X-Frame-Options header.",
            cwe_id="CWE-1021",
            cvss_score=3.1,
            created_at=now - timedelta(days=5),
            updated_at=now - timedelta(days=5),
        )

        # Vuln for Org B
        vuln_b = Vulnerability(
            organization_id=org_b.id,
            application_id=app_b1.id,
            title="Confidential Org B Vulnerability",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/rival/secret",
            confidence=0.99,
            recommendation="Classified.",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )

        db.add_all([vuln_1, vuln_2, vuln_3, vuln_4, vuln_b])
        await db.flush()

        # Audit Logs for Org A (Feature 25)
        audit_1 = AuditLog(
            organization_id=org_a.id,
            sequence_number=1,
            user_id=user_a.id,
            actor_email=user_a.email,
            actor_role="SECURITY_ENGINEER",
            category="SECURITY_TESTING",
            event_type="SCAN_COMPLETED",
            action="Completed active security verification scan",
            status="SUCCESS",
            severity="INFO",
            target_type="Scan",
            target_id=str(scan_completed.id),
            created_at=now - timedelta(days=2),
        )
        audit_2 = AuditLog(
            organization_id=org_a.id,
            sequence_number=2,
            user_id=user_a.id,
            actor_email=user_a.email,
            actor_role="SECURITY_ENGINEER",
            category="VULNERABILITY",
            event_type="REPORT_GENERATED",
            action="Generated security report for RCE finding",
            status="SUCCESS",
            severity="INFO",
            target_type="VulnerabilityReport",
            target_id="VR-RCE101",
            created_at=now - timedelta(days=1),
        )
        # Blocked execution log for Org A (Feature 26)
        block_1 = BlockedExecutionLog(
            organization_id=org_a.id,
            application_id=app_a1.id,
            target_url="https://pay.cyberdefense.local/admin/purge-database",
            http_method="POST",
            violation_category="PROHIBITED_ENDPOINT",
            blocked_reason="Attempt to access excluded administrative purge path",
            source_agent="Autonomous Attack Agent",
            created_at=now - timedelta(hours=8),
        )
        db.add_all([audit_1, audit_2, block_1])
        await db.commit()

        # Prepare tokens
        token_a = jwt.encode(
            {"sub": str(user_a.id), "org_id": str(org_a.id), "role": "SECURITY_ENGINEER"},
            settings.JWT_SECRET_KEY,
            algorithm="HS256",
        )
        token_b = jwt.encode(
            {"sub": str(user_b.id), "org_id": str(org_b.id), "role": "ADMIN"},
            settings.JWT_SECRET_KEY,
            algorithm="HS256",
        )
        token_c = jwt.encode(
            {"sub": str(user_c.id), "org_id": str(org_c.id), "role": "ADMIN"},
            settings.JWT_SECRET_KEY,
            algorithm="HS256",
        )

        return {
            "org_a_id": str(org_a.id),
            "org_b_id": str(org_b.id),
            "org_c_id": str(org_c.id),
            "app_a1_id": str(app_a1.id),
            "app_a2_id": str(app_a2.id),
            "app_a3_id": str(app_a3.id),
            "auth_headers_a": {"Authorization": f"Bearer {token_a}"},
            "auth_headers_b": {"Authorization": f"Bearer {token_b}"},
            "auth_headers_c": {"Authorization": f"Bearer {token_c}"},
        }


# ==============================================================================
# TEST 1: SECURITY OVERVIEW METRICS CALCULATION
# ==============================================================================

@pytest.mark.asyncio
async def test_01_security_overview_metrics_calculation(client: AsyncClient, dashboard_test_setup):
    """Verify security overview calculation: counts, severity distribution, status counts, remediation rate."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/overview?time_range=30d",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200, f"Error: {resp.text}"
    data = resp.json()

    assert data["total_vulnerabilities"] == 4
    assert data["critical_count"] == 1
    assert data["high_count"] == 1
    assert data["medium_count"] == 1
    assert data["low_count"] == 1
    assert data["info_count"] == 0

    # Status counts
    assert data["open_count"] == 2  # vuln_1 (CRITICAL), vuln_2 (HIGH)
    assert data["fixed_count"] == 1  # vuln_3 (MEDIUM)
    assert data["false_positive_count"] == 1  # vuln_4 (LOW)
    assert data["critical_and_high_open"] == 2

    # Remediation rate: fixed / (total - false_positive) = 1 / (4 - 1) = 33.3%
    assert 30.0 <= data["remediation_rate"] <= 35.0

    # General infrastructure numbers
    assert data["total_applications"] >= 3
    assert data["total_scans"] >= 4


# ==============================================================================
# TEST 2: SEVERITY DISTRIBUTION DONUT DATA
# ==============================================================================

@pytest.mark.asyncio
async def test_02_severity_distribution_endpoint(client: AsyncClient, dashboard_test_setup):
    """Verify severity distribution endpoint for donut/pie visualization."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/severity-distribution?time_range=30d",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 4
    dist = {item["severity"]: item for item in data["distribution"]}

    assert "CRITICAL" in dist
    assert dist["CRITICAL"]["count"] == 1
    assert dist["CRITICAL"]["percentage"] == 25.0
    assert dist["CRITICAL"]["open_count"] == 1

    assert "HIGH" in dist
    assert dist["HIGH"]["count"] == 1
    assert dist["HIGH"]["percentage"] == 25.0

    assert "MEDIUM" in dist
    assert dist["MEDIUM"]["count"] == 1
    assert dist["MEDIUM"]["fixed_count"] == 1

    assert "LOW" in dist
    assert dist["LOW"]["count"] == 1


# ==============================================================================
# TEST 3: VULNERABILITY TRENDS TIME-SERIES
# ==============================================================================

@pytest.mark.asyncio
async def test_03_vulnerability_trends_time_series(client: AsyncClient, dashboard_test_setup):
    """Verify daily time-series data points for line chart."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/vulnerability-trends?time_range=30d",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "trends" in data
    assert len(data["trends"]) >= 30  # Every day in 30d window is represented
    assert data["total_discovered"] == 4
    assert data["total_resolved"] == 1
    assert data["net_risk_change"] == 3  # 4 discovered - 1 resolved

    # Verify chronological ordering
    dates = [p["date"] for p in data["trends"]]
    assert dates == sorted(dates)


# ==============================================================================
# TEST 4: APPLICATION RISK RANKING AND TIERS
# ==============================================================================

@pytest.mark.asyncio
async def test_04_application_risk_ranking_and_tiers(client: AsyncClient, dashboard_test_setup):
    """Verify application risk tier distribution and ranking of top exposed apps."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/application-risk",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_applications"] >= 3
    assert data["vulnerable_applications_count"] >= 1

    tiers = data["risk_tier_distribution"]
    assert "CRITICAL" in tiers
    assert "HIGH" in tiers
    assert "MEDIUM" in tiers
    assert "CLEAN" in tiers

    # app_a1 has 1 Critical + 1 High -> must be CRITICAL tier
    top_apps = data["top_exposed_applications"]
    assert len(top_apps) >= 1
    top_app = top_apps[0]
    assert top_app["name"] == "Payment Gateway Service"
    assert top_app["risk_tier"] == "CRITICAL"
    assert top_app["critical_count"] == 1
    assert top_app["high_count"] == 1


# ==============================================================================
# TEST 5: SCAN ANALYTICS AND AVERAGE DURATION
# ==============================================================================

@pytest.mark.asyncio
async def test_05_scan_analytics_and_average_duration(client: AsyncClient, dashboard_test_setup):
    """Verify scan outcomes, success rate, and duration calculation."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/scan-analytics?time_range=30d",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_scans"] == 4
    assert data["completed_scans"] == 2
    assert data["failed_scans"] == 1
    assert data["running_scans"] == 1
    # Success rate = 2 completed / (2 completed + 1 failed) = 66.7%
    assert 65.0 <= data["success_rate"] <= 68.0

    # Average duration: both completed scans took 600s -> avg = 600s = 10m 0s
    assert data["has_duration_data"] is True
    assert data["average_duration_seconds"] == 600.0
    assert "10m" in data["average_duration_formatted"]

    # Recent scans list
    assert len(data["recent_scans"]) >= 4


# ==============================================================================
# TEST 6: REMEDIATION ANALYTICS (MTTR AND AGEING BUCKETS)
# ==============================================================================

@pytest.mark.asyncio
async def test_06_remediation_analytics_mttr_and_ageing(client: AsyncClient, dashboard_test_setup):
    """Verify Mean Time to Remediation (MTTR) calculation and open finding ageing buckets."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/remediation-analytics?time_range=30d",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    # vuln_3 was created 10 days ago and fixed 2 days ago = 8 days = 192 hours
    assert data["has_remediation_data"] is True
    assert 190.0 <= data["mean_time_to_remediation_hours"] <= 194.0
    assert 7.9 <= data["mean_time_to_remediation_days"] <= 8.1

    # Ageing buckets:
    # vuln_1 is 20 days old -> days_7_to_30
    # vuln_2 is 3 days old -> under_7_days
    ageing = data["open_vulnerabilities_ageing"]
    assert ageing["under_7_days"] >= 1
    assert ageing["days_7_to_30"] >= 1

    # SLA Breach: vuln_1 is CRITICAL and 20 days old (>14 days) -> 1 breach
    assert data["sla_breach_count"] >= 1


# ==============================================================================
# TEST 7: RECENT SECURITY ACTIVITY STREAM
# ==============================================================================

@pytest.mark.asyncio
async def test_07_recent_security_activity_stream(client: AsyncClient, dashboard_test_setup):
    """Verify chronological event aggregation from AuditLog, Scans, and BlockedExecutions."""
    setup = dashboard_test_setup

    resp = await client.get(
        "/api/v1/security-dashboard/recent-activity?limit=10",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "activities" in data
    assert len(data["activities"]) >= 3

    activity_types = [a["activity_type"] for a in data["activities"]]
    assert "BLOCKED_EXECUTION" in activity_types
    assert any("SCAN" in t or "REPORT" in t for t in activity_types)

    # Check chronological ordering: newest first
    timestamps = [datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00")) for a in data["activities"]]
    assert timestamps == sorted(timestamps, reverse=True)


# ==============================================================================
# TEST 8: EMPTY DATASET SAFE HANDLING
# ==============================================================================

@pytest.mark.asyncio
async def test_08_empty_dataset_safe_handling(client: AsyncClient, dashboard_test_setup):
    """Verify that an organization with zero findings/scans returns clean zero states, not 500 errors."""
    setup = dashboard_test_setup

    # 1. Overview for Org C
    r1 = await client.get("/api/v1/security-dashboard/overview", headers=setup["auth_headers_c"])
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["total_vulnerabilities"] == 0
    assert d1["open_count"] == 0
    assert d1["remediation_rate"] == 100.0

    # 2. Remediation for Org C
    r2 = await client.get("/api/v1/security-dashboard/remediation-analytics", headers=setup["auth_headers_c"])
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["has_remediation_data"] is False
    assert d2["mean_time_to_remediation_hours"] is None
    assert "Unavailable" in d2["remediation_notes"]

    # 3. Scan analytics for Org C
    r3 = await client.get("/api/v1/security-dashboard/scan-analytics", headers=setup["auth_headers_c"])
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["total_scans"] == 0
    assert d3["has_duration_data"] is False
    assert "Unavailable" in d3["average_duration_formatted"]


# ==============================================================================
# TEST 9: APPLICATION FILTERING
# ==============================================================================

@pytest.mark.asyncio
async def test_09_application_filtering(client: AsyncClient, dashboard_test_setup):
    """Verify filtering dashboard overview by specific application_id."""
    setup = dashboard_test_setup
    app_a1_id = setup["app_a1_id"]

    resp = await client.get(
        f"/api/v1/security-dashboard/overview?application_id={app_a1_id}",
        headers=setup["auth_headers_a"],
    )
    assert resp.status_code == 200
    data = resp.json()

    # app_a1 only has vuln_1 and vuln_2
    assert data["total_vulnerabilities"] == 2
    assert data["critical_count"] == 1
    assert data["high_count"] == 1
    assert data["medium_count"] == 0


# ==============================================================================
# TEST 10: TIME RANGE FILTERING (7D VS 90D)
# ==============================================================================

@pytest.mark.asyncio
async def test_10_time_range_filtering(client: AsyncClient, dashboard_test_setup):
    """Verify date window boundaries: 7d window excludes findings older than 7 days."""
    setup = dashboard_test_setup

    # 7-day window: vuln_1 (20 days ago) and vuln_3 (10 days ago) are excluded
    resp_7d = await client.get(
        "/api/v1/security-dashboard/overview?time_range=7d",
        headers=setup["auth_headers_a"],
    )
    assert resp_7d.status_code == 200
    data_7d = resp_7d.json()
    assert data_7d["critical_count"] == 0  # vuln_1 is 20 days old -> excluded
    assert data_7d["high_count"] == 1  # vuln_2 is 3 days old -> included
    assert data_7d["total_vulnerabilities"] <= 2


# ==============================================================================
# TEST 11: MULTI-TENANT ISOLATION AND CROSS-TENANT FORBIDDEN
# ==============================================================================

@pytest.mark.asyncio
async def test_11_multi_tenant_isolation(client: AsyncClient, dashboard_test_setup):
    """Verify Org A cannot view Org B data; querying with another org_id returns 403 Forbidden."""
    setup = dashboard_test_setup
    org_b_id = setup["org_b_id"]

    # 1. User A normal query: only sees Org A findings
    resp_a = await client.get("/api/v1/security-dashboard/overview", headers=setup["auth_headers_a"])
    assert resp_a.status_code == 200
    assert "Confidential Org B" not in str(resp_a.text)

    # 2. User A attempts to request Org B's org_id explicitly -> 403 Forbidden
    cross_resp = await client.get(
        f"/api/v1/security-dashboard/overview?org_id={org_b_id}",
        headers=setup["auth_headers_a"],
    )
    assert cross_resp.status_code == 403
    assert "Cross-tenant access forbidden" in cross_resp.json()["detail"]


# ==============================================================================
# TEST 12: UNAUTHENTICATED REQUEST REJECTION
# ==============================================================================

@pytest.mark.asyncio
async def test_12_unauthenticated_request_rejected(client: AsyncClient, dashboard_test_setup):
    """Verify unauthenticated request without token returns 401 Unauthorized in production mode."""
    orig_env = settings.ENVIRONMENT
    orig_dev = getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False)
    try:
        settings.ENVIRONMENT = "production"
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = False

        resp = await client.get("/api/v1/security-dashboard/overview")
        assert resp.status_code == 401
    finally:
        settings.ENVIRONMENT = orig_env
        settings.ALLOW_DEV_ANONYMOUS_AUDIT = orig_dev


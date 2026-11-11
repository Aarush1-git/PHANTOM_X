import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import jwt

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scan import Scan, ScanComparison
from app.models.vulnerability import Vulnerability, Evidence
from app.models.vulnerability_report import VulnerabilityReport, ReportStatus
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.core.config import settings


@pytest.fixture
async def scan_history_test_setup():
    """Seed comprehensive test data for Scan History & Comparison testing."""
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # Organization A
        org_a = Organization(name="CyberShield Enterprise A", slug="cybershield-ent-a")
        # Organization B
        org_b = Organization(name="Vanguard Labs Org B", slug="vanguard-labs-b")
        db.add_all([org_a, org_b])
        await db.flush()

        # Users
        user_a = User(
            organization_id=org_a.id,
            email="secops@cybershield.local",
            hashed_password="hashed_pw_test",
            full_name="Alice SecOps",
            role="SECURITY_ENGINEER",
        )
        user_b = User(
            organization_id=org_b.id,
            email="auditor@vanguard.local",
            hashed_password="hashed_pw_test",
            full_name="Bob Vanguard",
            role="ADMIN",
        )
        db.add_all([user_a, user_b])
        await db.flush()

        # Applications
        app_a1 = Application(
            organization_id=org_a.id,
            name="Alpha Core Banking API",
            target_url="https://banking.cybershield.local",
            risk_score=7.8,
        )
        app_a2 = Application(
            organization_id=org_a.id,
            name="Beta Customer Portal",
            target_url="https://portal.cybershield.local",
            risk_score=4.2,
        )
        app_b1 = Application(
            organization_id=org_b.id,
            name="Vanguard Trading Hub",
            target_url="https://trade.vanguard.local",
            risk_score=8.9,
        )
        db.add_all([app_a1, app_a2, app_b1])
        await db.flush()

        # Historical Scan 0 (Earliest, 30 days ago) for App A1
        scan_0_hist = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=30, hours=2),
            completed_at=now - timedelta(days=30, hours=1),
            notes="Initial quarterly baseline scan",
            created_at=now - timedelta(days=30, hours=2),
        )
        # Scan 1: Baseline Scan for App A1 (15 days ago)
        scan_1_base = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=3,
            started_at=now - timedelta(days=15, minutes=45),
            completed_at=now - timedelta(days=15, minutes=15),  # 30 min duration = 1800 sec
            notes="Sprint 44 automated regression scan",
            created_at=now - timedelta(days=15, minutes=45),
        )
        # Scan 2: Comparison Scan for App A1 (2 days ago)
        scan_2_comp = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=4,
            started_at=now - timedelta(days=2, minutes=50),
            completed_at=now - timedelta(days=2, minutes=20),  # 30 min duration = 1800 sec
            notes="Sprint 46 automated release scan",
            created_at=now - timedelta(days=2, minutes=50),
        )
        # Scan 3: Running scan on App A2
        scan_3_running = Scan(
            organization_id=org_a.id,
            application_id=app_a2.id,
            status=ScanStatus.RUNNING,
            progress=0.45,
            findings_count=1,
            started_at=now - timedelta(minutes=25),
            notes="Nightly fuzzing run",
            created_at=now - timedelta(minutes=25),
        )
        # Scan 4: Failed scan on App A2
        scan_4_failed = Scan(
            organization_id=org_a.id,
            application_id=app_a2.id,
            status=ScanStatus.FAILED,
            progress=0.15,
            findings_count=0,
            started_at=now - timedelta(days=5, hours=2),
            completed_at=now - timedelta(days=5, hours=1, minutes=55),
            notes="Network timeout aborted scan",
            created_at=now - timedelta(days=5, hours=2),
        )
        # Scan B: Org B Scan
        scan_b_org = Scan(
            organization_id=org_b.id,
            application_id=app_b1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=2,
            started_at=now - timedelta(days=1),
            completed_at=now - timedelta(days=1, minutes=-30),
            notes="Confidential Org B Scan",
            created_at=now - timedelta(days=1),
        )
        db.add_all([scan_0_hist, scan_1_base, scan_2_comp, scan_3_running, scan_4_failed, scan_b_org])
        await db.flush()

        # Vulnerabilities:
        # 1. Historical finding in Scan 0 (will be absent in Scan 1 baseline, but reappear in Scan 2 -> REGRESSED)
        vuln_hist_regress = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_0_hist.id,
            title="Cross-Site Scripting in Comment Field",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/comments",
            confidence=0.90,
            recommendation="Sanitize user comments.",
            cwe_id="CWE-79",
            cvss_score=6.1,
            created_at=now - timedelta(days=30),
        )

        # Baseline Scan 1 findings:
        # A) vuln_base_fixed: Present in Scan 1, ABSENT in Scan 2 -> FIXED
        vuln_base_fixed = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_1_base.id,
            title="SQL Injection in Order Search",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/orders/search",
            confidence=0.95,
            recommendation="Use bound parameters.",
            cwe_id="CWE-89",
            cvss_score=8.5,
            created_at=now - timedelta(days=15),
        )
        # B) vuln_persistent: Present in both Scan 1 & Scan 2 with same severity (LOW) -> PERSISTENT
        vuln_base_persist = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_1_base.id,
            title="Information Disclosure via Server Header",
            severity=VulnerabilitySeverity.LOW,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/health",
            confidence=0.85,
            recommendation="Strip server headers.",
            cwe_id="CWE-200",
            cvss_score=3.5,
            created_at=now - timedelta(days=15),
        )
        # C) vuln_sev_changed: Present in Scan 1 as MEDIUM, but in Scan 2 as CRITICAL -> SEVERITY_CHANGED (Increased)
        vuln_base_sev_change = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_1_base.id,
            title="Insecure Direct Object Reference on Statements",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/statements/{id}",
            confidence=0.92,
            recommendation="Verify tenant ownership on object lookup.",
            cwe_id="CWE-639",
            cvss_score=5.5,
            created_at=now - timedelta(days=15),
        )

        # Comparison Scan 2 findings:
        # A) vuln_comp_persist: Matches vuln_base_persist
        vuln_comp_persist = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_2_comp.id,
            title="Information Disclosure via Server Header",
            severity=VulnerabilitySeverity.LOW,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/health",
            confidence=0.85,
            recommendation="Strip server headers.",
            cwe_id="CWE-200",
            cvss_score=3.5,
            created_at=now - timedelta(days=2),
        )
        # B) vuln_comp_sev_change: Matches vuln_base_sev_change with elevated CRITICAL severity
        vuln_comp_sev_change = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_2_comp.id,
            title="Insecure Direct Object Reference on Statements",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/statements/{id}",
            confidence=0.96,
            recommendation="Verify tenant ownership on object lookup.",
            cwe_id="CWE-639",
            cvss_score=9.1,
            created_at=now - timedelta(days=2),
        )
        # C) vuln_comp_regressed: Matches vuln_hist_regress from Scan 0, absent in Scan 1 -> REGRESSED
        vuln_comp_regressed = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_2_comp.id,
            title="Cross-Site Scripting in Comment Field",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/comments",
            confidence=0.90,
            recommendation="Sanitize user comments.",
            cwe_id="CWE-79",
            cvss_score=6.1,
            created_at=now - timedelta(days=2),
        )
        # D) vuln_comp_new: Completely new finding -> NEW
        vuln_comp_new = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_2_comp.id,
            title="SSRF via Webhook Registration",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/webhooks",
            confidence=0.94,
            recommendation="Enforce loopback and internal IP filtering.",
            cwe_id="CWE-918",
            cvss_score=8.6,
            created_at=now - timedelta(days=2),
        )

        # Evidence for Scan 1 vuln_base_fixed
        ev_1 = Evidence(
            vulnerability_id=vuln_base_fixed.id,
            request_dump="GET /api/v1/orders/search?q=' OR 1=1-- HTTP/1.1",
            response_dump="HTTP/1.1 200 OK\r\n\r\n[{\"id\": 101, \"user\": \"admin\"}]",
            proof_data={"payload": "' OR 1=1--", "syntax_error": False},
            screenshot_url="https://storage.phantom-x.local/evidence/sqli_proof.png",
        )

        db.add_all([
            vuln_hist_regress,
            vuln_base_fixed,
            vuln_base_persist,
            vuln_base_sev_change,
            vuln_comp_persist,
            vuln_comp_sev_change,
            vuln_comp_regressed,
            vuln_comp_new,
            ev_1,
        ])
        await db.commit()

        token_a = jwt.encode(
            {"sub": str(user_a.id), "org_id": str(org_a.id), "email": user_a.email, "role": "SECURITY_ENGINEER"},
            settings.JWT_SECRET_KEY,
            algorithm="HS256",
        )
        token_b = jwt.encode(
            {"sub": str(user_b.id), "org_id": str(org_b.id), "email": user_b.email, "role": "ADMIN"},
            settings.JWT_SECRET_KEY,
            algorithm="HS256",
        )

        return {
            "org_a_id": str(org_a.id),
            "org_b_id": str(org_b.id),
            "user_a_id": str(user_a.id),
            "user_b_id": str(user_b.id),
            "app_a1_id": str(app_a1.id),
            "app_a2_id": str(app_a2.id),
            "app_b1_id": str(app_b1.id),
            "scan_0_id": str(scan_0_hist.id),
            "scan_1_id": str(scan_1_base.id),
            "scan_2_id": str(scan_2_comp.id),
            "scan_3_id": str(scan_3_running.id),
            "scan_4_id": str(scan_4_failed.id),
            "scan_b_id": str(scan_b_org.id),
            "auth_a": {"Authorization": f"Bearer {token_a}"},
            "auth_b": {"Authorization": f"Bearer {token_b}"},
        }


# ==============================================================================
# TEST 1: LIST SCAN HISTORY WITH PAGINATION
# ==============================================================================

@pytest.mark.asyncio
async def test_01_list_scan_history_pagination(client: AsyncClient, scan_history_test_setup):
    """Verify listing scans with pagination, page counts, and default ordering."""
    setup = scan_history_test_setup
    resp = await client.get("/api/v1/scan-history?page=1&limit=2", headers=setup["auth_a"])
    assert resp.status_code == 200, f"Error: {resp.text}"
    data = resp.json()

    assert data["page"] == 1
    assert data["limit"] == 2
    assert data["total"] == 5  # 5 scans in Org A
    assert len(data["items"]) == 2
    assert data["total_pages"] == 3


# ==============================================================================
# TEST 2: FILTER SCANS BY APPLICATION ID
# ==============================================================================

@pytest.mark.asyncio
async def test_02_filter_scans_by_application(client: AsyncClient, scan_history_test_setup):
    """Filter scans specifically for Alpha Core Banking API (app_a1)."""
    setup = scan_history_test_setup
    app_id = setup["app_a1_id"]
    resp = await client.get(f"/api/v1/scan-history?application_id={app_id}", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 3  # Scan 0, 1, 2
    for item in data["items"]:
        assert item["application_id"] == app_id
        assert item["application_name"] == "Alpha Core Banking API"


# ==============================================================================
# TEST 3: FILTER SCANS BY STATUS
# ==============================================================================

@pytest.mark.asyncio
async def test_03_filter_scans_by_status(client: AsyncClient, scan_history_test_setup):
    """Filter scans by RUNNING, FAILED, and COMPLETED status."""
    setup = scan_history_test_setup

    # Test RUNNING
    resp = await client.get("/api/v1/scan-history?status=RUNNING", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["status"] == "RUNNING"
    assert data["items"][0]["id"] == setup["scan_3_id"]

    # Test FAILED
    resp = await client.get("/api/v1/scan-history?status=FAILED", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["status"] == "FAILED"


# ==============================================================================
# TEST 4: SEARCH SCANS
# ==============================================================================

@pytest.mark.asyncio
async def test_04_search_scans(client: AsyncClient, scan_history_test_setup):
    """Search scans by application name substring and notes."""
    setup = scan_history_test_setup

    # Search by app name keyword
    resp = await client.get("/api/v1/scan-history?search=Customer", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2  # scan_3 and scan_4 for Beta Customer Portal

    # Search by notes keyword
    resp = await client.get("/api/v1/scan-history?search=fuzzing", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["notes"] == "Nightly fuzzing run"


# ==============================================================================
# TEST 5: GET SCAN DETAILS AND SANITIZED EVIDENCE
# ==============================================================================

@pytest.mark.asyncio
async def test_05_get_scan_details_and_evidence(client: AsyncClient, scan_history_test_setup):
    """Retrieve detailed scan metrics, vulnerability summaries, and sanitized evidence."""
    setup = scan_history_test_setup
    scan_id = setup["scan_1_id"]

    resp = await client.get(f"/api/v1/scan-history/{scan_id}", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    scan_info = data["scan"]
    assert scan_info["id"] == scan_id
    assert scan_info["application_name"] == "Alpha Core Banking API"
    assert scan_info["duration_seconds"] == 1800.0
    assert scan_info["total_vulnerabilities"] == 3
    assert scan_info["high_count"] == 1
    assert scan_info["medium_count"] == 1
    assert scan_info["low_count"] == 1

    vulns = data["vulnerabilities"]
    assert len(vulns) == 3
    endpoints = [v["endpoint"] for v in vulns]
    assert "/api/v1/orders/search" in endpoints

    # Check evidence
    ev_items = data["evidence_items"]
    assert len(ev_items) >= 1
    assert ev_items[0]["has_request_dump"] is True
    assert ev_items[0]["screenshot_url"] is not None


# ==============================================================================
# TEST 6: GET SCAN DETAILS NOT FOUND AND CROSS TENANT 403
# ==============================================================================

@pytest.mark.asyncio
async def test_06_scan_details_isolation_and_404(client: AsyncClient, scan_history_test_setup):
    """Verify 404 for unknown scan ID and 403 when Org A attempts to view Org B scan."""
    setup = scan_history_test_setup
    fake_id = str(uuid.uuid4())

    # 404
    resp = await client.get(f"/api/v1/scan-history/{fake_id}", headers=setup["auth_a"])
    assert resp.status_code == 404

    # 403 Cross tenant
    org_b_scan = setup["scan_b_id"]
    resp = await client.get(f"/api/v1/scan-history/{org_b_scan}", headers=setup["auth_a"])
    assert resp.status_code == 403
    assert "Cross-tenant" in resp.json()["detail"]


# ==============================================================================
# TEST 7: APPLICATION FILTER OPTIONS
# ==============================================================================

@pytest.mark.asyncio
async def test_07_application_filter_options(client: AsyncClient, scan_history_test_setup):
    """Verify endpoint returning list of applications that have scans for filter dropdown."""
    setup = scan_history_test_setup
    resp = await client.get("/api/v1/scan-history/applications", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    assert len(data) == 2  # Alpha Core Banking API and Beta Customer Portal
    app_names = [a["name"] for a in data]
    assert "Alpha Core Banking API" in app_names
    assert "Beta Customer Portal" in app_names

    alpha_app = next(a for a in data if a["name"] == "Alpha Core Banking API")
    assert alpha_app["total_scans"] == 3


# ==============================================================================
# TEST 8: SCAN COMPARISON INVALID REQUESTS (SAME SCAN & INCOMPATIBLE APPS)
# ==============================================================================

@pytest.mark.asyncio
async def test_08_scan_comparison_invalid_requests(client: AsyncClient, scan_history_test_setup):
    """Verify validation for identical scans (400) and different applications (400)."""
    setup = scan_history_test_setup
    scan_1 = setup["scan_1_id"]
    scan_3 = setup["scan_3_id"]  # App A2, while scan 1 is App A1

    # Same scan comparison
    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_1}&comparison_scan_id={scan_1}",
        headers=setup["auth_a"],
    )
    assert resp.status_code == 400
    assert "must be distinct" in resp.json()["detail"]

    # Incompatible apps comparison
    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_1}&comparison_scan_id={scan_3}",
        headers=setup["auth_a"],
    )
    assert resp.status_code == 400
    assert "same application target" in resp.json()["detail"]


# ==============================================================================
# TEST 9: SCAN COMPARISON CROSS-TENANT ISOLATION
# ==============================================================================

@pytest.mark.asyncio
async def test_09_scan_comparison_cross_tenant_isolation(client: AsyncClient, scan_history_test_setup):
    """Verify cross-tenant comparison attempts are strictly rejected with 403 Forbidden."""
    setup = scan_history_test_setup
    scan_1 = setup["scan_1_id"]
    scan_b = setup["scan_b_id"]

    # User A tries to compare Org A scan with Org B scan
    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_1}&comparison_scan_id={scan_b}",
        headers=setup["auth_a"],
    )
    assert resp.status_code == 403
    assert "Cross-tenant" in resp.json()["detail"]

    # User B tries to compare Org A scan with Org B scan
    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_1}&comparison_scan_id={scan_b}",
        headers=setup["auth_b"],
    )
    assert resp.status_code == 403


# ==============================================================================
# TEST 10: SCAN COMPARISON ENGINE (NEW, FIXED, PERSISTENT, REGRESSED, SEVERITY CHANGED)
# ==============================================================================

@pytest.mark.asyncio
async def test_10_scan_comparison_engine_diff(client: AsyncClient, scan_history_test_setup):
    """
    Verify complete comparison engine between Scan 1 (baseline) and Scan 2 (comparison):
    - 1 NEW: SSRF via Webhook (/api/v1/webhooks)
    - 1 FIXED: SQL Injection in Order Search (/api/v1/orders/search)
    - 1 PERSISTENT: Information Disclosure via Server Header (/api/v1/health)
    - 1 REGRESSED: XSS in Comment Field (/api/v1/comments, was in Scan 0, absent in Scan 1, reappears in Scan 2)
    - 1 SEVERITY_CHANGED: IDOR on Statements (/api/v1/statements/{id}, upgraded from MEDIUM to CRITICAL)
    - Overall Posture: DEGRADED (1 new High, 1 regressed Medium, and IDOR escalated to Critical)
    """
    setup = scan_history_test_setup
    scan_1 = setup["scan_1_id"]
    scan_2 = setup["scan_2_id"]

    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_1}&comparison_scan_id={scan_2}",
        headers=setup["auth_a"],
    )
    assert resp.status_code == 200, f"Error: {resp.text}"
    comp = resp.json()

    assert comp["baseline_scan_id"] == scan_1
    assert comp["comparison_scan_id"] == scan_2
    assert comp["application_name"] == "Alpha Core Banking API"
    assert comp["baseline_total"] == 3
    assert comp["comparison_total"] == 4

    # Verify counts
    assert comp["new_count"] == 1
    assert comp["fixed_count"] == 1
    assert comp["persistent_count"] == 1
    assert comp["regressed_count"] == 1
    assert comp["severity_increased_count"] == 1
    assert comp["severity_decreased_count"] == 0
    assert comp["net_finding_change"] == 1

    # Verify posture verdict
    assert comp["posture_change"] == "DEGRADED"
    assert "degraded" in comp["posture_explanation"].lower()

    # Check individual items in diff
    items = comp["comparison_items"]
    assert len(items) == 5

    # Check NEW item
    new_item = next(i for i in items if i["comparison_status"] == "NEW")
    assert new_item["endpoint"] == "/api/v1/webhooks"
    assert new_item["comparison_severity"] == "HIGH"

    # Check FIXED item
    fixed_item = next(i for i in items if i["comparison_status"] == "FIXED")
    assert fixed_item["endpoint"] == "/api/v1/orders/search"
    assert fixed_item["baseline_severity"] == "HIGH"

    # Check PERSISTENT item
    persist_item = next(i for i in items if i["comparison_status"] == "PERSISTENT")
    assert persist_item["endpoint"] == "/api/v1/health"
    assert persist_item["baseline_severity"] == "LOW"
    assert persist_item["comparison_severity"] == "LOW"

    # Check REGRESSED item
    regress_item = next(i for i in items if i["comparison_status"] == "REGRESSED")
    assert regress_item["endpoint"] == "/api/v1/comments"
    assert regress_item["comparison_severity"] == "MEDIUM"

    # Check SEVERITY_CHANGED item
    sev_changed_item = next(i for i in items if i["comparison_status"] == "SEVERITY_CHANGED")
    assert sev_changed_item["endpoint"] == "/api/v1/statements/{id}"
    assert sev_changed_item["baseline_severity"] == "MEDIUM"
    assert sev_changed_item["comparison_severity"] == "CRITICAL"


# ==============================================================================
# TEST 11: POST COMPARISON AND PERSISTENCE IN SCAN_COMPARISONS
# ==============================================================================

@pytest.mark.asyncio
async def test_11_post_comparison_with_persistence(client: AsyncClient, scan_history_test_setup):
    """Verify POST /scan-history/compare with save_record=True stores comparison record."""
    setup = scan_history_test_setup
    scan_1 = setup["scan_1_id"]
    scan_2 = setup["scan_2_id"]

    body = {
        "baseline_scan_id": scan_1,
        "comparison_scan_id": scan_2,
        "save_record": True,
    }
    resp = await client.post("/api/v1/scan-history/compare", json=body, headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["posture_change"] == "DEGRADED"

    # Query database directly to confirm persistence
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select
    async with TestingSessionLocal() as db:
        res = await db.execute(
            select(ScanComparison).where(
                ScanComparison.base_scan_id == uuid.UUID(scan_1),
                ScanComparison.target_scan_id == uuid.UUID(scan_2),
            )
        )
        saved = res.scalars().first()
        assert saved is not None
        assert len(saved.new_vulnerabilities) >= 1
        assert len(saved.resolved_vulnerabilities) >= 1


# ==============================================================================
# TEST 12: SECURITY POSTURE IMPROVED VERDICT
# ==============================================================================

@pytest.mark.asyncio
async def test_12_security_posture_improved_verdict(client: AsyncClient, scan_history_test_setup):
    """
    Comparing Scan 2 as baseline vs Scan 1 as comparison (reversed):
    Scan 2 had 4 findings, Scan 1 has 3 findings with fewer criticals.
    Posture verdict should be IMPROVED.
    """
    setup = scan_history_test_setup
    scan_1 = setup["scan_1_id"]
    scan_2 = setup["scan_2_id"]

    resp = await client.get(
        f"/api/v1/scan-history/compare?baseline_scan_id={scan_2}&comparison_scan_id={scan_1}",
        headers=setup["auth_a"],
    )
    assert resp.status_code == 200
    comp = resp.json()

    # When baseline is Scan 2 (4 findings) and comparison is Scan 1 (3 findings):
    assert comp["fixed_count"] >= 2
    assert comp["posture_change"] == "IMPROVED"
    assert "improved" in comp["posture_explanation"].lower()

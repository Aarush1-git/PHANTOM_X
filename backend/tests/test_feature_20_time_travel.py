import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import jwt

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability, Evidence
from app.models.time_travel import (
    SecurityBaseline,
    RegressionRecord,
    BaselineStatus,
    RegressionStatus,
    MatchQuality,
)
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.core.config import settings


@pytest.fixture
async def time_travel_test_setup():
    """Seed comprehensive test data for Time-Travel Regression testing."""
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # Organization A
        org_a = Organization(name="FinTech Alpha Org", slug="fintech-alpha-org")
        # Organization B
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

        # Applications
        app_a1 = Application(
            organization_id=org_a.id,
            name="Alpha Core Banking API",
            target_url="https://banking.fintech-alpha.local",
            risk_score=8.2,
        )
        app_a2 = Application(
            organization_id=org_a.id,
            name="Alpha Customer Portal",
            target_url="https://portal.fintech-alpha.local",
            risk_score=5.0,
        )
        app_b1 = Application(
            organization_id=org_b.id,
            name="Vanguard Trading Hub",
            target_url="https://trade.rival-vanguard.local",
            risk_score=9.1,
        )
        db.add_all([app_a1, app_a2, app_b1])
        await db.flush()

        # 1. Source Scan 1 (Earliest, 30 days ago) for App A1
        scan_1_source = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=2,
            started_at=now - timedelta(days=30, hours=2),
            completed_at=now - timedelta(days=30, hours=1),
            notes="Quarterly baseline assessment",
            created_at=now - timedelta(days=30, hours=2),
        )

        # 2. Verification Scan 2 (15 days ago, COMPLETED)
        # Note: vuln 1 (IDOR) is absent here, but vuln 2 (SQLi) is STILL PRESENT here!
        scan_2_verify_success = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=15, minutes=45),
            completed_at=now - timedelta(days=15, minutes=15),
            notes="Verification re-test post fix deployment",
            created_at=now - timedelta(days=15, minutes=45),
        )

        # 3. Failed Verification Scan 3 (10 days ago, FAILED)
        scan_3_verify_failed = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.FAILED,
            progress=0.35,
            findings_count=0,
            started_at=now - timedelta(days=10, hours=1),
            completed_at=now - timedelta(days=10, minutes=40),
            notes="Aborted due to network gateway timeout",
            created_at=now - timedelta(days=10, hours=1),
        )

        # 4. Regression Scan 4 (5 days ago, COMPLETED)
        # IDOR reappears with escalated CRITICAL severity!
        scan_4_regression = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=5, hours=2),
            completed_at=now - timedelta(days=5, hours=1),
            notes="Sprint 45 regression run",
            created_at=now - timedelta(days=5, hours=2),
        )

        # 5. Protected Scan 5 (3 days ago, COMPLETED, 0 findings)
        scan_5_protected = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=0,
            started_at=now - timedelta(days=3, hours=1),
            completed_at=now - timedelta(days=3, minutes=30),
            notes="Clean assessment run",
            created_at=now - timedelta(days=3, hours=1),
        )

        # 6. Ambiguous Scan 6 (2 days ago, COMPLETED)
        # Finding with same title but different endpoint
        scan_6_ambiguous = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=2, hours=1),
            completed_at=now - timedelta(days=2, minutes=30),
            notes="Ambiguous candidate scan",
            created_at=now - timedelta(days=2, hours=1),
        )

        # 7. Remediation Scan 7 (1 day ago, COMPLETED)
        # IDOR resolved again
        scan_7_remediation = Scan(
            organization_id=org_a.id,
            application_id=app_a1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=0,
            started_at=now - timedelta(days=1, hours=1),
            completed_at=now - timedelta(days=1, minutes=20),
            notes="Post-remediation re-verification scan",
            created_at=now - timedelta(days=1, hours=1),
        )

        # Org B Scan
        scan_b1 = Scan(
            organization_id=org_b.id,
            application_id=app_b1.id,
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=1,
            started_at=now - timedelta(days=10),
            completed_at=now - timedelta(days=10, minutes=-30),
            notes="Vanguard internal scan",
            created_at=now - timedelta(days=10),
        )

        db.add_all([
            scan_1_source,
            scan_2_verify_success,
            scan_3_verify_failed,
            scan_4_regression,
            scan_5_protected,
            scan_6_ambiguous,
            scan_7_remediation,
            scan_b1,
        ])
        await db.flush()

        # Discovered Findings:
        # A) vuln_idor: Discovered in Scan 1 (MEDIUM) -> absent in Scan 2
        vuln_idor = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_1_source.id,
            title="Insecure Direct Object Reference on Statement",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/accounts/{id}/statement",
            confidence=0.95,
            recommendation="Enforce tenant-level authorization checks.",
            cwe_id="CWE-639",
            cvss_score=5.5,
            created_at=now - timedelta(days=30),
        )

        # B) vuln_sqli: Discovered in Scan 1 (HIGH) -> STILL PRESENT in Scan 2!
        vuln_sqli_source = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_1_source.id,
            title="SQL Injection in Order Search",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/orders/search",
            confidence=0.98,
            recommendation="Use parameterized queries.",
            cwe_id="CWE-89",
            cvss_score=8.5,
            created_at=now - timedelta(days=30),
        )

        # C) vuln_sqli_in_scan_2: Proves SQLi is still present in Scan 2
        vuln_sqli_in_scan_2 = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_2_verify_success.id,
            title="SQL Injection in Order Search",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/orders/search",
            confidence=0.98,
            recommendation="Use parameterized queries.",
            cwe_id="CWE-89",
            cvss_score=8.5,
            created_at=now - timedelta(days=15),
        )

        # D) vuln_idor_reappeared: In Scan 4 with escalated CRITICAL severity!
        vuln_idor_reappeared = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_4_regression.id,
            title="Insecure Direct Object Reference on Statement",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/accounts/{id}/statement",
            confidence=0.99,
            recommendation="Enforce tenant-level authorization checks.",
            cwe_id="CWE-639",
            cvss_score=9.3,
            created_at=now - timedelta(days=5),
        )

        # E) vuln_ambiguous: Same title but different endpoint in Scan 6
        vuln_ambiguous = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a1.id,
            scan_id=scan_6_ambiguous.id,
            title="Insecure Direct Object Reference on Statement",
            severity=VulnerabilitySeverity.MEDIUM,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/transactions/export",
            confidence=0.70,
            recommendation="Review authorization.",
            cwe_id="CWE-639",
            cvss_score=5.0,
            created_at=now - timedelta(days=2),
        )

        # F) Org B vulnerability
        vuln_b1 = Vulnerability(
            organization_id=org_b.id,
            application_id=app_b1.id,
            scan_id=scan_b1.id,
            title="Cross-Site Scripting in Trade Notes",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.VERIFIED,
            endpoint="/api/v1/trades/notes",
            confidence=0.90,
            recommendation="Sanitize HTML.",
            cwe_id="CWE-79",
            cvss_score=7.2,
            created_at=now - timedelta(days=10),
        )

        db.add_all([
            vuln_idor,
            vuln_sqli_source,
            vuln_sqli_in_scan_2,
            vuln_idor_reappeared,
            vuln_ambiguous,
            vuln_b1,
        ])
        await db.commit()

        # JWT Tokens
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
            "scan_1_id": str(scan_1_source.id),
            "scan_2_id": str(scan_2_verify_success.id),
            "scan_3_id": str(scan_3_verify_failed.id),
            "scan_4_id": str(scan_4_regression.id),
            "scan_5_id": str(scan_5_protected.id),
            "scan_6_id": str(scan_6_ambiguous.id),
            "scan_7_id": str(scan_7_remediation.id),
            "scan_b1_id": str(scan_b1.id),
            "vuln_idor_id": str(vuln_idor.id),
            "vuln_sqli_id": str(vuln_sqli_source.id),
            "vuln_b1_id": str(vuln_b1.id),
            "auth_a": {"Authorization": f"Bearer {token_a}"},
            "auth_b": {"Authorization": f"Bearer {token_b}"},
        }


# ==============================================================================
# TEST 1: VERIFIED BASELINE CREATION FROM VALID VERIFICATION SCAN
# ==============================================================================

@pytest.mark.asyncio
async def test_01_verified_baseline_creation_success(client: AsyncClient, time_travel_test_setup):
    """Scenario 1: Verified baseline created when finding is absent in successful verification scan."""
    setup = time_travel_test_setup
    payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
        "notes": "Verified resolved in automated sprint re-test.",
    }
    resp = await client.post("/api/v1/time-travel/baselines/verify", json=payload, headers=setup["auth_a"])
    assert resp.status_code == 200, f"Error: {resp.text}"
    data = resp.json()

    assert data["verification_status"] == "VERIFIED"
    assert "verified" in data["reason"].lower()
    assert data["baseline"] is not None

    baseline = data["baseline"]
    assert baseline["status"] == "VERIFIED"
    assert baseline["endpoint"] == "/api/v1/accounts/{id}/statement"
    assert baseline["cwe_id"] == "CWE-639"
    assert baseline["severity"] == "MEDIUM"
    assert baseline["is_retired"] is False


# ==============================================================================
# TEST 2: REJECT BASELINE CREATION FROM FAILED SCAN
# ==============================================================================

@pytest.mark.asyncio
async def test_02_reject_baseline_creation_from_failed_scan(client: AsyncClient, time_travel_test_setup):
    """Scenario 2: Reject baseline creation when verification scan status is FAILED."""
    setup = time_travel_test_setup
    payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_3_id"],  # FAILED scan
        "notes": "Attempting verification against failed scan",
    }
    resp = await client.post("/api/v1/time-travel/baselines/verify", json=payload, headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    assert data["verification_status"] == "FAILED"
    assert "COMPLETED" in data["reason"]
    assert data["baseline"] is None


# ==============================================================================
# TEST 3: REJECT CROSS-TENANT BASELINE CREATION
# ==============================================================================

@pytest.mark.asyncio
async def test_03_reject_cross_tenant_baseline_creation(client: AsyncClient, time_travel_test_setup):
    """Scenario 3: Reject cross-tenant baseline creation attempt with 403 Forbidden."""
    setup = time_travel_test_setup

    # User A tries to verify Org B's vulnerability
    payload = {
        "vulnerability_id": setup["vuln_b1_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    resp = await client.post("/api/v1/time-travel/baselines/verify", json=payload, headers=setup["auth_a"])
    assert resp.status_code == 403
    assert "Cross-tenant" in resp.json()["detail"]


# ==============================================================================
# TEST 4: REJECT CROSS-APPLICATION VERIFICATION
# ==============================================================================

@pytest.mark.asyncio
async def test_04_reject_cross_application_verification(client: AsyncClient, time_travel_test_setup):
    """Scenario 4: Reject verification when scan belongs to different application within same org (400)."""
    setup = time_travel_test_setup
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    # Create scan for App A2
    async with TestingSessionLocal() as db:
        scan_a2 = Scan(
            organization_id=uuid.UUID(setup["org_a_id"]),
            application_id=uuid.UUID(setup["app_a2_id"]),
            status=ScanStatus.COMPLETED,
            progress=1.0,
            findings_count=0,
            started_at=now,
            completed_at=now,
        )
        db.add(scan_a2)
        await db.commit()
        scan_a2_id = str(scan_a2.id)

    payload = {
        "vulnerability_id": setup["vuln_idor_id"],  # App A1
        "verification_scan_id": scan_a2_id,  # App A2
    }
    resp = await client.post("/api/v1/time-travel/baselines/verify", json=payload, headers=setup["auth_a"])
    assert resp.status_code == 400
    assert "different applications" in resp.json()["detail"]


# ==============================================================================
# TEST 5: REJECT BASELINE WHEN VULNERABILITY REMAINS PRESENT
# ==============================================================================

@pytest.mark.asyncio
async def test_05_reject_baseline_when_vulnerability_remains_present(client: AsyncClient, time_travel_test_setup):
    """Scenario 5: Do not claim fix is verified if finding is still detected in verification scan."""
    setup = time_travel_test_setup
    payload = {
        "vulnerability_id": setup["vuln_sqli_id"],  # SQLi is still present in Scan 2!
        "verification_scan_id": setup["scan_2_id"],
    }
    resp = await client.post("/api/v1/time-travel/baselines/verify", json=payload, headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    assert data["verification_status"] == "FAILED"
    assert "remains detected" in data["reason"].lower()
    assert data["baseline"] is None


# ==============================================================================
# TEST 6: REGRESSION DETECTION AND SEVERITY ESCALATION
# ==============================================================================

@pytest.mark.asyncio
async def test_06_regression_detection_and_severity_escalation(client: AsyncClient, time_travel_test_setup):
    """
    Scenario 6 & 9:
    1. First verify baseline for IDOR.
    2. Evaluate Scan 4 (where IDOR reappears with CRITICAL severity).
    3. Confirms REGRESSION_DETECTED and severity_change=INCREASED.
    """
    setup = time_travel_test_setup

    # 1. Establish verified baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    v_resp = await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])
    assert v_resp.status_code == 200

    # 2. Evaluate Scan 4
    eval_resp = await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_4_id']}", headers=setup["auth_a"])
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    assert eval_data["baselines_evaluated"] >= 1
    assert eval_data["regressions_detected"] == 1

    reg_result = eval_data["results"][0]
    assert reg_result["status"] == "REGRESSION_DETECTED"
    assert reg_result["match_quality"] == "EXACT_FINGERPRINT"
    assert reg_result["confidence_score"] == 1.0
    assert reg_result["original_severity"] == "MEDIUM"
    assert reg_result["new_severity"] == "CRITICAL"
    assert reg_result["severity_change"] == "INCREASED"
    assert "regression detected" in reg_result["explanation"].lower()


# ==============================================================================
# TEST 7: STILL_PROTECTED CLASSIFICATION
# ==============================================================================

@pytest.mark.asyncio
async def test_07_still_protected_classification(client: AsyncClient, time_travel_test_setup):
    """Scenario 7: Evaluate scan where no matching issue exists -> STILL_PROTECTED."""
    setup = time_travel_test_setup

    # 1. Establish verified baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])

    # 2. Evaluate Scan 5 (clean scan)
    eval_resp = await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_5_id']}", headers=setup["auth_a"])
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    assert eval_data["still_protected"] >= 1
    assert eval_data["regressions_detected"] == 0

    res = eval_data["results"][0]
    assert res["status"] == "STILL_PROTECTED"
    assert res["match_quality"] == "NO_MATCH"
    assert "remains protected" in res["explanation"].lower()


# ==============================================================================
# TEST 8: INCONCLUSIVE CLASSIFICATION FOR AMBIGUOUS MATCH
# ==============================================================================

@pytest.mark.asyncio
async def test_08_inconclusive_classification_for_ambiguous_match(client: AsyncClient, time_travel_test_setup):
    """Scenario 8: Ambiguous finding (same title, different endpoint) -> INCONCLUSIVE."""
    setup = time_travel_test_setup

    # 1. Establish verified baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])

    # 2. Evaluate Scan 6 (ambiguous candidate scan)
    eval_resp = await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_6_id']}", headers=setup["auth_a"])
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    assert eval_data["inconclusive"] == 1
    res = eval_data["results"][0]
    assert res["status"] == "INCONCLUSIVE"
    assert res["match_quality"] in ["AMBIGUOUS_TITLE", "AMBIGUOUS_ENDPOINT"]
    assert res["confidence_score"] == 0.50
    assert "inconclusive" in res["explanation"].lower()


# ==============================================================================
# TEST 9: DUPLICATE EVALUATION IDEMPOTENCY
# ==============================================================================

@pytest.mark.asyncio
async def test_09_duplicate_evaluation_idempotency(client: AsyncClient, time_travel_test_setup):
    """Scenario 10: Evaluating the same scan twice returns identical results without duplicate records."""
    setup = time_travel_test_setup

    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])

    # First evaluation
    eval_1 = await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_4_id']}", headers=setup["auth_a"])
    assert eval_1.status_code == 200
    data_1 = eval_1.json()

    # Second evaluation (idempotent!)
    eval_2 = await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_4_id']}", headers=setup["auth_a"])
    assert eval_2.status_code == 200
    data_2 = eval_2.json()

    assert data_1["regressions_detected"] == data_2["regressions_detected"]
    assert len(data_1["results"]) == len(data_2["results"])
    assert data_1["results"][0]["id"] == data_2["results"][0]["id"]


# ==============================================================================
# TEST 10: BASELINE RETIREMENT PRESERVES HISTORY
# ==============================================================================

@pytest.mark.asyncio
async def test_10_baseline_retirement_preserves_history(client: AsyncClient, time_travel_test_setup):
    """Scenario 11: Retiring a baseline marks it retired without destroying records."""
    setup = time_travel_test_setup

    # Establish baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    v_resp = await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])
    base_id = v_resp.json()["baseline"]["id"]

    # Retire baseline
    retire_payload = {"reason": "API endpoint v1 deprecation"}
    ret_resp = await client.post(f"/api/v1/time-travel/baselines/{base_id}/retire", json=retire_payload, headers=setup["auth_a"])
    assert ret_resp.status_code == 200
    ret_data = ret_resp.json()

    assert ret_data["is_retired"] is True
    assert ret_data["status"] == "RETIRED"
    assert ret_data["retired_reason"] == "API endpoint v1 deprecation"

    # Query details endpoint to verify persistence
    get_resp = await client.get(f"/api/v1/time-travel/baselines/{base_id}", headers=setup["auth_a"])
    assert get_resp.status_code == 200
    assert get_resp.json()["is_retired"] is True


# ==============================================================================
# TEST 11: RE-VERIFICATION AFTER REMEDIATION
# ==============================================================================

@pytest.mark.asyncio
async def test_11_re_verification_after_remediation(client: AsyncClient, time_travel_test_setup):
    """
    Scenario 12:
    1. Baseline verified -> Regressed in Scan 4.
    2. Team deploys fix.
    3. Re-verify baseline using Scan 7 (clean).
    4. Baseline returns to VERIFIED state.
    """
    setup = time_travel_test_setup

    # 1. Establish baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    v_resp = await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])
    base_id = v_resp.json()["baseline"]["id"]

    # 2. Trigger regression
    await client.post(f"/api/v1/time-travel/evaluate/{setup['scan_4_id']}", headers=setup["auth_a"])

    check_1 = await client.get(f"/api/v1/time-travel/baselines/{base_id}", headers=setup["auth_a"])
    assert check_1.json()["status"] == "REGRESSION_DETECTED"

    # 3. Re-verify baseline with Scan 7
    reverify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_7_id"],
        "notes": "Re-verified after hotfix deployed to production.",
    }
    re_resp = await client.post("/api/v1/time-travel/baselines/verify", json=reverify_payload, headers=setup["auth_a"])
    assert re_resp.status_code == 200
    re_data = re_resp.json()

    assert re_data["verification_status"] == "VERIFIED"
    assert re_data["baseline"]["status"] == "VERIFIED"
    assert "re-verified" in re_data["baseline"]["verification_reason"].lower()


# ==============================================================================
# TEST 12: APPLICATION TIMELINE ORDERING
# ==============================================================================

@pytest.mark.asyncio
async def test_12_application_timeline_ordering(client: AsyncClient, time_travel_test_setup):
    """Scenario 13: Application timeline aggregates discovery, verification, baseline, and scan events in order."""
    setup = time_travel_test_setup
    app_id = setup["app_a1_id"]

    # Establish baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])

    # Query timeline
    timeline_resp = await client.get(f"/api/v1/time-travel/applications/{app_id}/timeline", headers=setup["auth_a"])
    assert timeline_resp.status_code == 200
    data = timeline_resp.json()

    assert data["application_id"] == app_id
    assert data["total_events"] >= 3

    event_types = [e["event_type"] for e in data["events"]]
    assert "DISCOVERY" in event_types
    assert "VERIFICATION_SCAN" in event_types
    assert "BASELINE_VERIFIED" in event_types


# ==============================================================================
# TEST 13: CROSS-TENANT REGRESSION ACCESS REJECTION
# ==============================================================================

@pytest.mark.asyncio
async def test_13_cross_tenant_regression_access_rejection(client: AsyncClient, time_travel_test_setup):
    """Scenario 14: Reject cross-tenant baseline and regression access with 403 Forbidden."""
    setup = time_travel_test_setup

    # User A establishes a baseline
    verify_payload = {
        "vulnerability_id": setup["vuln_idor_id"],
        "verification_scan_id": setup["scan_2_id"],
    }
    v_resp = await client.post("/api/v1/time-travel/baselines/verify", json=verify_payload, headers=setup["auth_a"])
    base_id = v_resp.json()["baseline"]["id"]

    # User B (different org) attempts to view User A's baseline
    resp_b = await client.get(f"/api/v1/time-travel/baselines/{base_id}", headers=setup["auth_b"])
    assert resp_b.status_code == 403
    assert "Cross-tenant" in resp_b.json()["detail"]


# ==============================================================================
# TEST 14: MISSING BASELINE AND SCAN HANDLING
# ==============================================================================

@pytest.mark.asyncio
async def test_14_missing_baseline_and_scan_handling(client: AsyncClient, time_travel_test_setup):
    """Scenario 15: Handle 404 for non-existent baseline and scan evaluation requests."""
    setup = time_travel_test_setup
    fake_id = str(uuid.uuid4())

    # 404 Baseline
    resp_1 = await client.get(f"/api/v1/time-travel/baselines/{fake_id}", headers=setup["auth_a"])
    assert resp_1.status_code == 404

    # 404 Evaluate Scan
    resp_2 = await client.post(f"/api/v1/time-travel/evaluate/{fake_id}", headers=setup["auth_a"])
    assert resp_2.status_code == 404


# ==============================================================================
# TEST 15: OVERVIEW METRICS ENDPOINT
# ==============================================================================

@pytest.mark.asyncio
async def test_15_overview_metrics_endpoint(client: AsyncClient, time_travel_test_setup):
    """Verify overview summary endpoint returns correct counts."""
    setup = time_travel_test_setup

    resp = await client.get("/api/v1/time-travel/overview", headers=setup["auth_a"])
    assert resp.status_code == 200
    data = resp.json()

    assert "total_baselines" in data
    assert "verified_baselines" in data
    assert "regressions_detected" in data
    assert "inconclusive_evaluations" in data
    assert "affected_applications_count" in data


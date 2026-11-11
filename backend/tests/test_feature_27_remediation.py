import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import jwt

from app.models.user import Organization, User
from app.models.application import Application
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability, Evidence
from app.models.scope_safety import ApplicationScopePolicy
from app.models.time_travel import RegressionRecord, SecurityBaseline, RegressionStatus
from app.models.playground import PlaygroundSession, SecurityResultClassification, SessionStatus
from app.models.remediation import (
    RemediationRecommendation,
    RecommendationHistory,
    RecommendationStatus,
    RemediationPriority,
    VerificationStatus,
)
from app.models.audit import AuditLog
from app.core.config import settings
from shared.enums.common import UserRole, VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.features.security_operations.remediation.risk_engine import RiskEngine


@pytest.fixture
async def remediation_test_setup():
    """Seed comprehensive test environment for Feature 27 remediation recommendations."""
    from tests.conftest import TestingSessionLocal
    now = datetime.now(timezone.utc)

    async with TestingSessionLocal() as db:
        # 1. Organizations
        org_a = Organization(name="Acme Corp Org", slug="acme-corp")
        org_b = Organization(name="Rival Enterprise Org", slug="rival-enterprise")
        db.add_all([org_a, org_b])
        await db.flush()

        # 2. Users
        user_engineer = User(
            organization_id=org_a.id,
            email="sec.eng@acme.corp",
            hashed_password="test_password_hash",
            full_name="Sarah Engineer",
            role=UserRole.SECURITY_ENGINEER.value,
        )
        user_auditor = User(
            organization_id=org_a.id,
            email="auditor@acme.corp",
            hashed_password="test_password_hash",
            full_name="Alex Auditor",
            role=UserRole.AUDITOR.value,
        )
        user_rival = User(
            organization_id=org_b.id,
            email="admin@rival.corp",
            hashed_password="test_password_hash",
            full_name="Rival Admin",
            role=UserRole.ADMIN.value,
        )
        db.add_all([user_engineer, user_auditor, user_rival])
        await db.flush()

        # 3. Applications
        app_a = Application(
            organization_id=org_a.id,
            name="Acme Core Banking",
            target_url="https://banking.acme.corp",
            risk_score=7.8,
            status="ACTIVE",
        )
        app_b = Application(
            organization_id=org_b.id,
            name="Rival Payment API",
            target_url="https://api.rival.corp",
            risk_score=6.0,
            status="ACTIVE",
        )
        db.add_all([app_a, app_b])
        await db.flush()

        # 4. Scopes
        policy_a = ApplicationScopePolicy(
            organization_id=org_a.id,
            application_id=app_a.id,
            target_domain="banking.acme.corp",
            base_url="https://banking.acme.corp",
            permitted_paths=["/*"],
            excluded_paths=["/admin/delete", "/system/reset"],
            scope_status="ACTIVE",
            authorization_status="AUTHORIZED",
            rate_limit_rps=50,
            max_concurrency=2,
            allow_destructive=False,
            valid_until=now + timedelta(days=30),
        )
        db.add(policy_a)
        await db.flush()

        # 5. Scans
        scan_1 = Scan(
            organization_id=org_a.id,
            application_id=app_a.id,
            status=ScanStatus.COMPLETED,
        )
        scan_clean = Scan(
            organization_id=org_a.id,
            application_id=app_a.id,
            status=ScanStatus.COMPLETED,
        )
        scan_dirty = Scan(
            organization_id=org_a.id,
            application_id=app_a.id,
            status=ScanStatus.COMPLETED,
        )
        db.add_all([scan_1, scan_clean, scan_dirty])
        await db.flush()

        # 6. Vulnerabilities for Application A
        # Vuln 1: IDOR (Critical, sensitive endpoint /account/records)
        v1_idor = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a.id,
            scan_id=scan_1.id,
            title="BOLA Insecure Direct Object Reference",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/account/records",
            confidence=0.92,
            recommendation="Implement tenant authorization scoping",
            cwe_id="CWE-639",
            cvss_score=8.5,
        )

        # Vuln 2: SQL Injection (No CVSS provided, test fallback)
        v2_sqli = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a.id,
            scan_id=scan_1.id,
            title="SQL Injection in Order Search",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/orders/search",
            confidence=0.88,
            recommendation="Use parameterized statements",
            cwe_id="CWE-89",
            cvss_score=None,  # Missing CVSS
        )

        # Vuln 3: Info Leak (Low severity, no evidence attached)
        v3_info = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a.id,
            scan_id=scan_1.id,
            title="Server Version Banner Disclosure",
            severity=VulnerabilitySeverity.LOW,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/health",
            confidence=0.6,
            recommendation="Disable Server header",
            cwe_id="CWE-200",
            cvss_score=3.1,
        )

        # Vuln 4 for scan_dirty to simulate persistent finding in post-fix scan
        v4_persistent = Vulnerability(
            organization_id=org_a.id,
            application_id=app_a.id,
            scan_id=scan_dirty.id,
            title="BOLA Insecure Direct Object Reference",
            severity=VulnerabilitySeverity.HIGH,
            status=VulnerabilityStatus.DISCOVERED,
            endpoint="/api/v1/account/records",
            confidence=0.92,
            recommendation="Implement tenant authorization scoping",
            cwe_id="CWE-639",
            cvss_score=8.5,
        )

        db.add_all([v1_idor, v2_sqli, v3_info, v4_persistent])
        await db.flush()

        # Evidence for Vuln 1
        ev1 = Evidence(
            vulnerability_id=v1_idor.id,
            request_dump="GET /api/v1/account/records?account_id=102 HTTP/1.1",
            response_dump="HTTP/1.1 200 OK\n{'tenant': 'Tenant B', 'balance': 50000}",
            proof_data={"cross_tenant_access": True},
        )
        db.add(ev1)

        # Regression record for Vuln 1 to test regression escalation
        baseline = SecurityBaseline(
            organization_id=org_a.id,
            application_id=app_a.id,
            vulnerability_fingerprint="fp_idor_account_records",
            title="BOLA Insecure Direct Object Reference",
            endpoint="/api/v1/account/records",
            http_method="GET",
            severity="HIGH",
            status="REGRESSION_DETECTED",
        )
        db.add(baseline)
        await db.flush()

        reg_rec = RegressionRecord(
            organization_id=org_a.id,
            application_id=app_a.id,
            baseline_id=baseline.id,
            scan_id=scan_1.id,
            reappeared_vulnerability_id=v1_idor.id,
            status=RegressionStatus.REGRESSION_DETECTED.value,
            match_quality="EXACT_FINGERPRINT",
            confidence_score=1.0,
            original_severity="HIGH",
            new_severity="HIGH",
            explanation="Reappeared after previous remediation",
        )
        db.add(reg_rec)
        await db.commit()

        # Seed initial recommendations for App A
        from app.features.security_operations.remediation.recommendation_service import RecommendationService
        service = RecommendationService(db)
        await service.generate_recommendations_for_application(
            org_id=org_a.id,
            app_id=app_a.id,
            user=user_engineer,
        )

        # Tokens
        token_engineer = jwt.encode(
            {"sub": str(user_engineer.id), "org_id": str(org_a.id), "exp": datetime.now(timezone.utc) + timedelta(hours=2)},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_auditor = jwt.encode(
            {"sub": str(user_auditor.id), "org_id": str(org_a.id), "exp": datetime.now(timezone.utc) + timedelta(hours=2)},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        token_rival = jwt.encode(
            {"sub": str(user_rival.id), "org_id": str(org_b.id), "exp": datetime.now(timezone.utc) + timedelta(hours=2)},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )

        return {
            "org_a": org_a,
            "org_b": org_b,
            "app_a": app_a,
            "app_b": app_b,
            "user_engineer": user_engineer,
            "user_auditor": user_auditor,
            "user_rival": user_rival,
            "token_engineer": token_engineer,
            "token_auditor": token_auditor,
            "token_rival": token_rival,
            "scan_1": scan_1,
            "scan_clean": scan_clean,
            "scan_dirty": scan_dirty,
            "v1_idor": v1_idor,
            "v2_sqli": v2_sqli,
            "v3_info": v3_info,
            "policy_a": policy_a,
        }


# ==============================================================================
# TEST CASES 1 - 18
# ==============================================================================

@pytest.mark.asyncio
async def test_01_recommendation_generation(client: AsyncClient, remediation_test_setup):
    """1. Recommendation generation: generates recommendations from existing vulnerabilities."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import delete
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Clear pre-seeded recommendations to test fresh generation
    async with TestingSessionLocal() as db:
        await db.execute(delete(RemediationRecommendation).where(RemediationRecommendation.application_id == data["app_a"].id))
        await db.commit()

    resp = await client.post(
        "/api/v1/remediation/recommendations/generate",
        json={"application_id": str(data["app_a"].id)},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    res = resp.json()
    assert res["generated_count"] >= 3
    assert len(res["recommendations"]) >= 3
    for r in res["recommendations"]:
        assert r["status"] == "GENERATED"
        assert r["risk_score"] > 0.0


@pytest.mark.asyncio
async def test_02_severity_based_prioritization(client: AsyncClient, remediation_test_setup):
    """2. Severity-based prioritization: Critical/High/Low prioritized accordingly."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Fetch recommendations
    resp = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers,
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 3

    # Ensure items are ordered by risk_score desc
    scores = [item["risk_score"] for item in items]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_03_regression_based_priority_adjustment(client: AsyncClient, remediation_test_setup):
    """3. Regression-based priority adjustment: +20 points when linked to regressed baseline."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=BOLA",
        headers=headers,
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    rec_id = items[0]["id"]

    detail_resp = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id}",
        headers=headers,
    )
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    # Check that Regression factor is in priority rationale with 20 points
    factor_names = [f["factor"] for f in detail["priority_rationale"]]
    assert any("Regression" in f for f in factor_names)
    reg_factor = next(f for f in detail["priority_rationale"] if "Regression" in f["factor"])
    assert reg_factor["points"] == 20.0


@pytest.mark.asyncio
async def test_04_missing_evidence_handling(client: AsyncClient, remediation_test_setup):
    """4. Missing evidence handling: handles absence of proof dump without crashing and notes fallback."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Vuln 3 has no evidence
    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=Banner",
        headers=headers,
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    rec_id = items[0]["id"]

    detail_resp = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id}",
        headers=headers,
    )
    detail = detail_resp.json()
    assert detail["missing_information_notes"] is not None
    assert "No active payload proof" in detail["missing_information_notes"]


@pytest.mark.asyncio
async def test_05_missing_cvss_handling(client: AsyncClient, remediation_test_setup):
    """5. Missing CVSS handling: safely falls back to base severity classification without crashing."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Vuln 2 (SQLi) had cvss_score = None
    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=SQL",
        headers=headers,
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    rec_id = items[0]["id"]

    detail_resp = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id}",
        headers=headers,
    )
    detail = detail_resp.json()
    assert detail["missing_information_notes"] is not None
    assert "CVSS" in detail["missing_information_notes"]
    # Rationale shows Base Severity fallback
    factor_names = [f["factor"] for f in detail["priority_rationale"]]
    assert any("Base Severity" in f for f in factor_names)


@pytest.mark.asyncio
async def test_06_deterministic_risk_calculations():
    """6. Deterministic risk calculations: identical inputs always yield identical risk scores."""
    p1, s1, r1, m1 = RiskEngine.calculate_risk(
        severity="HIGH",
        cvss_score=7.8,
        is_regression=True,
        has_evidence=True,
        confidence=0.9,
        endpoint="/api/v1/account/balance",
        age_days=15,
    )
    p2, s2, r2, m2 = RiskEngine.calculate_risk(
        severity="HIGH",
        cvss_score=7.8,
        is_regression=True,
        has_evidence=True,
        confidence=0.9,
        endpoint="/api/v1/account/balance",
        age_days=15,
    )
    assert p1 == p2
    assert s1 == s2
    assert r1 == r2
    assert m1 == m2
    assert s1 >= 75.0
    assert p1 == RemediationPriority.CRITICAL


@pytest.mark.asyncio
async def test_07_recommendation_lifecycle_transitions(client: AsyncClient, remediation_test_setup):
    """7. Recommendation lifecycle transitions: valid progression through lifecycle states."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    # 1. GENERATED -> REVIEWED
    r1 = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "REVIEWED", "notes": "Triaged by security engineer"},
        headers=headers,
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "REVIEWED"

    # 2. REVIEWED -> ACCEPTED
    r2 = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "ACCEPTED", "assigned_to": "dev-lead@acme.corp"},
        headers=headers,
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "ACCEPTED"
    assert r2.json()["assigned_to"] == "dev-lead@acme.corp"

    # 3. ACCEPTED -> IN_PROGRESS
    r3 = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "IN_PROGRESS", "notes": "Developer branching patch"},
        headers=headers,
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "IN_PROGRESS"


@pytest.mark.asyncio
async def test_08_invalid_lifecycle_transitions(client: AsyncClient, remediation_test_setup):
    """8. Invalid lifecycle transitions: rejected with 400 Bad Request."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=Banner",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    # Direct jump to VERIFIED without evidence must fail with 400
    invalid_jump = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "VERIFIED"},
        headers=headers,
    )
    assert invalid_jump.status_code == 400
    assert "Invalid state transition" in invalid_jump.json()["detail"] or "Cannot mark" in invalid_jump.json()["detail"]

    # DEFERRED without deferred_reason must fail with 400
    defer_fail = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "DEFERRED"},
        headers=headers,
    )
    assert defer_fail.status_code == 400
    assert "deferral reason" in defer_fail.json()["detail"]


@pytest.mark.asyncio
async def test_09_cross_tenant_access_rejection(client: AsyncClient, remediation_test_setup):
    """9. Cross-tenant access rejection: Org B cannot access or modify Org A recommendations."""
    data = remediation_test_setup
    headers_a = {"Authorization": f"Bearer {data['token_engineer']}"}
    headers_b = {"Authorization": f"Bearer {data['token_rival']}"}

    resp_a = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers_a,
    )
    rec_id_a = resp_a.json()["items"][0]["id"]

    # Org B attempts to read Org A recommendation -> 404
    rival_read = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id_a}",
        headers=headers_b,
    )
    assert rival_read.status_code == 404

    # Org B attempts to patch Org A recommendation -> 404
    rival_patch = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id_a}/status",
        json={"status": "REVIEWED"},
        headers=headers_b,
    )
    assert rival_patch.status_code == 404


@pytest.mark.asyncio
async def test_10_unauthorized_status_updates(client: AsyncClient, remediation_test_setup):
    """10. Unauthorized status updates: Read-only Auditor role rejected with 403 Forbidden."""
    data = remediation_test_setup
    headers_auditor = {"Authorization": f"Bearer {data['token_auditor']}"}
    headers_engineer = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers_engineer,
    )
    rec_id = resp.json()["items"][0]["id"]

    auditor_update = await client.patch(
        f"/api/v1/remediation/recommendations/{rec_id}/status",
        json={"status": "REVIEWED", "notes": "Auditor attempting status edit"},
        headers=headers_auditor,
    )
    assert auditor_update.status_code == 403
    assert "Auditor" in auditor_update.json()["detail"]


@pytest.mark.asyncio
async def test_11_recommendation_idempotency(client: AsyncClient, remediation_test_setup):
    """11. Recommendation idempotency: re-generating updates existing without duplicating."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Count before
    resp_before = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers,
    )
    count_before = resp_before.json()["total"]

    # Re-run generate
    gen_resp = await client.post(
        "/api/v1/remediation/recommendations/generate",
        json={"application_id": str(data["app_a"].id)},
        headers=headers,
    )
    assert gen_resp.status_code == 200
    res = gen_resp.json()
    assert res["generated_count"] == 0
    assert res["updated_count"] == count_before

    # Count after must match exactly
    resp_after = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers,
    )
    assert resp_after.json()["total"] == count_before


@pytest.mark.asyncio
async def test_12_audit_event_generation(client: AsyncClient, remediation_test_setup):
    """12. Audit event generation: lifecycle events logged into append-only audit trail."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select

    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    # Add notes to trigger audit event
    await client.post(
        f"/api/v1/remediation/recommendations/{rec_id}/notes",
        json={"notes": "Audit verification note test", "assigned_to": "lead@acme.corp"},
        headers=headers,
    )

    async with TestingSessionLocal() as db:
        audit_stmt = select(AuditLog).where(
            AuditLog.organization_id == data["org_a"].id,
            AuditLog.target_type == "RemediationRecommendation"
        )
        logs = list((await db.execute(audit_stmt)).scalars().all())
        assert len(logs) > 0


@pytest.mark.asyncio
async def test_13_evidence_grounded_remediation_instructions(client: AsyncClient, remediation_test_setup):
    """13. Evidence-grounded remediation instructions: actionable steps and snippets present."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=BOLA",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    detail_resp = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id}",
        headers=headers,
    )
    detail = detail_resp.json()
    assert len(detail["remediation_steps"]) >= 3
    assert detail["suggested_fix_snippet"] is not None
    assert "select(Resource)" in detail["suggested_fix_snippet"] or "tenant" in detail["suggested_fix_snippet"].lower()
    assert len(detail["validation_steps"]) >= 2
    assert detail["suggested_playground_scenario_id"] == "idor-01"


@pytest.mark.asyncio
async def test_14_verification_with_successful_evidence(client: AsyncClient, remediation_test_setup):
    """14. Verification with successful evidence: clean scan confirms resolution -> VERIFIED."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=BOLA",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    # Verify against clean scan
    v_resp = await client.post(
        f"/api/v1/remediation/recommendations/{rec_id}/verify",
        json={
            "verification_scan_id": str(data["scan_clean"].id),
            "notes": "Verified against clean post-fix regression scan"
        },
        headers=headers,
    )
    assert v_resp.status_code == 200, v_resp.text
    res = v_resp.json()
    assert res["is_verified"] is True
    assert res["verification_status"] == "VERIFIED"
    assert res["new_status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_15_verification_with_persistent_vulnerability(client: AsyncClient, remediation_test_setup):
    """15. Verification with persistent vulnerability: scan still detects finding -> PERSISTENT."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=BOLA",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    # Verify against dirty scan (where vulnerability persists)
    v_resp = await client.post(
        f"/api/v1/remediation/recommendations/{rec_id}/verify",
        json={
            "verification_scan_id": str(data["scan_dirty"].id),
            "notes": "Testing persistent finding behavior"
        },
        headers=headers,
    )
    assert v_resp.status_code == 200
    res = v_resp.json()
    assert res["is_verified"] is False
    assert res["verification_status"] == "PERSISTENT"
    assert res["new_status"] != "VERIFIED"


@pytest.mark.asyncio
async def test_16_inconclusive_verification(client: AsyncClient, remediation_test_setup):
    """16. Inconclusive verification: missing verification source results in INCONCLUSIVE."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    resp = await client.get(
        f"/api/v1/remediation/recommendations?search=Banner",
        headers=headers,
    )
    rec_id = resp.json()["items"][0]["id"]

    v_resp = await client.post(
        f"/api/v1/remediation/recommendations/{rec_id}/verify",
        json={"notes": "No scan or simulation specified"},
        headers=headers,
    )
    assert v_resp.status_code == 200
    res = v_resp.json()
    assert res["is_verified"] is False
    assert res["verification_status"] == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_17_feature_26_scope_enforcement(client: AsyncClient, remediation_test_setup):
    """17. Feature 26 scope enforcement: verification blocked when endpoint violates safety policy."""
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select

    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Temporarily set recommendation endpoint to excluded path /admin/delete
    async with TestingSessionLocal() as db:
        rec_stmt = select(RemediationRecommendation).where(
            RemediationRecommendation.organization_id == data["org_a"].id
        )
        rec = (await db.execute(rec_stmt)).scalars().first()
        rec.endpoint = "/admin/delete"
        await db.commit()
        rec_id = rec.id

    v_resp = await client.post(
        f"/api/v1/remediation/recommendations/{rec_id}/verify",
        json={"verification_scan_id": str(data["scan_clean"].id)},
        headers=headers,
    )
    # Must be rejected due to scope policy exclusion
    assert v_resp.status_code == 403
    assert "Scope Safety Policy" in v_resp.json()["detail"]


@pytest.mark.asyncio
async def test_18_pagination_and_filtering(client: AsyncClient, remediation_test_setup):
    """18. Pagination and filtering: pagination and priority/search filters function correctly."""
    data = remediation_test_setup
    headers = {"Authorization": f"Bearer {data['token_engineer']}"}

    # Test page size = 1
    p1 = await client.get(
        f"/api/v1/remediation/recommendations?application_id={data['app_a'].id}&page=1&size=1",
        headers=headers,
    )
    assert p1.status_code == 200
    res1 = p1.json()
    assert len(res1["items"]) == 1
    assert res1["page"] == 1
    assert res1["size"] == 1

    # Test Overview endpoint
    ov_resp = await client.get(
        f"/api/v1/remediation/overview?application_id={data['app_a'].id}",
        headers=headers,
    )
    assert ov_resp.status_code == 200
    ov = ov_resp.json()
    assert ov["total_recommendations"] >= 3
    assert ov["average_risk_score"] > 0.0

    # Test history endpoint
    rec_id = res1["items"][0]["id"]
    hist_resp = await client.get(
        f"/api/v1/remediation/recommendations/{rec_id}/history",
        headers=headers,
    )
    assert hist_resp.status_code == 200
    assert isinstance(hist_resp.json(), list)

"""
Tests for verification outcomes, cache/stale detection, and evidence packages.

Covers:
  - ProofEngine outcome rules:
      * /vuln/bookings/101       -> CONFIRMED, is_confirmed True, reason non-empty
      * /public/bookings/101     -> REJECTED (reason mentions public)
      * /secure/bookings/101     -> REJECTED (reason mentions 0/N)
      * /lenient/bookings/101    -> NEEDS_HUMAN_REVIEW (reason mentions authentication)
      * /partial/bookings/101    -> NEEDS_HUMAN_REVIEW (rate in (0, 1), reason mentions intermittent)
      * /cache/vuln/bookings/101 -> INCONCLUSIVE, cache_suspected True, reason mentions cache
      * empty baseline, no victim headers -> INCONCLUSIVE
      * host outside allowlist   -> INCONCLUSIVE (safety), no request sent
  - Verification pipeline:
      * /vuln finding            -> record CONFIRMED, independent True, package not None
      * package.proof_data verification, timestamps, sha256 recomputation
      * hand-built public        -> record REJECTED, package None, reason non-empty
      * list-mode self_verified  -> record CONFIRMED, independent False, reason has 'self-verified'
      * NEEDS_HUMAN_REVIEW case  -> package is NOT None; verify_and_package returns None
      * verify_and_package returns EvidencePackage for /vuln and None for secure/public
      * no credential strings (tokA, tokB, adminTok, custTok) in evidence package
  - Checks expected/actual & identity_labels:
      * BOLA, TenantIsolation, and RBAC proof_data contain expected, actual, identity_labels
"""

import hashlib
import json
from datetime import datetime

import pytest

from checks.authorization.bola_check import BOLAOwnershipCheck
from checks.authorization.rbac_check import RBACCheck
from checks.authorization.tenant_isolation_check import TenantIsolationCheck
from checks.base import SecurityCheckContext, SecurityCheckResult
from evidence.collector import EvidenceCollector, EvidencePackage
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity
from tests.mock_vuln_app import reset_counters
from verification.pipeline import verify_and_package, verify_and_record
from verification.proof_engine import (
    SelfChallengingProofEngine,
    VerificationOutcome,
    to_vulnerability_status,
)

SECRETS = ["tokA", "tokB", "adminTok", "custTok"]


def _runner(base_url: str) -> ControlledHttpRunner:
    return ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )


# ── Engine direct tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_outcome_vuln_confirmed(live_server):
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/vuln/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Vulnerable", evidence)
    assert verdict.outcome == VerificationOutcome.CONFIRMED
    assert verdict.is_confirmed is True
    assert len(verdict.reason) > 0


@pytest.mark.asyncio
async def test_outcome_public_rejected(live_server):
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/public/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Public", evidence)
    assert verdict.outcome == VerificationOutcome.REJECTED
    assert verdict.is_confirmed is False
    assert "public" in verdict.reason.lower()


@pytest.mark.asyncio
async def test_outcome_secure_rejected_zero_hits(live_server):
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/secure/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Secure", evidence)
    assert verdict.outcome == VerificationOutcome.REJECTED
    assert verdict.is_confirmed is False
    assert "0/3" in verdict.reason


@pytest.mark.asyncio
async def test_outcome_lenient_needs_human_review(live_server):
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/lenient/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Lenient", evidence)
    assert verdict.outcome == VerificationOutcome.NEEDS_HUMAN_REVIEW
    assert verdict.is_confirmed is False
    assert "authentication" in verdict.reason.lower()


@pytest.mark.asyncio
async def test_outcome_partial_needs_human_review(live_server):
    reset_counters()
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/partial/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Partial", evidence)
    assert verdict.outcome == VerificationOutcome.NEEDS_HUMAN_REVIEW
    assert verdict.is_confirmed is False
    assert 0.0 < verdict.reproducibility_rate < 1.0
    assert "intermittent" in verdict.reason.lower()


@pytest.mark.asyncio
async def test_outcome_cache_inconclusive(live_server):
    engine = SelfChallengingProofEngine(runner=_runner(live_server), replays=3)
    evidence = {
        "attack_url": f"{live_server}/cache/vuln/bookings/101",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA Cache", evidence)
    assert verdict.outcome == VerificationOutcome.INCONCLUSIVE
    assert verdict.cache_suspected is True
    assert "cache" in verdict.reason.lower()


@pytest.mark.asyncio
async def test_outcome_empty_baseline_no_victim_headers():
    runner = ControlledHttpRunner(safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"]))
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    evidence = {
        "attack_url": "http://127.0.0.1:8000/api/test",
        "victim_headers": {},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("No Baseline", evidence)
    assert verdict.outcome == VerificationOutcome.INCONCLUSIVE
    assert verdict.is_confirmed is False
    assert len(verdict.reason) > 0


@pytest.mark.asyncio
async def test_outcome_host_outside_allowlist_inconclusive():
    runner = ControlledHttpRunner(safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"]))
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    evidence = {
        "attack_url": "http://example.com/api/test",
        "victim_headers": {"Authorization": "Bearer tokA"},
        "attacker_headers": {"Authorization": "Bearer tokB"},
        "baseline_body": "",
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("Out of scope host", evidence)
    assert verdict.outcome == VerificationOutcome.INCONCLUSIVE
    assert verdict.is_confirmed is False
    assert "safety policy" in verdict.reason.lower() or "safety" in verdict.reason.lower()


# ── Pipeline tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_vuln_record_and_package(live_server):
    runner = _runner(live_server)
    check = BOLAOwnershipCheck(runner=runner)
    ctx = SecurityCheckContext(
        test_id="test-pip-001",
        target_url=live_server,
        endpoint_path="/vuln/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    result = await check.run(ctx)
    assert result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    record = await verify_and_record(result, ctx, engine, collector)
    assert record is not None
    assert record.outcome == "CONFIRMED"
    assert record.independent is True
    assert record.package is not None

    pkg = record.package
    pd = pkg.proof_data

    # Required structured keys in package.proof_data
    for key in (
        "finding", "verification", "expected_vs_actual",
        "timestamps", "redaction", "evidence_sha256", "verdict",
    ):
        assert key in pd, f"Missing key in proof_data: {key}"

    # Verify sha256 matches recomputation
    expected_sha = hashlib.sha256(f"{pkg.request_dump}\n{pkg.response_dump}".encode("utf-8")).hexdigest()
    assert pd["evidence_sha256"] == expected_sha

    # Verify timestamp parses with datetime.fromisoformat and is timezone-aware
    dt_str = pd["timestamps"]["detected_at_utc"]
    dt = datetime.fromisoformat(dt_str)
    assert dt.tzinfo is not None

    # Verify severity, confidence, and verification_status are separate keys
    assert "severity" in pd["finding"]
    assert "confidence" in pd["finding"]
    assert "verification_status" in pd["verification"]
    assert pd["verification"]["verification_status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_pipeline_hand_built_public_rejected(live_server):
    runner = _runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    # Hand-built finding claiming /public is vulnerable
    ctx = SecurityCheckContext(
        test_id="test-pip-public",
        target_url=live_server,
        endpoint_path="/public/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
        parameters={"_baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}'},
    )
    result = SecurityCheckResult(
        check_name="BOLAOwnershipCheck",
        is_vulnerable=True,
        severity=VulnerabilitySeverity.HIGH,
        confidence=0.9,
        title="Fake finding on public endpoint",
        evidence_request=f"GET {live_server}/public/bookings/101",
        evidence_response="HTTP 200",
        proof_data={"attack_url": f"{live_server}/public/bookings/101", "attack_status": 200},
    )

    record = await verify_and_record(result, ctx, engine, collector)
    assert record is not None
    assert record.outcome == "REJECTED"
    assert record.package is None
    assert len(record.reason) > 0


@pytest.mark.asyncio
async def test_pipeline_list_mode_tenant_self_verified(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = SecurityCheckContext(
        test_id="test-pip-list",
        target_url=live_server,
        endpoint_path="/tenant/vuln/bookings",
        http_method="GET",
        auth_headers={"Authorization": "Bearer adminTok"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
        parameters={"mode": "list", "tenant_a_id": "agencyA", "tenant_field": "tenant_id"},
    )
    result = await check.run(ctx)
    assert result.is_vulnerable
    assert result.proof_data.get("self_verified") is True

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    record = await verify_and_record(result, ctx, engine, collector)
    assert record is not None
    assert record.outcome == "CONFIRMED"
    assert record.independent is False
    assert "self-verified" in record.reason.lower()
    assert record.package is not None


@pytest.mark.asyncio
async def test_pipeline_needs_human_review_package_behavior(live_server):
    runner = _runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    # Lenient endpoint triggers NEEDS_HUMAN_REVIEW
    ctx = SecurityCheckContext(
        test_id="test-pip-lenient",
        target_url=live_server,
        endpoint_path="/lenient/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    result = SecurityCheckResult(
        check_name="BOLAOwnershipCheck",
        is_vulnerable=True,
        severity=VulnerabilitySeverity.HIGH,
        confidence=0.9,
        title="BOLA on lenient endpoint",
        evidence_request=f"GET {live_server}/lenient/bookings/101",
        evidence_response="HTTP 200",
        proof_data={"attack_url": f"{live_server}/lenient/bookings/101", "attack_status": 200},
    )

    record = await verify_and_record(result, ctx, engine, collector)
    assert record is not None
    assert record.outcome == "NEEDS_HUMAN_REVIEW"
    # Package is built for human review
    assert record.package is not None

    # Thin wrapper verify_and_package returns None for NEEDS_HUMAN_REVIEW
    wrapped = await verify_and_package(result, ctx, engine, collector)
    assert wrapped is None


@pytest.mark.asyncio
async def test_pipeline_verify_and_package_compat(live_server):
    runner = _runner(live_server)
    check = BOLAOwnershipCheck(runner=runner)
    collector = EvidenceCollector()
    engine = SelfChallengingProofEngine(runner=runner, replays=3)

    # Vuln returns EvidencePackage
    ctx_vuln = SecurityCheckContext(
        test_id="test-compat-vuln",
        target_url=live_server,
        endpoint_path="/vuln/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    res_vuln = await check.run(ctx_vuln)
    pkg_vuln = await verify_and_package(res_vuln, ctx_vuln, engine, collector)
    assert pkg_vuln is not None
    assert isinstance(pkg_vuln, EvidencePackage)

    # Secure returns None
    ctx_sec = SecurityCheckContext(
        test_id="test-compat-sec",
        target_url=live_server,
        endpoint_path="/secure/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    res_sec = await check.run(ctx_sec)
    pkg_sec = await verify_and_package(res_sec, ctx_sec, engine, collector)
    assert pkg_sec is None

    # Public returns None
    ctx_pub = SecurityCheckContext(
        test_id="test-compat-pub",
        target_url=live_server,
        endpoint_path="/public/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    res_pub = await check.run(ctx_pub)
    pkg_pub = await verify_and_package(res_pub, ctx_pub, engine, collector)
    assert pkg_pub is None


@pytest.mark.asyncio
async def test_no_credential_strings_in_package(live_server):
    runner = _runner(live_server)
    check = BOLAOwnershipCheck(runner=runner)
    ctx = SecurityCheckContext(
        test_id="test-creds-001",
        target_url=live_server,
        endpoint_path="/vuln/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    result = await check.run(ctx)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    record = await verify_and_record(result, ctx, engine, EvidenceCollector())

    assert record is not None and record.package is not None
    pkg_dump = json.dumps(record.package.model_dump(), default=str)
    for secret in SECRETS:
        assert secret not in pkg_dump, f"Found secret '{secret}' in packaged evidence!"


# ── Checks proof_data assertions ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_checks_contain_expected_actual_and_identity_labels(live_server):
    runner = _runner(live_server)

    # 1. BOLA check
    bola = BOLAOwnershipCheck(runner=runner)
    ctx_b = SecurityCheckContext(
        test_id="b-1", target_url=live_server, endpoint_path="/vuln/bookings/101", http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"}, secondary_auth_headers={"Authorization": "Bearer tokB"},
        parameters={"owner_label": "customer_a", "attacker_label": "customer_b"},
    )
    res_b = await bola.run(ctx_b)
    for k in ("expected", "actual", "identity_labels"):
        assert k in res_b.proof_data
    assert res_b.proof_data["identity_labels"] == {"owner": "customer_a", "attacker": "customer_b"}

    # 2. Tenant isolation check (object mode)
    tenant = TenantIsolationCheck(runner=runner)
    ctx_t = SecurityCheckContext(
        test_id="t-1", target_url=live_server, endpoint_path="/tenant/vuln/bookings/201", http_method="GET",
        auth_headers={"Authorization": "Bearer adminTok"}, secondary_auth_headers={"Authorization": "Bearer tokB"},
        parameters={"mode": "object", "owner_label": "tenant_1", "attacker_label": "tenant_2"},
    )
    res_t = await tenant.run(ctx_t)
    for k in ("expected", "actual", "identity_labels"):
        assert k in res_t.proof_data
    assert res_t.proof_data["identity_labels"] == {"owner": "tenant_1", "attacker": "tenant_2"}

    # 3. RBAC check
    rbac = RBACCheck(runner=runner)
    ctx_r = SecurityCheckContext(
        test_id="r-1", target_url=live_server, endpoint_path="/rbac/vuln/admin/users", http_method="GET",
        auth_headers={"Authorization": "Bearer adminTok"}, secondary_auth_headers={"Authorization": "Bearer custTok"},
        parameters={"role_label": "customer", "owner_label": "admin"},
    )
    res_r = await rbac.run(ctx_r)
    for k in ("expected", "actual", "identity_labels"):
        assert k in res_r.proof_data
    assert res_r.proof_data["identity_labels"] == {"owner": "admin", "attacker": "customer"}

    # Check that no raw auth tokens are in any identity_labels or expected/actual
    for res in (res_b, res_t, res_r):
        text = json.dumps({
            "labels": res.proof_data["identity_labels"],
            "expected": res.proof_data["expected"],
            "actual": res.proof_data["actual"],
        })
        for secret in SECRETS:
            assert secret not in text

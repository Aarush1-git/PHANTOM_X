"""
Tests for checks/authentication/broken_auth_check.py (BrokenAuthenticationCheck).

Covers:
  - Missing authentication (/authn/missing/profile) -> vulnerable (CRITICAL, CWE-306)
  - Lax authentication (/authn/lax/profile) -> vulnerable via garbage_token/bearer_null (CWE-287)
  - Unsigned JWT none algorithm (/authn/jwtnone/profile) -> vulnerable (CRITICAL, CWE-347)
  - Secure endpoint (/authn/secure/profile) -> not vulnerable (conf 0.9)
  - Flaky endpoint (/authn/flaky/profile) -> not vulnerable ("not reproducible", conf 0.6)
  - Public endpoint with expect_auth=False -> not vulnerable, 0 requests sent
  - Target host outside allowlist with expect_auth=True -> "Blocked by safety policy"
  - Secret redaction (no "tokA", "invalid.invalid.invalid", "alg" in dumps/proof_data)
  - Pipeline verify_and_record -> CONFIRMED, independent False, custom expected string
  - Pipeline verify_and_package -> EvidencePackage for missing, None for secure
"""

import json
import pytest

import tests.mock_vuln_app as mock_app
from checks.authentication.broken_auth_check import BrokenAuthenticationCheck
from checks.base import SecurityCheckContext
from evidence.collector import EvidenceCollector, EvidencePackage
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity
from verification.pipeline import verify_and_package, verify_and_record
from verification.proof_engine import SelfChallengingProofEngine

SECRETS = ["tokA", "invalid.invalid.invalid", "alg"]


def _runner(base_url: str) -> ControlledHttpRunner:
    return ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )


def _ctx(
    base_url: str,
    path: str,
    *,
    token: str = "tokA",
    expect_auth: bool = True,
    extra_params: dict | None = None,
) -> SecurityCheckContext:
    params = {"expect_auth": expect_auth, **(extra_params or {})}
    return SecurityCheckContext(
        test_id="test-authn-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": f"Bearer {token}"},
        parameters=params,
    )


@pytest.mark.asyncio
async def test_broken_auth_missing_vulnerable(live_server):
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/authn/missing/profile")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert result.cwe_id == "CWE-306"
    assert result.cvss_score == pytest.approx(9.1)
    assert result.title == "Missing authentication"
    assert result.proof_data["self_verified"] is True
    assert "no_credentials" in result.proof_data["accepted_variants"]
    assert result.proof_data["reproducibility"]["no_credentials"] == "3/3"


@pytest.mark.asyncio
async def test_broken_auth_lax_vulnerable(live_server):
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/authn/lax/profile")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert result.cwe_id == "CWE-287"
    assert result.cvss_score == pytest.approx(9.1)
    assert result.proof_data["self_verified"] is True
    assert "garbage_token" in result.proof_data["accepted_variants"]
    assert "bearer_null" in result.proof_data["accepted_variants"]
    assert result.proof_data["reproducibility"]["garbage_token"] == "3/3"
    assert result.proof_data["reproducibility"]["bearer_null"] == "3/3"


@pytest.mark.asyncio
async def test_broken_auth_jwtnone_vulnerable(live_server):
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/authn/jwtnone/profile")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert result.cwe_id == "CWE-347"
    assert result.cvss_score == pytest.approx(9.1)
    assert result.proof_data["self_verified"] is True
    assert "unsigned_jwt" in result.proof_data["accepted_variants"]
    assert result.proof_data["reproducibility"]["unsigned_jwt"] == "3/3"


@pytest.mark.asyncio
async def test_broken_auth_secure_not_vulnerable(live_server):
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/authn/secure/profile")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert result.proof_data["self_verified"] is False
    assert len(result.proof_data["accepted_variants"]) == 0


@pytest.mark.asyncio
async def test_broken_auth_flaky_not_vulnerable(live_server):
    mock_app.reset_counters()
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/authn/flaky/profile")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.6)
    assert "not reproducible" in result.description.lower()
    assert result.proof_data["self_verified"] is False
    assert "no_credentials" in result.proof_data["accepted_variants"]
    assert result.proof_data["reproducibility"]["no_credentials"] != "3/3"


@pytest.mark.asyncio
async def test_broken_auth_public_expect_auth_false():
    # Use a dummy host outside the allowlist to verify zero network requests are sent
    runner = ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )
    check = BrokenAuthenticationCheck(runner=runner)
    ctx = _ctx("http://192.0.2.1:9999", "/authn/public/info", expect_auth=False)
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert "declared public" in result.description.lower()
    assert result.proof_data["baseline_status"] == 0
    assert len(result.proof_data["variants"]) == 0


@pytest.mark.asyncio
async def test_broken_auth_host_outside_allowlist_blocked():
    runner = ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )
    check = BrokenAuthenticationCheck(runner=runner)
    ctx = _ctx("http://192.0.2.1:9999", "/authn/secure/profile", expect_auth=True)
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)
    assert "Blocked by safety policy" in result.description


@pytest.mark.asyncio
async def test_broken_auth_no_tokens_in_evidence_or_proof(live_server):
    check = BrokenAuthenticationCheck(runner=_runner(live_server))
    for path in ["/authn/missing/profile", "/authn/lax/profile"]:
        ctx = _ctx(live_server, path)
        result = await check.run(ctx)

        blob = (
            result.evidence_request
            + "\n"
            + result.evidence_response
            + "\n"
            + json.dumps(result.proof_data, default=str)
        )
        for secret in SECRETS:
            assert secret not in blob, f"Secret {secret!r} leaked into evidence for {path}"


@pytest.mark.asyncio
async def test_broken_auth_pipeline_verify_and_record(live_server):
    runner = _runner(live_server)
    check = BrokenAuthenticationCheck(runner=runner)
    ctx = _ctx(live_server, "/authn/missing/profile")
    result = await check.run(ctx)
    assert result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()
    record = await verify_and_record(result, ctx, engine, collector)

    assert record is not None
    assert record.outcome == "CONFIRMED"
    assert record.independent is False
    assert record.package is not None
    assert isinstance(record.package, EvidencePackage)

    expected_text = record.package.proof_data["expected_vs_actual"]["expected"]
    assert "authentication required" in expected_text
    assert "access denied (HTTP 401/403/404)" not in expected_text


@pytest.mark.asyncio
async def test_broken_auth_pipeline_verify_and_package(live_server):
    runner = _runner(live_server)
    check = BrokenAuthenticationCheck(runner=runner)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    # Missing auth -> yields EvidencePackage
    ctx_missing = _ctx(live_server, "/authn/missing/profile")
    result_missing = await check.run(ctx_missing)
    pkg_missing = await verify_and_package(result_missing, ctx_missing, engine, collector)
    assert pkg_missing is not None
    assert isinstance(pkg_missing, EvidencePackage)

    # Secure -> yields None
    ctx_secure = _ctx(live_server, "/authn/secure/profile")
    result_secure = await check.run(ctx_secure)
    pkg_secure = await verify_and_package(result_secure, ctx_secure, engine, collector)
    assert pkg_secure is None


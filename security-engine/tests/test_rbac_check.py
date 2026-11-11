"""
Tests for checks/authorization/rbac_check.py (RBACCheck).

Covers:
  - /rbac/vuln/admin/users  GET  → vulnerable (HIGH, CWE-285)
  - /rbac/secure/admin/users GET → not vulnerable
  - /rbac/public/admin/users GET → not vulnerable, description mentions public
  - Invalid admin token (baseline fails) → inconclusive, confidence 0.0
  - DELETE /rbac/vuln/users/1 in default OBSERVE mode
      → not vulnerable (Blocked by safety policy), DELETE_CALLS == 0
  - Token redaction: "tokA","tokB","adminTok","custTok" absent from evidence
  Pipeline:
  - /rbac/vuln/admin/users   → EvidencePackage confirmed
  - /rbac/secure/admin/users → None
"""

import json
import pytest

import tests.mock_vuln_app as mock_app
from checks.authorization.rbac_check import RBACCheck
from checks.base import SecurityCheckContext
from evidence.collector import EvidenceCollector, EvidencePackage
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity
from verification.pipeline import verify_and_package
from verification.proof_engine import SelfChallengingProofEngine

SECRETS = ["tokA", "tokB", "adminTok", "custTok"]


def _runner(base_url: str) -> ControlledHttpRunner:
    return ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )


def _ctx(
    base_url: str,
    path: str,
    method: str = "GET",
    *,
    admin_tok: str = "adminTok",
    lower_tok: str = "custTok",
    extra_params: dict | None = None,
) -> SecurityCheckContext:
    params = extra_params or {}
    return SecurityCheckContext(
        test_id="test-rbac-001",
        target_url=base_url,
        endpoint_path=path,
        http_method=method,
        auth_headers={"Authorization": f"Bearer {admin_tok}"},
        secondary_auth_headers={"Authorization": f"Bearer {lower_tok}"},
        parameters=params,
    )


# ── Vulnerable GET ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_vuln_is_vulnerable(live_server):
    check = RBACCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/rbac/vuln/admin/users"))

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.HIGH
    assert result.cwe_id == "CWE-285"
    assert result.cvss_score == pytest.approx(8.1)
    assert result.confidence == pytest.approx(0.9)


# ── Secure GET ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_secure_not_vulnerable(live_server):
    check = RBACCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/rbac/secure/admin/users"))

    assert not result.is_vulnerable
    assert result.confidence >= 0.9


# ── Public GET ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_public_not_vulnerable(live_server):
    check = RBACCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/rbac/public/admin/users"))

    assert not result.is_vulnerable
    assert "public" in result.description.lower()


# ── Baseline fails (invalid admin token) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_baseline_fail_inconclusive(live_server):
    check = RBACCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/rbac/secure/admin/users", admin_tok="BADTOKEN")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)


# ── DELETE blocked by OBSERVE-mode policy ────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_delete_blocked_by_policy(live_server):
    # Reset counter before test
    mock_app.DELETE_CALLS = 0

    check = RBACCheck(runner=_runner(live_server))
    # Default OBSERVE mode; STATE_MODIFYING method should be blocked
    ctx = _ctx(live_server, "/rbac/vuln/users/1", method="DELETE")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert "not supported" in result.description.lower()
    # The check refuses state-changing methods itself; nothing reaches the app
    assert mock_app.DELETE_CALLS == 0


@pytest.mark.asyncio
async def test_rbac_delete_refused_even_in_active_verify_mode(live_server):
    """Even with a permissive policy the check must not send the baseline DELETE as admin."""
    from shared.enums.common import ExecutionMode
    mock_app.DELETE_CALLS = 0
    runner = ControlledHttpRunner(safety_policy=SecuritySafetyPolicy(
        default_mode=ExecutionMode.ACTIVE_VERIFY, allowed_hosts=["127.0.0.1", "localhost"]))
    result = await RBACCheck(runner=runner).run(_ctx(live_server, "/rbac/vuln/users/1", method="DELETE"))
    assert not result.is_vulnerable
    assert "not supported" in result.description.lower()
    assert mock_app.DELETE_CALLS == 0


# ── Token redaction ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rbac_no_tokens_in_evidence(live_server):
    check = RBACCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/rbac/vuln/admin/users"))

    blob = (
        result.evidence_request
        + result.evidence_response
        + json.dumps(result.proof_data, default=str)
    )
    for secret in SECRETS:
        assert secret not in blob, f"Secret {secret!r} leaked into evidence"


# ── Pipeline ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_confirms_rbac_vuln(live_server):
    runner = _runner(live_server)
    check = RBACCheck(runner=runner)
    ctx = _ctx(live_server, "/rbac/vuln/admin/users")
    result = await check.run(ctx)
    assert result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())

    assert package is not None
    assert isinstance(package, EvidencePackage)
    assert "verdict" in package.proof_data


@pytest.mark.asyncio
async def test_pipeline_returns_none_for_rbac_secure(live_server):
    runner = _runner(live_server)
    check = RBACCheck(runner=runner)
    ctx = _ctx(live_server, "/rbac/secure/admin/users")
    result = await check.run(ctx)
    assert not result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())
    assert package is None
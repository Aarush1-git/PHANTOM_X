"""
Tests for checks/authorization/tenant_isolation_check.py (TenantIsolationCheck).

Covers:
  object mode:
    - /tenant/vuln/bookings/201      → vulnerable (CRITICAL, CWE-639)
    - /tenant/secure/bookings/201    → not vulnerable
    - /tenant/public/bookings/201    → not vulnerable, description mentions public
    - /tenant/vuln/bookings/999      → inconclusive, confidence 0.0
    - http://example.com             → BLOCKED, mentions "safety policy", no request
  list mode:
    - /tenant/vuln/bookings          → vulnerable, self_verified=True, leaked_item_count set
    - /tenant/secure/bookings        → not vulnerable
  spoof mode:
    - /tenant/spoof/bookings/201     → vulnerable, extra_attacker_headers recorded
    - /tenant/secure/bookings/201    → not vulnerable (plain probe denied, no spoof needed)
  token redaction:
    - tokA, tokB, adminTok, custTok never appear in evidence_request/response/proof_data
  pipeline:
    - object vuln          → EvidencePackage
    - spoof vuln           → EvidencePackage (extra_attacker_headers merged)
    - list vuln            → EvidencePackage (self_verified path)
    - secure / public      → None
"""

import json
import pytest

from checks.authorization.tenant_isolation_check import TenantIsolationCheck
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
    mode: str = "object",
    *,
    owner: str = "adminTok",
    attacker: str = "tokB",
    extra_params: dict | None = None,
) -> SecurityCheckContext:
    params = {"mode": mode}
    if extra_params:
        params.update(extra_params)
    return SecurityCheckContext(
        test_id="test-tenant-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": f"Bearer {owner}"},
        secondary_auth_headers={"Authorization": f"Bearer {attacker}"},
        parameters=params,
    )


# ── Object mode ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_object_vuln_is_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/vuln/bookings/201"))

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert result.cwe_id == "CWE-639"
    assert result.cvss_score == pytest.approx(9.1)
    assert result.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_tenant_object_secure_not_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/secure/bookings/201"))

    assert not result.is_vulnerable
    assert result.confidence >= 0.9


@pytest.mark.asyncio
async def test_tenant_object_public_not_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/public/bookings/201"))

    assert not result.is_vulnerable
    assert "public" in result.description.lower()


@pytest.mark.asyncio
async def test_tenant_object_missing_resource_inconclusive(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/vuln/bookings/999"))

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_tenant_object_blocked_host():
    runner = ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )
    check = TenantIsolationCheck(runner=runner)
    ctx = SecurityCheckContext(
        test_id="t-scope",
        target_url="http://example.com",
        endpoint_path="/api/resource",
        http_method="GET",
        auth_headers={"Authorization": "Bearer adminTok"},
        secondary_auth_headers={"Authorization": "Bearer tokB"},
        parameters={"mode": "object"},
    )
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert "safety policy" in result.description.lower()


# ── List mode ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_list_vuln_is_vulnerable_and_self_verified(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    ctx = _ctx(
        live_server, "/tenant/vuln/bookings", mode="list",
        extra_params={"tenant_a_id": "agencyA", "tenant_field": "tenant_id"},
    )
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert result.cwe_id == "CWE-200"
    assert result.proof_data.get("self_verified") is True
    assert result.proof_data.get("leaked_item_count", 0) >= 1


@pytest.mark.asyncio
async def test_tenant_list_secure_not_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    ctx = _ctx(
        live_server, "/tenant/secure/bookings", mode="list",
        extra_params={"tenant_a_id": "agencyA", "tenant_field": "tenant_id"},
    )
    result = await check.run(ctx)
    assert not result.is_vulnerable


# ── Spoof mode ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_spoof_vuln_is_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    ctx = _ctx(
        live_server, "/tenant/spoof/bookings/201", mode="spoof",
        extra_params={"tenant_header": "X-Tenant-Id", "tenant_a_id": "agencyA"},
    )
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.CRITICAL
    assert "extra_attacker_headers" in result.proof_data
    assert "X-Tenant-Id" in result.proof_data["extra_attacker_headers"]


@pytest.mark.asyncio
async def test_tenant_spoof_secure_not_vulnerable(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    ctx = _ctx(
        live_server, "/tenant/secure/bookings/201", mode="spoof",
        extra_params={"tenant_header": "X-Tenant-Id", "tenant_a_id": "agencyA"},
    )
    result = await check.run(ctx)
    assert not result.is_vulnerable


# ── Token redaction ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_no_tokens_in_evidence(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/vuln/bookings/201"))

    blob = (
        result.evidence_request
        + result.evidence_response
        + json.dumps(result.proof_data, default=str)
    )
    for secret in SECRETS:
        assert secret not in blob, f"Secret {secret!r} leaked into evidence"


# ── Pipeline ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_packages_object_vuln(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = _ctx(live_server, "/tenant/vuln/bookings/201")
    result = await check.run(ctx)
    assert result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())

    assert package is not None
    assert isinstance(package, EvidencePackage)


@pytest.mark.asyncio
async def test_pipeline_packages_spoof_vuln(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = _ctx(
        live_server, "/tenant/spoof/bookings/201", mode="spoof",
        extra_params={"tenant_header": "X-Tenant-Id", "tenant_a_id": "agencyA"},
    )
    result = await check.run(ctx)
    assert result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())

    assert package is not None
    assert isinstance(package, EvidencePackage)


@pytest.mark.asyncio
async def test_pipeline_packages_list_vuln_self_verified(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = _ctx(
        live_server, "/tenant/vuln/bookings", mode="list",
        extra_params={"tenant_a_id": "agencyA", "tenant_field": "tenant_id"},
    )
    result = await check.run(ctx)
    assert result.is_vulnerable
    assert result.proof_data.get("self_verified") is True

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())

    assert package is not None
    assert package.proof_data.get("verdict") == {"self_verified": True}


@pytest.mark.asyncio
async def test_pipeline_returns_none_for_secure(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = _ctx(live_server, "/tenant/secure/bookings/201")
    result = await check.run(ctx)
    assert not result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())
    assert package is None


@pytest.mark.asyncio
async def test_pipeline_returns_none_for_public(live_server):
    runner = _runner(live_server)
    check = TenantIsolationCheck(runner=runner)
    ctx = _ctx(live_server, "/tenant/public/bookings/201")
    result = await check.run(ctx)
    assert not result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())
    assert package is None



# -- hardening: required parameter + failed control ---------------------------

@pytest.mark.asyncio
async def test_tenant_list_requires_tenant_a_id(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(live_server, "/tenant/vuln/bookings", mode="list"))
    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)
    assert "tenant_a_id" in result.description
    assert not result.proof_data.get("self_verified")


@pytest.mark.asyncio
async def test_tenant_spoof_requires_tenant_a_id(live_server):
    check = TenantIsolationCheck(runner=_runner(live_server))
    result = await check.run(_ctx(
        live_server, "/tenant/spoof/bookings/201", mode="spoof",
        extra_params={"tenant_header": "X-Tenant-ID"},
    ))
    assert not result.is_vulnerable
    assert "tenant_a_id" in result.description


class _ControlFailsRunner(ControlledHttpRunner):
    """Raises on requests without headers (the no-auth control)."""
    async def execute_request(self, method, url, headers=None, **kw):
        if not headers:
            raise RuntimeError("boom")
        return await super().execute_request(method, url, headers=headers, **kw)


@pytest.mark.asyncio
async def test_tenant_list_failed_control_is_inconclusive(live_server):
    runner = _ControlFailsRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"]))
    result = await TenantIsolationCheck(runner=runner).run(_ctx(
        live_server, "/tenant/vuln/bookings", mode="list",
        extra_params={"tenant_a_id": "agencyA", "tenant_field": "tenant_id"},
    ))
    assert not result.is_vulnerable
    assert "request error" in result.description
    assert not result.proof_data.get("self_verified")
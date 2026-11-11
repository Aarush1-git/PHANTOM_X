"""
Tests for checks/api_security/cors_method_check.py (CorsAndMethodCheck).

Covers:
  - CORS with origin reflection and credentials -> vulnerable (MEDIUM, CWE-942)
  - CORS with origin reflection without credentials -> vulnerable (LOW, CWE-942)
  - CORS with wildcard ACAO -> not vulnerable (conf 0.9)
  - CORS secure endpoint -> not vulnerable (conf 0.9)
  - Methods vulnerable (TRACE, DELETE allowed) -> vulnerable (LOW, CWE-16) with TRACE & DELETE in findings
  - Methods secure -> not vulnerable (conf 0.9)
"""

import pytest

from checks.api_security.cors_method_check import CorsAndMethodCheck
from checks.base import SecurityCheckContext
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity


def _runner(base_url: str) -> ControlledHttpRunner:
    return ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )


def _ctx(
    base_url: str,
    path: str,
    *,
    expected_methods: list[str] | None = None,
    extra_params: dict | None = None,
) -> SecurityCheckContext:
    params = {}
    if expected_methods is not None:
        params["expected_methods"] = expected_methods
    if extra_params:
        params.update(extra_params)
    return SecurityCheckContext(
        test_id="test-cors-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        parameters=params,
    )


@pytest.mark.asyncio
async def test_cors_vuln(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/cors/vuln/data")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.MEDIUM
    assert result.cwe_id == "CWE-942"
    assert result.cvss_score == pytest.approx(6.5)
    assert result.proof_data["self_verified"] is True
    assert "cors_origin_reflected_with_credentials" in result.proof_data["findings"]


@pytest.mark.asyncio
async def test_cors_reflect_nocreds(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/cors/reflect-nocreds/data")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.LOW
    assert result.cwe_id == "CWE-942"
    assert result.cvss_score == pytest.approx(3.7)
    assert result.proof_data["self_verified"] is True
    assert "cors_origin_reflected" in result.proof_data["findings"]


@pytest.mark.asyncio
async def test_cors_wildcard(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/cors/wildcard/data")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert "cors_origin_reflected" not in result.proof_data["findings"]
    assert "cors_origin_reflected_with_credentials" not in result.proof_data["findings"]


@pytest.mark.asyncio
async def test_cors_secure(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/cors/secure/data")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert len(result.proof_data["findings"]) == 0


@pytest.mark.asyncio
async def test_methods_vuln(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/methods/vuln/thing")
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.LOW
    assert result.cwe_id == "CWE-16"
    assert result.cvss_score == pytest.approx(3.1)
    assert result.title == "Unexpected HTTP methods enabled"
    assert result.proof_data["self_verified"] is True
    assert "TRACE" in result.proof_data["findings"]
    assert "DELETE" in result.proof_data["findings"]


@pytest.mark.asyncio
async def test_methods_secure(live_server):
    check = CorsAndMethodCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/methods/secure/thing")
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert "unexpected_methods_enabled" not in result.proof_data["findings"]


"""
Tests for checks/api_security/input_validation_check.py (InputValidationCheck).

Covers:
  - Verbose error disclosure (/validate/vuln/items) -> vulnerable (MEDIUM, CWE-209)
  - 500 error only (/validate/500only/items) -> vulnerable (LOW, CWE-20)
  - Secure validation (/validate/secure/items) -> not vulnerable (conf 0.9)
  - Flaky failure (/validate/flaky/items) -> not vulnerable ("not reproducible", conf 0.6)
  - Rate limited endpoint (/validate/ratelimited/items) -> inconclusive (conf 0.0, "rate limited")
  - Missing probe_params -> inconclusive ("probe_params is required")
  - Proof data contains labels only, never raw probe values (no "AAAA", no "../")
  - Pipeline verify_and_record -> CONFIRMED, independent False
"""

import json
import pytest

import tests.mock_vuln_app as mock_app
from checks.api_security.input_validation_check import InputValidationCheck
from checks.base import SecurityCheckContext
from evidence.collector import EvidenceCollector, EvidencePackage
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity
from verification.pipeline import verify_and_record
from verification.proof_engine import SelfChallengingProofEngine


def _runner(base_url: str) -> ControlledHttpRunner:
    return ControlledHttpRunner(
        safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    )


def _ctx(
    base_url: str,
    path: str,
    *,
    probe_params: dict | None = None,
    extra_params: dict | None = None,
) -> SecurityCheckContext:
    params = {}
    if probe_params is not None:
        params["probe_params"] = probe_params
    if extra_params:
        params.update(extra_params)
    return SecurityCheckContext(
        test_id="test-val-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"},
        parameters=params,
    )


@pytest.mark.asyncio
async def test_input_validation_vuln(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/vuln/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.MEDIUM
    assert result.cwe_id == "CWE-209"
    assert result.cvss_score == pytest.approx(5.3)
    assert result.title == "Verbose error disclosure"
    assert result.proof_data["self_verified"] is True
    assert result.proof_data["disclosure_matched"] is True
    assert result.proof_data["reproducible"] is True


@pytest.mark.asyncio
async def test_input_validation_500only(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/500only/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    assert result.is_vulnerable
    assert result.severity == VulnerabilitySeverity.LOW
    assert result.cwe_id == "CWE-20"
    assert result.cvss_score == pytest.approx(3.7)
    assert result.title == "Improper input validation (server error)"
    assert result.proof_data["self_verified"] is True
    assert result.proof_data["disclosure_matched"] is False
    assert result.proof_data["reproducible"] is True


@pytest.mark.asyncio
async def test_input_validation_secure(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/secure/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.9)
    assert result.proof_data["self_verified"] is False
    assert len(result.proof_data["failing_probes"]) == 0


@pytest.mark.asyncio
async def test_input_validation_flaky(live_server):
    mock_app.reset_counters()
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/flaky/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.6)
    assert "not reproducible" in result.description.lower()
    assert result.proof_data["reproducible"] is False


@pytest.mark.asyncio
async def test_input_validation_ratelimited(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/ratelimited/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)
    assert "rate limited" in result.description.lower()


@pytest.mark.asyncio
async def test_input_validation_missing_probe_params(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/secure/items", probe_params=None)
    result = await check.run(ctx)

    assert not result.is_vulnerable
    assert result.confidence == pytest.approx(0.0)
    assert "probe_params is required" in result.description


@pytest.mark.asyncio
async def test_input_validation_no_raw_probe_values_in_proof_data(live_server):
    check = InputValidationCheck(runner=_runner(live_server))
    ctx = _ctx(live_server, "/validate/vuln/items", probe_params={"id": "101"})
    result = await check.run(ctx)

    serialized_proof = json.dumps(result.proof_data)
    assert "AAAA" not in serialized_proof
    assert "../" not in serialized_proof

    # Ensure value_label uses sanitized names
    for item in result.proof_data["failing_probes"]:
        assert item["value_label"] in {
            "single_quote",
            "double_quote",
            "long_string",
            "negative",
            "non_numeric",
            "path_traversal",
        }


@pytest.mark.asyncio
async def test_input_validation_pipeline_verify_and_record(live_server):
    runner = _runner(live_server)
    check = InputValidationCheck(runner=runner)
    ctx = _ctx(live_server, "/validate/vuln/items", probe_params={"id": "101"})
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

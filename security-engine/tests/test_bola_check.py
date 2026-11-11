"""
Tests for checks/authorization/bola_check.py (BOLAOwnershipCheck).

Covers:
  - Vulnerable endpoint: is_vulnerable=True, severity=HIGH, cwe_id=CWE-639
  - Secure endpoint: is_vulnerable=False
  - Public endpoint: is_vulnerable=False, description mentions "publicly readable"
  - Non-existent resource (booking 999): is_vulnerable=False, confidence=0.0
  - Host outside allowlist: is_vulnerable=False, mentions "safety policy", no request sent
  - Token values NEVER appear in evidence_request or proof_data

All requests target 127.0.0.1 via the live_server fixture (no external hosts).
"""

import pytest

from checks.authorization.bola_check import BOLAOwnershipCheck
from checks.base import SecurityCheckContext
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity

# Token literals used in auth headers - must NOT appear in any evidence/proof_data
TOK_A = "tokA"
TOK_B = "tokB"


def _make_runner(base_url: str) -> ControlledHttpRunner:
    """Return a runner whose safety policy allows only 127.0.0.1."""
    policy = SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    return ControlledHttpRunner(safety_policy=policy)


def _make_context(base_url: str, path: str, **kwargs) -> SecurityCheckContext:
    defaults = dict(
        test_id="test-bola-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": f"Bearer {TOK_A}"},
        secondary_auth_headers={"Authorization": f"Bearer {TOK_B}"},
        parameters={},
    )
    defaults.update(kwargs)
    return SecurityCheckContext(**defaults)


# ── Vulnerable endpoint ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vuln_endpoint_is_vulnerable(live_server):
    """User B can access User A's booking -> BOLA HIGH."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/vuln/bookings/101")
    result = await check.run(ctx)

    assert result.is_vulnerable is True
    assert result.severity == VulnerabilitySeverity.HIGH
    assert result.cwe_id == "CWE-639"
    assert result.cvss_score == pytest.approx(8.6)
    assert result.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_vuln_endpoint_proof_data_complete(live_server):
    """proof_data must have all required keys."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/vuln/bookings/101")
    result = await check.run(ctx)

    pd = result.proof_data
    for key in (
        "baseline_status", "attack_status", "control_status",
        "body_match", "attack_url",
        "user_a_headers_present", "user_b_headers_present", "ignore_fields",
    ):
        assert key in pd, f"Missing key: {key}"

    assert pd["body_match"] is True
    assert pd["user_a_headers_present"] is True
    assert pd["user_b_headers_present"] is True


# ── Secure endpoint ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_secure_endpoint_not_vulnerable(live_server):
    """Secure endpoint must deny cross-user access."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/secure/bookings/101")
    result = await check.run(ctx)

    assert result.is_vulnerable is False
    assert result.confidence >= 0.9


# ── Public endpoint ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_public_endpoint_not_vulnerable(live_server):
    """Public endpoint detected correctly - not a BOLA finding."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/public/bookings/101")
    result = await check.run(ctx)

    assert result.is_vulnerable is False
    assert "publicly readable" in result.description.lower() or "public" in result.description.lower()


# ── Missing resource (baseline 404) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_baseline_404_inconclusive(live_server):
    """When baseline returns 404, check must be inconclusive with confidence=0.0."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/vuln/bookings/999")
    result = await check.run(ctx)

    assert result.is_vulnerable is False
    assert result.confidence == pytest.approx(0.0)
    assert "inconclusive" in result.title.lower()


# ── Out-of-scope host ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_out_of_scope_host_blocked():
    """
    Requests to external hosts must be blocked by the safety policy.
    is_vulnerable=False, description mentions safety policy, no actual request sent.
    """
    policy = SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    runner = ControlledHttpRunner(safety_policy=policy)
    check = BOLAOwnershipCheck(runner=runner)

    ctx = SecurityCheckContext(
        test_id="test-scope-001",
        target_url="http://example.com",
        endpoint_path="/api/bookings/101",
        http_method="GET",
        auth_headers={"Authorization": f"Bearer {TOK_A}"},
        secondary_auth_headers={"Authorization": f"Bearer {TOK_B}"},
    )
    result = await check.run(ctx)

    assert result.is_vulnerable is False
    assert "safety policy" in result.description.lower()


# ── Token redaction ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tokens_not_in_evidence(live_server):
    """Raw token values must never appear in evidence_request or proof_data."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/vuln/bookings/101")
    result = await check.run(ctx)

    evidence_text = result.evidence_request + str(result.proof_data)
    assert TOK_A not in evidence_text, "tokA value found in evidence!"
    assert TOK_B not in evidence_text, "tokB value found in evidence!"


@pytest.mark.asyncio
async def test_tokens_not_in_evidence_secure(live_server):
    """Token redaction must hold even for non-vulnerable results."""
    check = BOLAOwnershipCheck(runner=_make_runner(live_server))
    ctx = _make_context(live_server, "/secure/bookings/101")
    result = await check.run(ctx)

    evidence_text = result.evidence_request + str(result.proof_data)
    assert TOK_A not in evidence_text
    assert TOK_B not in evidence_text


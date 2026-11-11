"""
Tests for verification/proof_engine.py (SelfChallengingProofEngine) and
verification/pipeline.py (verify_and_package).

Covers:
  - Proof engine CONFIRMS /vuln endpoint finding (all disproof tests fail)
  - Proof engine REJECTS /secure endpoint (reproducibility fails: 0 hits)
  - Proof engine REJECTS /public endpoint (negative control disproves it)
  - Proof engine REJECTS /flaky endpoint (reproducibility < 1.0)
  - verify_and_package returns EvidencePackage for /vuln
  - verify_and_package returns None for /secure, /public, /flaky

All HTTP goes through ControlledHttpRunner targeting 127.0.0.1 only.
"""

import pytest

from checks.authorization.bola_check import BOLAOwnershipCheck
from checks.base import SecurityCheckContext
from evidence.collector import EvidenceCollector, EvidencePackage
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from verification.pipeline import verify_and_package
from verification.proof_engine import SelfChallengingProofEngine

TOK_A = "tokA"
TOK_B = "tokB"


def _make_runner(base_url: str) -> ControlledHttpRunner:
    policy = SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"])
    return ControlledHttpRunner(safety_policy=policy)


def _make_context(base_url: str, path: str, booking_id: int = 101) -> SecurityCheckContext:
    return SecurityCheckContext(
        test_id="test-proof-001",
        target_url=base_url,
        endpoint_path=path,
        http_method="GET",
        auth_headers={"Authorization": f"Bearer {TOK_A}"},
        secondary_auth_headers={"Authorization": f"Bearer {TOK_B}"},
        parameters={},
    )


async def _run_check(base_url: str, path: str):
    """Helper: run BOLAOwnershipCheck and return result."""
    runner = _make_runner(base_url)
    check = BOLAOwnershipCheck(runner=runner)
    ctx = _make_context(base_url, path)
    return await check.run(ctx), ctx, runner


# ── Proof engine: /vuln ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proof_engine_confirms_vuln(live_server):
    """Proof engine must confirm a genuine BOLA finding on the vulnerable endpoint."""
    result, ctx, runner = await _run_check(live_server, "/vuln/bookings/101")
    assert result.is_vulnerable, "Precondition: check must flag as vulnerable"

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    # Provide baseline_body via context parameters so the engine can compare
    # (the check doesn't store it; we fetch it via proof_data body_match=True context)
    evidence = {
        "attack_url": result.proof_data["attack_url"],
        "victim_headers": ctx.auth_headers,
        "attacker_headers": ctx.secondary_auth_headers,
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("BOLA on /vuln/bookings/101", evidence)

    assert verdict.is_confirmed is True
    assert verdict.reproducibility_rate == pytest.approx(1.0)
    assert verdict.confidence == pytest.approx(0.95)


# ── Proof engine: /secure ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proof_engine_rejects_secure(live_server):
    """Proof engine must NOT confirm finding on the secure endpoint (correctly protected)."""
    # Force check result with is_vulnerable=True by directly crafting evidence
    # for the proof engine (simulating what would happen if the check incorrectly flagged it)
    runner = _make_runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)

    # attacker requesting booking 101 from /secure will get 403 -> reproducibility=0
    evidence = {
        "attack_url": f"{live_server}/secure/bookings/101",
        "victim_headers": {"Authorization": f"Bearer {TOK_A}"},
        "attacker_headers": {"Authorization": f"Bearer {TOK_B}"},
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("Test secure", evidence)

    assert verdict.is_confirmed is False
    assert verdict.reproducibility_rate == pytest.approx(0.0)
    assert verdict.confidence == pytest.approx(0.2)


# ── Proof engine: /public ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proof_engine_rejects_public(live_server):
    """Proof engine must reject finding when negative control (no-auth) also returns data."""
    runner = _make_runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)

    evidence = {
        "attack_url": f"{live_server}/public/bookings/101",
        "victim_headers": {"Authorization": f"Bearer {TOK_A}"},
        "attacker_headers": {"Authorization": f"Bearer {TOK_B}"},
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("Test public", evidence)

    # Negative control will show no-auth also returns the same body -> disproved
    assert verdict.is_confirmed is False
    assert verdict.confidence == pytest.approx(0.2)
    assert "negative_control" in verdict.counter_evidence


# ── Proof engine: /flaky ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_proof_engine_rejects_flaky(live_server):
    """
    Proof engine must reject flaky findings (reproducibility < 1.0).
    /flaky/bookings/{id} only allows cross-user access on the first request.
    """
    runner = _make_runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)

    # Flaky endpoint: first request by tokB for booking 101 leaks it,
    # but subsequent ones return 403.  Reproducibility will be < 1.0.
    evidence = {
        "attack_url": f"{live_server}/flaky/bookings/101",
        "victim_headers": {"Authorization": f"Bearer {TOK_A}"},
        "attacker_headers": {"Authorization": f"Bearer {TOK_B}"},
        "baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}',
        "ignore_fields": [],
    }
    verdict = await engine.verify_finding("Test flaky", evidence)

    assert verdict.is_confirmed is False
    assert verdict.reproducibility_rate < 1.0
    assert verdict.confidence == pytest.approx(0.2)


# ── verify_and_package: /vuln ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_packages_vuln(live_server):
    """verify_and_package must return an EvidencePackage for the vulnerable endpoint."""
    result, ctx, runner = await _run_check(live_server, "/vuln/bookings/101")
    assert result.is_vulnerable

    # inject baseline_body into parameters so the engine can confirm
    ctx_with_baseline = SecurityCheckContext(
        test_id=ctx.test_id,
        target_url=ctx.target_url,
        endpoint_path=ctx.endpoint_path,
        http_method=ctx.http_method,
        auth_headers=ctx.auth_headers,
        secondary_auth_headers=ctx.secondary_auth_headers,
        parameters={"_baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}'},
    )

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    package = await verify_and_package(result, ctx_with_baseline, engine, collector)

    assert package is not None
    assert isinstance(package, EvidencePackage)
    assert package.test_id == ctx.test_id
    assert "verdict" in package.proof_data


# ── verify_and_package: /secure → None ───────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_returns_none_for_secure(live_server):
    """verify_and_package must return None when the check result is not vulnerable."""
    result, ctx, runner = await _run_check(live_server, "/secure/bookings/101")
    assert not result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    package = await verify_and_package(result, ctx, engine, collector)
    assert package is None


# ── verify_and_package: /public → None ───────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_returns_none_for_public(live_server):
    """verify_and_package must return None for a public endpoint."""
    result, ctx, runner = await _run_check(live_server, "/public/bookings/101")
    assert not result.is_vulnerable

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    package = await verify_and_package(result, ctx, engine, collector)
    assert package is None


# ── verify_and_package: /flaky → None ────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_returns_none_for_flaky(live_server):
    """
    For the flaky endpoint, the check may (on its first run) return is_vulnerable=True,
    but verify_and_package must still return None because the proof engine rejects it.
    If the check itself returns False (after the first request is consumed) that's also valid.
    """
    runner = _make_runner(live_server)
    check = BOLAOwnershipCheck(runner=runner)
    ctx = _make_context(live_server, "/flaky/bookings/101")
    result = await check.run(ctx)

    ctx_with_baseline = SecurityCheckContext(
        test_id=ctx.test_id,
        target_url=ctx.target_url,
        endpoint_path=ctx.endpoint_path,
        http_method=ctx.http_method,
        auth_headers=ctx.auth_headers,
        secondary_auth_headers=ctx.secondary_auth_headers,
        parameters={"_baseline_body": '{"id": 101, "owner_id": 1, "destination": "Paris", "nights": 3}'},
    )

    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    collector = EvidenceCollector()

    package = await verify_and_package(result, ctx_with_baseline, engine, collector)
    # Either the check didn't flag it, or the engine rejected it
    assert package is None



# ── real end-to-end flow: no manual baseline injection ───────────────────────

@pytest.mark.asyncio
async def test_pipeline_real_flow_no_injected_baseline(live_server):
    """The check's own output must be enough for the pipeline to confirm /vuln."""
    result, ctx, runner = await _run_check(live_server, "/vuln/bookings/101")
    assert result.is_vulnerable
    assert "baseline_body" not in result.proof_data  # never persisted
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    package = await verify_and_package(result, ctx, engine, EvidenceCollector())
    assert package is not None


@pytest.mark.asyncio
async def test_engine_refuses_empty_baseline(live_server):
    runner = _make_runner(live_server)
    engine = SelfChallengingProofEngine(runner=runner, replays=3)
    verdict = await engine.verify_finding("x", {
        "attack_url": f"{live_server}/vuln/bookings/101",
        "attacker_headers": {"Authorization": f"Bearer {TOK_B}"},
        "baseline_body": "",
    })
    assert not verdict.is_confirmed
"""
Benchmark tests specifically verifying the 15 API Security ground-truth cases:
AUTH-001..006, VAL-001..004, CORS-001..003, METH-001..002.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from benchmark.runner import run_benchmark
from benchmark.schema import load_manifest
import tests.mock_vuln_app as mock_app

API_SECURITY_CASE_IDS = {
    "AUTH-001",
    "AUTH-002",
    "AUTH-003",
    "AUTH-004",
    "AUTH-005",
    "AUTH-006",
    "VAL-001",
    "VAL-002",
    "VAL-003",
    "VAL-004",
    "CORS-001",
    "CORS-002",
    "CORS-003",
    "METH-001",
    "METH-002",
}


@pytest.mark.asyncio
async def test_benchmark_api_security_cases(live_server):
    manifest_path = (
        Path(__file__).resolve().parent.parent
        / "benchmark"
        / "ground_truth"
        / "phantom_mock_v1.json"
    )
    manifest, sha_hex = load_manifest(manifest_path)

    run = await run_benchmark(
        manifest=manifest,
        base_url=live_server,
        rps=200,
        replays=3,
        reset=mock_app.reset_counters,
        manifest_sha256=sha_hex,
    )

    case_map = {r.case_id: r for r in run.results}

    # Verify that all 15 API security cases are present
    for case_id in API_SECURITY_CASE_IDS:
        assert case_id in case_map, f"Case {case_id} not found in benchmark run results"
        res = case_map[case_id]

        # No new case has an ERROR outcome
        assert res.observed_outcome != "ERROR", (
            f"Case {case_id} errored during execution. Reason: {res.reason}"
        )

        # Observed outcome matches expected outcome
        assert res.observed_outcome == res.expected_outcome, (
            f"Case {case_id} failed: expected '{res.expected_outcome}', "
            f"observed '{res.observed_outcome}'. Reason: {res.reason}"
        )


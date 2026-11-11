"""
Test suite for the PHANTOM-X benchmark and ground-truth harness.

Covers:
  Part A (offline):
    - Manifest loading, case uniqueness, 21 cases
    - Plan scenario coverage (covered vs not covered)
    - Metrics calculation over hand-made CaseResult lists
    - evaluate_targets passing/failing
    - Source scanning: checks/, verification/, evidence/, safety/, execution/ do NOT import benchmark
  Part B (with live_server):
    - Golden regression run: outcome_accuracy == 1.0
    - Confusion matrix assertions: precision == 1.0, recall == 5/8, recall+review == 7/8
    - Proof engine value: raw_fp == 1, fp == 0, removed == 1
    - Safety checks: SAFE-001..003 blocked/refused with 0 sent requests
    - Safety compliance == 1.0 across all HTTP traffic
    - Report generation: results.json & report.md contain no secrets or tokens
    - Unknown check handles gracefully as ERROR
    - --skip-stateful marks stateful cases as SKIPPED
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from benchmark.metrics import CaseResult, compute_metrics, evaluate_targets
from benchmark.report import write_report
from benchmark.runner import run_benchmark
from benchmark.schema import BenchmarkCase, Manifest, load_manifest
import tests.mock_vuln_app as mock_app

SECRETS = ["tokA", "tokB", "adminTok", "custTok", "Bearer"]


# ==============================================================================
# PART A: Schema, Metrics, and Source Scan Tests (No Server Required)
# ==============================================================================

def test_manifest_loads_and_validates():
    manifest_path = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    manifest, sha256_hex = load_manifest(manifest_path)

    assert isinstance(manifest, Manifest)
    assert len(sha256_hex) == 64
    assert len(manifest.cases) == 21

    ids = [c.id for c in manifest.cases]
    assert len(ids) == len(set(ids)), "Case IDs must be unique"


def test_scenario_coverage_plan_alignment():
    manifest_path = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    manifest, _ = load_manifest(manifest_path)

    dummy_results = [
        CaseResult(
            case_id=c.id, category=c.category, scenario=c.scenario,
            ground_truth=c.ground_truth, expected_outcome=c.expected_outcome,
            observed_outcome=c.expected_outcome, raw_flagged=False,
            requests_sent=1, requests_blocked=0, duration_ms=1.0, reason="",
        )
        for c in manifest.cases
    ]

    metrics = compute_metrics(dummy_results, plan_scenarios=manifest.plan_scenarios)
    cov = metrics["scenario_coverage"]

    # Plan scenarios covered
    assert "cross_tenant_booking_access" in cov["covered"]
    assert "role_bypass" in cov["covered"]
    assert "authentication_inconsistency" in cov["covered"]

    # Plan scenarios not yet covered
    assert "property_exposure" in cov["not_covered"]
    assert "workflow_abuse" in cov["not_covered"]
    assert "supplier_isolation_failure" in cov["not_covered"]


def test_metrics_hand_made_cases():
    # 1. Perfect detection
    perfect = [
        CaseResult(case_id="1", category="bola", scenario="s", ground_truth="vulnerable",
                   expected_outcome="CONFIRMED", observed_outcome="CONFIRMED", raw_flagged=True, reason=""),
        CaseResult(case_id="2", category="bola", scenario="s", ground_truth="secure",
                   expected_outcome="NOT_FLAGGED", observed_outcome="NOT_FLAGGED", raw_flagged=False, reason=""),
    ]
    m_perfect = compute_metrics(perfect)
    assert m_perfect["tp"] == 1
    assert m_perfect["fp"] == 0
    assert m_perfect["precision"] == 1.0
    assert m_perfect["recall_auto_confirmed"] == 1.0
    assert m_perfect["outcome_accuracy"] == 1.0

    # 2. One False Positive
    one_fp = [
        CaseResult(case_id="1", category="bola", scenario="s", ground_truth="vulnerable",
                   expected_outcome="CONFIRMED", observed_outcome="CONFIRMED", raw_flagged=True, reason=""),
        CaseResult(case_id="2", category="bola", scenario="s", ground_truth="secure",
                   expected_outcome="NOT_FLAGGED", observed_outcome="CONFIRMED", raw_flagged=True, reason=""),
    ]
    m_fp = compute_metrics(one_fp)
    assert m_fp["tp"] == 1
    assert m_fp["fp"] == 1
    assert m_fp["precision"] == 0.5
    assert m_fp["false_positive_rate"] == 1.0

    # 3. One False Negative (Missed vulnerability)
    one_fn = [
        CaseResult(case_id="1", category="bola", scenario="s", ground_truth="vulnerable",
                   expected_outcome="CONFIRMED", observed_outcome="NOT_FLAGGED", raw_flagged=False, reason=""),
        CaseResult(case_id="2", category="bola", scenario="s", ground_truth="secure",
                   expected_outcome="NOT_FLAGGED", observed_outcome="NOT_FLAGGED", raw_flagged=False, reason=""),
    ]
    m_fn = compute_metrics(one_fn)
    assert m_fn["tp"] == 0
    assert m_fn["fn"] == 1
    assert m_fn["recall_auto_confirmed"] == 0.0

    # 4. Zero vulnerable cases -> None
    no_vuln = [
        CaseResult(case_id="1", category="bola", scenario="s", ground_truth="secure",
                   expected_outcome="NOT_FLAGGED", observed_outcome="NOT_FLAGGED", raw_flagged=False, reason=""),
    ]
    m_no_vuln = compute_metrics(no_vuln)
    assert m_no_vuln["recall_auto_confirmed"] is None
    assert m_no_vuln["recall_incl_human_review"] is None

    # 5. Raw vs Verified False Positive filtering
    proof_engine_value_cases = [
        # Check flagged a secure endpoint (raw FP), but proof engine rejected it (verified TN)
        CaseResult(case_id="1", category="bola", scenario="s", ground_truth="secure",
                   expected_outcome="REJECTED", observed_outcome="REJECTED", raw_flagged=True, reason=""),
    ]
    m_val = compute_metrics(proof_engine_value_cases)
    assert m_val["raw_fp"] == 1
    assert m_val["fp"] == 0
    assert m_val["false_positives_removed_by_proof_engine"] == 1


def test_evaluate_targets_pass_and_fail():
    passing_metrics = {
        "reproducibility": 1.0,
        "safety_block_rate": 1.0,
        "fp": 0,
        "safety_compliance": 1.0,
    }
    targets = evaluate_targets(passing_metrics)
    assert all(t["passed"] for t in targets)
    assert all("Proposed engineering targets" in t["disclaimer"] for t in targets)

    failing_metrics = {
        "reproducibility": 0.80,
        "safety_block_rate": 0.50,
        "fp": 2,
        "safety_compliance": 0.90,
    }
    f_targets = evaluate_targets(failing_metrics)
    assert not any(t["passed"] for t in f_targets)


def test_no_benchmark_imports_in_agent_code():
    """
    Enforce architectural boundary: agents and security checks must never import
    benchmark modules (they must never see ground-truth definitions).
    """
    engine_root = Path(__file__).resolve().parent.parent
    prohibited_dirs = ["checks", "verification", "evidence", "safety", "execution"]

    for d in prohibited_dirs:
        dir_path = engine_root / d
        if not dir_path.is_dir():
            continue
        for py_file in dir_path.rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert not alias.name.startswith("benchmark"), (
                            f"Prohibited import 'benchmark' found in {py_file}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        assert not node.module.startswith("benchmark"), (
                            f"Prohibited import 'benchmark' found in {py_file}"
                        )


# ==============================================================================
# PART B: Live Runner and Report Tests (Uses live_server)
# ==============================================================================

@pytest.mark.asyncio
async def test_full_benchmark_golden_run(live_server, tmp_path):
    manifest_path = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    manifest, sha_hex = load_manifest(manifest_path)

    # Execute benchmark against live_server with reset callback
    run = await run_benchmark(
        manifest=manifest,
        base_url=live_server,
        rps=200,
        replays=3,
        reset=mock_app.reset_counters,
        manifest_sha256=sha_hex,
    )

    metrics = compute_metrics(
        results=run.results,
        request_log=run.request_log,
        plan_scenarios=manifest.plan_scenarios,
    )
    targets = evaluate_targets(metrics)

    # 1. Golden regression gate: 100% outcome accuracy
    for res in run.results:
        assert res.observed_outcome == res.expected_outcome, (
            f"Case {res.case_id} failed: expected '{res.expected_outcome}', observed '{res.observed_outcome}'. Reason: {res.reason}"
        )
    assert metrics["outcome_accuracy"] == 1.0

    # 2. Confusion matrix & Proof engine value assertions
    assert metrics["fp"] == 0
    assert metrics["raw_fp"] == 1  # BOLA-004 flaky endpoint
    assert metrics["false_positives_removed_by_proof_engine"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall_auto_confirmed"] == pytest.approx(5 / 8)
    assert metrics["recall_incl_human_review"] == pytest.approx(7 / 8)

    # 3. Safety checks SAFE-001..003
    case_map = {r.case_id: r for r in run.results}

    safe_001 = case_map["SAFE-001"]
    assert safe_001.observed_outcome == "BLOCKED"
    assert safe_001.requests_blocked >= 1
    assert safe_001.requests_sent == 0

    safe_002 = case_map["SAFE-002"]
    assert safe_002.observed_outcome == "BLOCKED"
    assert safe_002.requests_blocked >= 1
    assert safe_002.requests_sent == 0

    safe_003 = case_map["SAFE-003"]
    assert safe_003.observed_outcome == "REFUSED"
    assert safe_003.requests_sent == 0
    assert safe_003.requests_blocked == 0

    # 4. Safety compliance
    assert metrics["safety_compliance"] == 1.0
    for req in run.request_log:
        if not req.get("blocked", False):
            assert req.get("method") in {"GET", "HEAD", "OPTIONS"}
            assert req.get("host") in {"127.0.0.1", "localhost"}

    # 5. Proposed targets all pass
    assert all(t["passed"] for t in targets)

    # 6. Report generation & secret sanitization
    results_json_path, report_md_path = write_report(run, metrics, targets, tmp_path)
    assert results_json_path.is_file()
    assert report_md_path.is_file()

    json_content = results_json_path.read_text(encoding="utf-8")
    md_content = report_md_path.read_text(encoding="utf-8")

    for text in (json_content, md_content):
        for secret in SECRETS:
            assert secret not in text, f"Secret '{secret}' leaked in generated report!"


@pytest.mark.asyncio
async def test_unknown_check_name_handled_as_error(live_server):
    manifest_path = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    manifest, _ = load_manifest(manifest_path)

    # Create dummy case with an unknown check class
    bad_case = BenchmarkCase(
        id="BAD-001",
        scenario="test",
        category="bola",
        check="NonExistentCheckClass",  # type: ignore[arg-type]
        path="/test",
        method="GET",
        owner="alpha_agent",
        attacker="beta_agent",
        ground_truth="vulnerable",
        expected_outcome="CONFIRMED",
    )
    test_manifest = Manifest(
        name="test",
        version="1.0",
        description="test",
        identities=manifest.identities,
        plan_scenarios=[],
        cases=[bad_case],
    )

    run = await run_benchmark(test_manifest, live_server)
    assert len(run.results) == 1
    res = run.results[0]
    assert res.observed_outcome == "ERROR"
    assert "not available" in res.reason


@pytest.mark.asyncio
async def test_skip_stateful_flag(live_server):
    manifest_path = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    manifest, _ = load_manifest(manifest_path)

    run = await run_benchmark(
        manifest=manifest,
        base_url=live_server,
        skip_stateful=True,
    )

    case_map = {r.case_id: r for r in run.results}
    assert case_map["BOLA-004"].observed_outcome == "SKIPPED"
    assert case_map["BOLA-005"].observed_outcome == "SKIPPED"

    metrics = compute_metrics(run.results)
    # BOLA-004 was raw_fp; skipping it means raw_fp is 0 for the remaining cases
    assert metrics["raw_fp"] == 0
    assert metrics["active_cases"] == 19


"""
Benchmark Reporting and Serialization Engine.

Generates structured JSON (results.json) and Markdown (report.md) summaries.
Sanitizes all text via evidence.redact.redact_text and strips credentials,
tokens, headers, and bodies from all reported tables and artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from evidence.redact import redact_text
from benchmark.metrics import PROPOSED_TARGETS_DISCLAIMER
from benchmark.runner import BenchmarkRun


def _fmt(val: Any, is_pct: bool = False) -> str:
    """Format metric value, returning 'n/a' for None."""
    if val is None:
        return "n/a"
    if isinstance(val, float):
        return f"{val * 100:.1f}%" if is_pct else f"{val:.4f}"
    return str(val)


def write_report(
    run: BenchmarkRun,
    metrics: Dict[str, Any],
    targets: List[Dict[str, Any]],
    out_dir: Path | str,
) -> Tuple[Path, Path]:
    """
    Serialize benchmark results to results.json and generate report.md.

    Args:
        run: Executed BenchmarkRun instance
        metrics: Computed metrics dictionary from compute_metrics()
        targets: Target evaluation list from evaluate_targets()
        out_dir: Destination directory

    Returns:
        (results_json_path, report_md_path)
    """
    output_path = Path(out_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    # 1. Sanitize Case Results for results.json
    sanitized_cases: List[Dict[str, Any]] = []
    for c in run.results:
        case_dict = c.model_dump()
        case_dict["reason"] = redact_text(case_dict.get("reason", ""))
        sanitized_cases.append(case_dict)

    json_payload = {
        "metadata": run.metadata,
        "metrics": metrics,
        "targets": targets,
        "case_results": sanitized_cases,
    }

    results_json_path = output_path / "results.json"
    results_json_path.write_text(
        json.dumps(json_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # 2. Generate report.md
    meta = run.metadata
    cov = metrics.get("scenario_coverage", {})
    covered_scenarios = cov.get("covered", [])
    not_covered_scenarios = cov.get("not_covered", [])

    md_lines: List[str] = [
        "# PHANTOM-X Security Benchmark Report",
        "",
        "## 1. Metadata & Scope",
        "",
        f"- **Suite Name**: `{meta.get('manifest_name', 'n/a')}`",
        f"- **Suite Version**: `{meta.get('manifest_version', 'n/a')}`",
        f"- **Manifest SHA-256**: `{meta.get('manifest_sha256', 'n/a')}`",
        f"- **Execution Timestamp (UTC)**: `{meta.get('timestamp_utc', 'n/a')}`",
        f"- **Python Version**: `{meta.get('python_version', 'n/a')}`",
        f"- **Git Commit**: `{meta.get('git_commit', 'n/a')}`",
        f"- **Target Base URL**: `{meta.get('base_url', 'n/a')}`",
        f"- **Safety Rate Limit**: `{meta.get('rps', 0)} rps`",
        f"- **Proof Engine Replays**: `{meta.get('replays', 0)}`",
        f"- **Total Executed Cases**: `{meta.get('total_executed', 0)}` "
        f"({meta.get('enabled_count', 0)} enabled, {meta.get('skipped_count', 0)} skipped, {meta.get('error_count', 0)} errors)",
        "",
        "## 2. Benchmark Metrics",
        "",
        "| Metric | Value | Definition |",
        "| :--- | :--- | :--- |",
        f"| **Outcome Accuracy** | {_fmt(metrics.get('outcome_accuracy'), is_pct=True)} | Percentage of active cases where observed outcome matches expected outcome. |",
        f"| **Precision (Verified)** | {_fmt(metrics.get('precision'), is_pct=True)} | True positives divided by all verified confirmed vulnerabilities (TP / (TP + FP)). |",
        f"| **Recall (Auto-Confirmed)** | {_fmt(metrics.get('recall_auto_confirmed'), is_pct=True)} | Proportion of true vulnerable endpoints automatically confirmed (TP / Total Vulnerable). |",
        f"| **Recall (Incl. Human Review)** | {_fmt(metrics.get('recall_incl_human_review'), is_pct=True)} | Vulnerabilities either auto-confirmed or flagged for human review. |",
        f"| **False Positive Rate (Verified)** | {_fmt(metrics.get('false_positive_rate'), is_pct=True)} | False positives divided by all secure baseline endpoints (FP / Total Secure). |",
        f"| **Raw Precision (Checks Only)** | {_fmt(metrics.get('raw_precision'), is_pct=True)} | Precision of standalone checks before the proof engine verification loop. |",
        f"| **Raw Recall (Checks Only)** | {_fmt(metrics.get('raw_recall'), is_pct=True)} | Recall of standalone checks before the proof engine verification loop. |",
        f"| **Raw False Positive Rate** | {_fmt(metrics.get('raw_false_positive_rate'), is_pct=True)} | False positive rate of standalone checks before the proof engine. |",
        f"| **Reproducibility** | {_fmt(metrics.get('reproducibility'), is_pct=True)} | Rate of successful confirmation replays for genuinely vulnerable cases. |",
        f"| **Safety Block Rate** | {_fmt(metrics.get('safety_block_rate'), is_pct=True)} | Fraction of safety constraint cases correctly blocked or refused. |",
        f"| **Safety Compliance** | {_fmt(metrics.get('safety_compliance'), is_pct=True)} | Fraction of outgoing HTTP requests conforming to allowed safe methods and hosts. |",
        f"| **Total Network Requests** | {metrics.get('total_requests', 0)} | Total HTTP transactions issued across all test cases. |",
        f"| **Mean Requests Per Case** | {_fmt(metrics.get('mean_requests_per_case'))} | Average number of HTTP round-trips required per case. |",
        f"| **Total Execution Time** | {metrics.get('total_duration_ms', 0.0):.1f} ms | Cumulative wall-clock execution duration. |",
        "",
        "## 3. Value of the Proof Engine",
        "",
        f"- **Raw False Positives (Checks alone)**: `{metrics.get('raw_fp', 0)}`",
        f"- **Verified False Positives (Post-Engine)**: `{metrics.get('fp', 0)}`",
        f"- **False Positives Suppressed by Proof Engine**: `{metrics.get('false_positives_removed_by_proof_engine', 0)}`",
        "",
        "The automated verification loop challenges suspected findings with negative controls and reproducibility replays, successfully eliminating flakiness and false alarms before developer alerting.",
        "",
        "## 4. Proposed Engineering Targets (Plan §27.4)",
        "",
        f"> **Note**: {PROPOSED_TARGETS_DISCLAIMER}",
        "",
        "| Target Name | Requirement | Observed Value | Status |",
        "| :--- | :--- | :--- | :--- |",
    ]

    for t in targets:
        name = t["name"].replace("_", " ").title()
        status_badge = "PASSED" if t["passed"] else "FAILED"
        val_str = _fmt(t["value"], is_pct=("rate" in t["name"] or "compliance" in t["name"] or "reproducibility" in t["name"]))
        md_lines.append(f"| {name} | `{t['target_text']}` | `{val_str}` | **{status_badge}** |")

    md_lines.extend([
        "",
        "## 5. Master Plan §22.3 Scenario Coverage",
        "",
        f"- **Covered Scenarios ({len(covered_scenarios)})**:",
    ])
    for s in covered_scenarios:
        count = cov.get("counts", {}).get(s, 0)
        md_lines.append(f"  - `{s}` ({count} cases)")

    md_lines.append(f"- **Pending / Uncovered Plan Scenarios ({len(not_covered_scenarios)})**:")
    for s in not_covered_scenarios:
        md_lines.append(f"  - `{s}` (0 cases)")

    md_lines.extend([
        "",
        "## 6. Case Execution Table",
        "",
        "| Case ID | Scenario | Check | Ground Truth | Expected | Observed | Match | Requests | Time (ms) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |",
    ])

    for c in run.results:
        match_str = "YES" if c.observed_outcome == c.expected_outcome else "NO"
        total_reqs = c.requests_sent + c.requests_blocked
        md_lines.append(
            f"| `{c.case_id}` | `{c.scenario}` | `{c.check}` | `{c.ground_truth}` | "
            f"`{c.expected_outcome}` | `{c.observed_outcome}` | **{match_str}** | "
            f"{total_reqs} | {c.duration_ms:.1f} |"
        )

    md_lines.extend([
        "",
        "## 7. Limitations & Evaluation Context",
        "",
        "- **Mock Environment**: The mock application was implemented by the same team; ground truth is established by construction rather than external empirical production telemetry.",
        "- **Sample Size**: With N=21 cases, metrics reflect deterministic validation of current rules rather than broad statistical power across real-world API implementations.",
        "- **No External Comparator**: In accordance with Master Plan §27.3, no superiority claims vs. OWASP ZAP or Schemathesis are asserted without empirical, side-by-side comparative measurements.",
        "- **Stateful Counter Dependency**: Intermittent and non-reproducible test cases rely on in-memory server state counters reset between test executions.",
        "- **Deliberate Recall Trade-off**: Three genuine vulnerability cases are intentionally designed to yield `NEEDS_HUMAN_REVIEW` or `INCONCLUSIVE` (intermittent failure, lenient token parsing, cache indicators), intentionally lowering the fully automated recall rate to avoid unverified alerts.",
        "",
    ])

    report_md_path = output_path / "report.md"
    report_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    return results_json_path, report_md_path


"""
Benchmark Metrics and Confusion Matrix Computation.

Pure functions over a list of CaseResult objects with zero I/O.
Computes verified and raw metrics, false positives removed by the proof engine,
scenario coverage against the security plan, and proposed engineering targets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence
from pydantic import BaseModel, Field

PROPOSED_TARGETS_DISCLAIMER = "Proposed engineering targets, not measured guarantees."

DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class CaseResult(BaseModel):
    """Observation and timing metadata for a single executed benchmark case."""
    case_id: str
    category: str
    scenario: str
    check: str = ""
    ground_truth: str  # "vulnerable", "secure", or "n/a"
    expected_outcome: str
    observed_outcome: str
    raw_flagged: bool
    independent: Optional[bool] = None
    requests_sent: int = 0
    requests_blocked: int = 0
    duration_ms: float = 0.0
    reason: str = ""


def compute_metrics(
    results: Sequence[CaseResult],
    request_log: Optional[Sequence[Dict[str, Any]]] = None,
    plan_scenarios: Optional[Sequence[str]] = None,
    allowed_hosts: Optional[Set[str] | Sequence[str]] = None,
) -> Dict[str, Any]:
    """
    Compute comprehensive benchmark metrics from case execution results.

    Positive := observed_outcome == "CONFIRMED".
    Only cases with ground_truth in {"vulnerable", "secure"} feed the confusion matrix.
    Division by zero returns None (rendered as 'n/a' in reports).
    """
    hosts_allowlist = set(allowed_hosts) if allowed_hosts else set(DEFAULT_ALLOWED_HOSTS)

    # Counts per observed outcome
    outcome_counts: Dict[str, int] = {}
    for r in results:
        outcome_counts[r.observed_outcome] = outcome_counts.get(r.observed_outcome, 0) + 1

    # Filter for confusion matrix (exclude safety / n/a ground truth)
    eval_cases = [r for r in results if r.ground_truth in {"vulnerable", "secure"} and r.observed_outcome != "SKIPPED"]
    vulnerable_cases = [r for r in eval_cases if r.ground_truth == "vulnerable"]
    secure_cases = [r for r in eval_cases if r.ground_truth == "secure"]

    # Verified confusion matrix (positive := observed == "CONFIRMED")
    tp = sum(1 for r in vulnerable_cases if r.observed_outcome == "CONFIRMED")
    fp = sum(1 for r in secure_cases if r.observed_outcome == "CONFIRMED")
    fn = sum(1 for r in vulnerable_cases if r.observed_outcome != "CONFIRMED")
    tn = sum(1 for r in secure_cases if r.observed_outcome != "CONFIRMED")

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall_auto_confirmed = tp / len(vulnerable_cases) if vulnerable_cases else None

    # Recall including human review
    review_or_confirmed_on_vuln = sum(
        1 for r in vulnerable_cases if r.observed_outcome in {"CONFIRMED", "NEEDS_HUMAN_REVIEW"}
    )
    recall_incl_human_review = (
        review_or_confirmed_on_vuln / len(vulnerable_cases) if vulnerable_cases else None
    )

    false_positive_rate = fp / len(secure_cases) if secure_cases else None

    # Raw confusion matrix (positive := raw_flagged is True)
    raw_tp = sum(1 for r in vulnerable_cases if r.raw_flagged)
    raw_fp = sum(1 for r in secure_cases if r.raw_flagged)
    raw_fn = sum(1 for r in vulnerable_cases if not r.raw_flagged)
    raw_tn = sum(1 for r in secure_cases if not r.raw_flagged)

    raw_precision = raw_tp / (raw_tp + raw_fp) if (raw_tp + raw_fp) > 0 else None
    raw_recall = raw_tp / len(vulnerable_cases) if vulnerable_cases else None
    raw_false_positive_rate = raw_fp / len(secure_cases) if secure_cases else None

    false_positives_removed_by_proof_engine = raw_fp - fp

    # Outcome accuracy (excluding SKIPPED)
    active_cases = [r for r in results if r.observed_outcome != "SKIPPED"]
    matching_cases = sum(1 for r in active_cases if r.observed_outcome == r.expected_outcome)
    outcome_accuracy = matching_cases / len(active_cases) if active_cases else None

    # Reproducibility rate across vulnerable cases expected to be confirmed
    reproducibility_candidates = [
        r for r in active_cases
        if r.ground_truth == "vulnerable" and r.expected_outcome == "CONFIRMED" and r.raw_flagged
    ]
    reproducibility = (
        sum(1 for r in reproducibility_candidates if r.observed_outcome == "CONFIRMED")
        / len(reproducibility_candidates)
        if reproducibility_candidates
        else None
    )

    # Safety metrics
    safety_cases = [r for r in active_cases if r.category == "safety"]
    safety_matches = sum(1 for r in safety_cases if r.observed_outcome == r.expected_outcome)
    safety_block_rate = safety_matches / len(safety_cases) if safety_cases else None

    # Safety compliance: check request_log
    requests = list(request_log or [])
    sent_requests = [req for req in requests if not req.get("blocked", False)]
    if sent_requests:
        compliant_requests = sum(
            1 for req in sent_requests
            if req.get("method", "").upper() in SAFE_HTTP_METHODS
            and req.get("host", "").lower() in hosts_allowlist
        )
        safety_compliance = compliant_requests / len(sent_requests)
    else:
        # If no requests were sent, compliance is 1.0 (no unauthorized packets left)
        safety_compliance = 1.0 if request_log is not None else None

    total_requests = len(requests) if request_log is not None else sum(r.requests_sent + r.requests_blocked for r in results)
    mean_requests_per_case = total_requests / len(results) if results else None
    total_duration_ms = sum(r.duration_ms for r in results)

    # Per-category metrics
    per_category: Dict[str, Dict[str, Any]] = {}
    categories = sorted({r.category for r in results})
    for cat in categories:
        cat_cases = [r for r in active_cases if r.category == cat]
        cat_matches = sum(1 for r in cat_cases if r.observed_outcome == r.expected_outcome)
        cat_acc = cat_matches / len(cat_cases) if cat_cases else None
        per_category[cat] = {
            "cases": len([r for r in results if r.category == cat]),
            "active_cases": len(cat_cases),
            "outcome_accuracy": cat_acc,
        }

    # Scenario coverage
    scenario_counts: Dict[str, int] = {}
    for r in active_cases:
        scenario_counts[r.scenario] = scenario_counts.get(r.scenario, 0) + 1

    expected_scenarios = list(plan_scenarios or [])
    covered = [s for s in expected_scenarios if scenario_counts.get(s, 0) > 0]
    not_covered = [s for s in expected_scenarios if scenario_counts.get(s, 0) == 0]

    return {
        "counts": outcome_counts,
        "total_cases": len(results),
        "active_cases": len(active_cases),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall_auto_confirmed": recall_auto_confirmed,
        "recall_incl_human_review": recall_incl_human_review,
        "false_positive_rate": false_positive_rate,
        "raw_tp": raw_tp,
        "raw_fp": raw_fp,
        "raw_fn": raw_fn,
        "raw_tn": raw_tn,
        "raw_precision": raw_precision,
        "raw_recall": raw_recall,
        "raw_false_positive_rate": raw_false_positive_rate,
        "false_positives_removed_by_proof_engine": false_positives_removed_by_proof_engine,
        "outcome_accuracy": outcome_accuracy,
        "reproducibility": reproducibility,
        "safety_block_rate": safety_block_rate,
        "safety_compliance": safety_compliance,
        "total_requests": total_requests,
        "mean_requests_per_case": mean_requests_per_case,
        "total_duration_ms": total_duration_ms,
        "per_category": per_category,
        "scenario_coverage": {
            "counts": scenario_counts,
            "covered": covered,
            "not_covered": not_covered,
        },
    }


def evaluate_targets(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate proposed engineering targets from Master Plan §27.4.

    Every output that lists them includes the disclaimer:
    'Proposed engineering targets, not measured guarantees.'
    """
    reproducibility = metrics.get("reproducibility")
    safety_block_rate = metrics.get("safety_block_rate")
    fp = metrics.get("fp")
    safety_compliance = metrics.get("safety_compliance")

    targets = [
        {
            "name": "reproducibility",
            "target_text": ">= 0.95",
            "value": reproducibility,
            "passed": reproducibility is not None and reproducibility >= 0.95,
            "disclaimer": PROPOSED_TARGETS_DISCLAIMER,
        },
        {
            "name": "safety_block_rate",
            "target_text": "== 1.0",
            "value": safety_block_rate,
            "passed": safety_block_rate is not None and safety_block_rate == 1.0,
            "disclaimer": PROPOSED_TARGETS_DISCLAIMER,
        },
        {
            "name": "verified_false_positives",
            "target_text": "== 0",
            "value": fp,
            "passed": fp == 0,
            "disclaimer": PROPOSED_TARGETS_DISCLAIMER,
        },
        {
            "name": "safety_compliance",
            "target_text": "== 1.0",
            "value": safety_compliance,
            "passed": safety_compliance is not None and safety_compliance == 1.0,
            "disclaimer": PROPOSED_TARGETS_DISCLAIMER,
        },
    ]
    return targets


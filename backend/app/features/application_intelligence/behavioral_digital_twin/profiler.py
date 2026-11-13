import math
from typing import Any, Dict, List, Optional
from datetime import datetime

from app.features.application_intelligence.behavioral_digital_twin.schema_inference import (
    merge_structural_schemas,
    infer_payload_schema,
)


def calculate_confidence(
    sample_count: int,
    status_code_distribution: Optional[Dict[str, int]] = None,
    schema_stability: float = 1.0,
) -> float:
    """
    Computes a statistical confidence score between 0.0 and 1.0 for a behavioral profile.
    Guarantees:
    - 0 observations: 0.0
    - 1-2 observations: strictly <= 0.15 (never treated as reliable baseline behavior)
    - Scale smoothly reaches ~0.70 at N=30 and ~0.95 at N=100+
    - Penalizes erratic status-code distributions or conflicting schemas.
    """
    if sample_count <= 0:
        return 0.0

    # Sample-size saturation curve: 1 - exp(-N / 25.0)
    sample_factor = 1.0 - math.exp(-float(sample_count) / 25.0)

    # Hard threshold: never permit high confidence on 1 or 2 observations
    if sample_count <= 2:
        sample_factor = min(sample_factor, 0.10)

    # Consistency factor based on dominant status code frequency
    consistency_factor = 1.0
    if status_code_distribution and sum(status_code_distribution.values()) > 0:
        total = sum(status_code_distribution.values())
        dominant_count = max(status_code_distribution.values())
        dominant_ratio = dominant_count / float(total)
        # Ratio of dominant behavior (e.g. 95% 200s is highly consistent)
        consistency_factor = 0.5 + 0.5 * dominant_ratio

    stability_factor = max(0.2, min(1.0, schema_stability))

    score = sample_factor * consistency_factor * stability_factor
    return round(max(0.0, min(1.0, score)), 4)


def compute_latency_stats(latencies: List[float]) -> Dict[str, float]:
    """
    Calculate min, max, avg, and 95th percentile latency from samples.
    """
    if not latencies:
        return {"min_ms": 0.0, "max_ms": 0.0, "avg_ms": 0.0, "p95_ms": 0.0}

    sorted_l = sorted(latencies)
    n = len(sorted_l)
    p95_idx = int(math.ceil(0.95 * n)) - 1
    p95_val = sorted_l[max(0, min(p95_idx, n - 1))]

    return {
        "min_ms": round(min(sorted_l), 2),
        "max_ms": round(max(sorted_l), 2),
        "avg_ms": round(sum(sorted_l) / float(n), 2),
        "p95_ms": round(p95_val, 2),
    }


def aggregate_endpoint_observations(
    observations: List[Any],
) -> Dict[str, Any]:
    """
    Aggregates a collection of BehavioralObservation records or observation dictionaries
    into a structured endpoint profile containing:
    - total_requests
    - status_code_distribution
    - latency_stats
    - inferred_request_schema
    - inferred_response_schema
    - confidence_score
    """
    if not observations:
        return {
            "total_requests": 0,
            "status_code_distribution": {},
            "latency_stats": {"min_ms": 0.0, "max_ms": 0.0, "avg_ms": 0.0, "p95_ms": 0.0},
            "inferred_request_schema": {},
            "inferred_response_schema": {},
            "confidence_score": 0.0,
        }

    status_counts: Dict[str, int] = {}
    latencies: List[float] = []
    merged_req_schema: Optional[Dict[str, Any]] = None
    merged_resp_schema: Optional[Dict[str, Any]] = None

    for obs in observations:
        # Support both ORM object and dictionary
        sc = getattr(obs, "status_code", None) if hasattr(obs, "status_code") else obs.get("status_code")
        lat = getattr(obs, "latency_ms", 0.0) if hasattr(obs, "latency_ms") else obs.get("latency_ms", 0.0)
        req_schema = getattr(obs, "sanitized_request_schema", {}) if hasattr(obs, "sanitized_request_schema") else obs.get("sanitized_request_schema", {})
        resp_schema = getattr(obs, "sanitized_response_schema", {}) if hasattr(obs, "sanitized_response_schema") else obs.get("sanitized_response_schema", {})

        if sc is not None:
            sc_str = str(sc)
            status_counts[sc_str] = status_counts.get(sc_str, 0) + 1

        if lat is not None:
            latencies.append(float(lat))

        if req_schema:
            merged_req_schema = merge_structural_schemas(merged_req_schema, req_schema)

        if resp_schema:
            merged_resp_schema = merge_structural_schemas(merged_resp_schema, resp_schema)

    total_requests = len(observations)
    confidence = calculate_confidence(total_requests, status_counts)
    latency_stats = compute_latency_stats(latencies)

    return {
        "total_requests": total_requests,
        "status_code_distribution": status_counts,
        "latency_stats": latency_stats,
        "inferred_request_schema": merged_req_schema or {},
        "inferred_response_schema": merged_resp_schema or {},
        "confidence_score": confidence,
    }

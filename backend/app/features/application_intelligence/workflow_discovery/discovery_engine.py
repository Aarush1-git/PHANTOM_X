"""
PHANTOM-X - Feature 5: Application Workflow Discovery
Workflow Discovery Engine

Algorithmic engine for:
- Reconstructing ordered user journeys from observed application traffic.
- Grouping events by session identity (session_token_hash) without raw secrets.
- Mining canonical workflow sequences, branching points, and loops.
- Tagging ENTRY, INTERMEDIATE, TERMINAL, and DROPOUT steps.
- Detecting abandoned and incomplete user journeys.
- Calculating statistically grounded confidence scores and transition probabilities.
- Compiling structured graph nodes and directed edges.
"""

import math
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.features.application_intelligence.workflow_discovery.models import (
    WorkflowType,
    WorkflowStatus,
    StepType,
)


def extract_node_key(obs: Any) -> str:
    """Generate a canonical key for an endpoint: METHOD:normalized_path."""
    method = getattr(obs, "method", "GET") if hasattr(obs, "method") else obs.get("method", "GET")
    norm_path = getattr(obs, "normalized_path", "/") if hasattr(obs, "normalized_path") else obs.get("normalized_path", "/")
    return f"{method.upper()}:{norm_path}"


class WorkflowDiscoveryEngine:
    """
    Statistically grounded discovery engine that synthesizes raw API observations
    into structured application workflows.
    """

    MIN_OBSERVATIONS_FOR_DISCOVERY = 2
    CONFIDENCE_SATURATION_K = 10  # 10 sessions saturate sample count weight to ~1.0

    @classmethod
    def discover_workflows(
        cls,
        observations: List[Any],
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        min_confidence: float = 0.0,
        min_sample_count: int = 1,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Main entry point for discovery.
        Returns:
            (discovered_workflow_dicts, discovery_metadata)
        """
        if not observations or len(observations) < cls.MIN_OBSERVATIONS_FOR_DISCOVERY:
            return [], {
                "insufficient_data": True,
                "insufficient_data_reason": (
                    f"Insufficient observations (observed: {len(observations)}, "
                    f"minimum required: {cls.MIN_OBSERVATIONS_FOR_DISCOVERY})"
                ),
                "analyzed_observations_count": len(observations) if observations else 0,
                "analyzed_sessions_count": 0,
            }

        # 1. Group observations by session_token_hash
        sessions: Dict[str, List[Any]] = defaultdict(list)
        unattributed_count = 0

        for obs in observations:
            sess_hash = getattr(obs, "session_token_hash", None) if hasattr(obs, "session_token_hash") else obs.get("session_token_hash")
            if sess_hash:
                sessions[sess_hash].append(obs)
            else:
                # Group unattributed into individual pseudo-sessions to prevent false merging
                unattributed_count += 1
                sessions[f"__unattributed_{unattributed_count}__"].append(obs)

        total_sessions = len(sessions)
        if total_sessions == 0:
            return [], {
                "insufficient_data": True,
                "insufficient_data_reason": "No distinct session traces could be reconstructed.",
                "analyzed_observations_count": len(observations),
                "analyzed_sessions_count": 0,
            }

        # 2. Extract ordered session journeys
        def get_observed_at(o: Any) -> datetime:
            val = getattr(o, "observed_at", None) if hasattr(o, "observed_at") else o.get("observed_at")
            if isinstance(val, datetime):
                return val
            return datetime.min

        session_journeys: List[List[Dict[str, Any]]] = []
        for sess_id, obs_list in sessions.items():
            sorted_obs = sorted(obs_list, key=get_observed_at)
            journey_steps = []
            for obs in sorted_obs:
                node_k = extract_node_key(obs)
                method = getattr(obs, "method", "GET") if hasattr(obs, "method") else obs.get("method", "GET")
                norm_path = getattr(obs, "normalized_path", "/") if hasattr(obs, "normalized_path") else obs.get("normalized_path", "/")
                eid = getattr(obs, "endpoint_id", None) if hasattr(obs, "endpoint_id") else obs.get("endpoint_id")
                lat = getattr(obs, "latency_ms", 0.0) if hasattr(obs, "latency_ms") else obs.get("latency_ms", 0.0)
                status_c = getattr(obs, "status_code", 200) if hasattr(obs, "status_code") else obs.get("status_code", 200)
                obs_id = getattr(obs, "id", None) if hasattr(obs, "id") else obs.get("id")

                journey_steps.append({
                    "node_key": node_k,
                    "method": method.upper(),
                    "normalized_path": norm_path,
                    "endpoint_id": str(eid) if eid else None,
                    "latency_ms": float(lat) if lat is not None else 0.0,
                    "status_code": int(status_c) if status_c is not None else 200,
                    "observation_id": str(obs_id) if obs_id else None,
                    "observed_at": get_observed_at(obs),
                })
            session_journeys.append(journey_steps)

        # 3. Cluster session journeys into sequence patterns
        # Key: tuple of node_keys
        path_clusters: Dict[Tuple[str, ...], List[List[Dict[str, Any]]]] = defaultdict(list)
        for journey in session_journeys:
            path_tuple = tuple(step["node_key"] for step in journey)
            path_clusters[path_tuple].append(journey)

        # 4. Identify complete vs incomplete / abandoned journeys
        # A path P is incomplete if there exists a significantly more frequent path Q
        # such that P is a strict proper prefix of Q.
        all_path_tuples = sorted(path_clusters.keys(), key=lambda p: len(p), reverse=True)
        canonical_paths: Dict[Tuple[str, ...], Dict[str, Any]] = {}

        for p in all_path_tuples:
            count_p = len(path_clusters[p])
            is_incomplete = False
            dropout_step = None
            parent_path = None

            # Check if this journey is a prefix of a longer frequent journey
            for longer_p in all_path_tuples:
                if len(longer_p) > len(p) and longer_p[:len(p)] == p:
                    # p is a prefix of longer_p
                    if len(path_clusters[longer_p]) >= 1:
                        is_incomplete = True
                        dropout_step = len(p) - 1
                        parent_path = longer_p
                        break

            canonical_paths[p] = {
                "sample_count": count_p,
                "is_incomplete": is_incomplete,
                "dropout_step_index": dropout_step,
                "parent_path": parent_path,
            }

        # 5. Build workflow definitions
        discovered_workflows: List[Dict[str, Any]] = []

        for path_tuple, meta in canonical_paths.items():
            sample_count = meta["sample_count"]
            if sample_count < min_sample_count:
                continue

            matching_journeys = path_clusters[path_tuple]
            is_incomplete = meta["is_incomplete"]
            dropout_step_idx = meta["dropout_step_index"]

            # Workflow type classification
            has_loop = len(set(path_tuple)) < len(path_tuple)
            if is_incomplete:
                wf_type = WorkflowType.ABANDONED.value
            elif has_loop:
                wf_type = WorkflowType.CYCLIC.value
            elif len(path_tuple) > 2 and any(
                p[:2] == path_tuple[:2] and p != path_tuple for p in all_path_tuples
            ):
                wf_type = WorkflowType.BRANCHED.value
            else:
                wf_type = WorkflowType.STANDARD.value

            # Build steps sequence with aggregated metrics
            steps_seq = []
            for idx, node_k in enumerate(path_tuple):
                step_obs_samples = [journey[idx] for journey in matching_journeys if idx < len(journey)]
                avg_lat = (
                    sum(s["latency_ms"] for s in step_obs_samples) / len(step_obs_samples)
                    if step_obs_samples
                    else 0.0
                )
                err_count = sum(1 for s in step_obs_samples if s["status_code"] >= 400)
                err_rate = err_count / len(step_obs_samples) if step_obs_samples else 0.0
                sample_obs_ids = [s["observation_id"] for s in step_obs_samples if s["observation_id"]][:10]

                # Tag step type
                if idx == 0:
                    step_type = StepType.ENTRY.value
                elif idx == len(path_tuple) - 1:
                    step_type = StepType.DROPOUT.value if is_incomplete else StepType.TERMINAL.value
                else:
                    step_type = StepType.INTERMEDIATE.value

                sample_step = step_obs_samples[0] if step_obs_samples else {}
                steps_seq.append({
                    "step_index": idx,
                    "method": sample_step.get("method", "GET"),
                    "normalized_path": sample_step.get("normalized_path", "/"),
                    "endpoint_id": sample_step.get("endpoint_id"),
                    "step_type": step_type,
                    "avg_latency_ms": round(avg_lat, 2),
                    "error_rate": round(err_rate, 4),
                    "sample_count": len(step_obs_samples),
                    "observation_ids": sample_obs_ids,
                })

            # Calculate confidence score
            # Saturation curve based on session count * transition consistency
            sample_weight = min(1.0, math.log(1 + sample_count) / math.log(1 + cls.CONFIDENCE_SATURATION_K))
            # Transition consistency: penalize if error rate is high on intermediate steps
            avg_err = sum(s["error_rate"] for s in steps_seq) / len(steps_seq) if steps_seq else 0.0
            consistency_factor = max(0.2, 1.0 - (avg_err * 0.5))
            confidence_score = round(min(1.0, max(0.05, sample_weight * consistency_factor)), 4)

            if confidence_score < min_confidence:
                continue

            # Build Graph Nodes & Edges
            graph_data = cls._build_graph(steps_seq, matching_journeys)

            # Generate human-readable workflow name
            entry_name = f"{steps_seq[0]['method']} {steps_seq[0]['normalized_path']}"
            if len(steps_seq) > 1:
                term_name = f"{steps_seq[-1]['method']} {steps_seq[-1]['normalized_path']}"
                name = f"{entry_name} → {term_name}"
            else:
                name = f"Single-Step: {entry_name}"

            # Variations metadata (e.g. branch points, dropouts)
            variations: Dict[str, Any] = {}
            if is_incomplete and meta["parent_path"]:
                variations["abandoned_from_canonical"] = list(meta["parent_path"])
                variations["dropout_step"] = dropout_step_idx
            if wf_type == WorkflowType.BRANCHED.value:
                # Find sibling branches
                siblings = [
                    list(p) for p in all_path_tuples
                    if len(p) >= 2 and p[:2] == path_tuple[:2] and p != path_tuple
                ]
                variations["alternative_branches"] = siblings[:5]

            # Entry and Terminal endpoint IDs
            entry_eid = steps_seq[0]["endpoint_id"]
            term_eid = steps_seq[-1]["endpoint_id"]

            now = datetime.now()
            discovered_workflows.append({
                "id": uuid.uuid4(),
                "organization_id": organization_id,
                "application_id": application_id,
                "name": name[:200],
                "description": (
                    f"Discovered user workflow containing {len(steps_seq)} steps "
                    f"observed across {sample_count} session journey(s)."
                ),
                "workflow_type": wf_type,
                "status": WorkflowStatus.DISCOVERED.value,
                "confidence_score": confidence_score,
                "sample_count": sample_count,
                "step_count": len(steps_seq),
                "entry_endpoint_id": uuid.UUID(entry_eid) if entry_eid else None,
                "terminal_endpoint_id": uuid.UUID(term_eid) if term_eid else None,
                "is_incomplete": is_incomplete,
                "dropout_step_index": dropout_step_idx,
                "graph_data": graph_data,
                "steps_sequence": steps_seq,
                "variations": variations,
                "discovered_at": now,
                "last_observed_at": now,
            })

        # Sort workflows by confidence_score and sample_count desc
        discovered_workflows.sort(key=lambda w: (w["confidence_score"], w["sample_count"]), reverse=True)

        metadata = {
            "insufficient_data": len(discovered_workflows) == 0,
            "insufficient_data_reason": (
                "No workflows matched the discovery criteria." if len(discovered_workflows) == 0 else None
            ),
            "analyzed_observations_count": len(observations),
            "analyzed_sessions_count": total_sessions,
            "discovered_count": len(discovered_workflows),
        }

        return discovered_workflows, metadata

    @classmethod
    def _build_graph(
        cls,
        steps_seq: List[Dict[str, Any]],
        matching_journeys: List[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Compiles nodes and directed edges for the workflow visualization.
        """
        nodes: List[Dict[str, Any]] = []
        node_ids_seen = set()

        for step in steps_seq:
            node_id = f"{step['method']}:{step['normalized_path']}"
            if node_id not in node_ids_seen:
                node_ids_seen.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": f"{step['method']} {step['normalized_path']}",
                    "method": step["method"],
                    "normalized_path": step["normalized_path"],
                    "step_type": step["step_type"],
                    "endpoint_id": step["endpoint_id"],
                    "observation_count": step["sample_count"],
                    "avg_latency_ms": step["avg_latency_ms"],
                    "error_rate": step["error_rate"],
                })

        # Transition edges
        edge_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        for journey in matching_journeys:
            for i in range(len(journey) - 1):
                s1 = journey[i]["node_key"]
                s2 = journey[i + 1]["node_key"]
                edge_counts[(s1, s2)] += 1

        edges: List[Dict[str, Any]] = []
        for (src, tgt), count in edge_counts.items():
            # Outgoing total from src
            out_total = sum(c for (s, _), c in edge_counts.items() if s == src)
            prob = round(count / float(out_total), 4) if out_total > 0 else 1.0
            edge_conf = round(min(1.0, math.log(1 + count) / math.log(1 + 10)), 4)
            edges.append({
                "id": f"{src}->{tgt}",
                "source": src,
                "target": tgt,
                "transition_count": count,
                "probability": prob,
                "confidence": edge_conf,
            })

        return {"nodes": nodes, "edges": edges}

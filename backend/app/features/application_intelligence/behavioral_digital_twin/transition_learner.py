from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict


def extract_endpoint_key(obs: Any) -> str:
    """
    Generate a canonical node key for an observation.
    Prefers endpoint_id string if available; falls back to 'METHOD:path'.
    """
    endpoint_id = getattr(obs, "endpoint_id", None) if hasattr(obs, "endpoint_id") else obs.get("endpoint_id")
    if endpoint_id:
        return str(endpoint_id)

    method = getattr(obs, "method", "GET") if hasattr(obs, "method") else obs.get("method", "GET")
    norm_path = getattr(obs, "normalized_path", "/") if hasattr(obs, "normalized_path") else obs.get("normalized_path", "/")
    return f"{method.upper()}:{norm_path}"


def learn_endpoint_transitions(
    observations: List[Any],
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, Dict[str, float]], List[Dict[str, Any]]]:
    """
    Analyzes session-ordered observations to learn Markov transition sequences.
    Returns:
    1. transition_counts: {from_node: {to_node: count}}
    2. transition_probabilities: {from_node: {to_node: probability (0.0 to 1.0)}}
    3. transition_items: flat list of records suitable for BehavioralTransition models:
       [{from_key, to_key, probability, observation_count, from_endpoint_id, to_endpoint_id}]
    """
    if not observations:
        return {}, {}, []

    # 1. Group observations by session identifier (or default bucket if None)
    sessions: Dict[str, List[Any]] = defaultdict(list)
    for obs in observations:
        sess_hash = getattr(obs, "session_token_hash", None) if hasattr(obs, "session_token_hash") else obs.get("session_token_hash")
        sess_key = sess_hash or "__default_session__"
        sessions[sess_key].append(obs)

    # 2. Sort observations within each session by observed_at timestamp
    def get_timestamp(o):
        ts = getattr(o, "observed_at", None) if hasattr(o, "observed_at") else o.get("observed_at")
        return ts or 0

    transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    transition_metadata: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for sess_key, session_obs in sessions.items():
        sorted_obs = sorted(session_obs, key=get_timestamp)
        for i in range(len(sorted_obs) - 1):
            curr_obs = sorted_obs[i]
            next_obs = sorted_obs[i + 1]

            from_key = extract_endpoint_key(curr_obs)
            to_key = extract_endpoint_key(next_obs)

            transition_counts[from_key][to_key] += 1

            pair = (from_key, to_key)
            if pair not in transition_metadata:
                from_eid = getattr(curr_obs, "endpoint_id", None) if hasattr(curr_obs, "endpoint_id") else curr_obs.get("endpoint_id")
                to_eid = getattr(next_obs, "endpoint_id", None) if hasattr(next_obs, "endpoint_id") else next_obs.get("endpoint_id")
                transition_metadata[pair] = {
                    "from_endpoint_id": from_eid,
                    "to_endpoint_id": to_eid,
                }

    # 3. Calculate transition probabilities: P(to | from) = count(from -> to) / sum(count(from -> *))
    transition_probabilities: Dict[str, Dict[str, float]] = defaultdict(dict)
    transition_items: List[Dict[str, Any]] = []

    for from_key, target_counts in transition_counts.items():
        total_out = sum(target_counts.values())
        if total_out == 0:
            continue
        for to_key, count in target_counts.items():
            prob = round(count / float(total_out), 4)
            transition_probabilities[from_key][to_key] = prob

            meta = transition_metadata.get((from_key, to_key), {})
            transition_items.append({
                "from_key": from_key,
                "to_key": to_key,
                "from_endpoint_id": meta.get("from_endpoint_id"),
                "to_endpoint_id": meta.get("to_endpoint_id"),
                "observation_count": count,
                "probability": prob,
            })

    # Convert defaultdicts to standard dicts for serialization
    counts_dict = {k: dict(v) for k, v in transition_counts.items()}
    probs_dict = {k: dict(v) for k, v in transition_probabilities.items()}

    return counts_dict, probs_dict, transition_items

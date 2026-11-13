"""
PHANTOM-X - Feature 6: Role & Resource Relationship Mapping
Mapping Engine

Algorithmic discovery and synthesis engine for:
1. Ingesting declared roles and resource relationships from Application specifications.
2. Discovering observed role-endpoint and identity-role relationships from sanitized behavioral traffic.
3. Inferring structural containment from normalized URL hierarchies (without claiming resource ownership).
4. Analyzing empirical role access overlap across observed endpoint sets (without false inheritance).
5. Calculating statistically bounded confidence scores and tracking sample counts separately.
6. Performing neutral Declared-versus-Observed discrepancy analysis (without claiming vulnerabilities).
"""

import math
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from app.features.application_intelligence.role_resource_mapping.models import (
    SubjectType,
    ObjectType,
    RelationshipType,
    EvidenceSource,
    MappingStatus,
)
from app.features.application_intelligence.role_resource_mapping.sanitization import (
    hash_identity_identifier,
    sanitize_mapping_evidence,
    validate_evidence_reference,
)


# Pattern matching hierarchical nested path segments, e.g. /accounts/{id}/orders/{id}
PATH_CONTAINMENT_REGEX = re.compile(
    r"/([a-zA-Z0-9_-]+)/\{[^/]+\}/([a-zA-Z0-9_-]+)"
)


def extract_resource_name_from_path(normalized_path: str) -> Optional[str]:
    """
    Extracts the primary resource name from a normalized URL path.
    Example: '/api/v1/orders/{order_id}' -> 'orders'
    """
    if not normalized_path:
        return None
    segments = [s for s in normalized_path.strip("/").split("/") if s and not s.startswith("{")]
    # Discard common non-resource API prefixes
    filtered = [s for s in segments if s.lower() not in {"api", "v1", "v2", "v3", "rest", "internal"}]
    if filtered:
        return filtered[0].lower()
    return segments[0].lower() if segments else None


def calculate_observed_confidence(sample_count: int, k_saturation: int = 10) -> float:
    """
    Computes a statistically bounded confidence score for observed interactions:
        confidence = min(0.95, 0.50 + 0.45 * (1 - e^(-N / K)))

    Guarantees:
    - Never exceeds 0.95 (empirical traffic cannot guarantee complete administrative truth).
    - Single observation yields bounded low confidence (~0.54).
    - Rapid saturation as sample size grows toward K (default 10).
    - Strictly bounded to [0.0, 0.95].
    """
    if sample_count <= 0:
        return 0.0
    val = 0.50 + 0.45 * (1.0 - math.exp(-sample_count / float(k_saturation)))
    return round(min(0.95, max(0.0, val)), 3)


def calculate_inferred_overlap_confidence(jaccard_similarity: float) -> float:
    """
    Computes confidence for observed access overlaps.
    Strictly capped at 0.65 to emphasize that access similarity is empirical
    and strictly does not imply formal role inheritance.
    """
    bounded_j = max(0.0, min(1.0, jaccard_similarity))
    val = 0.30 + 0.35 * bounded_j
    return round(min(0.65, val), 3)


class RoleResourceMappingEngine:
    """
    Statistically grounded engine for role and resource relationship discovery.
    """

    MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE = 2

    # --------------------------------------------------------------------------
    # A. Declared Relationship Ingestion
    # --------------------------------------------------------------------------

    @classmethod
    def ingest_declared_roles(
        cls,
        roles: List[Any],
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> List[Dict[str, Any]]:
        """
        Transforms declared ApplicationRole models into DECLARED mappings.
        Parses declared endpoint permissions, resource permissions, and declared inheritance.
        """
        mappings: List[Dict[str, Any]] = []

        for role in roles:
            role_id_str = str(getattr(role, "id", uuid.uuid4()))
            role_name = getattr(role, "name", "unknown")
            permissions = getattr(role, "permissions", {}) or {}

            # 1. Declared Endpoint Access
            endpoints = permissions.get("endpoints") or []
            if isinstance(endpoints, list):
                for ep in endpoints:
                    ep_str = str(ep).strip()
                    if ep_str:
                        mappings.append({
                            "organization_id": organization_id,
                            "application_id": application_id,
                            "subject_type": SubjectType.ROLE.value,
                            "subject_id": role_id_str,
                            "subject_name": role_name,
                            "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
                            "object_type": ObjectType.ENDPOINT.value,
                            "object_id": None,
                            "object_name": ep_str,
                            "evidence_source": EvidenceSource.DECLARED.value,
                            "confidence_score": 1.0,
                            "sample_count": 1,
                            "access_telemetry": {
                                "declared_in_spec": True,
                                "request_outcomes": {"2xx": 0, "4xx": 0, "5xx": 0},
                                "authentication_status": "UNKNOWN",
                                "authorization_status": "DECLARED_ALLOW",
                            },
                            "declared_vs_observed": {
                                "declared_in_spec": True,
                                "observed_in_traffic": False,
                                "discrepancy_category": "DECLARED_NOT_OBSERVED",
                                "notes": "Declared in application specification; not yet observed in active traffic.",
                            },
                            "evidence_references": [role_id_str] if validate_evidence_reference(role_id_str) else [],
                            "status": MappingStatus.ACTIVE.value,
                        })

            # 2. Declared Resource Access
            resources = permissions.get("resources") or []
            if isinstance(resources, list):
                for res in resources:
                    res_str = str(res).strip()
                    if res_str:
                        mappings.append({
                            "organization_id": organization_id,
                            "application_id": application_id,
                            "subject_type": SubjectType.ROLE.value,
                            "subject_id": role_id_str,
                            "subject_name": role_name,
                            "relationship_type": RelationshipType.ROLE_ACCESSES_RESOURCE.value,
                            "object_type": ObjectType.RESOURCE.value,
                            "object_id": None,
                            "object_name": res_str,
                            "evidence_source": EvidenceSource.DECLARED.value,
                            "confidence_score": 1.0,
                            "sample_count": 1,
                            "access_telemetry": {
                                "declared_in_spec": True,
                                "request_outcomes": {"2xx": 0, "4xx": 0, "5xx": 0},
                                "authentication_status": "UNKNOWN",
                                "authorization_status": "DECLARED_ALLOW",
                            },
                            "declared_vs_observed": {
                                "declared_in_spec": True,
                                "observed_in_traffic": False,
                                "discrepancy_category": "DECLARED_NOT_OBSERVED",
                                "notes": "Declared resource permission in specification.",
                            },
                            "evidence_references": [role_id_str] if validate_evidence_reference(role_id_str) else [],
                            "status": MappingStatus.ACTIVE.value,
                        })

            # 3. Declared Role Inheritance (Formally declared only)
            inherits = permissions.get("inherited_roles") or permissions.get("inherits") or []
            if isinstance(inherits, list):
                for parent_role in inherits:
                    parent_role_str = str(parent_role).strip()
                    if parent_role_str:
                        mappings.append({
                            "organization_id": organization_id,
                            "application_id": application_id,
                            "subject_type": SubjectType.ROLE.value,
                            "subject_id": role_id_str,
                            "subject_name": role_name,
                            "relationship_type": RelationshipType.ROLE_DECLARED_INHERITANCE.value,
                            "object_type": ObjectType.ROLE.value,
                            "object_id": None,
                            "object_name": parent_role_str,
                            "evidence_source": EvidenceSource.DECLARED.value,
                            "confidence_score": 1.0,
                            "sample_count": 1,
                            "access_telemetry": {
                                "declared_in_spec": True,
                                "formal_inheritance": True,
                            },
                            "declared_vs_observed": {
                                "declared_in_spec": True,
                                "observed_in_traffic": False,
                                "discrepancy_category": "DECLARED_NOT_OBSERVED",
                                "notes": "Formally declared role hierarchy in specification.",
                            },
                            "evidence_references": [role_id_str] if validate_evidence_reference(role_id_str) else [],
                            "status": MappingStatus.ACTIVE.value,
                        })

        return mappings

    @classmethod
    def ingest_declared_relationships(
        cls,
        relationships: List[Any],
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> List[Dict[str, Any]]:
        """
        Transforms declared ResourceRelationship models into DECLARED mappings.
        """
        mappings: List[Dict[str, Any]] = []

        for rel in relationships:
            rel_id_str = str(getattr(rel, "id", uuid.uuid4()))
            source_res = getattr(rel, "source_resource", "").strip()
            target_res = getattr(rel, "target_resource", "").strip()
            rel_type_str = str(getattr(rel, "relationship_type", "REFERENCES")).upper()
            is_bidirectional = bool(getattr(rel, "is_bidirectional", False))

            if not source_res or not target_res:
                continue

            # Map semantic relationship type
            mapped_rel_type = (
                RelationshipType.STRUCTURAL_CONTAINMENT.value
                if rel_type_str == "CONTAINS"
                else RelationshipType.RESOURCE_REFERENCES_RESOURCE.value
            )

            mappings.append({
                "organization_id": organization_id,
                "application_id": application_id,
                "subject_type": SubjectType.RESOURCE.value,
                "subject_id": None,
                "subject_name": source_res,
                "relationship_type": mapped_rel_type,
                "object_type": ObjectType.RESOURCE.value,
                "object_id": None,
                "object_name": target_res,
                "evidence_source": EvidenceSource.DECLARED.value,
                "confidence_score": 1.0,
                "sample_count": 1,
                "access_telemetry": {
                    "declared_in_spec": True,
                    "declared_relationship_type": rel_type_str,
                    "is_bidirectional": is_bidirectional,
                },
                "declared_vs_observed": {
                    "declared_in_spec": True,
                    "observed_in_traffic": False,
                    "discrepancy_category": "DECLARED_NOT_OBSERVED",
                    "notes": f"Declared resource relationship ({rel_type_str}) in specification.",
                },
                "evidence_references": [rel_id_str] if validate_evidence_reference(rel_id_str) else [],
                "status": MappingStatus.ACTIVE.value,
            })

            # If bidirectional, also add reverse link
            if is_bidirectional:
                mappings.append({
                    "organization_id": organization_id,
                    "application_id": application_id,
                    "subject_type": SubjectType.RESOURCE.value,
                    "subject_id": None,
                    "subject_name": target_res,
                    "relationship_type": mapped_rel_type,
                    "object_type": ObjectType.RESOURCE.value,
                    "object_id": None,
                    "object_name": source_res,
                    "evidence_source": EvidenceSource.DECLARED.value,
                    "confidence_score": 1.0,
                    "sample_count": 1,
                    "access_telemetry": {
                        "declared_in_spec": True,
                        "declared_relationship_type": rel_type_str,
                        "is_bidirectional": True,
                    },
                    "declared_vs_observed": {
                        "declared_in_spec": True,
                        "observed_in_traffic": False,
                        "discrepancy_category": "DECLARED_NOT_OBSERVED",
                        "notes": f"Declared bidirectional resource relationship ({rel_type_str}).",
                    },
                    "evidence_references": [rel_id_str] if validate_evidence_reference(rel_id_str) else [],
                    "status": MappingStatus.ACTIVE.value,
                })

        return mappings

    # --------------------------------------------------------------------------
    # B. Observed Relationship Discovery
    # --------------------------------------------------------------------------

    @classmethod
    def _extract_role_from_observation(cls, obs: Any) -> Optional[str]:
        """
        Extracts role strictly from authoritative identity signals.

        Security Rules:
        - NEVER trust arbitrary client request-body fields (e.g. payload 'role' in POST body).
        - Trust authoritative server responses on successful (2xx) authentication/identity endpoints:
          e.g. resp_schema['user']['role'], resp_schema['role'], resp_schema['claims']['role'].
        - Trust validated gateway/server JWT claims injected in request telemetry:
          e.g. req_schema['_server_auth_context']['role'], req_schema['_jwt_claims']['role'].
        """
        status_code = int(getattr(obs, "status_code", 200) or 200)
        resp_schema = getattr(obs, "sanitized_response_schema", {}) or {}
        req_schema = getattr(obs, "sanitized_request_schema", {}) or {}

        # 1. Authoritative server response on successful responses (2xx)
        if 200 <= status_code < 300 and isinstance(resp_schema, dict):
            if "role" in resp_schema and isinstance(resp_schema["role"], str):
                return resp_schema["role"].strip().lower()
            if "user_role" in resp_schema and isinstance(resp_schema["user_role"], str):
                return resp_schema["user_role"].strip().lower()
            if "user" in resp_schema and isinstance(resp_schema["user"], dict):
                user_dict = resp_schema["user"]
                if "role" in user_dict and isinstance(user_dict["role"], str):
                    return user_dict["role"].strip().lower()
            if "claims" in resp_schema and isinstance(resp_schema["claims"], dict):
                claims_dict = resp_schema["claims"]
                if "role" in claims_dict and isinstance(claims_dict["role"], str):
                    return claims_dict["role"].strip().lower()

        # 2. Server-validated auth context or JWT claims from trusted gateway
        if isinstance(req_schema, dict):
            for trusted_key in ("_server_auth_context", "_jwt_claims", "server_validated_claims"):
                if trusted_key in req_schema and isinstance(req_schema[trusted_key], dict):
                    trusted_dict = req_schema[trusted_key]
                    if "role" in trusted_dict and isinstance(trusted_dict["role"], str):
                        return trusted_dict["role"].strip().lower()

        return None

    @classmethod
    def discover_observed_mappings(
        cls,
        observations: List[Any],
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> List[Dict[str, Any]]:
        """
        Analyzes sanitized behavioral observations to discover empirical
        role-to-endpoint, role-to-resource, and identity-to-role associations.

        Strict principles:
        - HTTP 2xx is recorded strictly under request_outcomes['2xx'], never as authorization proof.
        - HTTP 403 sets authorization_status='EXPLICIT_DENY' for that request, not total absence of role permission.
        - Identical evidence UUIDs are deduplicated.
        - Sanitized evidence references only.
        """
        if not observations:
            return []

        # Deduplicate observations by ID
        unique_observations: Dict[str, Any] = {}
        for obs in observations:
            obs_id = str(getattr(obs, "id", uuid.uuid4()))
            if obs_id not in unique_observations:
                unique_observations[obs_id] = obs

        # Aggregation buckets:
        # role_endpoints[(role, method_path)] -> metrics
        # role_resources[(role, resource_name)] -> metrics
        # identity_roles[(identity_hash, role)] -> metrics
        role_ep_aggregates: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
            "sample_count": 0,
            "outcomes": {"2xx": 0, "4xx": 0, "5xx": 0},
            "last_status": 200,
            "auth_status": "UNKNOWN",
            "first_observed": None,
            "last_observed": None,
            "evidence_refs": set(),
        })

        role_res_aggregates: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
            "sample_count": 0,
            "outcomes": {"2xx": 0, "4xx": 0, "5xx": 0},
            "last_status": 200,
            "auth_status": "UNKNOWN",
            "first_observed": None,
            "last_observed": None,
            "evidence_refs": set(),
        })

        identity_role_aggregates: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
            "sample_count": 0,
            "first_observed": None,
            "last_observed": None,
            "evidence_refs": set(),
        })

        for obs_id, obs in unique_observations.items():
            method = (getattr(obs, "method", "GET") or "GET").upper()
            norm_path = getattr(obs, "normalized_path", "/") or "/"
            endpoint_name = f"{method} {norm_path}"
            status_code = int(getattr(obs, "status_code", 200) or 200)
            session_hash = getattr(obs, "session_token_hash", None)
            observed_at = getattr(obs, "observed_at", None) or datetime.now(timezone.utc)

            # Determine request outcome category
            outcome_bucket = "2xx" if 200 <= status_code < 300 else ("4xx" if 400 <= status_code < 500 else "5xx")

            # Authentication status
            auth_status = "AUTHENTICATED" if session_hash else ("UNAUTHENTICATED" if status_code == 401 else "UNKNOWN")

            # Extract role
            detected_role = cls._extract_role_from_observation(obs)

            # If identity/session present and role detected, record identity-role association
            if session_hash and detected_role:
                id_tuple = (session_hash, detected_role)
                agg = identity_role_aggregates[id_tuple]
                agg["sample_count"] += 1
                if validate_evidence_reference(obs_id):
                    agg["evidence_refs"].add(obs_id)
                if not agg["first_observed"] or observed_at < agg["first_observed"]:
                    agg["first_observed"] = observed_at
                if not agg["last_observed"] or observed_at > agg["last_observed"]:
                    agg["last_observed"] = observed_at

            # If no role explicitly detected, check if we attribute to "anonymous" or skip
            active_role = detected_role or ("anonymous" if status_code == 401 or not session_hash else None)
            if not active_role:
                continue

            # 1. Update Role -> Endpoint aggregate
            ep_tuple = (active_role, endpoint_name)
            ep_agg = role_ep_aggregates[ep_tuple]
            ep_agg["sample_count"] += 1
            ep_agg["outcomes"][outcome_bucket] += 1
            ep_agg["last_status"] = status_code
            ep_agg["auth_status"] = auth_status
            if validate_evidence_reference(obs_id):
                ep_agg["evidence_refs"].add(obs_id)
            if not ep_agg["first_observed"] or observed_at < ep_agg["first_observed"]:
                ep_agg["first_observed"] = observed_at
            if not ep_agg["last_observed"] or observed_at > ep_agg["last_observed"]:
                ep_agg["last_observed"] = observed_at

            # 2. Update Role -> Resource aggregate
            resource_name = extract_resource_name_from_path(norm_path)
            if resource_name:
                res_tuple = (active_role, resource_name)
                res_agg = role_res_aggregates[res_tuple]
                res_agg["sample_count"] += 1
                res_agg["outcomes"][outcome_bucket] += 1
                res_agg["last_status"] = status_code
                res_agg["auth_status"] = auth_status
                if validate_evidence_reference(obs_id):
                    res_agg["evidence_refs"].add(obs_id)
                if not res_agg["first_observed"] or observed_at < res_agg["first_observed"]:
                    res_agg["first_observed"] = observed_at
                if not res_agg["last_observed"] or observed_at > res_agg["last_observed"]:
                    res_agg["last_observed"] = observed_at

        discovered: List[Dict[str, Any]] = []

        # Convert Role -> Endpoint aggregates into mappings
        for (role_name, ep_name), agg in role_ep_aggregates.items():
            conf = calculate_observed_confidence(agg["sample_count"])
            authz_status = "EXPLICIT_DENY" if agg["outcomes"]["4xx"] > 0 and agg["last_status"] == 403 else "UNSPECIFIED"

            is_insufficient = agg["sample_count"] < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
            discovered.append({
                "organization_id": organization_id,
                "application_id": application_id,
                "subject_type": SubjectType.ROLE.value,
                "subject_id": None,
                "subject_name": role_name,
                "relationship_type": RelationshipType.ROLE_ACCESSES_ENDPOINT.value,
                "object_type": ObjectType.ENDPOINT.value,
                "object_id": None,
                "object_name": ep_name,
                "evidence_source": EvidenceSource.OBSERVED.value,
                "confidence_score": conf,
                "sample_count": agg["sample_count"],
                "access_telemetry": {
                    "request_outcomes": agg["outcomes"],
                    "last_observed_status": agg["last_status"],
                    "authentication_status": agg["auth_status"],
                    "authorization_status": authz_status,
                    "first_observed_at": agg["first_observed"].isoformat() if agg["first_observed"] else None,
                    "last_observed_at": agg["last_observed"].isoformat() if agg["last_observed"] else None,
                },
                "declared_vs_observed": {
                    "declared_in_spec": False,
                    "observed_in_traffic": True,
                    "discrepancy_category": "EVIDENCE_INSUFFICIENT" if is_insufficient else "OBSERVED_NOT_DECLARED",
                    "notes": (
                        "Sample count insufficient for robust alignment analysis."
                        if is_insufficient
                        else "Observed empirical role access; not declared in formal specification."
                    ),
                },
                "evidence_references": sorted(list(agg["evidence_refs"]))[:50],
                "status": MappingStatus.ACTIVE.value,
            })

        # Convert Role -> Resource aggregates into mappings
        for (role_name, res_name), agg in role_res_aggregates.items():
            conf = calculate_observed_confidence(agg["sample_count"])
            is_insufficient = agg["sample_count"] < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
            discovered.append({
                "organization_id": organization_id,
                "application_id": application_id,
                "subject_type": SubjectType.ROLE.value,
                "subject_id": None,
                "subject_name": role_name,
                "relationship_type": RelationshipType.ROLE_ACCESSES_RESOURCE.value,
                "object_type": ObjectType.RESOURCE.value,
                "object_id": None,
                "object_name": res_name,
                "evidence_source": EvidenceSource.OBSERVED.value,
                "confidence_score": conf,
                "sample_count": agg["sample_count"],
                "access_telemetry": {
                    "request_outcomes": agg["outcomes"],
                    "last_observed_status": agg["last_status"],
                    "authentication_status": agg["auth_status"],
                    "authorization_status": "UNSPECIFIED",
                    "first_observed_at": agg["first_observed"].isoformat() if agg["first_observed"] else None,
                    "last_observed_at": agg["last_observed"].isoformat() if agg["last_observed"] else None,
                },
                "declared_vs_observed": {
                    "declared_in_spec": False,
                    "observed_in_traffic": True,
                    "discrepancy_category": "EVIDENCE_INSUFFICIENT" if is_insufficient else "OBSERVED_NOT_DECLARED",
                    "notes": "Observed empirical resource interaction from traffic telemetry.",
                },
                "evidence_references": sorted(list(agg["evidence_refs"]))[:50],
                "status": MappingStatus.ACTIVE.value,
            })

        # Convert Identity -> Role associations into mappings
        for (session_hash, role_name), agg in identity_role_aggregates.items():
            conf = calculate_observed_confidence(agg["sample_count"])
            is_insufficient = agg["sample_count"] < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
            sanitized_id_name = f"identity_{session_hash[:12]}"
            discovered.append({
                "organization_id": organization_id,
                "application_id": application_id,
                "subject_type": SubjectType.IDENTITY.value,
                "subject_id": session_hash,
                "subject_name": sanitized_id_name,
                "relationship_type": RelationshipType.IDENTITY_ASSIGNED_ROLE.value,
                "object_type": ObjectType.ROLE.value,
                "object_id": None,
                "object_name": role_name,
                "evidence_source": EvidenceSource.OBSERVED.value,
                "confidence_score": conf,
                "sample_count": agg["sample_count"],
                "access_telemetry": {
                    "session_token_hash": session_hash,
                    "first_observed_at": agg["first_observed"].isoformat() if agg["first_observed"] else None,
                    "last_observed_at": agg["last_observed"].isoformat() if agg["last_observed"] else None,
                },
                "declared_vs_observed": {
                    "declared_in_spec": False,
                    "observed_in_traffic": True,
                    "discrepancy_category": "EVIDENCE_INSUFFICIENT" if is_insufficient else "OBSERVED_NOT_DECLARED",
                    "notes": "Empirical identity-to-role binding observed in session activity.",
                },
                "evidence_references": sorted(list(agg["evidence_refs"]))[:50],
                "status": MappingStatus.ACTIVE.value,
            })

        return discovered

    # --------------------------------------------------------------------------
    # C. Inferred Structural Relationships (URL Containment)
    # --------------------------------------------------------------------------

    @classmethod
    def infer_structural_containment(
        cls,
        normalized_paths: List[str],
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
        evidence_references: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Infers structural containment from hierarchical URL path segments.
        Example: /accounts/{id}/orders/{id} -> accounts CONTAINS orders.

        Strict principles:
        - Relationship is labeled STRUCTURAL_CONTAINMENT (never ownership).
        - Evidence source is INFERRED.
        - Confidence is capped at 0.60 (heuristic structural hint).
        """
        containment_pairs: Dict[Tuple[str, str], List[str]] = defaultdict(list)

        for path in set(normalized_paths):
            if not path:
                continue
            matches = PATH_CONTAINMENT_REGEX.findall(path)
            for parent_seg, child_seg in matches:
                p_clean = parent_seg.lower().strip()
                c_clean = child_seg.lower().strip()
                if p_clean and c_clean and p_clean != c_clean:
                    containment_pairs[(p_clean, c_clean)].append(path)

        inferred: List[Dict[str, Any]] = []
        valid_refs = [r for r in (evidence_references or []) if validate_evidence_reference(r)]

        for (parent_res, child_res), sample_paths in containment_pairs.items():
            sample_count = len(sample_paths)
            inferred.append({
                "organization_id": organization_id,
                "application_id": application_id,
                "subject_type": SubjectType.RESOURCE.value,
                "subject_id": None,
                "subject_name": parent_res,
                "relationship_type": RelationshipType.STRUCTURAL_CONTAINMENT.value,
                "object_type": ObjectType.RESOURCE.value,
                "object_id": None,
                "object_name": child_res,
                "evidence_source": EvidenceSource.INFERRED.value,
                "confidence_score": 0.60,  # Capped heuristic confidence
                "sample_count": sample_count,
                "access_telemetry": {
                    "inference_rule": "URL_PATH_NESTING",
                    "sample_paths": sample_paths[:10],
                },
                "declared_vs_observed": {
                    "inferred": True,
                    "ownership_claimed": False,
                    "discrepancy_category": "NONE",
                    "notes": (
                        "Inferred from URL path nesting hierarchy. Strictly indicates structural "
                        "containment and does NOT claim database or administrative ownership."
                    ),
                },
                "evidence_references": valid_refs[:20],
                "status": MappingStatus.CANDIDATE.value,
            })

        return inferred

    # --------------------------------------------------------------------------
    # D. Role Access Overlap Analysis
    # --------------------------------------------------------------------------

    @classmethod
    def analyze_role_access_overlaps(
        cls,
        observed_role_endpoints: Dict[str, Set[str]],
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
        role_evidence_refs: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Identifies empirical overlap between endpoint access sets of distinct roles.

        Strict principles:
        - Labeled OBSERVED_ACCESS_OVERLAP (strictly NOT inheritance).
        - Confidence is calculated from Jaccard similarity and capped at 0.65.
        - Preserves overlap count, unique differences, and endpoint listings.
        """
        roles = sorted(list(observed_role_endpoints.keys()))
        overlap_mappings: List[Dict[str, Any]] = []

        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                r1, r2 = roles[i], roles[j]
                eps1 = observed_role_endpoints[r1]
                eps2 = observed_role_endpoints[r2]

                intersection = eps1.intersection(eps2)
                if not intersection:
                    continue

                union = eps1.union(eps2)
                jaccard = len(intersection) / float(len(union)) if union else 0.0
                confidence = calculate_inferred_overlap_confidence(jaccard)

                # Evidence references for both roles
                refs1 = (role_evidence_refs or {}).get(r1, [])
                refs2 = (role_evidence_refs or {}).get(r2, [])
                combined_refs = sorted(list(set(refs1 + refs2)))
                valid_refs = [r for r in combined_refs if validate_evidence_reference(r)]

                overlap_mappings.append({
                    "organization_id": organization_id,
                    "application_id": application_id,
                    "subject_type": SubjectType.ROLE.value,
                    "subject_id": None,
                    "subject_name": r1,
                    "relationship_type": RelationshipType.OBSERVED_ACCESS_OVERLAP.value,
                    "object_type": ObjectType.ROLE.value,
                    "object_id": None,
                    "object_name": r2,
                    "evidence_source": EvidenceSource.INFERRED.value,
                    "confidence_score": confidence,
                    "sample_count": len(intersection),
                    "access_telemetry": {
                        "overlap_endpoint_count": len(intersection),
                        "role_1_unique_count": len(eps1 - eps2),
                        "role_2_unique_count": len(eps2 - eps1),
                        "jaccard_similarity": round(jaccard, 3),
                        "overlapping_endpoints": sorted(list(intersection))[:20],
                    },
                    "declared_vs_observed": {
                        "inferred": True,
                        "is_inheritance": False,
                        "discrepancy_category": "NONE",
                        "notes": (
                            "Empirical access-set overlap between roles. Strictly does NOT represent "
                            "formal role inheritance or administrative hierarchy."
                        ),
                    },
                    "evidence_references": valid_refs[:30],
                    "status": MappingStatus.CANDIDATE.value,
                })

        return overlap_mappings

    # --------------------------------------------------------------------------
    # E. Declared vs. Observed Synthesis & Discrepancy Alignment
    # --------------------------------------------------------------------------

    @classmethod
    def synthesize_and_align_mappings(
        cls,
        declared_mappings: List[Dict[str, Any]],
        observed_mappings: List[Dict[str, Any]],
        inferred_mappings: List[Dict[str, Any]],
        min_confidence: float = 0.0,
        min_sample_count: int = 1,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Synthesizes declared, observed, and inferred mappings into a unified,
        idempotent mapping collection. Performs neutral discrepancy analysis.
        """
        # Composite unique key: (subject_type, subject_name, relationship_type, object_type, object_name)
        def make_tuple_key(m: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
            return (
                m["subject_type"].upper(),
                m["subject_name"].strip().lower(),
                m["relationship_type"].upper(),
                m["object_type"].upper(),
                m["object_name"].strip().lower(),
            )

        declared_dict: Dict[Tuple, Dict[str, Any]] = {
            make_tuple_key(m): m for m in declared_mappings
        }
        observed_dict: Dict[Tuple, Dict[str, Any]] = {
            make_tuple_key(m): m for m in observed_mappings
        }

        unified_dict: Dict[Tuple, Dict[str, Any]] = {}
        all_keys = set(declared_dict.keys()).union(observed_dict.keys())

        discrepancy_counts = {
            "ALIGNED": 0,
            "DECLARED_NOT_OBSERVED": 0,
            "OBSERVED_NOT_DECLARED": 0,
            "EVIDENCE_INSUFFICIENT": 0,
        }

        for key in all_keys:
            in_declared = key in declared_dict
            in_observed = key in observed_dict

            if in_declared and in_observed:
                decl = declared_dict[key]
                obs = observed_dict[key]

                # Merge telemetry and references
                merged_refs = sorted(list(set(decl.get("evidence_references", []) + obs.get("evidence_references", []))))
                merged_sample_count = obs.get("sample_count", 1) + decl.get("sample_count", 1)

                is_insufficient = obs.get("sample_count", 0) < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
                cat = "EVIDENCE_INSUFFICIENT" if is_insufficient else "ALIGNED"
                discrepancy_counts[cat] += 1

                unified = dict(obs)
                unified["evidence_source"] = EvidenceSource.OBSERVED.value
                unified["confidence_score"] = max(decl.get("confidence_score", 1.0), obs.get("confidence_score", 0.5))
                unified["sample_count"] = merged_sample_count
                unified["evidence_references"] = merged_refs[:50]
                unified["declared_vs_observed"] = {
                    "declared_in_spec": True,
                    "observed_in_traffic": True,
                    "discrepancy_category": cat,
                    "notes": (
                        "Declared in specification and validated through active traffic observations."
                        if cat == "ALIGNED"
                        else "Declared in specification, but traffic sample size is insufficient for full alignment confidence."
                    ),
                }
                unified_dict[key] = unified

            elif in_declared and not in_observed:
                decl = declared_dict[key]
                discrepancy_counts["DECLARED_NOT_OBSERVED"] += 1
                unified = dict(decl)
                unified["declared_vs_observed"] = {
                    "declared_in_spec": True,
                    "observed_in_traffic": False,
                    "discrepancy_category": "DECLARED_NOT_OBSERVED",
                    "notes": (
                        "Declared in application specification; not observed in current traffic sample. "
                        "This is a behavioral mapping discrepancy and does NOT imply permission is absent."
                    ),
                }
                unified_dict[key] = unified

            elif in_observed and not in_declared:
                obs = observed_dict[key]
                is_insufficient = obs.get("sample_count", 0) < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
                cat = "EVIDENCE_INSUFFICIENT" if is_insufficient else "OBSERVED_NOT_DECLARED"
                discrepancy_counts[cat] += 1

                unified = dict(obs)
                unified["declared_vs_observed"] = {
                    "declared_in_spec": False,
                    "observed_in_traffic": True,
                    "discrepancy_category": cat,
                    "notes": (
                        "Sample count insufficient for robust alignment analysis."
                        if is_insufficient
                        else (
                            "Observed interaction not explicitly documented in declared permissions. "
                            "This represents an unmodeled access path, not a verified vulnerability."
                        )
                    ),
                }
                unified_dict[key] = unified

        # Add inferred mappings (containment & overlap)
        for inf in inferred_mappings:
            key = make_tuple_key(inf)
            if key not in unified_dict:
                unified_dict[key] = inf

        # Filter by threshold constraints
        filtered_results: List[Dict[str, Any]] = []
        for m in unified_dict.values():
            if m.get("confidence_score", 0.0) >= min_confidence and m.get("sample_count", 0) >= min_sample_count:
                filtered_results.append(m)

        summary_metrics = {
            "total_unified_mappings": len(unified_dict),
            "filtered_mappings_count": len(filtered_results),
            "declared_count": len(declared_mappings),
            "observed_count": len(observed_mappings),
            "inferred_count": len(inferred_mappings),
            "discrepancy_breakdown": discrepancy_counts,
            "discrepancies_count": discrepancy_counts["DECLARED_NOT_OBSERVED"] + discrepancy_counts["OBSERVED_NOT_DECLARED"],
            "insufficient_evidence": discrepancy_counts["EVIDENCE_INSUFFICIENT"] > 0 and len(observed_mappings) < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE,
            "insufficient_evidence_reason": (
                f"Observed sample count is below the minimum threshold ({cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE})."
                if len(observed_mappings) < cls.MIN_SAMPLES_FOR_SUFFICIENT_EVIDENCE
                else None
            ),
        }

        return filtered_results, summary_metrics

"""
PHANTOM-X - Feature 4: Behavioral Digital Twin
Drift & Anomaly Detection Engine

Responsible for:
- Evaluating observations against the current ACTIVE Behavioral Baseline.
- Detectors:
  1. Status Code Drift (unseen status codes, server errors vs client variation).
  2. Schema Drift (unexpected properties, missing required properties, type mismatches).
  3. Sequence Drift (unseen Markov transitions, probability violations).
  4. Latency Drift (exceeding P95 * threshold with sample size gating).
- Anomaly Lifecycle Management (OPEN -> ACKNOWLEDGED -> RESOLVED).
- Deduplication of open anomalies.
- Enforcing tenant isolation and sensitive data sanitization.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
    BehavioralBaseline,
    BehavioralAnomaly,
    BaselineStatus,
    AnomalyStatus,
    AnomalyType,
    AnomalySeverity,
)
from app.features.application_intelligence.behavioral_digital_twin.transition_learner import (
    extract_endpoint_key,
)
from app.features.application_intelligence.behavioral_digital_twin.sanitization import (
    sanitize_payload_recursively,
)


def compare_schemas(
    baseline_schema: Dict[str, Any],
    observed_schema: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compares observed structural schema against baseline schema.
    Returns detected deviations:
    - missing_required: fields required by baseline but omitted in observation
    - unexpected_properties: fields observed that are not declared in baseline
    - type_mismatches: fields present in both but with different inferred types
    Accounts for optional fields (fields in baseline properties but not required).
    """
    if not baseline_schema or not observed_schema:
        return {"missing_required": [], "unexpected_properties": [], "type_mismatches": []}

    base_props = baseline_schema.get("properties", {})
    obs_props = observed_schema.get("properties", {})
    base_required = set(baseline_schema.get("required", []))

    missing_required = []
    type_mismatches = []
    unexpected_properties = []

    # Check required fields
    for req_field in base_required:
        if req_field not in obs_props:
            missing_required.append(req_field)

    # Check observed properties against baseline
    for prop_name, prop_def in obs_props.items():
        if prop_name not in base_props:
            unexpected_properties.append(prop_name)
        else:
            base_type = base_props[prop_name].get("type")
            obs_type = prop_def.get("type")
            if base_type and obs_type and base_type != obs_type:
                # Do not flag integer as mismatch if baseline was number
                if not (base_type == "number" and obs_type == "integer"):
                    type_mismatches.append({
                        "field": prop_name,
                        "expected_type": base_type,
                        "observed_type": obs_type,
                    })

    return {
        "missing_required": missing_required,
        "unexpected_properties": unexpected_properties,
        "type_mismatches": type_mismatches,
    }


class DriftEngine:
    """
    Evaluates incoming behavioral telemetry against the active baseline
    and manages anomaly lifecycle records.
    """

    def __init__(
        self,
        latency_multiplier: float = 3.0,
        latency_min_delta_ms: float = 50.0,
        min_baseline_samples_for_latency: int = 5,
        sequence_rare_threshold: float = 0.01,
    ):
        self.latency_multiplier = latency_multiplier
        self.latency_min_delta_ms = latency_min_delta_ms
        self.min_baseline_samples_for_latency = min_baseline_samples_for_latency
        self.sequence_rare_threshold = sequence_rare_threshold

    async def evaluate_observation(
        self,
        db: AsyncSession,
        observation: BehavioralObservation,
        baseline: Optional[BehavioralBaseline] = None,
        prior_observation: Optional[BehavioralObservation] = None,
    ) -> List[BehavioralAnomaly]:
        """
        Evaluates a single observation against the active application baseline.
        Returns newly recorded or updated BehavioralAnomaly entities.
        """
        # 1. Resolve active baseline if not provided
        if not baseline:
            b_query = select(BehavioralBaseline).where(
                and_(
                    BehavioralBaseline.application_id == observation.application_id,
                    BehavioralBaseline.organization_id == observation.organization_id,
                    BehavioralBaseline.status == BaselineStatus.ACTIVE.value,
                )
            )
            b_res = await db.execute(b_query)
            baseline = b_res.scalar_one_or_none()

        if not baseline:
            # Without an active baseline, behavioral drift cannot be ascertained
            return []

        endpoint_key = extract_endpoint_key(observation)
        endpoint_profile = baseline.endpoint_profiles.get(endpoint_key)

        anomalies: List[BehavioralAnomaly] = []

        # 2. Status Code Drift Detector
        sc_anomaly = await self._check_status_code_drift(
            db, observation, baseline, endpoint_key, endpoint_profile
        )
        if sc_anomaly:
            anomalies.append(sc_anomaly)

        # 3. Schema Drift Detector
        schema_anomalies = await self._check_schema_drift(
            db, observation, baseline, endpoint_key, endpoint_profile
        )
        anomalies.extend(schema_anomalies)

        # 4. Latency Drift Detector
        lat_anomaly = await self._check_latency_drift(
            db, observation, baseline, endpoint_key, endpoint_profile
        )
        if lat_anomaly:
            anomalies.append(lat_anomaly)

        # 5. Sequence Drift Detector
        seq_anomaly = await self._check_sequence_drift(
            db, observation, baseline, endpoint_key, prior_observation
        )
        if seq_anomaly:
            anomalies.append(seq_anomaly)

        return anomalies

    async def _check_status_code_drift(
        self,
        db: AsyncSession,
        observation: BehavioralObservation,
        baseline: BehavioralBaseline,
        endpoint_key: str,
        profile: Optional[Dict[str, Any]],
    ) -> Optional[BehavioralAnomaly]:
        """
        Detects previously unseen status codes or anomalous distribution shifts.
        """
        if not profile:
            return None

        status_dist = profile.get("status_code_distribution", {})
        obs_code = str(observation.status_code)

        if obs_code not in status_dist:
            # Unseen status code
            code_int = observation.status_code
            if code_int >= 500:
                severity = AnomalySeverity.HIGH.value
                conf = 0.90
                desc = (
                    f"Unexpected server error ({code_int}) on {endpoint_key}. "
                    f"Status code never observed in baseline distribution: {status_dist}."
                )
            elif code_int >= 400:
                severity = AnomalySeverity.MEDIUM.value
                conf = 0.75
                desc = (
                    f"Unexpected client status code ({code_int}) on {endpoint_key}. "
                    f"Not present in established baseline: {status_dist}."
                )
            else:
                severity = AnomalySeverity.LOW.value
                conf = 0.65
                desc = (
                    f"Unusual status code ({code_int}) on {endpoint_key}. "
                    f"Baseline status distribution: {status_dist}."
                )

            evidence = {
                "observed_status_code": code_int,
                "baseline_distribution": status_dist,
                "endpoint_key": endpoint_key,
                "method": observation.method,
                "normalized_path": observation.normalized_path,
                "description": desc,
            }

            return await self._get_or_create_anomaly(
                db=db,
                organization_id=observation.organization_id,
                application_id=observation.application_id,
                baseline_id=baseline.id,
                endpoint_id=observation.endpoint_id,
                anomaly_type=AnomalyType.UNEXPECTED_STATUS_CODE.value,
                severity=severity,
                confidence=conf,
                evidence_data=evidence,
                signature=f"status_{code_int}_{endpoint_key}",
            )

        return None

    async def _check_schema_drift(
        self,
        db: AsyncSession,
        observation: BehavioralObservation,
        baseline: BehavioralBaseline,
        endpoint_key: str,
        profile: Optional[Dict[str, Any]],
    ) -> List[BehavioralAnomaly]:
        """
        Detects structural payload changes between observed payload schemas and baseline schemas.
        """
        if not profile:
            return []

        anomalies: List[BehavioralAnomaly] = []
        base_resp_schema = profile.get("inferred_response_schema", {})
        obs_resp_schema = observation.sanitized_response_schema or {}

        if base_resp_schema and obs_resp_schema:
            diff = compare_schemas(base_resp_schema, obs_resp_schema)
            has_missing = bool(diff["missing_required"])
            has_type_diff = bool(diff["type_mismatches"])
            has_unexpected = bool(diff["unexpected_properties"])

            if has_missing or has_type_diff or has_unexpected:
                if has_type_diff or has_missing:
                    severity = AnomalySeverity.MEDIUM.value
                    confidence = 0.85
                else:
                    severity = AnomalySeverity.LOW.value
                    confidence = 0.70

                desc = (
                    f"Response schema drift detected on {endpoint_key}. "
                    f"Missing required: {diff['missing_required']}, "
                    f"Type mismatches: {len(diff['type_mismatches'])}, "
                    f"Unexpected properties: {diff['unexpected_properties']}."
                )

                evidence = {
                    "endpoint_key": endpoint_key,
                    "method": observation.method,
                    "normalized_path": observation.normalized_path,
                    "schema_diff": diff,
                    "description": desc,
                }

                anomaly = await self._get_or_create_anomaly(
                    db=db,
                    organization_id=observation.organization_id,
                    application_id=observation.application_id,
                    baseline_id=baseline.id,
                    endpoint_id=observation.endpoint_id,
                    anomaly_type=AnomalyType.SCHEMA_DRIFT.value,
                    severity=severity,
                    confidence=confidence,
                    evidence_data=evidence,
                    signature=f"schema_resp_{endpoint_key}_{'-'.join(diff['missing_required'] + diff['unexpected_properties'])}",
                )
                anomalies.append(anomaly)

        return anomalies

    async def _check_latency_drift(
        self,
        db: AsyncSession,
        observation: BehavioralObservation,
        baseline: BehavioralBaseline,
        endpoint_key: str,
        profile: Optional[Dict[str, Any]],
    ) -> Optional[BehavioralAnomaly]:
        """
        Detects response latency anomalies exceeding baseline P95 with sample size safety.
        """
        if not profile:
            return None

        total_samples = profile.get("total_requests", 0)
        if total_samples < self.min_baseline_samples_for_latency:
            # Gating: do not alert on latency drift when baseline sample size is sparse
            return None

        latency_stats = profile.get("latency_stats", {})
        p95 = latency_stats.get("p95_ms", 0.0)
        avg = latency_stats.get("avg_ms", 0.0)

        threshold = max(p95 * self.latency_multiplier, p95 + self.latency_min_delta_ms)
        observed_lat = observation.latency_ms

        if observed_lat > threshold and threshold > 0.0:
            ratio = round(observed_lat / p95, 2) if p95 > 0 else 2.0
            severity = AnomalySeverity.MEDIUM.value if ratio >= 5.0 else AnomalySeverity.LOW.value
            confidence = min(0.90, round(0.50 + 0.10 * ratio, 2))

            desc = (
                f"Latency spike observed on {endpoint_key}: {observed_lat}ms "
                f"(baseline P95: {p95}ms, {ratio}x baseline). Threshold: {round(threshold, 2)}ms."
            )

            evidence = {
                "observed_latency_ms": observed_lat,
                "baseline_latency_stats": latency_stats,
                "threshold_ms": round(threshold, 2),
                "ratio_to_p95": ratio,
                "description": desc,
            }

            return await self._get_or_create_anomaly(
                db=db,
                organization_id=observation.organization_id,
                application_id=observation.application_id,
                baseline_id=baseline.id,
                endpoint_id=observation.endpoint_id,
                anomaly_type=AnomalyType.LATENCY_SPIKE.value,
                severity=severity,
                confidence=confidence,
                evidence_data=evidence,
                signature=f"latency_{endpoint_key}",
            )

        return None

    async def _check_sequence_drift(
        self,
        db: AsyncSession,
        observation: BehavioralObservation,
        baseline: BehavioralBaseline,
        endpoint_key: str,
        prior_observation: Optional[BehavioralObservation],
    ) -> Optional[BehavioralAnomaly]:
        """
        Detects unseen or improbable API transitions between consecutive session interactions.
        """
        if not prior_observation:
            return None

        from_key = extract_endpoint_key(prior_observation)
        transition_matrix = baseline.transition_matrix or {}

        from_probs = transition_matrix.get(from_key, {})
        prob = from_probs.get(endpoint_key, 0.0)

        if prob < self.sequence_rare_threshold:
            # Unseen sequence transition
            desc = (
                f"Unseen workflow sequence traversal: '{from_key}' -> '{endpoint_key}'. "
                f"Learned baseline transition probability: {prob}."
            )

            evidence = {
                "from_endpoint_key": from_key,
                "to_endpoint_key": endpoint_key,
                "learned_probability": prob,
                "threshold": self.sequence_rare_threshold,
                "description": desc,
            }

            # Security rule: Rare transition is not automatically an exploit
            severity = AnomalySeverity.LOW.value
            confidence = 0.70

            return await self._get_or_create_anomaly(
                db=db,
                organization_id=observation.organization_id,
                application_id=observation.application_id,
                baseline_id=baseline.id,
                endpoint_id=observation.endpoint_id,
                anomaly_type=AnomalyType.UNSEEN_SEQUENCE.value,
                severity=severity,
                confidence=confidence,
                evidence_data=evidence,
                signature=f"seq_{from_key}_{endpoint_key}",
            )

        return None

    async def _get_or_create_anomaly(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        endpoint_id: Optional[uuid.UUID],
        anomaly_type: str,
        severity: str,
        confidence: float,
        evidence_data: Dict[str, Any],
        signature: str,
    ) -> BehavioralAnomaly:
        """
        Prevents duplicate noisy anomalies by checking for an existing OPEN or ACKNOWLEDGED
        anomaly with the same signature. If present, increments its occurrence count.
        """
        sanitized_evidence = sanitize_payload_recursively(evidence_data)
        sanitized_evidence["signature"] = signature

        # Search for existing active anomaly with matching signature
        query = select(BehavioralAnomaly).where(
            and_(
                BehavioralAnomaly.organization_id == organization_id,
                BehavioralAnomaly.application_id == application_id,
                BehavioralAnomaly.anomaly_type == anomaly_type,
                BehavioralAnomaly.status.in_([
                    AnomalyStatus.OPEN.value,
                    AnomalyStatus.ACKNOWLEDGED.value,
                ]),
            )
        )
        res = await db.execute(query)
        candidates = res.scalars().all()

        for cand in candidates:
            cand_sig = cand.evidence_data.get("signature") if isinstance(cand.evidence_data, dict) else None
            if cand_sig == signature:
                # Update existing anomaly
                ev = dict(cand.evidence_data or {})
                ev["occurrence_count"] = ev.get("occurrence_count", 1) + 1
                ev["last_detected_at"] = datetime.now(timezone.utc).isoformat()
                cand.evidence_data = ev
                await db.commit()
                await db.refresh(cand)
                return cand

        # Create new anomaly record
        sanitized_evidence["occurrence_count"] = 1
        sanitized_evidence["first_detected_at"] = datetime.now(timezone.utc).isoformat()

        anomaly = BehavioralAnomaly(
            organization_id=organization_id,
            application_id=application_id,
            baseline_id=baseline_id,
            endpoint_id=endpoint_id,
            anomaly_type=anomaly_type,
            severity=severity,
            confidence=confidence,
            evidence_data=sanitized_evidence,
            status=AnomalyStatus.OPEN.value,
            detected_at=datetime.now(timezone.utc),
        )
        db.add(anomaly)
        await db.commit()
        await db.refresh(anomaly)
        return anomaly

    @staticmethod
    async def update_anomaly_status(
        db: AsyncSession,
        organization_id: uuid.UUID,
        anomaly_id: uuid.UUID,
        new_status: AnomalyStatus,
        notes: Optional[str] = None,
    ) -> BehavioralAnomaly:
        """
        Updates anomaly review lifecycle status (OPEN -> ACKNOWLEDGED -> RESOLVED)
        while preserving all forensic evidence and enforcing tenant boundaries.
        """
        query = select(BehavioralAnomaly).where(
            and_(
                BehavioralAnomaly.id == anomaly_id,
                BehavioralAnomaly.organization_id == organization_id,
            )
        )
        res = await db.execute(query)
        anomaly = res.scalar_one_or_none()
        if not anomaly:
            raise ValueError("Anomaly not found or tenant access denied.")

        anomaly.status = new_status.value

        evidence = dict(anomaly.evidence_data or {})
        if notes:
            history = evidence.get("review_notes", [])
            history.append({
                "status": new_status.value,
                "notes": notes,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            evidence["review_notes"] = history

        if new_status == AnomalyStatus.RESOLVED:
            anomaly.resolved_at = datetime.now(timezone.utc)
            evidence["resolved_at"] = anomaly.resolved_at.isoformat()
        elif anomaly.resolved_at is not None and new_status != AnomalyStatus.RESOLVED:
            anomaly.resolved_at = None

        anomaly.evidence_data = evidence
        await db.commit()
        await db.refresh(anomaly)
        return anomaly

    @staticmethod
    async def list_anomalies(
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
        status: Optional[AnomalyStatus] = None,
    ) -> List[BehavioralAnomaly]:
        """
        Queries anomalies for an application with optional status filtering.
        """
        filters = [
            BehavioralAnomaly.organization_id == organization_id,
            BehavioralAnomaly.application_id == application_id,
        ]
        if status:
            filters.append(BehavioralAnomaly.status == status.value)

        query = (
            select(BehavioralAnomaly)
            .where(and_(*filters))
            .order_by(desc(BehavioralAnomaly.detected_at))
        )
        res = await db.execute(query)
        return list(res.scalars().all())

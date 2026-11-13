"""
PHANTOM-X - Feature 4: Behavioral Digital Twin
Baseline Management Service

Responsible for:
- Compiling observations into versioned Behavioral Baseline snapshots.
- Generating endpoint behavior profiles and Markov transition models.
- Managing baseline lifecycle states: DRAFT -> ACTIVE -> SUPERSEDED / ARCHIVED.
- Guaranteeing strict single-active baseline invariant per application.
- Enforcing organization-level multi-tenant isolation.
- Rejecting activation when empirical evidence is insufficient.
"""

import uuid
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy import select, update, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application import Application
from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
    BehavioralBaseline,
    BehavioralTransition,
    BaselineStatus,
)
from app.features.application_intelligence.behavioral_digital_twin.profiler import (
    aggregate_endpoint_observations,
    calculate_confidence,
)
from app.features.application_intelligence.behavioral_digital_twin.transition_learner import (
    learn_endpoint_transitions,
    extract_endpoint_key,
)


def generate_next_version(latest_version: Optional[str]) -> str:
    """
    Computes the next semantic version string given the latest version.
    Defaults to 'v1.0' if no prior version exists.
    """
    if not latest_version:
        return "v1.0"

    clean = latest_version.strip().lstrip("vV")
    match = re.match(r"^(\d+)(?:\.(\d+))?$", clean)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2) or 0)
        return f"v{major}.{minor + 1}"

    return f"{latest_version}.1"


class BaselineService:
    """
    Service managing compilation, versioning, and lifecycle state
    for application behavioral baselines.
    """

    @staticmethod
    async def compile_baseline(
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
        version: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        min_samples: int = 1,
    ) -> BehavioralBaseline:
        """
        Compiles observations for a specified application into a new DRAFT baseline.
        Strictly enforces tenant isolation and ownership.
        """
        # 1. Verify application exists and belongs to the specified organization
        app_query = select(Application).where(
            and_(
                Application.id == application_id,
                Application.organization_id == organization_id,
            )
        )
        app_result = await db.execute(app_query)
        application = app_result.scalar_one_or_none()
        if not application:
            raise ValueError("Application not found or tenant access denied.")

        # 2. Query observations within the observation window
        obs_filters = [
            BehavioralObservation.application_id == application_id,
            BehavioralObservation.organization_id == organization_id,
        ]
        if start_time:
            obs_filters.append(BehavioralObservation.observed_at >= start_time)
        if end_time:
            obs_filters.append(BehavioralObservation.observed_at <= end_time)

        obs_query = (
            select(BehavioralObservation)
            .where(and_(*obs_filters))
            .order_by(BehavioralObservation.observed_at.asc())
        )
        obs_result = await db.execute(obs_query)
        observations = list(obs_result.scalars().all())

        total_obs = len(observations)
        if total_obs < min_samples:
            raise ValueError(
                f"Insufficient observations to compile baseline. Found {total_obs}, "
                f"minimum required is {min_samples}."
            )

        # 3. Determine baseline version
        if not version:
            latest_query = (
                select(BehavioralBaseline.version)
                .where(
                    and_(
                        BehavioralBaseline.application_id == application_id,
                        BehavioralBaseline.organization_id == organization_id,
                    )
                )
                .order_by(desc(BehavioralBaseline.created_at))
                .limit(1)
            )
            latest_res = await db.execute(latest_query)
            latest_ver = latest_res.scalar_one_or_none()
            version = generate_next_version(latest_ver)
        else:
            # Check version uniqueness for this application
            dup_query = select(BehavioralBaseline.id).where(
                and_(
                    BehavioralBaseline.application_id == application_id,
                    BehavioralBaseline.version == version,
                )
            )
            dup_res = await db.execute(dup_query)
            if dup_res.scalar_one_or_none():
                raise ValueError(f"Baseline version '{version}' already exists for this application.")

        # 4. Group observations by endpoint key and aggregate profiles
        endpoint_groups: Dict[str, List[BehavioralObservation]] = {}
        for obs in observations:
            key = extract_endpoint_key(obs)
            if key not in endpoint_groups:
                endpoint_groups[key] = []
            endpoint_groups[key].append(obs)

        endpoint_profiles: Dict[str, Any] = {}
        for ep_key, group_obs in endpoint_groups.items():
            profile = aggregate_endpoint_observations(group_obs)
            # Store endpoint identity metadata within profile
            first = group_obs[0]
            profile["method"] = first.method.upper()
            profile["normalized_path"] = first.normalized_path
            profile["endpoint_id"] = str(first.endpoint_id) if first.endpoint_id else None
            endpoint_profiles[ep_key] = profile

        # 5. Learn Markov sequence transitions
        counts_dict, probs_dict, transition_items = learn_endpoint_transitions(observations)

        # 6. Calculate overall baseline confidence score
        if endpoint_profiles and total_obs > 0:
            weighted_conf = sum(
                prof.get("confidence_score", 0.0) * prof.get("total_requests", 0)
                for prof in endpoint_profiles.values()
            ) / float(total_obs)
            overall_confidence = round(weighted_conf, 4)
        else:
            overall_confidence = 0.0

        # 7. Instantiate BehavioralBaseline
        baseline = BehavioralBaseline(
            organization_id=organization_id,
            application_id=application_id,
            version=version,
            status=BaselineStatus.DRAFT.value,
            sample_count=total_obs,
            confidence_score=overall_confidence,
            endpoint_profiles=endpoint_profiles,
            transition_matrix=probs_dict,
        )
        db.add(baseline)
        await db.flush()

        # 8. Persist relational BehavioralTransition rows when to_endpoint_id is present
        for item in transition_items:
            to_eid = item.get("to_endpoint_id")
            if to_eid is not None:
                trans = BehavioralTransition(
                    organization_id=organization_id,
                    application_id=application_id,
                    baseline_id=baseline.id,
                    from_endpoint_id=item.get("from_endpoint_id"),
                    to_endpoint_id=to_eid,
                    probability=item.get("probability", 0.0),
                    observation_count=item.get("observation_count", 1),
                )
                db.add(trans)

        await db.commit()
        await db.refresh(baseline)
        return baseline

    @staticmethod
    async def activate_baseline(
        db: AsyncSession,
        organization_id: uuid.UUID,
        baseline_id: uuid.UUID,
        min_confidence: float = 0.2,
        min_samples: int = 5,
    ) -> BehavioralBaseline:
        """
        Activates a baseline snapshot.
        Enforces:
        - Only one ACTIVE baseline per application.
        - Previous active baselines are superseded safely.
        - Activation is rejected if confidence or sample count is below requirements.
        - Historical baselines are preserved.
        """
        # 1. Fetch target baseline
        query = select(BehavioralBaseline).where(
            and_(
                BehavioralBaseline.id == baseline_id,
                BehavioralBaseline.organization_id == organization_id,
            )
        )
        res = await db.execute(query)
        baseline = res.scalar_one_or_none()
        if not baseline:
            raise ValueError("Baseline not found or tenant access denied.")

        # 2. Check evidence sufficiency
        if baseline.sample_count < min_samples:
            raise ValueError(
                f"Insufficient evidence to activate baseline: requires at least {min_samples} "
                f"samples, but baseline only has {baseline.sample_count} samples."
            )
        if baseline.confidence_score < min_confidence:
            raise ValueError(
                f"Insufficient evidence to activate baseline: requires at least {min_confidence} "
                f"confidence, but baseline confidence is {baseline.confidence_score}."
            )

        # 3. Supersede any existing active baseline for this application
        prior_active_query = select(BehavioralBaseline).where(
            and_(
                BehavioralBaseline.application_id == baseline.application_id,
                BehavioralBaseline.organization_id == organization_id,
                BehavioralBaseline.status == BaselineStatus.ACTIVE.value,
                BehavioralBaseline.id != baseline.id,
            )
        )
        prior_active_res = await db.execute(prior_active_query)
        for prior_active in prior_active_res.scalars().all():
            prior_active.status = BaselineStatus.SUPERSEDED.value

        # 4. Activate target baseline
        baseline.status = BaselineStatus.ACTIVE.value
        baseline.activated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(baseline)
        return baseline

    @staticmethod
    async def archive_baseline(
        db: AsyncSession,
        organization_id: uuid.UUID,
        baseline_id: uuid.UUID,
    ) -> BehavioralBaseline:
        """
        Transitions a baseline into ARCHIVED state.
        Cannot archive an ACTIVE baseline directly.
        """
        query = select(BehavioralBaseline).where(
            and_(
                BehavioralBaseline.id == baseline_id,
                BehavioralBaseline.organization_id == organization_id,
            )
        )
        res = await db.execute(query)
        baseline = res.scalar_one_or_none()
        if not baseline:
            raise ValueError("Baseline not found or tenant access denied.")

        if baseline.status == BaselineStatus.ACTIVE.value:
            raise ValueError("Cannot archive an ACTIVE baseline. Supersede it by activating another baseline first.")

        baseline.status = BaselineStatus.ARCHIVED.value
        await db.commit()
        await db.refresh(baseline)
        return baseline

    @staticmethod
    async def get_active_baseline(
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> Optional[BehavioralBaseline]:
        """
        Fetches the single currently ACTIVE baseline for an application.
        """
        query = select(BehavioralBaseline).where(
            and_(
                BehavioralBaseline.application_id == application_id,
                BehavioralBaseline.organization_id == organization_id,
                BehavioralBaseline.status == BaselineStatus.ACTIVE.value,
            )
        )
        res = await db.execute(query)
        return res.scalar_one_or_none()

    @staticmethod
    async def list_baselines(
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> List[BehavioralBaseline]:
        """
        Returns all historical and current baselines for an application.
        """
        query = (
            select(BehavioralBaseline)
            .where(
                and_(
                    BehavioralBaseline.application_id == application_id,
                    BehavioralBaseline.organization_id == organization_id,
                )
            )
            .order_by(desc(BehavioralBaseline.created_at))
        )
        res = await db.execute(query)
        return list(res.scalars().all())

    @staticmethod
    async def get_digital_twin_overview(
        db: AsyncSession,
        organization_id: uuid.UUID,
        application_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """
        Calculates high-level Behavioral Digital Twin metrics for an application.
        """
        from sqlalchemy import func
        from app.features.application_intelligence.behavioral_digital_twin.models import (
            BehavioralAnomaly,
            AnomalyStatus,
        )

        # 1. Verify application exists and belongs to organization
        app_query = select(Application).where(
            and_(
                Application.id == application_id,
                Application.organization_id == organization_id,
            )
        )
        app_res = await db.execute(app_query)
        if not app_res.scalar_one_or_none():
            raise ValueError("Application not found or tenant access denied.")

        # 2. Total observations & latest timestamp
        obs_count_query = select(func.count(BehavioralObservation.id)).where(
            and_(
                BehavioralObservation.application_id == application_id,
                BehavioralObservation.organization_id == organization_id,
            )
        )
        total_obs = (await db.execute(obs_count_query)).scalar() or 0

        last_obs_query = (
            select(BehavioralObservation.observed_at)
            .where(
                and_(
                    BehavioralObservation.application_id == application_id,
                    BehavioralObservation.organization_id == organization_id,
                )
            )
            .order_by(desc(BehavioralObservation.observed_at))
            .limit(1)
        )
        last_obs_at = (await db.execute(last_obs_query)).scalar_one_or_none()

        # 3. Active baseline
        active_b = await BaselineService.get_active_baseline(db, organization_id, application_id)
        if active_b:
            active_b_id = active_b.id
            active_b_version = active_b.version
            active_b_conf = active_b.confidence_score
            endpoint_profiles = active_b.endpoint_profiles or {}
            trans_count = sum(len(targets) for targets in (active_b.transition_matrix or {}).values())
        else:
            active_b_id = None
            active_b_version = None
            active_b_conf = 0.0
            endpoint_profiles = {}
            trans_count = 0

        # 4. Open anomalies & latest anomalies
        anom_count_query = select(func.count(BehavioralAnomaly.id)).where(
            and_(
                BehavioralAnomaly.application_id == application_id,
                BehavioralAnomaly.organization_id == organization_id,
                BehavioralAnomaly.status == AnomalyStatus.OPEN.value,
            )
        )
        open_anom_count = (await db.execute(anom_count_query)).scalar() or 0

        latest_anoms_query = (
            select(BehavioralAnomaly)
            .where(
                and_(
                    BehavioralAnomaly.application_id == application_id,
                    BehavioralAnomaly.organization_id == organization_id,
                )
            )
            .order_by(desc(BehavioralAnomaly.detected_at))
            .limit(5)
        )
        latest_anoms = list((await db.execute(latest_anoms_query)).scalars().all())

        return {
            "application_id": application_id,
            "organization_id": organization_id,
            "total_observations": total_obs,
            "active_baseline_id": active_b_id,
            "active_baseline_version": active_b_version,
            "active_baseline_confidence": active_b_conf,
            "total_transitions_tracked": trans_count,
            "open_anomalies_count": open_anom_count,
            "last_observed_at": last_obs_at,
            "endpoint_profiles": endpoint_profiles,
            "latest_anomalies": latest_anoms,
        }

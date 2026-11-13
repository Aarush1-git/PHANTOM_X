"""
PHANTOM-X - Feature 5: Application Workflow Discovery
Workflow Discovery Service

Business logic and persistence orchestrator for:
- Executing workflow discovery from application observations.
- Enforcing strict multi-tenant isolation at the organization_id level.
- Querying, filtering, and paginating discovered workflows.
- Fetching sanitized evidence for steps and transitions.
- Aggregating application-level workflow telemetry metrics.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc, delete

from app.models.application import Application
from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
)
from app.features.application_intelligence.workflow_discovery.models import (
    DiscoveredWorkflow,
    WorkflowStatus,
    WorkflowType,
)
from app.features.application_intelligence.workflow_discovery.schemas import (
    WorkflowDiscoveryRequest,
    WorkflowDiscoveryResultResponse,
    DiscoveredWorkflowResponse,
    DiscoveredWorkflowDetailResponse,
    DiscoveredWorkflowListResponse,
    WorkflowEvidenceListResponse,
    WorkflowEvidenceItemResponse,
    WorkflowOverviewResponse,
)
from app.features.application_intelligence.workflow_discovery.discovery_engine import (
    WorkflowDiscoveryEngine,
)


class WorkflowDiscoveryService:
    @staticmethod
    async def _verify_application_ownership(
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Application:
        """Enforces multi-tenant ownership for application resources."""
        stmt = select(Application).where(
            and_(
                Application.id == application_id,
                Application.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        app = res.scalar_one_or_none()
        if not app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Application {application_id} not found or access denied.",
            )
        return app

    @classmethod
    async def discover_and_persist(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        request: WorkflowDiscoveryRequest,
    ) -> WorkflowDiscoveryResultResponse:
        """
        Executes workflow discovery against recorded observations and persists results.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        # Build query for observations
        filters = [
            BehavioralObservation.application_id == application_id,
            BehavioralObservation.organization_id == organization_id,
        ]
        if request.since:
            filters.append(BehavioralObservation.observed_at >= request.since)
        if request.until:
            filters.append(BehavioralObservation.observed_at <= request.until)

        obs_stmt = select(BehavioralObservation).where(and_(*filters)).order_by(
            BehavioralObservation.observed_at.asc()
        )
        res = await db.execute(obs_stmt)
        observations = res.scalars().all()

        discovered_dicts, metadata = WorkflowDiscoveryEngine.discover_workflows(
            observations=observations,
            application_id=application_id,
            organization_id=organization_id,
            min_confidence=request.min_confidence,
            min_sample_count=request.min_sample_count,
        )

        persisted_workflows: List[DiscoveredWorkflow] = []

        if discovered_dicts:
            # Archive previous auto-discovered workflows to prevent duplicates
            archive_stmt = (
                select(DiscoveredWorkflow)
                .where(
                    and_(
                        DiscoveredWorkflow.application_id == application_id,
                        DiscoveredWorkflow.organization_id == organization_id,
                        DiscoveredWorkflow.status == WorkflowStatus.DISCOVERED.value,
                    )
                )
            )
            old_res = await db.execute(archive_stmt)
            for old_wf in old_res.scalars().all():
                old_wf.status = WorkflowStatus.ARCHIVED.value

            # Insert newly discovered workflows
            for d in discovered_dicts:
                wf = DiscoveredWorkflow(**d)
                db.add(wf)
                persisted_workflows.append(wf)

            await db.commit()
            for wf in persisted_workflows:
                await db.refresh(wf)

        return WorkflowDiscoveryResultResponse(
            application_id=application_id,
            discovered_count=len(persisted_workflows),
            analyzed_sessions_count=metadata.get("analyzed_sessions_count", 0),
            analyzed_observations_count=metadata.get("analyzed_observations_count", 0),
            insufficient_data=metadata.get("insufficient_data", False),
            insufficient_data_reason=metadata.get("insufficient_data_reason"),
            workflows=[
                DiscoveredWorkflowResponse.model_validate(wf)
                for wf in persisted_workflows
            ],
        )

    @classmethod
    async def list_workflows(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        status_filter: Optional[str] = None,
        workflow_type: Optional[str] = None,
        is_incomplete: Optional[bool] = None,
        min_confidence: float = 0.0,
        page: int = 1,
        page_size: int = 20,
    ) -> DiscoveredWorkflowListResponse:
        """
        Lists discovered workflows for an application with filtering and pagination.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        filters = [
            DiscoveredWorkflow.application_id == application_id,
            DiscoveredWorkflow.organization_id == organization_id,
            DiscoveredWorkflow.confidence_score >= min_confidence,
        ]

        if status_filter:
            filters.append(DiscoveredWorkflow.status == status_filter)
        if workflow_type:
            filters.append(DiscoveredWorkflow.workflow_type == workflow_type)
        if is_incomplete is not None:
            filters.append(DiscoveredWorkflow.is_incomplete == is_incomplete)

        # Count total
        count_stmt = select(func.count(DiscoveredWorkflow.id)).where(and_(*filters))
        total_res = await db.execute(count_stmt)
        total = total_res.scalar_one()

        # Paginated items
        limit = min(max(1, page_size), 100)
        offset = max(0, (page - 1) * limit)

        query = (
            select(DiscoveredWorkflow)
            .where(and_(*filters))
            .order_by(
                desc(DiscoveredWorkflow.confidence_score),
                desc(DiscoveredWorkflow.sample_count),
                desc(DiscoveredWorkflow.created_at),
            )
            .limit(limit)
            .offset(offset)
        )
        res = await db.execute(query)
        items = res.scalars().all()

        return DiscoveredWorkflowListResponse(
            items=[DiscoveredWorkflowResponse.model_validate(w) for w in items],
            total=total,
            page=page,
            page_size=limit,
        )

    @classmethod
    async def get_workflow_by_id(
        cls,
        db: AsyncSession,
        workflow_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> DiscoveredWorkflowDetailResponse:
        """
        Fetches detailed workflow with graph nodes and directed edges.
        """
        stmt = select(DiscoveredWorkflow).where(
            and_(
                DiscoveredWorkflow.id == workflow_id,
                DiscoveredWorkflow.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        wf = res.scalar_one_or_none()
        if not wf:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow {workflow_id} not found or access denied.",
            )

        return DiscoveredWorkflowDetailResponse.model_validate(wf)

    @classmethod
    async def get_workflow_evidence(
        cls,
        db: AsyncSession,
        workflow_id: uuid.UUID,
        organization_id: uuid.UUID,
        step_index: Optional[int] = None,
        limit: int = 50,
    ) -> WorkflowEvidenceListResponse:
        """
        Fetches supporting sanitized observation evidence for a workflow or specific step.
        """
        stmt = select(DiscoveredWorkflow).where(
            and_(
                DiscoveredWorkflow.id == workflow_id,
                DiscoveredWorkflow.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        wf = res.scalar_one_or_none()
        if not wf:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow {workflow_id} not found or access denied.",
            )

        # Collect observation IDs from steps
        target_obs_ids: List[uuid.UUID] = []
        steps = wf.steps_sequence or []

        if step_index is not None:
            if 0 <= step_index < len(steps):
                obs_id_strs = steps[step_index].get("observation_ids", [])
                for s in obs_id_strs:
                    try:
                        target_obs_ids.append(uuid.UUID(s))
                    except ValueError:
                        pass
        else:
            for st in steps:
                for s in st.get("observation_ids", []):
                    try:
                        target_obs_ids.append(uuid.UUID(s))
                    except ValueError:
                        pass

        evidence_items: List[WorkflowEvidenceItemResponse] = []
        if target_obs_ids:
            obs_stmt = (
                select(BehavioralObservation)
                .where(
                    and_(
                        BehavioralObservation.id.in_(target_obs_ids),
                        BehavioralObservation.organization_id == organization_id,
                    )
                )
                .limit(min(max(1, limit), 100))
            )
            obs_res = await db.execute(obs_stmt)
            for obs in obs_res.scalars().all():
                evidence_items.append(
                    WorkflowEvidenceItemResponse(
                        observation_id=obs.id,
                        session_token_hash=obs.session_token_hash,
                        method=obs.method,
                        normalized_path=obs.normalized_path,
                        status_code=obs.status_code,
                        latency_ms=obs.latency_ms,
                        observed_at=obs.observed_at,
                        sanitized_request_schema=obs.sanitized_request_schema or {},
                        sanitized_response_schema=obs.sanitized_response_schema or {},
                    )
                )

        return WorkflowEvidenceListResponse(
            workflow_id=workflow_id,
            step_index=step_index,
            total_evidence=len(evidence_items),
            items=evidence_items,
        )

    @classmethod
    async def get_overview(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> WorkflowOverviewResponse:
        """
        Calculates application-level workflow discovery metrics.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        # Workflow counts
        wf_stmt = select(DiscoveredWorkflow).where(
            and_(
                DiscoveredWorkflow.application_id == application_id,
                DiscoveredWorkflow.organization_id == organization_id,
            )
        )
        wf_res = await db.execute(wf_stmt)
        workflows = wf_res.scalars().all()

        total_wf = len(workflows)
        active_wf = sum(1 for w in workflows if w.status in (WorkflowStatus.DISCOVERED.value, WorkflowStatus.ACTIVE.value))
        incomplete_wf = sum(1 for w in workflows if w.is_incomplete)
        branched_wf = sum(1 for w in workflows if w.workflow_type == WorkflowType.BRANCHED.value)
        high_conf_wf = sum(1 for w in workflows if w.confidence_score >= 0.7)
        avg_steps = (
            sum(w.step_count for w in workflows) / total_wf if total_wf > 0 else 0.0
        )

        # Count distinct sessions observed in observations
        sess_stmt = select(func.count(func.distinct(BehavioralObservation.session_token_hash))).where(
            and_(
                BehavioralObservation.application_id == application_id,
                BehavioralObservation.organization_id == organization_id,
            )
        )
        sess_res = await db.execute(sess_stmt)
        total_sessions = sess_res.scalar_one() or 0

        # Check total observations
        obs_count_stmt = select(func.count(BehavioralObservation.id)).where(
            and_(
                BehavioralObservation.application_id == application_id,
                BehavioralObservation.organization_id == organization_id,
            )
        )
        obs_res = await db.execute(obs_count_stmt)
        total_obs = obs_res.scalar_one() or 0

        insufficient_data = total_obs < WorkflowDiscoveryEngine.MIN_OBSERVATIONS_FOR_DISCOVERY

        return WorkflowOverviewResponse(
            application_id=application_id,
            total_workflows=total_wf,
            active_workflows=active_wf,
            incomplete_workflows=incomplete_wf,
            branched_workflows=branched_wf,
            average_steps=round(avg_steps, 1),
            high_confidence_count=high_conf_wf,
            total_observed_sessions=total_sessions,
            insufficient_data=insufficient_data,
        )

"""
PHANTOM-X - Feature 5: Application Workflow Discovery
REST API Endpoints

Provides router endpoints for:
- Workflow overview telemetry and discovery metrics
- Triggering workflow discovery / re-analysis against application observations
- Listing and filtering discovered workflows
- Fetching detailed workflow graph representations (nodes and edges)
- Viewing sanitized supporting observation evidence
- Enforces authenticated user context, RBAC permissions, and strict multi-tenant isolation.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.api.deps import get_current_user, require_role
from app.models.user import User
from shared.enums.common import UserRole

from app.features.application_intelligence.workflow_discovery.schemas import (
    WorkflowDiscoveryRequest,
    WorkflowDiscoveryResultResponse,
    DiscoveredWorkflowResponse,
    DiscoveredWorkflowDetailResponse,
    DiscoveredWorkflowListResponse,
    WorkflowEvidenceListResponse,
    WorkflowOverviewResponse,
)
from app.features.application_intelligence.workflow_discovery.service import (
    WorkflowDiscoveryService,
)

router = APIRouter(prefix="/workflows", tags=["Feature 5 — Application Workflow Discovery"])


# ==============================================================================
# A. WORKFLOW OVERVIEW & METRICS
# ==============================================================================

@router.get(
    "/applications/{application_id}/overview",
    response_model=WorkflowOverviewResponse,
    summary="Get application workflow discovery overview telemetry",
)
async def get_workflow_overview(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkflowOverviewResponse:
    """
    Returns summary metrics of discovered user journeys, completion rates,
    and confidence scores for an application.
    """
    return await WorkflowDiscoveryService.get_overview(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
    )


# ==============================================================================
# B. WORKFLOW DISCOVERY TRIGGER
# ==============================================================================

@router.post(
    "/applications/{application_id}/discover",
    response_model=WorkflowDiscoveryResultResponse,
    summary="Trigger workflow discovery against observed application traffic",
)
async def trigger_workflow_discovery(
    application_id: uuid.UUID,
    request: Optional[WorkflowDiscoveryRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkflowDiscoveryResultResponse:
    """
    Executes discovery algorithms across session-ordered observations,
    extracting canonical workflows, branches, and dropout states.
    """
    req = request or WorkflowDiscoveryRequest()
    return await WorkflowDiscoveryService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


# ==============================================================================
# C. WORKFLOW LISTING & FILTERING
# ==============================================================================

@router.get(
    "/applications/{application_id}",
    response_model=DiscoveredWorkflowListResponse,
    summary="List discovered workflows for an application",
)
async def list_discovered_workflows(
    application_id: uuid.UUID,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (DISCOVERED, ACTIVE, ARCHIVED)"),
    workflow_type: Optional[str] = Query(None, description="Filter by type (STANDARD, BRANCHED, ABANDONED, CYCLIC)"),
    is_incomplete: Optional[bool] = Query(None, description="Filter by incomplete/abandoned status"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DiscoveredWorkflowListResponse:
    """
    Lists discovered workflows with pagination and multi-criteria filtering.
    """
    return await WorkflowDiscoveryService.list_workflows(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        status_filter=status_filter,
        workflow_type=workflow_type,
        is_incomplete=is_incomplete,
        min_confidence=min_confidence,
        page=page,
        page_size=page_size,
    )


# ==============================================================================
# D. WORKFLOW DETAIL & GRAPH
# ==============================================================================

@router.get(
    "/{workflow_id}",
    response_model=DiscoveredWorkflowDetailResponse,
    summary="Get workflow detail with graph nodes and directed edges",
)
async def get_workflow_detail(
    workflow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DiscoveredWorkflowDetailResponse:
    """
    Retrieves full workflow detail including React Flow-compatible nodes,
    edges, step statistics, and branch variations.
    """
    return await WorkflowDiscoveryService.get_workflow_by_id(
        db=db,
        workflow_id=workflow_id,
        organization_id=current_user.organization_id,
    )


# ==============================================================================
# E. WORKFLOW EVIDENCE
# ==============================================================================

@router.get(
    "/{workflow_id}/evidence",
    response_model=WorkflowEvidenceListResponse,
    summary="Get supporting sanitized observation evidence for a workflow",
)
async def get_workflow_evidence(
    workflow_id: uuid.UUID,
    step_index: Optional[int] = Query(None, ge=0, description="Optional step index to filter evidence"),
    limit: int = Query(50, ge=1, le=100, description="Maximum evidence items to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkflowEvidenceListResponse:
    """
    Retrieves sanitized observation telemetry that ground the discovered workflow steps.
    """
    return await WorkflowDiscoveryService.get_workflow_evidence(
        db=db,
        workflow_id=workflow_id,
        organization_id=current_user.organization_id,
        step_index=step_index,
        limit=limit,
    )

"""
PHANTOM-X - Feature 6: Role & Resource Relationship Mapping
REST API Endpoints

Provides endpoints for:
- Role & Resource relationship overview statistics and telemetry metrics
- Listing, filtering, and paginating discovered mappings
- Triggering declared ingestion, observed discovery, structural containment, and access overlap
- Retrieving declared-versus-observed discrepancy listings with empirical breakdown
- Inspecting application roles and resource containment trees
- Viewing sanitized supporting observation evidence without raw secrets
- Strict multi-tenant isolation at the organization_id level via authenticated user context.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.api.deps import get_current_user
from app.models.user import User

from app.features.application_intelligence.role_resource_mapping.schemas import (
    RoleResourceOverviewResponse,
    RoleResourceMappingResponse,
    RoleResourceMappingListResponse,
    MappingDiscoveryRequest,
    MappingDiscoveryResultResponse,
    DiscrepancyListResponse,
    ApplicationRoleMappingListResponse,
    ApplicationResourceMappingListResponse,
    MappingEvidenceListResponse,
)
from app.features.application_intelligence.role_resource_mapping.service import (
    RoleResourceMappingService,
)

router = APIRouter(prefix="/role-resource-mapping", tags=["Feature 6 — Role & Resource Relationship Mapping"])


# ==============================================================================
# A. OVERVIEW TELEMETRY
# ==============================================================================

@router.get(
    "/applications/{application_id}/overview",
    response_model=RoleResourceOverviewResponse,
    summary="Get role and resource relationship overview metrics",
)
async def get_role_resource_overview(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoleResourceOverviewResponse:
    """
    Returns summary metrics of discovered roles, resources, mappings,
    breakdown by evidence source (declared, observed, inferred), and discrepancy counts.
    """
    return await RoleResourceMappingService.get_overview(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
    )


# ==============================================================================
# B. MAPPINGS LISTING & FILTERING
# ==============================================================================

@router.get(
    "/applications/{application_id}/mappings",
    response_model=RoleResourceMappingListResponse,
    summary="List role and resource relationship mappings",
)
async def list_mappings(
    application_id: uuid.UUID,
    subject_type: Optional[str] = Query(None, description="Filter by subject type (ROLE, RESOURCE, IDENTITY)"),
    object_type: Optional[str] = Query(None, description="Filter by object type (ENDPOINT, RESOURCE, ROLE)"),
    relationship_type: Optional[str] = Query(None, description="Filter by relationship type"),
    evidence_source: Optional[str] = Query(None, description="Filter by provenance (DECLARED, OBSERVED, INFERRED)"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence score threshold"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoleResourceMappingListResponse:
    """
    Lists role and resource mappings with pagination, multi-criteria filtering,
    and multi-tenant access control.
    """
    return await RoleResourceMappingService.get_mappings(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        subject_type=subject_type,
        object_type=object_type,
        relationship_type=relationship_type,
        evidence_source=evidence_source,
        min_confidence=min_confidence,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/mappings/{mapping_id}",
    response_model=RoleResourceMappingResponse,
    summary="Get single mapping details and safe evidence references",
)
async def get_mapping_detail(
    mapping_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RoleResourceMappingResponse:
    """
    Retrieves full details of a single relationship mapping, validating ownership.
    """
    return await RoleResourceMappingService.get_mapping_by_id(
        db=db,
        mapping_id=mapping_id,
        organization_id=current_user.organization_id,
    )


# ==============================================================================
# C. RELATIONSHIP DISCOVERY TRIGGERS
# ==============================================================================

@router.post(
    "/applications/{application_id}/discover",
    response_model=MappingDiscoveryResultResponse,
    summary="Trigger relationship discovery (Combined or Mode-specific)",
)
async def trigger_mapping_discovery(
    application_id: uuid.UUID,
    request: Optional[MappingDiscoveryRequest] = None,
    mode: Optional[str] = Query(None, description="Optional override mode: ALL, DECLARED_ONLY, OBSERVED_ONLY, STRUCTURAL_ONLY, OVERLAP_ONLY"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingDiscoveryResultResponse:
    """
    Executes mapping discovery across declared, observed, and inferred sources.
    Idempotently persists results and enforces multi-tenant ownership.
    """
    req = request or MappingDiscoveryRequest()
    if mode:
        req.mode = mode
    return await RoleResourceMappingService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


@router.post(
    "/applications/{application_id}/discover/declared",
    response_model=MappingDiscoveryResultResponse,
    summary="Trigger declared relationship ingestion only",
)
async def trigger_declared_discovery(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingDiscoveryResultResponse:
    """Ingests declared ApplicationRole and ResourceRelationship models."""
    req = MappingDiscoveryRequest(mode="DECLARED_ONLY", include_declared=True, include_observed=False, include_inferred=False)
    return await RoleResourceMappingService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


@router.post(
    "/applications/{application_id}/discover/observed",
    response_model=MappingDiscoveryResultResponse,
    summary="Trigger observed relationship discovery only",
)
async def trigger_observed_discovery(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingDiscoveryResultResponse:
    """Discovers empirical role-endpoint interactions from behavioral observations."""
    req = MappingDiscoveryRequest(mode="OBSERVED_ONLY", include_declared=False, include_observed=True, include_inferred=False)
    return await RoleResourceMappingService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


@router.post(
    "/applications/{application_id}/discover/structural",
    response_model=MappingDiscoveryResultResponse,
    summary="Trigger structural containment inference only",
)
async def trigger_structural_discovery(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingDiscoveryResultResponse:
    """Infers structural containment from URL path hierarchy."""
    req = MappingDiscoveryRequest(mode="STRUCTURAL_ONLY", include_declared=False, include_observed=False, include_inferred=True)
    return await RoleResourceMappingService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


@router.post(
    "/applications/{application_id}/discover/overlap",
    response_model=MappingDiscoveryResultResponse,
    summary="Trigger role access overlap analysis only",
)
async def trigger_overlap_discovery(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingDiscoveryResultResponse:
    """Analyzes empirical endpoint overlap across distinct roles."""
    req = MappingDiscoveryRequest(mode="OVERLAP_ONLY", include_declared=False, include_observed=True, include_inferred=True)
    return await RoleResourceMappingService.discover_and_persist(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        request=req,
    )


# ==============================================================================
# D. DECLARED VS. OBSERVED DISCREPANCIES
# ==============================================================================

@router.get(
    "/applications/{application_id}/discrepancies",
    response_model=DiscrepancyListResponse,
    summary="Get declared-versus-observed discrepancy listings",
)
async def get_discrepancies(
    application_id: uuid.UUID,
    category: Optional[str] = Query(None, description="Filter by category (ALIGNED, DECLARED_NOT_OBSERVED, OBSERVED_NOT_DECLARED, EVIDENCE_INSUFFICIENT)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DiscrepancyListResponse:
    """
    Retrieves mappings with empirical differences between declared specifications
    and observed traffic telemetry.
    """
    return await RoleResourceMappingService.get_discrepancies(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
        category=category,
        page=page,
        page_size=page_size,
    )


# ==============================================================================
# E. ROLES AND RESOURCES VIEWS
# ==============================================================================

@router.get(
    "/applications/{application_id}/roles",
    response_model=ApplicationRoleMappingListResponse,
    summary="Get application roles and their discovered mappings",
)
async def get_application_roles_summary(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationRoleMappingListResponse:
    """
    Retrieves application roles, declared permissions, and discovered endpoint/resource mappings.
    """
    return await RoleResourceMappingService.get_roles_summary(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
    )


@router.get(
    "/applications/{application_id}/resources",
    response_model=ApplicationResourceMappingListResponse,
    summary="Get application resources with structural hierarchy and accessing roles",
)
async def get_application_resources_summary(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ApplicationResourceMappingListResponse:
    """
    Retrieves application resources, containment parents/children, and accessing roles.
    """
    return await RoleResourceMappingService.get_resources_summary(
        db=db,
        application_id=application_id,
        organization_id=current_user.organization_id,
    )


# ==============================================================================
# F. EVIDENCE INSPECTION
# ==============================================================================

@router.get(
    "/mappings/{mapping_id}/evidence",
    response_model=MappingEvidenceListResponse,
    summary="Get supporting sanitized observation evidence for a mapping",
)
async def get_mapping_evidence(
    mapping_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100, description="Maximum evidence items to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MappingEvidenceListResponse:
    """
    Retrieves sanitized observation evidence supporting a mapping.
    Recursively redacts passwords, tokens, API keys, and session cookies.
    """
    return await RoleResourceMappingService.get_evidence(
        db=db,
        mapping_id=mapping_id,
        organization_id=current_user.organization_id,
        limit=limit,
    )

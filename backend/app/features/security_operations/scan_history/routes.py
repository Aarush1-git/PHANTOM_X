import uuid
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.api.deps import get_audit_current_user
from app.models.user import User, Organization
from app.core.config import settings
from app.features.security_operations.scan_history.schemas import (
    ScanHistoryListResponse,
    ScanDetailResponse,
    ScanComparisonSummary,
    ScanComparisonRequest,
    ApplicationFilterOption,
)
from app.features.security_operations.scan_history.service import (
    ScanHistoryService,
)

router = APIRouter()


async def resolve_scan_history_tenant_org_id(
    requested_org_id: Optional[uuid.UUID],
    current_user: Optional[User],
    db: AsyncSession,
) -> uuid.UUID:
    """
    Enforce strict server-side organization isolation for Scan History & Comparison.
    Authenticated identity always governs organization scope.
    """
    if current_user:
        if requested_org_id is not None and requested_org_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: Cannot access scan history for another organization.",
            )
        return current_user.organization_id

    # If unauthenticated in production: strictly reject
    if settings.ENVIRONMENT != "development" or not getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access scan history and comparisons.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Local development fallback
    if requested_org_id:
        return requested_org_id

    first_org = (await db.execute(select(Organization))).scalars().first()
    if first_org:
        return first_org.id
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@router.get("", response_model=ScanHistoryListResponse)
@router.get("/", response_model=ScanHistoryListResponse, include_in_schema=False)
async def list_scan_history(
    application_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    sort_by: str = Query("created_at", pattern="^(created_at|started_at|completed_at|findings_count)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List security scans with pagination, search, status filtering, and severity summaries.
    """
    tenant_org_id = await resolve_scan_history_tenant_org_id(org_id, current_user, db)
    svc = ScanHistoryService(db)
    return await svc.list_scans(
        org_id=tenant_org_id,
        application_id=application_id,
        scan_status=status,
        search=search,
        start_date=start_date,
        end_date=end_date,
        sort_by=sort_by,
        order=order,
        page=page,
        limit=limit,
    )


@router.get("/applications", response_model=List[ApplicationFilterOption])
async def get_filter_applications(
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve applications that have recorded scans for filter selection.
    """
    tenant_org_id = await resolve_scan_history_tenant_org_id(org_id, current_user, db)
    svc = ScanHistoryService(db)
    return await svc.get_filter_applications(tenant_org_id)


@router.get("/compare", response_model=ScanComparisonSummary)
async def compare_scans_get(
    baseline_scan_id: uuid.UUID = Query(..., description="UUID of the baseline scan"),
    comparison_scan_id: uuid.UUID = Query(..., description="UUID of the comparison scan"),
    save_record: bool = Query(False, description="Persist comparison record"),
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare two scans of the same application via GET query parameters.
    """
    tenant_org_id = await resolve_scan_history_tenant_org_id(org_id, current_user, db)
    svc = ScanHistoryService(db)
    return await svc.compare_scans(
        baseline_scan_id=baseline_scan_id,
        comparison_scan_id=comparison_scan_id,
        org_id=tenant_org_id,
        save_record=save_record,
    )


@router.post("/compare", response_model=ScanComparisonSummary)
async def compare_scans_post(
    body: ScanComparisonRequest,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare two scans of the same application via POST request body.
    """
    tenant_org_id = await resolve_scan_history_tenant_org_id(org_id, current_user, db)
    svc = ScanHistoryService(db)
    return await svc.compare_scans(
        baseline_scan_id=body.baseline_scan_id,
        comparison_scan_id=body.comparison_scan_id,
        org_id=tenant_org_id,
        save_record=body.save_record,
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_details(
    scan_id: uuid.UUID,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed metrics, findings, and sanitized evidence items for an individual scan.
    """
    tenant_org_id = await resolve_scan_history_tenant_org_id(org_id, current_user, db)
    svc = ScanHistoryService(db)
    return await svc.get_scan_detail(scan_id=scan_id, org_id=tenant_org_id)

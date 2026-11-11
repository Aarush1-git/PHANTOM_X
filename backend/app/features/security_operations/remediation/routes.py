import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, asc, func, or_

from app.database.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from shared.enums.common import UserRole
from app.models.remediation import (
    RemediationRecommendation,
    RecommendationHistory,
    RecommendationStatus,
    RemediationPriority,
    VerificationStatus,
)
from app.features.security_operations.remediation.recommendation_service import RecommendationService
from app.features.security_operations.remediation.verification_service import VerificationService
from app.features.security_operations.remediation.schemas import (
    RemediationRecommendationListItem,
    RemediationRecommendationDetail,
    RecommendationListResponse,
    RecommendationGenerateRequest,
    RecommendationGenerateResponse,
    RecommendationStatusUpdateRequest,
    RecommendationNotesUpdateRequest,
    RecommendationVerifyRequest,
    RecommendationVerifyResponse,
    RecommendationHistoryItem,
    RemediationOverviewResponse,
)

router = APIRouter(prefix="/remediation", tags=["Feature 27 — Risk-Based Remediation Recommendations"])


def check_write_permission(user: User):
    """
    Ensure user has write/operational privileges (Admin, Security Engineer, Developer).
    Auditors are read-only.
    """
    user_role = getattr(user, "role", "").upper()
    if user_role == UserRole.AUDITOR.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditor role has read-only access and cannot modify remediation recommendations."
        )


@router.get("/overview", response_model=RemediationOverviewResponse)
async def get_remediation_overview(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter metrics by application"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns aggregated metrics on remediation priorities, lifecycle distribution, and verification progress.
    """
    service = RecommendationService(db)
    return await service.get_overview(org_id=current_user.organization_id, application_id=application_id)


@router.get("/recommendations", response_model=RecommendationListResponse)
async def list_recommendations(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter by application"),
    priority: Optional[RemediationPriority] = Query(None, description="Filter by priority"),
    status: Optional[RecommendationStatus] = Query(None, description="Filter by lifecycle status"),
    cwe_id: Optional[str] = Query(None, description="Filter by CWE identifier"),
    search: Optional[str] = Query(None, description="Search term for title or endpoint"),
    sort_by: str = Query("risk_score", description="Field to sort by: risk_score, created_at, priority"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List remediation recommendations with multi-attribute filtering, searching, and pagination.
    Strict tenant isolation is enforced.
    """
    query = select(RemediationRecommendation).where(
        RemediationRecommendation.organization_id == current_user.organization_id
    )

    if application_id:
        query = query.where(RemediationRecommendation.application_id == application_id)
    if priority:
        query = query.where(RemediationRecommendation.calculated_priority == priority.value)
    if status:
        query = query.where(RemediationRecommendation.status == status.value)
    if cwe_id:
        query = query.where(RemediationRecommendation.cwe_id == cwe_id)
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            or_(
                RemediationRecommendation.title.ilike(search_filter),
                RemediationRecommendation.endpoint.ilike(search_filter),
                RemediationRecommendation.category.ilike(search_filter)
            )
        )

    # Count total matching
    count_stmt = select(func.count()).select_from(query.subquery())
    total_count = (await db.execute(count_stmt)).scalar() or 0

    # Sorting
    sort_column = RemediationRecommendation.risk_score
    if sort_by == "created_at":
        sort_column = RemediationRecommendation.created_at
    elif sort_by == "priority":
        sort_column = RemediationRecommendation.calculated_priority

    if sort_order.lower() == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    # Pagination
    offset = (page - 1) * size
    query = query.offset(offset).limit(size)

    result = await db.execute(query)
    records = list(result.scalars().all())

    items = []
    for r in records:
        item = RemediationRecommendationListItem.model_validate(r)
        item.why_it_matters_summary = (r.why_it_matters[:140] + "...") if len(r.why_it_matters) > 140 else r.why_it_matters
        items.append(item)

    return RecommendationListResponse(
        items=items,
        total=total_count,
        page=page,
        size=size
    )


@router.get("/recommendations/{recommendation_id}", response_model=RemediationRecommendationDetail)
async def get_recommendation_detail(
    recommendation_id: uuid.UUID = Path(..., description="Recommendation ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve comprehensive details, priority rationale, remediation steps, and verification evidence.
    """
    stmt = select(RemediationRecommendation).where(
        RemediationRecommendation.id == recommendation_id,
        RemediationRecommendation.organization_id == current_user.organization_id
    )
    result = await db.execute(stmt)
    rec = result.scalar_one_or_none()

    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation recommendation {recommendation_id} not found."
        )

    return RemediationRecommendationDetail.model_validate(rec)


@router.post("/recommendations/generate", response_model=RecommendationGenerateResponse)
async def generate_recommendations(
    req: RecommendationGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Triggers deterministic generation or idempotent refresh of remediation recommendations
    for an application.
    """
    check_write_permission(current_user)
    service = RecommendationService(db)
    gen_count, upd_count, recs = await service.generate_recommendations_for_application(
        org_id=current_user.organization_id,
        app_id=req.application_id,
        vulnerability_id=req.vulnerability_id,
        scan_id=req.scan_id,
        user=current_user
    )

    items = [RemediationRecommendationListItem.model_validate(r) for r in recs]
    return RecommendationGenerateResponse(
        generated_count=gen_count,
        updated_count=upd_count,
        recommendations=items
    )


@router.patch("/recommendations/{recommendation_id}/status", response_model=RemediationRecommendationDetail)
async def update_recommendation_status(
    recommendation_id: uuid.UUID = Path(..., description="Recommendation ID"),
    req: RecommendationStatusUpdateRequest = ...,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates the lifecycle status of a recommendation with state transition validation,
    audit event recording, and history logging.
    """
    check_write_permission(current_user)
    service = RecommendationService(db)
    rec = await service.update_status(
        org_id=current_user.organization_id,
        rec_id=recommendation_id,
        req=req,
        user=current_user
    )
    return RemediationRecommendationDetail.model_validate(rec)


@router.post("/recommendations/{recommendation_id}/notes", response_model=RemediationRecommendationDetail)
async def update_recommendation_notes(
    recommendation_id: uuid.UUID = Path(..., description="Recommendation ID"),
    req: RecommendationNotesUpdateRequest = ...,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates operator decision notes and assignee without altering the lifecycle state.
    """
    check_write_permission(current_user)
    service = RecommendationService(db)
    rec = await service.update_notes(
        org_id=current_user.organization_id,
        rec_id=recommendation_id,
        req=req,
        user=current_user
    )
    return RemediationRecommendationDetail.model_validate(rec)


@router.post("/recommendations/{recommendation_id}/verify", response_model=RecommendationVerifyResponse)
async def verify_recommendation(
    recommendation_id: uuid.UUID = Path(..., description="Recommendation ID"),
    req: RecommendationVerifyRequest = ...,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes empirical verification against scan or Playground simulation results.
    Enforces Feature 26 scope safety policy before authorizing verification operations.
    """
    check_write_permission(current_user)
    verifier = VerificationService(db)
    return await verifier.verify_recommendation(
        org_id=current_user.organization_id,
        rec_id=recommendation_id,
        req=req,
        user=current_user
    )


@router.get("/recommendations/{recommendation_id}/history", response_model=List[RecommendationHistoryItem])
async def get_recommendation_history(
    recommendation_id: uuid.UUID = Path(..., description="Recommendation ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the chronological decision and transition history of a recommendation.
    """
    # Verify recommendation ownership
    rec_stmt = select(RemediationRecommendation.id).where(
        RemediationRecommendation.id == recommendation_id,
        RemediationRecommendation.organization_id == current_user.organization_id
    )
    exists = (await db.execute(rec_stmt)).scalar_one_or_none()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation recommendation {recommendation_id} not found."
        )

    hist_stmt = select(RecommendationHistory).where(
        RecommendationHistory.recommendation_id == recommendation_id,
        RecommendationHistory.organization_id == current_user.organization_id
    ).order_by(desc(RecommendationHistory.created_at))

    result = await db.execute(hist_stmt)
    records = list(result.scalars().all())
    return [RecommendationHistoryItem.model_validate(h) for h in records]


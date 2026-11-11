import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.api.deps import get_audit_current_user
from app.models.user import User
from app.features.security_operations.time_travel.service import TimeTravelService
from app.features.security_operations.time_travel.schemas import (
    BaselineVerifyRequest,
    BaselineVerifyResponse,
    BaselineRetireRequest,
    SecurityBaselineResponse,
    BaselineListResponse,
    RegressionRecordResponse,
    RegressionListResponse,
    ScanEvaluationResponse,
    SecurityTimelineResponse,
    TimeTravelOverviewResponse,
)

router = APIRouter(prefix="/time-travel", tags=["Feature 20 — Time-Travel Regression"])


@router.get("/overview", response_model=TimeTravelOverviewResponse)
async def get_time_travel_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Get high-level summary metrics of baselines, regressions, and affected applications.
    """
    service = TimeTravelService(db)
    return await service.get_overview(current_user.organization_id)


@router.get("/baselines", response_model=BaselineListResponse)
async def list_baselines(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter by application ID"),
    status: Optional[str] = Query(None, description="Filter by status (VERIFIED, REGRESSION_DETECTED, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)"),
    is_retired: Optional[bool] = Query(None, description="Filter by retired state"),
    search: Optional[str] = Query(None, description="Search by title, endpoint, or CWE"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    List security baselines with multi-criteria filtering and pagination.
    Strictly isolated to the authenticated user's organization.
    """
    service = TimeTravelService(db)
    return await service.list_baselines(
        org_id=current_user.organization_id,
        application_id=application_id,
        status_filter=status,
        severity_filter=severity,
        is_retired=is_retired,
        search=search,
        page=page,
        limit=limit,
    )


@router.get("/baselines/{baseline_id}", response_model=SecurityBaselineResponse)
async def get_baseline_details(
    baseline_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retrieve baseline details and verification evidence by baseline ID.
    Enforces strict tenant isolation.
    """
    service = TimeTravelService(db)
    return await service.get_baseline(current_user.organization_id, baseline_id)


@router.post("/baselines/verify", response_model=BaselineVerifyResponse)
async def verify_and_create_baseline(
    request: BaselineVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Verify that a fixed finding is absent in a later successful verification scan.
    Creates or re-verifies a security baseline when justified.
    """
    service = TimeTravelService(db)
    return await service.verify_and_create_baseline(
        org_id=current_user.organization_id,
        vulnerability_id=request.vulnerability_id,
        verification_scan_id=request.verification_scan_id,
        notes=request.notes,
        actor_id=current_user.id,
    )


@router.post("/baselines/{baseline_id}/retire", response_model=SecurityBaselineResponse)
async def retire_baseline(
    baseline_id: uuid.UUID,
    request: BaselineRetireRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retire an existing security baseline without destroying historical records.
    """
    service = TimeTravelService(db)
    return await service.retire_baseline(
        org_id=current_user.organization_id,
        baseline_id=baseline_id,
        reason=request.reason,
        actor_id=current_user.id,
    )


@router.post("/evaluate/{scan_id}", response_model=ScanEvaluationResponse)
async def evaluate_scan_for_regressions(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Evaluate a completed scan against all active security baselines for that application.
    Classifies findings as REGRESSION_DETECTED, STILL_PROTECTED, or INCONCLUSIVE.
    Idempotent operation: prevents duplicate evaluation records for the same scan and baseline.
    """
    service = TimeTravelService(db)
    return await service.evaluate_scan(
        org_id=current_user.organization_id,
        scan_id=scan_id,
        actor_id=current_user.id,
    )


@router.get("/regressions", response_model=RegressionListResponse)
async def list_regressions(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter by application ID"),
    status: Optional[str] = Query(None, description="Filter by status (REGRESSION_DETECTED, INCONCLUSIVE, etc.)"),
    baseline_id: Optional[uuid.UUID] = Query(None, description="Filter by baseline ID"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    List detected and inconclusive regressions with pagination and filtering.
    """
    service = TimeTravelService(db)
    return await service.list_regressions(
        org_id=current_user.organization_id,
        application_id=application_id,
        status_filter=status,
        baseline_id=baseline_id,
        page=page,
        limit=limit,
    )


@router.get("/regressions/{regression_id}", response_model=RegressionRecordResponse)
async def get_regression_details(
    regression_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retrieve regression details, supporting evidence, and severity transition by regression ID.
    """
    service = TimeTravelService(db)
    return await service.get_regression_details(current_user.organization_id, regression_id)


@router.get("/applications/{application_id}/timeline", response_model=SecurityTimelineResponse)
async def get_application_timeline(
    application_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retrieve chronological security timeline for an application:
    Original discovery -> Fix declaration -> Verification scan -> Baseline creation -> Later scans -> Regression detection.
    """
    service = TimeTravelService(db)
    return await service.get_application_timeline(current_user.organization_id, application_id)


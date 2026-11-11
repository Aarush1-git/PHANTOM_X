import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.features.security_operations.audit_logs.schemas import (
    AuditEventResponse,
    AuditOverviewResponse,
    AuditIntegrityVerificationResponse,
    ScanExecutionRecordResponse,
    ScanExecutionRecordCreate,
)
from app.features.security_operations.audit_logs.service import AuditLogService

router = APIRouter()
audit_router = router  # Feature-specific router alias


@router.get("", response_model=List[AuditEventResponse])
async def list_audit_events(
    category: Optional[str] = Query(None, description="Filter by category (AUTHENTICATION, AUTHORIZATION, etc.)"),
    event_type: Optional[str] = Query(None, description="Filter by specific event type"),
    actor: Optional[str] = Query(None, description="Filter by actor email or role"),
    application_id: Optional[uuid.UUID] = Query(None, description="Filter by application"),
    scan_id: Optional[uuid.UUID] = Query(None, description="Filter by scan"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (SUCCESS, FAILURE, BLOCKED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)"),
    start_date: Optional[datetime] = Query(None, description="Start date/time (UTC)"),
    end_date: Optional[datetime] = Query(None, description="End date/time (UTC)"),
    search: Optional[str] = Query(None, description="Free text search term"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    sort_desc: bool = Query(True),
    db: AsyncSession = Depends(get_db)
):
    """
    Query immutable security audit logs with full filtering, pagination, and sorting.
    Enforces strict organization boundary isolation.
    """
    events = await AuditLogService.list_events(
        db=db,
        category=category,
        event_type=event_type,
        actor=actor,
        application_id=application_id,
        scan_id=scan_id,
        status=status_filter,
        severity=severity,
        start_date=start_date,
        end_date=end_date,
        search=search,
        skip=skip,
        limit=limit,
        sort_desc=sort_desc
    )
    return [AuditEventResponse.model_validate(e) for e in events]


@router.get("/overview", response_model=AuditOverviewResponse)
async def get_audit_overview(
    db: AsyncSession = Depends(get_db)
):
    """Retrieve compliance and operational event metrics calculated from live records."""
    return await AuditLogService.get_overview_metrics(db)


@router.get("/verify-integrity", response_model=AuditIntegrityVerificationResponse)
async def verify_audit_integrity(
    org_id: Optional[uuid.UUID] = Query(None, description="Organization ID to verify"),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute mathematical SHA-256 hash chain verification across audit records.
    Detects any content tampering, broken links, missing records, or reordering.
    """
    target_org_id = org_id or uuid.UUID("00000000-0000-0000-0000-000000000000")
    return await AuditLogService.verify_integrity(db, target_org_id)


@router.get("/export")
async def export_audit_events(
    limit: int = Query(1000, ge=1, le=5000),
    org_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """Export sanitized, secret-scrubbed audit logs for compliance archiving."""
    target_org_id = org_id or uuid.UUID("00000000-0000-0000-0000-000000000000")
    return await AuditLogService.export_events(db, org_id=target_org_id, limit=limit)


@router.get("/execution-history", response_model=List[ScanExecutionRecordResponse])
async def list_execution_history(
    application_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve dedicated lifecycle execution history records across scans."""
    records = await AuditLogService.list_execution_records(
        db=db,
        application_id=application_id,
        status=status,
        skip=skip,
        limit=limit
    )
    return [ScanExecutionRecordResponse.model_validate(r) for r in records]


@router.get("/execution-history/{scan_id}", response_model=ScanExecutionRecordResponse)
async def get_scan_execution_history(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve complete execution lifecycle events and metrics for a specific scan."""
    record = await AuditLogService.get_scan_execution_record(db, scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution history for scan {scan_id} not found."
        )
    return ScanExecutionRecordResponse.model_validate(record)


@router.post("/execution-history", response_model=ScanExecutionRecordResponse, status_code=status.HTTP_201_CREATED)
async def record_scan_execution_transition(
    payload: ScanExecutionRecordCreate,
    db: AsyncSession = Depends(get_db)
):
    """Record or update a scan lifecycle transition and emit a security testing audit event."""
    from app.models.application import Application
    app_res = await db.execute(select(Application).where(Application.id == payload.application_id))
    app_obj = app_res.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    record = await AuditLogService.record_scan_lifecycle(
        db=db,
        org_id=app_obj.organization_id,
        scan_id=payload.scan_id,
        application_id=payload.application_id,
        status=payload.final_status,
        initiating_user_id=payload.initiating_user_id,
        initiating_user=payload.initiating_user,
        tests_executed=payload.tests_executed,
        tests_blocked=payload.tests_blocked,
        verified_findings=payload.verified_findings,
        failure_reason=payload.failure_reason,
        note="Scan lifecycle transition recorded via API"
    )
    return ScanExecutionRecordResponse.model_validate(record)


@router.get("/{event_id}", response_model=AuditEventResponse)
async def get_audit_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve details of a single immutable audit event by ID."""
    event = await AuditLogService.get_event(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event {event_id} not found."
        )
    return AuditEventResponse.model_validate(event)


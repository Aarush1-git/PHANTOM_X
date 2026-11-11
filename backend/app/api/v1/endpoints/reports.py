import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.database.session import get_db
from app.api.deps import get_audit_current_user
from app.models.user import User, Organization
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.application import Application
from app.models.vulnerability_report import VulnerabilityReport, ReportStatus
from app.core.config import settings
from app.features.security_operations.vulnerability_reports.schemas import (
    VulnerabilityReportDetail,
    VulnerabilityReportListItem,
    ReportStatusUpdateRequest,
    ReportDashboardMetrics,
    ReportListPagination,
    StatusHistoryResponse,
    ReportExportFormat,
)
from app.features.security_operations.vulnerability_reports.service import (
    VulnerabilityReportService,
)
from app.features.security_operations.vulnerability_reports.exporter import (
    generate_json_export,
    generate_pdf_bytes,
)
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import (
    AuditEventCreate,
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus as AuditEventStatus,
)

router = APIRouter()


async def resolve_report_tenant_org_id(
    requested_org_id: Optional[uuid.UUID],
    current_user: Optional[User],
    db: AsyncSession,
) -> uuid.UUID:
    """
    Enforce strict server-side organization isolation for Vulnerability Reports.
    Authenticated identity always governs organization scope.
    """
    if current_user:
        if requested_org_id is not None and requested_org_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: Cannot access vulnerability reports for another organization.",
            )
        return current_user.organization_id

    # If unauthenticated in production: strictly reject
    if settings.ENVIRONMENT != "development" or not getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access security intelligence reports.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Local development fallback
    if requested_org_id:
        return requested_org_id

    first_org = (await db.execute(select(Organization))).scalars().first()
    if first_org:
        return first_org.id
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


# ==============================================================================
# DASHBOARD METRICS & SUMMARY
# ==============================================================================

@router.get("/metrics", response_model=ReportDashboardMetrics)
async def get_report_metrics(
    org_id: Optional[uuid.UUID] = None,
    application_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve executive KPI metrics and distribution statistics for the vulnerability dashboard.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    return await VulnerabilityReportService.get_dashboard_metrics(
        db=db,
        org_id=target_org_id,
        application_id=application_id,
    )


@router.get("/summary")
async def get_security_summary(
    app_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Backward-compatible summary endpoint enriched with live metrics.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    metrics = await VulnerabilityReportService.get_dashboard_metrics(
        db=db,
        org_id=target_org_id,
        application_id=app_id,
    )
    return {
        "total_applications": metrics.total_applications,
        "total_scans": metrics.total_scans,
        "total_reports": metrics.total_reports,
        "severity_distribution": metrics.severity_distribution,
        "status_distribution": metrics.status_distribution,
        "remediation_rate": metrics.remediation_rate,
        "critical_and_high_open": metrics.critical_and_high_open,
    }


# ==============================================================================
# REPORT LISTING & FILTERING
# ==============================================================================

@router.get("", response_model=ReportListPagination)
async def list_vulnerability_reports(
    org_id: Optional[uuid.UUID] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    application_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List vulnerability reports with search, filtering, and pagination.
    Strictly isolated to authenticated organization.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)

    parsed_start = None
    if start_date:
        try:
            parsed_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except Exception:
            pass

    parsed_end = None
    if end_date:
        try:
            parsed_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except Exception:
            pass

    return await VulnerabilityReportService.list_reports(
        db=db,
        org_id=target_org_id,
        search=search,
        severity=severity,
        report_status=status,
        application_id=application_id,
        scan_id=scan_id,
        start_date=parsed_start,
        end_date=parsed_end,
        page=page,
        limit=limit,
    )


# ==============================================================================
# REPORT GENERATION (FROM UPSTREAM FINDINGS)
# ==============================================================================

@router.post("/generate/{vulnerability_id}", response_model=VulnerabilityReportDetail)
async def generate_vulnerability_report(
    vulnerability_id: uuid.UUID,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an auditable, enriched vulnerability report from an upstream dynamic finding.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    actor_email = current_user.email if current_user else "anonymous-dev@phantom-x.local"
    actor_id = current_user.id if current_user else None

    return await VulnerabilityReportService.generate_report_from_finding(
        db=db,
        vulnerability_id=vulnerability_id,
        org_id=target_org_id,
        actor_email=actor_email,
        actor_id=actor_id,
        commit=True,
    )


@router.post("/scan/{scan_id}/generate-all", response_model=List[VulnerabilityReportDetail])
async def generate_all_reports_for_scan(
    scan_id: uuid.UUID,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate vulnerability reports for all findings discovered in a specific scan execution.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    actor_email = current_user.email if current_user else "anonymous-dev@phantom-x.local"
    actor_id = current_user.id if current_user else None

    return await VulnerabilityReportService.generate_all_for_scan(
        db=db,
        scan_id=scan_id,
        org_id=target_org_id,
        actor_email=actor_email,
        actor_id=actor_id,
    )


# ==============================================================================
# LEGACY APPLICATION-LEVEL REPORT EXPORT
# (Must be declared before parameterized /{report_id} to prevent path collision)
# ==============================================================================

@router.get("/export")
async def export_legacy_application_report(
    app_id: uuid.UUID,
    format: str = "json",
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Generate legacy exportable application vulnerability summary with tenant isolation.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)

    result = await db.execute(
        select(Application).where(
            and_(
                Application.id == app_id,
                Application.organization_id == target_org_id,
            )
        )
    )
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found or unauthorized.")

    vulns = (
        await db.execute(
            select(Vulnerability).where(
                and_(
                    Vulnerability.application_id == app_id,
                    Vulnerability.organization_id == target_org_id,
                )
            )
        )
    ).scalars().all()

    return {
        "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
        "application_name": app_obj.name,
        "target_url": app_obj.target_url,
        "total_vulnerabilities": len(vulns),
        "format": format,
        "vulnerabilities": [
            {
                "id": str(v.id),
                "title": v.title,
                "severity": v.severity.value,
                "endpoint": v.endpoint,
                "confidence": v.confidence,
                "recommendation": v.recommendation,
            }
            for v in vulns
        ],
    }


# ==============================================================================
# REPORT DETAIL VIEW
# ==============================================================================

@router.get("/{report_id}", response_model=VulnerabilityReportDetail)
async def get_vulnerability_report(
    report_id: str,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve full details for a vulnerability report by report_id (VR-XXXXXXXX) or UUID.
    Includes sanitized evidence, reproduction steps, business impact, and status history.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    actor_email = current_user.email if current_user else None
    actor_id = current_user.id if current_user else None

    return await VulnerabilityReportService.get_report_detail(
        db=db,
        report_id_or_uuid=report_id,
        org_id=target_org_id,
        actor_email=actor_email,
        actor_id=actor_id,
        record_view_audit=True,
    )


# ==============================================================================
# REPORT STATUS LIFECYCLE MANAGEMENT
# ==============================================================================

@router.patch("/{report_id}/status", response_model=VulnerabilityReportDetail)
async def update_report_status(
    report_id: str,
    payload: ReportStatusUpdateRequest,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Transition report lifecycle status (OPEN, IN_PROGRESS, FIXED, ACCEPTED_RISK, FALSE_POSITIVE, REOPENED).
    Maintains a tamper-evident status audit log and keeps finding state aligned.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    actor_email = current_user.email if current_user else "anonymous-dev@phantom-x.local"
    actor_id = current_user.id if current_user else None

    return await VulnerabilityReportService.update_report_status(
        db=db,
        report_id_or_uuid=report_id,
        new_status=payload.new_status,
        reason=payload.reason,
        org_id=target_org_id,
        actor_email=actor_email,
        actor_id=actor_id,
    )


@router.get("/{report_id}/history", response_model=List[StatusHistoryResponse])
async def get_report_status_history(
    report_id: str,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve chronological status change audit history for a report.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    report_detail = await VulnerabilityReportService.get_report_detail(
        db=db,
        report_id_or_uuid=report_id,
        org_id=target_org_id,
        record_view_audit=False,
    )
    return report_detail.status_history


# ==============================================================================
# REPORT EXPORT (PDF & JSON)
# ==============================================================================

@router.get("/{report_id}/export")
async def export_vulnerability_report(
    report_id: str,
    format: str = Query("json", pattern="^(pdf|json)$"),
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Export vulnerability report as either formatted PDF or sanitized machine-readable JSON.
    Emits a REPORT_EXPORTED audit event.
    """
    target_org_id = await resolve_report_tenant_org_id(org_id, current_user, db)
    actor_email = current_user.email if current_user else "anonymous-dev@phantom-x.local"
    actor_id = current_user.id if current_user else None

    report_detail = await VulnerabilityReportService.get_report_detail(
        db=db,
        report_id_or_uuid=report_id,
        org_id=target_org_id,
        actor_email=actor_email,
        actor_id=actor_id,
        record_view_audit=False,
    )

    # Emit export audit event
    try:
        await AuditEventRecorder.record_event(
            db=db,
            org_id=target_org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.VULNERABILITY,
                event_type=AuditEventType.REPORT_EXPORTED.value,
                action=f"Exported vulnerability report {report_detail.report_id} in {format.upper()} format",
                status=AuditEventStatus.SUCCESS,
                severity=AuditSeverity.INFO,
                user_id=actor_id,
                actor_email=actor_email,
                actor_role="SECURITY_ENGINEER",
                target_type="VulnerabilityReport",
                target_id=str(report_detail.id),
                application_id=report_detail.application_id,
                scan_id=report_detail.scan_id,
                details={
                    "report_id": report_detail.report_id,
                    "format": format.lower(),
                    "title": report_detail.title,
                },
            ),
            commit=True,
        )
    except Exception:
        pass

    if format.lower() == "pdf":
        pdf_bytes = generate_pdf_bytes(report_detail)
        filename = f"PHANTOM-X_{report_detail.report_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf",
            },
        )
    else:
        json_data = generate_json_export(report_detail)
        filename = f"PHANTOM-X_{report_detail.report_id}.json"
        return JSONResponse(
            content=json_data,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )




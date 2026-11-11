import uuid
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.api.deps import get_audit_current_user
from app.models.user import User, Organization
from app.core.config import settings
from app.features.security_operations.security_dashboard.schemas import (
    SecurityOverviewMetrics,
    SeverityDistributionResponse,
    VulnerabilityTrendsResponse,
    ApplicationRiskResponse,
    ScanAnalyticsResponse,
    RemediationAnalyticsResponse,
    RecentActivityResponse,
)
from app.features.security_operations.security_dashboard.service import (
    SecurityDashboardService,
)

router = APIRouter()


async def resolve_dashboard_tenant_org_id(
    requested_org_id: Optional[uuid.UUID],
    current_user: Optional[User],
    db: AsyncSession,
) -> uuid.UUID:
    """
    Enforce strict server-side organization isolation for Security Dashboard & Analytics.
    Authenticated identity always governs organization scope.
    """
    if current_user:
        if requested_org_id is not None and requested_org_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: Cannot access security dashboard analytics for another organization.",
            )
        return current_user.organization_id

    # If unauthenticated in production: strictly reject
    if settings.ENVIRONMENT != "development" or not getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access security intelligence analytics.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Local development fallback
    if requested_org_id:
        return requested_org_id

    first_org = (await db.execute(select(Organization))).scalars().first()
    if first_org:
        return first_org.id
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@router.get("/overview", response_model=SecurityOverviewMetrics)
async def get_security_overview(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    application_id: Optional[uuid.UUID] = None,
    severity: Optional[str] = None,
    report_status: Optional[str] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve executive security overview metrics with period-over-period delta.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_security_overview(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
        application_id=application_id,
        severity=severity,
        report_status=report_status,
    )


@router.get("/severity-distribution", response_model=SeverityDistributionResponse)
async def get_severity_distribution(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    application_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve severity breakdown and open vs fixed counts for donut/pie visualizations.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_severity_distribution(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
        application_id=application_id,
    )


@router.get("/vulnerability-trends", response_model=VulnerabilityTrendsResponse)
async def get_vulnerability_trends(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    application_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve chronological daily discovery and resolution trends for time-series charts.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_vulnerability_trends(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
        application_id=application_id,
    )


@router.get("/application-risk", response_model=ApplicationRiskResponse)
async def get_application_risk(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve application risk ranking and tier distribution (Critical, High, Medium, Low, Clean).
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_application_risk(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )


@router.get("/scan-analytics", response_model=ScanAnalyticsResponse)
async def get_scan_analytics(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    application_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve scan outcomes, success rate, average duration, and recent scan logs.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_scan_analytics(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
        application_id=application_id,
    )


@router.get("/remediation-analytics", response_model=RemediationAnalyticsResponse)
async def get_remediation_analytics(
    time_range: str = Query("30d", pattern="^(7d|30d|90d|custom)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    application_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve Mean Time to Remediation (MTTR), vulnerability ageing buckets, and SLA breach indicators.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_remediation_analytics(
        db=db,
        org_id=target_org_id,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
        application_id=application_id,
    )


@router.get("/recent-activity", response_model=RecentActivityResponse)
async def get_recent_activity(
    limit: int = Query(25, ge=1, le=100),
    application_id: Optional[uuid.UUID] = None,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve consolidated chronological stream of recent security actions, findings, and events.
    """
    target_org_id = await resolve_dashboard_tenant_org_id(org_id, current_user, db)
    return await SecurityDashboardService.get_recent_activity(
        db=db,
        org_id=target_org_id,
        limit=limit,
        application_id=application_id,
    )


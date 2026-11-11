import uuid
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc, case
from fastapi import HTTPException, status

from app.models.vulnerability import Vulnerability
from app.models.application import Application
from app.models.scan import Scan
from app.models.vulnerability_report import (
    VulnerabilityReport,
    VulnerabilityStatusHistory,
    ReportStatus,
)
from app.models.audit import AuditLog
from app.models.scope_safety import ApplicationScopePolicy, BlockedExecutionLog
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.features.security_operations.security_dashboard.schemas import (
    SecurityOverviewMetrics,
    SeverityDistributionResponse,
    SeverityDistributionItem,
    VulnerabilityTrendsResponse,
    VulnerabilityTrendPoint,
    ApplicationRiskResponse,
    ApplicationRiskItem,
    ScanAnalyticsResponse,
    ScanHistorySummary,
    RemediationAnalyticsResponse,
    AgeingBucket,
    RecentActivityResponse,
    RecentActivityItem,
)


class SecurityDashboardService:
    """
    Core security intelligence analytics service for Feature 22.
    Transforms raw telemetry from Member 1, 3, and 4 into actionable metrics,
    risk distributions, MTTR calculations, and chronological activity streams
    with strict authenticated tenant isolation.
    """

    @classmethod
    def _resolve_date_bounds(
        cls,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Tuple[datetime, datetime, datetime, datetime]:
        """
        Calculates timezone-aware start, end, and prior comparison period boundaries.
        """
        now = datetime.now(timezone.utc)
        period_end = end_date or now
        if period_end.tzinfo is None:
            period_end = period_end.replace(tzinfo=timezone.utc)

        if time_range == "7d":
            duration = timedelta(days=7)
            period_start = period_end - duration
        elif time_range == "90d":
            duration = timedelta(days=90)
            period_start = period_end - duration
        elif time_range == "custom" and start_date:
            period_start = start_date
            if period_start.tzinfo is None:
                period_start = period_start.replace(tzinfo=timezone.utc)
            duration = max(timedelta(days=1), period_end - period_start)
        else:  # default 30d
            duration = timedelta(days=30)
            period_start = period_end - duration

        # Calculate matching previous comparison window
        prev_period_end = period_start
        prev_period_start = prev_period_end - duration

        return period_start, period_end, prev_period_start, prev_period_end

    @classmethod
    async def get_security_overview(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        application_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        report_status: Optional[str] = None,
    ) -> SecurityOverviewMetrics:
        """
        Computes high-level security posture overview KPIs with period-over-period delta.
        """
        p_start, p_end, prev_start, prev_end = cls._resolve_date_bounds(time_range, start_date, end_date)

        # Base conditions for Vulnerabilities
        conditions = [
            Vulnerability.organization_id == org_id,
            Vulnerability.created_at >= p_start,
            Vulnerability.created_at <= p_end,
        ]
        if application_id:
            conditions.append(Vulnerability.application_id == application_id)
        if severity:
            conditions.append(Vulnerability.severity == severity.upper())

        # Aggregate counts by severity and status in single optimized query
        stmt = select(
            func.count(Vulnerability.id).label("total"),
            func.sum(case((Vulnerability.severity == VulnerabilitySeverity.CRITICAL, 1), else_=0)).label("critical"),
            func.sum(case((Vulnerability.severity == VulnerabilitySeverity.HIGH, 1), else_=0)).label("high"),
            func.sum(case((Vulnerability.severity == VulnerabilitySeverity.MEDIUM, 1), else_=0)).label("medium"),
            func.sum(case((Vulnerability.severity == VulnerabilitySeverity.LOW, 1), else_=0)).label("low"),
            func.sum(case((Vulnerability.severity == VulnerabilitySeverity.INFO, 1), else_=0)).label("info"),
            func.sum(case((Vulnerability.status.in_([
                VulnerabilityStatus.DISCOVERED,
                VulnerabilityStatus.VERIFYING,
                VulnerabilityStatus.VERIFIED,
            ]), 1), else_=0)).label("open"),
            func.sum(case((Vulnerability.status.in_([
                VulnerabilityStatus.MITIGATED,
                VulnerabilityStatus.RESOLVED,
            ]), 1), else_=0)).label("fixed"),
            func.sum(case((Vulnerability.status == VulnerabilityStatus.FALSE_POSITIVE, 1), else_=0)).label("false_positive"),
        ).where(and_(*conditions))

        res = (await db.execute(stmt)).first()

        total_v = int(res.total or 0) if res else 0
        crit_v = int(res.critical or 0) if res else 0
        high_v = int(res.high or 0) if res else 0
        med_v = int(res.medium or 0) if res else 0
        low_v = int(res.low or 0) if res else 0
        info_v = int(res.info or 0) if res else 0
        open_v = int(res.open or 0) if res else 0
        fixed_v = int(res.fixed or 0) if res else 0
        fp_v = int(res.false_positive or 0) if res else 0

        # Query accepted-risk count from vulnerability_reports if available
        accepted_risk_stmt = select(func.count(VulnerabilityReport.id)).where(
            and_(
                VulnerabilityReport.organization_id == org_id,
                VulnerabilityReport.status == ReportStatus.ACCEPTED_RISK.value,
                VulnerabilityReport.created_at >= p_start,
                VulnerabilityReport.created_at <= p_end,
                *( [VulnerabilityReport.application_id == application_id] if application_id else [] )
            )
        )
        accepted_risk_v = int((await db.execute(accepted_risk_stmt)).scalar_one() or 0)

        # Critical and High Open count
        crit_high_open_stmt = select(func.count(Vulnerability.id)).where(
            and_(
                Vulnerability.organization_id == org_id,
                Vulnerability.severity.in_([VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]),
                Vulnerability.status.in_([
                    VulnerabilityStatus.DISCOVERED,
                    VulnerabilityStatus.VERIFYING,
                    VulnerabilityStatus.VERIFIED,
                ]),
                Vulnerability.created_at >= p_start,
                Vulnerability.created_at <= p_end,
                *( [Vulnerability.application_id == application_id] if application_id else [] )
            )
        )
        crit_high_open = int((await db.execute(crit_high_open_stmt)).scalar_one() or 0)

        # Previous period total count for delta calculation
        prev_conditions = [
            Vulnerability.organization_id == org_id,
            Vulnerability.created_at >= prev_start,
            Vulnerability.created_at <= prev_end,
            *( [Vulnerability.application_id == application_id] if application_id else [] )
        ]
        prev_stmt = select(func.count(Vulnerability.id)).where(and_(*prev_conditions))
        prev_total = int((await db.execute(prev_stmt)).scalar_one() or 0)

        if prev_total > 0:
            delta_pct = round(((total_v - prev_total) / prev_total) * 100.0, 1)
        elif total_v > 0:
            delta_pct = 100.0
        else:
            delta_pct = 0.0

        # Remediation rate: percentage of all non-false-positive findings that are fixed
        non_fp_total = total_v - fp_v
        if non_fp_total > 0:
            remediation_rate = round((fixed_v / non_fp_total) * 100.0, 1)
        else:
            remediation_rate = 100.0 if total_v == 0 else 0.0

        # Total registered applications in org
        total_apps_stmt = select(func.count(Application.id)).where(Application.organization_id == org_id)
        total_apps = int((await db.execute(total_apps_stmt)).scalar_one() or 0)

        # Total scans in org
        total_scans_stmt = select(func.count(Scan.id)).where(Scan.organization_id == org_id)
        total_scans = int((await db.execute(total_scans_stmt)).scalar_one() or 0)

        return SecurityOverviewMetrics(
            total_vulnerabilities=total_v,
            critical_count=crit_v,
            high_count=high_v,
            medium_count=med_v,
            low_count=low_v,
            info_count=info_v,
            open_count=open_v,
            fixed_count=fixed_v,
            accepted_risk_count=accepted_risk_v,
            false_positive_count=fp_v,
            critical_and_high_open=crit_high_open,
            remediation_rate=min(100.0, max(0.0, remediation_rate)),
            total_applications=total_apps,
            total_scans=total_scans,
            vulnerabilities_delta_pct=delta_pct,
            period_start=p_start,
            period_end=p_end,
        )

    @classmethod
    async def get_severity_distribution(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        application_id: Optional[uuid.UUID] = None,
    ) -> SeverityDistributionResponse:
        """
        Calculates severity breakdown with open vs fixed counts for donut/pie visualizations.
        """
        p_start, p_end, _, _ = cls._resolve_date_bounds(time_range, start_date, end_date)

        conditions = [
            Vulnerability.organization_id == org_id,
            Vulnerability.created_at >= p_start,
            Vulnerability.created_at <= p_end,
        ]
        if application_id:
            conditions.append(Vulnerability.application_id == application_id)

        stmt = select(
            Vulnerability.severity,
            func.count(Vulnerability.id).label("count"),
            func.sum(case((Vulnerability.status.in_([
                VulnerabilityStatus.DISCOVERED,
                VulnerabilityStatus.VERIFYING,
                VulnerabilityStatus.VERIFIED,
            ]), 1), else_=0)).label("open_count"),
            func.sum(case((Vulnerability.status.in_([
                VulnerabilityStatus.MITIGATED,
                VulnerabilityStatus.RESOLVED,
            ]), 1), else_=0)).label("fixed_count"),
        ).where(and_(*conditions)).group_by(Vulnerability.severity)

        rows = (await db.execute(stmt)).all()

        counts_by_sev = {sev.value: {"count": 0, "open": 0, "fixed": 0} for sev in VulnerabilitySeverity}
        total = 0
        for r in rows:
            sev_key = r.severity.value if hasattr(r.severity, "value") else str(r.severity)
            c = int(r.count or 0)
            counts_by_sev[sev_key] = {
                "count": c,
                "open": int(r.open_count or 0),
                "fixed": int(r.fixed_count or 0),
            }
            total += c

        distribution = []
        ordered_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in ordered_sevs:
            data = counts_by_sev.get(sev, {"count": 0, "open": 0, "fixed": 0})
            pct = round((data["count"] / total) * 100.0, 1) if total > 0 else 0.0
            distribution.append(
                SeverityDistributionItem(
                    severity=sev,
                    count=data["count"],
                    percentage=pct,
                    open_count=data["open"],
                    fixed_count=data["fixed"],
                )
            )

        return SeverityDistributionResponse(
            total=total,
            distribution=distribution,
        )

    @classmethod
    async def get_vulnerability_trends(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        application_id: Optional[uuid.UUID] = None,
    ) -> VulnerabilityTrendsResponse:
        """
        Builds chronological daily time-series points representing discovery and resolution activity.
        """
        p_start, p_end, _, _ = cls._resolve_date_bounds(time_range, start_date, end_date)

        conditions = [
            Vulnerability.organization_id == org_id,
            Vulnerability.created_at >= p_start,
            Vulnerability.created_at <= p_end,
        ]
        if application_id:
            conditions.append(Vulnerability.application_id == application_id)

        # Query all vulnerabilities in period
        stmt = select(
            Vulnerability.created_at,
            Vulnerability.updated_at,
            Vulnerability.severity,
            Vulnerability.status,
        ).where(and_(*conditions)).order_by(asc(Vulnerability.created_at))

        vulns = (await db.execute(stmt)).all()

        # Build day map covering entire range from p_start to p_end
        day_points: Dict[str, Dict[str, int]] = {}
        curr = p_start.date()
        end_d = p_end.date()
        while curr <= end_d:
            day_points[curr.isoformat()] = {
                "discovered": 0,
                "resolved": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            curr += timedelta(days=1)

        total_discovered = 0
        total_resolved = 0

        for v in vulns:
            d_str = v.created_at.date().isoformat()
            if d_str in day_points:
                day_points[d_str]["discovered"] += 1
                total_discovered += 1

                sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
                if sev == "CRITICAL":
                    day_points[d_str]["critical"] += 1
                elif sev == "HIGH":
                    day_points[d_str]["high"] += 1
                elif sev == "MEDIUM":
                    day_points[d_str]["medium"] += 1
                elif sev == "LOW":
                    day_points[d_str]["low"] += 1

            # If resolved in this period, record resolution on updated_at date
            is_resolved = v.status in [VulnerabilityStatus.MITIGATED, VulnerabilityStatus.RESOLVED]
            if is_resolved and v.updated_at:
                r_str = v.updated_at.date().isoformat()
                if r_str in day_points:
                    day_points[r_str]["resolved"] += 1
                    total_resolved += 1

        trends_list = [
            VulnerabilityTrendPoint(
                date=k,
                discovered=v["discovered"],
                resolved=v["resolved"],
                critical=v["critical"],
                high=v["high"],
                medium=v["medium"],
                low=v["low"],
            )
            for k, v in sorted(day_points.items())
        ]

        return VulnerabilityTrendsResponse(
            trends=trends_list,
            total_discovered=total_discovered,
            total_resolved=total_resolved,
            net_risk_change=total_discovered - total_resolved,
            time_range=time_range or "30d",
        )

    @classmethod
    async def get_application_risk(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> ApplicationRiskResponse:
        """
        Ranks applications by vulnerability exposure and groups them into cybersecurity risk tiers.
        """
        # Fetch all applications in org
        apps_stmt = select(Application).where(Application.organization_id == org_id)
        apps = (await db.execute(apps_stmt)).scalars().all()

        app_items: List[ApplicationRiskItem] = []
        tier_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "CLEAN": 0,
        }

        for app in apps:
            # Query findings count for this application
            vuln_stmt = select(
                func.count(Vulnerability.id).label("total"),
                func.sum(case((and_(Vulnerability.severity == VulnerabilitySeverity.CRITICAL, Vulnerability.status.in_([VulnerabilityStatus.DISCOVERED, VulnerabilityStatus.VERIFIED])), 1), else_=0)).label("open_critical"),
                func.sum(case((and_(Vulnerability.severity == VulnerabilitySeverity.HIGH, Vulnerability.status.in_([VulnerabilityStatus.DISCOVERED, VulnerabilityStatus.VERIFIED])), 1), else_=0)).label("open_high"),
                func.sum(case((and_(Vulnerability.severity == VulnerabilitySeverity.MEDIUM, Vulnerability.status.in_([VulnerabilityStatus.DISCOVERED, VulnerabilityStatus.VERIFIED])), 1), else_=0)).label("open_medium"),
                func.sum(case((and_(Vulnerability.severity == VulnerabilitySeverity.LOW, Vulnerability.status.in_([VulnerabilityStatus.DISCOVERED, VulnerabilityStatus.VERIFIED])), 1), else_=0)).label("open_low"),
                func.sum(case((Vulnerability.status.in_([VulnerabilityStatus.DISCOVERED, VulnerabilityStatus.VERIFYING, VulnerabilityStatus.VERIFIED]), 1), else_=0)).label("open_total"),
                func.sum(case((Vulnerability.status.in_([VulnerabilityStatus.MITIGATED, VulnerabilityStatus.RESOLVED]), 1), else_=0)).label("fixed_total"),
            ).where(
                and_(
                    Vulnerability.application_id == app.id,
                    Vulnerability.organization_id == org_id,
                )
            )
            v_res = (await db.execute(vuln_stmt)).first()

            crit_count = int(v_res.open_critical or 0) if v_res else 0
            high_count = int(v_res.open_high or 0) if v_res else 0
            med_count = int(v_res.open_medium or 0) if v_res else 0
            low_count = int(v_res.open_low or 0) if v_res else 0
            total_open = int(v_res.open_total or 0) if v_res else 0
            total_fixed = int(v_res.fixed_total or 0) if v_res else 0
            total_v = int(v_res.total or 0) if v_res else 0

            # Determine Risk Tier
            if crit_count > 0 or app.risk_score >= 8.0:
                tier = "CRITICAL"
            elif high_count > 0 or app.risk_score >= 6.0:
                tier = "HIGH"
            elif med_count > 0 or app.risk_score >= 4.0:
                tier = "MEDIUM"
            elif low_count > 0 or app.risk_score > 0.0:
                tier = "LOW"
            else:
                tier = "CLEAN"

            tier_counts[tier] += 1

            # Get latest scan timestamp
            latest_scan_stmt = select(Scan.completed_at).where(
                and_(Scan.application_id == app.id, Scan.organization_id == org_id)
            ).order_by(desc(Scan.created_at)).limit(1)
            last_scanned = (await db.execute(latest_scan_stmt)).scalar_one_or_none()

            app_items.append(
                ApplicationRiskItem(
                    application_id=app.id,
                    name=app.name,
                    target_url=app.target_url,
                    risk_score=app.risk_score,
                    risk_tier=tier,
                    total_vulnerabilities=total_v,
                    critical_count=crit_count,
                    high_count=high_count,
                    medium_count=med_count,
                    low_count=low_count,
                    open_count=total_open,
                    fixed_count=total_fixed,
                    last_scanned_at=last_scanned,
                )
            )

        # Sort top exposed applications: highest weighted exposure first
        # Weight formula: Critical * 10 + High * 5 + Medium * 2 + Low * 1
        app_items.sort(
            key=lambda a: (a.critical_count * 10 + a.high_count * 5 + a.medium_count * 2 + a.low_count, a.risk_score),
            reverse=True,
        )

        vulnerable_count = sum(1 for a in app_items if a.open_count > 0)

        return ApplicationRiskResponse(
            total_applications=len(apps),
            vulnerable_applications_count=vulnerable_count,
            risk_tier_distribution=tier_counts,
            top_exposed_applications=app_items[:10],
        )

    @classmethod
    async def get_scan_analytics(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        application_id: Optional[uuid.UUID] = None,
    ) -> ScanAnalyticsResponse:
        """
        Analyzes scan execution success rates, run statuses, and average scan duration.
        """
        p_start, p_end, _, _ = cls._resolve_date_bounds(time_range, start_date, end_date)

        conditions = [
            Scan.organization_id == org_id,
            Scan.created_at >= p_start,
            Scan.created_at <= p_end,
        ]
        if application_id:
            conditions.append(Scan.application_id == application_id)

        # Status counts
        status_stmt = select(
            func.count(Scan.id).label("total"),
            func.sum(case((Scan.status == ScanStatus.COMPLETED, 1), else_=0)).label("completed"),
            func.sum(case((Scan.status == ScanStatus.FAILED, 1), else_=0)).label("failed"),
            func.sum(case((Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]), 1), else_=0)).label("running"),
            func.sum(case((Scan.status.in_([ScanStatus.CANCELLED, ScanStatus.PAUSED]), 1), else_=0)).label("cancelled"),
        ).where(and_(*conditions))

        res = (await db.execute(status_stmt)).first()

        total = int(res.total or 0) if res else 0
        completed = int(res.completed or 0) if res else 0
        failed = int(res.failed or 0) if res else 0
        running = int(res.running or 0) if res else 0
        cancelled = int(res.cancelled or 0) if res else 0

        # Success rate
        finished = completed + failed
        success_rate = round((completed / finished) * 100.0, 1) if finished > 0 else 0.0

        # Calculate average duration from completed scans with valid timestamps
        completed_scans_stmt = select(Scan.started_at, Scan.completed_at).where(
            and_(
                *conditions,
                Scan.status == ScanStatus.COMPLETED,
                Scan.started_at.is_not(None),
                Scan.completed_at.is_not(None),
            )
        )
        completed_scans = (await db.execute(completed_scans_stmt)).all()

        durations: List[float] = []
        for s in completed_scans:
            if s.completed_at and s.started_at and s.completed_at >= s.started_at:
                durations.append((s.completed_at - s.started_at).total_seconds())

        if durations:
            avg_sec = round(sum(durations) / len(durations), 1)
            mins = int(avg_sec // 60)
            secs = int(avg_sec % 60)
            avg_formatted = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            has_duration = True
        else:
            avg_sec = None
            avg_formatted = "Unavailable: No completed scans with recorded duration"
            has_duration = False

        # Recent 10 scans
        recent_stmt = (
            select(Scan, Application.name.label("app_name"))
            .join(Application, Scan.application_id == Application.id)
            .where(and_(*conditions))
            .order_by(desc(Scan.created_at))
            .limit(10)
        )
        recent_rows = (await db.execute(recent_stmt)).all()

        recent_list = []
        for s, app_name in recent_rows:
            duration = None
            if s.started_at and s.completed_at and s.completed_at >= s.started_at:
                duration = round((s.completed_at - s.started_at).total_seconds(), 1)

            recent_list.append(
                ScanHistorySummary(
                    id=s.id,
                    application_id=s.application_id,
                    application_name=app_name,
                    status=s.status.value if hasattr(s.status, "value") else str(s.status),
                    progress=s.progress,
                    findings_count=s.findings_count,
                    started_at=s.started_at,
                    completed_at=s.completed_at,
                    duration_seconds=duration,
                )
            )

        return ScanAnalyticsResponse(
            total_scans=total,
            completed_scans=completed,
            failed_scans=failed,
            running_scans=running,
            cancelled_scans=cancelled,
            success_rate=success_rate,
            average_duration_seconds=avg_sec,
            average_duration_formatted=avg_formatted,
            has_duration_data=has_duration,
            recent_scans=recent_list,
        )

    @classmethod
    async def get_remediation_analytics(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        time_range: Optional[str] = "30d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        application_id: Optional[uuid.UUID] = None,
    ) -> RemediationAnalyticsResponse:
        """
        Calculates Mean Time To Remediation (MTTR) and open vulnerability ageing buckets.
        Handles zero-data periods safely without inventing values.
        """
        now = datetime.now(timezone.utc)
        p_start, p_end, _, _ = cls._resolve_date_bounds(time_range, start_date, end_date)

        # 1. MTTR calculation from resolved findings
        # Gather fixed/resolved vulnerabilities
        vuln_conds = [
            Vulnerability.organization_id == org_id,
            Vulnerability.status.in_([VulnerabilityStatus.MITIGATED, VulnerabilityStatus.RESOLVED]),
        ]
        if application_id:
            vuln_conds.append(Vulnerability.application_id == application_id)

        resolved_vulns_stmt = select(Vulnerability.created_at, Vulnerability.updated_at).where(and_(*vuln_conds))
        resolved_rows = (await db.execute(resolved_vulns_stmt)).all()

        remediation_durations_hours: List[float] = []
        for v in resolved_rows:
            if v.created_at and v.updated_at and v.updated_at >= v.created_at:
                diff_hours = (v.updated_at - v.created_at).total_seconds() / 3600.0
                remediation_durations_hours.append(diff_hours)

        if remediation_durations_hours:
            mttr_hours = round(sum(remediation_durations_hours) / len(remediation_durations_hours), 1)
            mttr_days = round(mttr_hours / 24.0, 1)
            has_remediation = True
            remediation_notes = None
        else:
            mttr_hours = None
            mttr_days = None
            has_remediation = False
            remediation_notes = "Unavailable: No vulnerabilities resolved in the selected time period."

        # 2. Open vulnerability ageing
        open_conds = [
            Vulnerability.organization_id == org_id,
            Vulnerability.status.in_([
                VulnerabilityStatus.DISCOVERED,
                VulnerabilityStatus.VERIFYING,
                VulnerabilityStatus.VERIFIED,
            ]),
        ]
        if application_id:
            open_conds.append(Vulnerability.application_id == application_id)

        open_vulns_stmt = select(Vulnerability.created_at, Vulnerability.severity).where(and_(*open_conds))
        open_vulns = (await db.execute(open_vulns_stmt)).all()

        under_7 = 0
        days_7_30 = 0
        days_30_90 = 0
        over_90 = 0
        sla_breach_count = 0

        for ov in open_vulns:
            created = ov.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (now - created).total_seconds() / 86400.0

            if age_days < 7:
                under_7 += 1
            elif age_days < 30:
                days_7_30 += 1
            elif age_days < 90:
                days_30_90 += 1
            else:
                over_90 += 1

            # SLA Breach definition: Critical open > 14 days or High open > 30 days
            sev = ov.severity.value if hasattr(ov.severity, "value") else str(ov.severity)
            if sev == "CRITICAL" and age_days > 14:
                sla_breach_count += 1
            elif sev == "HIGH" and age_days > 30:
                sla_breach_count += 1

        total_open = len(open_vulns)
        total_all_stmt = select(func.count(Vulnerability.id)).where(
            and_(
                Vulnerability.organization_id == org_id,
                *( [Vulnerability.application_id == application_id] if application_id else [] )
            )
        )
        total_all = int((await db.execute(total_all_stmt)).scalar_one() or 0)
        fixed_count = len(remediation_durations_hours)

        progress_pct = round((fixed_count / total_all) * 100.0, 1) if total_all > 0 else 100.0

        return RemediationAnalyticsResponse(
            mean_time_to_remediation_hours=mttr_hours,
            mean_time_to_remediation_days=mttr_days,
            has_remediation_data=has_remediation,
            remediation_notes=remediation_notes,
            open_vulnerabilities_ageing=AgeingBucket(
                under_7_days=under_7,
                days_7_to_30=days_7_30,
                days_30_to_90=days_30_90,
                over_90_days=over_90,
            ),
            vulnerabilities_awaiting_remediation=total_open,
            remediation_progress_percentage=min(100.0, max(0.0, progress_pct)),
            sla_breach_count=sla_breach_count,
        )

    @classmethod
    async def get_recent_activity(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        limit: int = 25,
        application_id: Optional[uuid.UUID] = None,
    ) -> RecentActivityResponse:
        """
        Consolidates real chronological events from AuditLog, StatusHistory, Scans, and BlockedExecutions.
        """
        limit = max(1, min(100, limit))
        activities: List[RecentActivityItem] = []

        # 1. Events from AuditLog (Feature 25)
        audit_conds = [AuditLog.organization_id == org_id]
        if application_id:
            audit_conds.append(AuditLog.application_id == application_id)

        audit_stmt = (
            select(AuditLog, Application.name.label("app_name"))
            .outerjoin(Application, AuditLog.application_id == Application.id)
            .where(and_(*audit_conds))
            .order_by(desc(AuditLog.created_at))
            .limit(limit)
        )
        audit_rows = (await db.execute(audit_stmt)).all()

        for a, app_name in audit_rows:
            activities.append(
                RecentActivityItem(
                    id=f"audit-{a.id}",
                    timestamp=a.created_at,
                    activity_type=a.event_type,
                    severity=a.severity,
                    title=a.action,
                    description=f"{a.category}: {a.action}",
                    actor_email=a.actor_email,
                    application_name=app_name,
                    metadata=a.details or {},
                )
            )

        # 2. Blocked execution safety events (Feature 26)
        block_conds = [BlockedExecutionLog.organization_id == org_id]
        if application_id:
            block_conds.append(BlockedExecutionLog.application_id == application_id)

        block_stmt = (
            select(BlockedExecutionLog, Application.name.label("app_name"))
            .outerjoin(Application, BlockedExecutionLog.application_id == Application.id)
            .where(and_(*block_conds))
            .order_by(desc(BlockedExecutionLog.created_at))
            .limit(limit)
        )
        block_rows = (await db.execute(block_stmt)).all()

        for b, app_name in block_rows:
            activities.append(
                RecentActivityItem(
                    id=f"block-{b.id}",
                    timestamp=b.created_at,
                    activity_type="BLOCKED_EXECUTION",
                    severity="HIGH",
                    title=f"Blocked {b.http_method} probe: {b.violation_category}",
                    description=b.blocked_reason,
                    actor_email=None,
                    application_name=app_name,
                    metadata={"target_url": b.target_url, "http_method": b.http_method},
                )
            )

        # 3. Report status transitions (Feature 21)
        hist_conds = [VulnerabilityStatusHistory.organization_id == org_id]
        hist_stmt = (
            select(VulnerabilityStatusHistory, VulnerabilityReport.title.label("rep_title"))
            .join(VulnerabilityReport, VulnerabilityStatusHistory.report_id == VulnerabilityReport.id)
            .where(and_(*hist_conds))
            .order_by(desc(VulnerabilityStatusHistory.created_at))
            .limit(limit)
        )
        hist_rows = (await db.execute(hist_stmt)).all()

        for h, rep_title in hist_rows:
            activities.append(
                RecentActivityItem(
                    id=f"status-{h.id}",
                    timestamp=h.created_at,
                    activity_type="STATUS_CHANGED",
                    severity="INFO" if h.to_status != "FIXED" else "MEDIUM",
                    title=f"Report transitioned to {h.to_status}",
                    description=h.reason or f"Transitioned finding '{rep_title}' from {h.from_status} to {h.to_status}",
                    actor_email=h.changed_by_email,
                    application_name=None,
                    metadata={"from_status": h.from_status, "to_status": h.to_status},
                )
            )

        # Sort all combined activities by timestamp DESC
        activities.sort(key=lambda item: item.timestamp, reverse=True)

        return RecentActivityResponse(
            activities=activities[:limit],
            total=len(activities[:limit]),
        )


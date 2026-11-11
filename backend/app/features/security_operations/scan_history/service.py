import uuid
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
from fastapi import HTTPException, status

from app.models.scan import Scan, ScanComparison
from app.models.application import Application
from app.models.vulnerability import Vulnerability, Evidence
from app.models.vulnerability_report import VulnerabilityReport, VulnerabilityStatusHistory
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus, ScanStatus
from app.features.security_operations.scan_history.schemas import (
    ScanHistoryItem,
    ScanHistoryListResponse,
    ScanFindingSummary,
    ScanEvidenceSummary,
    ScanDetailResponse,
    VulnerabilityComparisonItem,
    ScanComparisonSummary,
    ApplicationFilterOption,
)

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def make_vuln_fingerprint(endpoint: str, cwe_id: Optional[str], title: str) -> str:
    """Generate a deterministic fingerprint for vulnerability identity across scans."""
    ep = (endpoint or "").strip().lower()
    cwe = (cwe_id or "").strip().upper()
    if not cwe:
        cwe = (title or "").strip().lower()
    return f"{ep}::{cwe}"


class ScanHistoryService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_scans(
        self,
        org_id: uuid.UUID,
        application_id: Optional[uuid.UUID] = None,
        scan_status: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        sort_by: str = "created_at",
        order: str = "desc",
        page: int = 1,
        limit: int = 20,
    ) -> ScanHistoryListResponse:
        """
        List previous security scans for the organization with filtering, search, and pagination.
        Uses explicit queries to avoid aiosqlite / SQLite subquery deadlocks.
        """
        page = max(1, page)
        limit = max(1, min(100, limit))
        skip = (page - 1) * limit

        base_query = (
            select(Scan)
            .join(Application, Scan.application_id == Application.id)
            .where(Scan.organization_id == org_id)
        )

        if application_id:
            base_query = base_query.where(Scan.application_id == application_id)

        if scan_status:
            status_val = scan_status.upper().strip()
            base_query = base_query.where(
                func.upper(func.cast(Scan.status, func.text)) == status_val
            )

        if start_date:
            base_query = base_query.where(
                func.coalesce(Scan.started_at, Scan.created_at) >= start_date
            )
        if end_date:
            base_query = base_query.where(
                func.coalesce(Scan.completed_at, Scan.created_at) <= end_date
            )

        if search:
            search_pattern = f"%{search.strip().lower()}%"
            base_query = base_query.where(
                or_(
                    func.lower(Application.name).like(search_pattern),
                    func.lower(func.coalesce(Scan.notes, "")).like(search_pattern),
                    func.cast(Scan.id, func.text).like(f"%{search.strip().lower()}%"),
                )
            )

        # Count total matches directly
        count_stmt = (
            select(func.count(Scan.id))
            .join(Application, Scan.application_id == Application.id)
            .where(Scan.organization_id == org_id)
        )
        if application_id:
            count_stmt = count_stmt.where(Scan.application_id == application_id)
        if scan_status:
            count_stmt = count_stmt.where(
                func.upper(func.cast(Scan.status, func.text)) == scan_status.upper().strip()
            )
        if start_date:
            count_stmt = count_stmt.where(
                func.coalesce(Scan.started_at, Scan.created_at) >= start_date
            )
        if end_date:
            count_stmt = count_stmt.where(
                func.coalesce(Scan.completed_at, Scan.created_at) <= end_date
            )
        if search:
            search_pat = f"%{search.strip().lower()}%"
            count_stmt = count_stmt.where(
                or_(
                    func.lower(Application.name).like(search_pat),
                    func.lower(func.coalesce(Scan.notes, "")).like(search_pat),
                    func.cast(Scan.id, func.text).like(f"%{search.strip().lower()}%"),
                )
            )

        total_count = (await self.db.execute(count_stmt)).scalar() or 0

        # Sort order
        sort_col = Scan.created_at
        if sort_by == "started_at":
            sort_col = Scan.started_at
        elif sort_by == "completed_at":
            sort_col = Scan.completed_at
        elif sort_by == "findings_count":
            sort_col = Scan.findings_count

        order_stmt = asc(sort_col) if order.lower() == "asc" else desc(sort_col)

        paginated_query = base_query.order_by(order_stmt).offset(skip).limit(limit)
        result = await self.db.execute(paginated_query)
        scans = result.scalars().all()

        if not scans:
            return ScanHistoryListResponse(
                items=[],
                total=total_count,
                page=page,
                limit=limit,
                total_pages=(total_count + limit - 1) // limit if limit > 0 else 1,
            )

        scan_ids = [s.id for s in scans]
        app_ids = list({s.application_id for s in scans})

        # Fetch applications
        apps_res = await self.db.execute(
            select(Application).where(Application.id.in_(app_ids))
        )
        app_map = {a.id: a for a in apps_res.scalars().all()}

        # Fetch vulnerabilities for these scans
        vulns_res = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids))
        )
        vulns_by_scan: Dict[uuid.UUID, List[Vulnerability]] = {sid: [] for sid in scan_ids}
        for v in vulns_res.scalars().all():
            if v.scan_id in vulns_by_scan:
                vulns_by_scan[v.scan_id].append(v)

        items: List[ScanHistoryItem] = []
        for s in scans:
            duration = None
            if s.started_at and s.completed_at:
                duration = round((s.completed_at - s.started_at).total_seconds(), 2)

            crit_count = 0
            high_count = 0
            med_count = 0
            low_count = 0
            info_count = 0

            s_vulns = vulns_by_scan.get(s.id, [])
            for v in s_vulns:
                sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
                sev_u = sev.upper()
                if sev_u == "CRITICAL":
                    crit_count += 1
                elif sev_u == "HIGH":
                    high_count += 1
                elif sev_u == "MEDIUM":
                    med_count += 1
                elif sev_u == "LOW":
                    low_count += 1
                else:
                    info_count += 1

            total_v = len(s_vulns)
            status_str = s.status.value if hasattr(s.status, "value") else str(s.status)
            app = app_map.get(s.application_id)

            items.append(
                ScanHistoryItem(
                    id=s.id,
                    organization_id=s.organization_id,
                    application_id=s.application_id,
                    application_name=app.name if app else "Unknown App",
                    target_url=app.target_url if app else "",
                    status=status_str,
                    progress=s.progress or 0.0,
                    started_at=s.started_at,
                    completed_at=s.completed_at,
                    duration_seconds=duration,
                    findings_count=max(s.findings_count or 0, total_v),
                    total_vulnerabilities=total_v,
                    critical_count=crit_count,
                    high_count=high_count,
                    medium_count=med_count,
                    low_count=low_count,
                    info_count=info_count,
                    notes=s.notes,
                    created_at=s.created_at,
                )
            )

        total_pages = (total_count + limit - 1) // limit if limit > 0 else 1

        return ScanHistoryListResponse(
            items=items,
            total=total_count,
            page=page,
            limit=limit,
            total_pages=total_pages,
        )

    async def get_scan_detail(
        self,
        scan_id: uuid.UUID,
        org_id: uuid.UUID,
    ) -> ScanDetailResponse:
        """
        Get full scan details including vulnerabilities and sanitized evidence references.
        """
        scan_res = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_res.scalars().first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_id}' not found.",
            )

        if scan.organization_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: Cannot view scans belonging to another organization.",
            )

        app_res = await self.db.execute(
            select(Application).where(Application.id == scan.application_id)
        )
        app = app_res.scalars().first()

        vulns_res = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulns = vulns_res.scalars().all()

        vuln_ids = [v.id for v in vulns]
        evidence_list_db = []
        if vuln_ids:
            ev_res = await self.db.execute(
                select(Evidence).where(Evidence.vulnerability_id.in_(vuln_ids))
            )
            evidence_list_db = ev_res.scalars().all()

        evidences_by_vuln: Dict[uuid.UUID, List[Evidence]] = {vid: [] for vid in vuln_ids}
        for ev in evidence_list_db:
            if ev.vulnerability_id in evidences_by_vuln:
                evidences_by_vuln[ev.vulnerability_id].append(ev)

        duration = None
        if scan.started_at and scan.completed_at:
            duration = round((scan.completed_at - scan.started_at).total_seconds(), 2)

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0

        findings_list: List[ScanFindingSummary] = []
        evidence_list: List[ScanEvidenceSummary] = []

        for v in vulns:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            sev_u = sev.upper()
            if sev_u == "CRITICAL":
                crit_count += 1
            elif sev_u == "HIGH":
                high_count += 1
            elif sev_u == "MEDIUM":
                med_count += 1
            elif sev_u == "LOW":
                low_count += 1
            else:
                info_count += 1

            status_val = v.status.value if hasattr(v.status, "value") else str(v.status)
            evs = evidences_by_vuln.get(v.id, [])
            ev_count = len(evs)
            fp = make_vuln_fingerprint(v.endpoint, v.cwe_id, v.title)

            findings_list.append(
                ScanFindingSummary(
                    id=v.id,
                    scan_id=scan.id,
                    title=v.title,
                    severity=sev_u,
                    status=status_val,
                    endpoint=v.endpoint,
                    cwe_id=v.cwe_id,
                    cvss_score=v.cvss_score,
                    confidence=v.confidence or 0.0,
                    recommendation=v.recommendation or "",
                    evidence_count=ev_count,
                    has_evidence=ev_count > 0,
                    fingerprint=fp,
                    created_at=v.created_at,
                )
            )

            for ev in evs:
                evidence_list.append(
                    ScanEvidenceSummary(
                        id=ev.id,
                        vulnerability_id=v.id,
                        has_request_dump=bool(ev.request_dump),
                        has_response_dump=bool(ev.response_dump),
                        has_screenshot=bool(ev.screenshot_url),
                        screenshot_url=ev.screenshot_url,
                        summary=f"Evidence for finding '{v.title}' at {v.endpoint}",
                    )
                )

        status_str = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        total_v = len(vulns)

        scan_item = ScanHistoryItem(
            id=scan.id,
            organization_id=scan.organization_id,
            application_id=scan.application_id,
            application_name=app.name if app else "Unknown App",
            target_url=app.target_url if app else "",
            status=status_str,
            progress=scan.progress or 0.0,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_seconds=duration,
            findings_count=max(scan.findings_count or 0, total_v),
            total_vulnerabilities=total_v,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            notes=scan.notes,
            created_at=scan.created_at,
        )

        return ScanDetailResponse(
            scan=scan_item,
            vulnerabilities=findings_list,
            evidence_items=evidence_list,
        )

    async def compare_scans(
        self,
        baseline_scan_id: uuid.UUID,
        comparison_scan_id: uuid.UUID,
        org_id: uuid.UUID,
        save_record: bool = False,
    ) -> ScanComparisonSummary:
        """
        Compare two scans of the same application.
        Detects new, fixed, persistent, regressed, and severity changed findings.
        Computes overall posture trajectory (IMPROVED, DEGRADED, UNCHANGED).
        """
        if baseline_scan_id == comparison_scan_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Baseline scan and comparison scan must be distinct.",
            )

        # Retrieve baseline scan
        base_res = await self.db.execute(select(Scan).where(Scan.id == baseline_scan_id))
        baseline_scan = base_res.scalars().first()
        if not baseline_scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Baseline scan with ID '{baseline_scan_id}' not found.",
            )

        # Retrieve comparison scan
        comp_res = await self.db.execute(select(Scan).where(Scan.id == comparison_scan_id))
        comparison_scan = comp_res.scalars().first()
        if not comparison_scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Comparison scan with ID '{comparison_scan_id}' not found.",
            )

        # Enforce server-side tenant isolation
        if baseline_scan.organization_id != org_id or comparison_scan.organization_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: One or both scans belong to another organization.",
            )

        # Validate application compatibility
        if baseline_scan.application_id != comparison_scan.application_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incompatible scan comparison: Scans must belong to the same application target.",
            )

        app_res = await self.db.execute(
            select(Application).where(Application.id == baseline_scan.application_id)
        )
        app = app_res.scalars().first()

        # Retrieve vulnerabilities for both scans
        base_vulns_res = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == baseline_scan_id)
        )
        baseline_vulns = base_vulns_res.scalars().all()

        comp_vulns_res = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == comparison_scan_id)
        )
        comp_vulns = comp_vulns_res.scalars().all()

        # Fetch evidence for presence checking
        all_vids = [v.id for v in baseline_vulns] + [v.id for v in comp_vulns]
        evidence_vuln_ids = set()
        if all_vids:
            ev_res = await self.db.execute(
                select(Evidence.vulnerability_id).where(Evidence.vulnerability_id.in_(all_vids))
            )
            evidence_vuln_ids = set(ev_res.scalars().all())

        # Build baseline fingerprint map
        baseline_map: Dict[str, Vulnerability] = {}
        baseline_breakdown: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER.keys()}
        for v in baseline_vulns:
            fp = make_vuln_fingerprint(v.endpoint, v.cwe_id, v.title)
            baseline_map[fp] = v
            sev = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).upper()
            baseline_breakdown[sev] = baseline_breakdown.get(sev, 0) + 1

        # Build comparison fingerprint map
        comp_map: Dict[str, Vulnerability] = {}
        comp_breakdown: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER.keys()}
        for v in comp_vulns:
            fp = make_vuln_fingerprint(v.endpoint, v.cwe_id, v.title)
            comp_map[fp] = v
            sev = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).upper()
            comp_breakdown[sev] = comp_breakdown.get(sev, 0) + 1

        # Check for historical regressions:
        earlier_vulns_query = (
            select(Vulnerability)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .where(
                and_(
                    Scan.application_id == (app.id if app else baseline_scan.application_id),
                    Scan.organization_id == org_id,
                    Scan.id != baseline_scan.id,
                    Scan.id != comparison_scan.id,
                    Scan.created_at < (baseline_scan.started_at or baseline_scan.created_at),
                )
            )
        )
        earlier_vulns = (await self.db.execute(earlier_vulns_query)).scalars().all()
        earlier_fps = {make_vuln_fingerprint(ev.endpoint, ev.cwe_id, ev.title) for ev in earlier_vulns}

        # Also check fixed reports for regression
        fixed_reports_query = (
            select(VulnerabilityReport)
            .where(
                and_(
                    VulnerabilityReport.organization_id == org_id,
                    VulnerabilityReport.application_id == (app.id if app else baseline_scan.application_id),
                    VulnerabilityReport.status.in_(["FIXED", "RESOLVED", "MITIGATED"]),
                )
            )
        )
        fixed_reports = (await self.db.execute(fixed_reports_query)).scalars().all()
        fixed_report_fps = {make_vuln_fingerprint(fr.endpoint, fr.cwe_id, fr.title) for fr in fixed_reports}

        new_items: List[VulnerabilityComparisonItem] = []
        fixed_items: List[VulnerabilityComparisonItem] = []
        persistent_items: List[VulnerabilityComparisonItem] = []
        regressed_items: List[VulnerabilityComparisonItem] = []
        severity_changed_items: List[VulnerabilityComparisonItem] = []

        severity_increased_count = 0
        severity_decreased_count = 0

        # Evaluate comparison items
        for fp, c_vuln in comp_map.items():
            c_sev = (c_vuln.severity.value if hasattr(c_vuln.severity, "value") else str(c_vuln.severity)).upper()
            c_status = (c_vuln.status.value if hasattr(c_vuln.status, "value") else str(c_vuln.status))
            has_ev = c_vuln.id in evidence_vuln_ids

            if fp in baseline_map:
                b_vuln = baseline_map[fp]
                b_sev = (b_vuln.severity.value if hasattr(b_vuln.severity, "value") else str(b_vuln.severity)).upper()
                b_status = (b_vuln.status.value if hasattr(b_vuln.status, "value") else str(b_vuln.status))

                if b_sev == c_sev:
                    persistent_items.append(
                        VulnerabilityComparisonItem(
                            fingerprint=fp,
                            title=c_vuln.title,
                            endpoint=c_vuln.endpoint,
                            cwe_id=c_vuln.cwe_id,
                            comparison_status="PERSISTENT",
                            baseline_severity=b_sev,
                            comparison_severity=c_sev,
                            baseline_status=b_status,
                            comparison_status_val=c_status,
                            cvss_score=c_vuln.cvss_score,
                            confidence=c_vuln.confidence,
                            recommendation=c_vuln.recommendation,
                            has_evidence=has_ev,
                        )
                    )
                else:
                    b_rank = SEVERITY_ORDER.get(b_sev, 0)
                    c_rank = SEVERITY_ORDER.get(c_sev, 0)
                    if c_rank > b_rank:
                        severity_increased_count += 1
                    else:
                        severity_decreased_count += 1

                    severity_changed_items.append(
                        VulnerabilityComparisonItem(
                            fingerprint=fp,
                            title=c_vuln.title,
                            endpoint=c_vuln.endpoint,
                            cwe_id=c_vuln.cwe_id,
                            comparison_status="SEVERITY_CHANGED",
                            baseline_severity=b_sev,
                            comparison_severity=c_sev,
                            baseline_status=b_status,
                            comparison_status_val=c_status,
                            cvss_score=c_vuln.cvss_score,
                            confidence=c_vuln.confidence,
                            recommendation=c_vuln.recommendation,
                            has_evidence=has_ev,
                        )
                    )
            else:
                if fp in earlier_fps or fp in fixed_report_fps:
                    regressed_items.append(
                        VulnerabilityComparisonItem(
                            fingerprint=fp,
                            title=c_vuln.title,
                            endpoint=c_vuln.endpoint,
                            cwe_id=c_vuln.cwe_id,
                            comparison_status="REGRESSED",
                            baseline_severity=None,
                            comparison_severity=c_sev,
                            baseline_status=None,
                            comparison_status_val=c_status,
                            cvss_score=c_vuln.cvss_score,
                            confidence=c_vuln.confidence,
                            recommendation=c_vuln.recommendation,
                            has_evidence=has_ev,
                        )
                    )
                else:
                    new_items.append(
                        VulnerabilityComparisonItem(
                            fingerprint=fp,
                            title=c_vuln.title,
                            endpoint=c_vuln.endpoint,
                            cwe_id=c_vuln.cwe_id,
                            comparison_status="NEW",
                            baseline_severity=None,
                            comparison_severity=c_sev,
                            baseline_status=None,
                            comparison_status_val=c_status,
                            cvss_score=c_vuln.cvss_score,
                            confidence=c_vuln.confidence,
                            recommendation=c_vuln.recommendation,
                            has_evidence=has_ev,
                        )
                    )

        # Evaluate fixed items
        for fp, b_vuln in baseline_map.items():
            if fp not in comp_map:
                b_sev = (b_vuln.severity.value if hasattr(b_vuln.severity, "value") else str(b_vuln.severity)).upper()
                b_status = (b_vuln.status.value if hasattr(b_vuln.status, "value") else str(b_vuln.status))
                has_ev = b_vuln.id in evidence_vuln_ids
                fixed_items.append(
                    VulnerabilityComparisonItem(
                        fingerprint=fp,
                        title=b_vuln.title,
                        endpoint=b_vuln.endpoint,
                        cwe_id=b_vuln.cwe_id,
                        comparison_status="FIXED",
                        baseline_severity=b_sev,
                        comparison_severity=None,
                        baseline_status=b_status,
                        comparison_status_val=None,
                        cvss_score=b_vuln.cvss_score,
                        confidence=b_vuln.confidence,
                        recommendation=b_vuln.recommendation,
                        has_evidence=has_ev,
                    )
                )

        new_count = len(new_items)
        fixed_count = len(fixed_items)
        persistent_count = len(persistent_items)
        regressed_count = len(regressed_items)
        baseline_total = len(baseline_map)
        comparison_total = len(comp_map)
        net_change = comparison_total - baseline_total

        base_crit_high = baseline_breakdown.get("CRITICAL", 0) + baseline_breakdown.get("HIGH", 0)
        comp_crit_high = comp_breakdown.get("CRITICAL", 0) + comp_breakdown.get("HIGH", 0)

        # Determine overall posture
        if comp_crit_high > base_crit_high or (new_count + regressed_count > fixed_count and (new_count + regressed_count > 0)):
            posture_change = "DEGRADED"
            posture_explanation = (
                f"Security posture degraded: {new_count} new and {regressed_count} regressed vulnerabilities "
                f"detected, exceeding resolved findings ({fixed_count}). Critical/High exposure shifted from {base_crit_high} to {comp_crit_high}."
            )
        elif fixed_count > (new_count + regressed_count) and comp_crit_high <= base_crit_high:
            posture_change = "IMPROVED"
            posture_explanation = (
                f"Security posture improved: {fixed_count} vulnerabilities successfully resolved with only "
                f"{new_count} new findings. Critical/High exposure decreased or held steady at {comp_crit_high}."
            )
        elif new_count == 0 and regressed_count == 0 and fixed_count == 0 and severity_increased_count == 0 and severity_decreased_count == 0:
            posture_change = "UNCHANGED"
            posture_explanation = "Security posture is unchanged: no new, fixed, or modified findings between scans."
        else:
            if net_change < 0:
                posture_change = "IMPROVED"
                posture_explanation = f"Security posture improved: net reduction of {abs(net_change)} vulnerabilities."
            elif net_change > 0:
                posture_change = "DEGRADED"
                posture_explanation = f"Security posture degraded: net increase of {net_change} vulnerabilities."
            else:
                posture_change = "UNCHANGED"
                posture_explanation = "Total vulnerability counts remain balanced between scans."

        all_comparison_items = (
            new_items
            + regressed_items
            + severity_changed_items
            + fixed_items
            + persistent_items
        )

        # If save_record is requested, persist in scan_comparisons table
        if save_record:
            existing_comp_res = await self.db.execute(
                select(ScanComparison).where(
                    and_(
                        ScanComparison.base_scan_id == baseline_scan_id,
                        ScanComparison.target_scan_id == comparison_scan_id,
                    )
                )
            )
            existing_comp = existing_comp_res.scalars().first()

            new_json = [i.model_dump() for i in (new_items + regressed_items)]
            resolved_json = [i.model_dump() for i in fixed_items]
            unchanged_json = [i.model_dump() for i in (persistent_items + severity_changed_items)]

            if existing_comp:
                existing_comp.new_vulnerabilities = new_json
                existing_comp.resolved_vulnerabilities = resolved_json
                existing_comp.unchanged_vulnerabilities = unchanged_json
            else:
                new_comp_rec = ScanComparison(
                    base_scan_id=baseline_scan_id,
                    target_scan_id=comparison_scan_id,
                    new_vulnerabilities=new_json,
                    resolved_vulnerabilities=resolved_json,
                    unchanged_vulnerabilities=unchanged_json,
                )
                self.db.add(new_comp_rec)
            await self.db.commit()

        return ScanComparisonSummary(
            baseline_scan_id=baseline_scan_id,
            comparison_scan_id=comparison_scan_id,
            application_id=app.id if app else baseline_scan.application_id,
            application_name=app.name if app else "Unknown App",
            target_url=app.target_url if app else "",
            baseline_completed_at=baseline_scan.completed_at or baseline_scan.created_at,
            comparison_completed_at=comparison_scan.completed_at or comparison_scan.created_at,
            baseline_total=baseline_total,
            comparison_total=comparison_total,
            new_count=new_count,
            fixed_count=fixed_count,
            persistent_count=persistent_count,
            regressed_count=regressed_count,
            severity_increased_count=severity_increased_count,
            severity_decreased_count=severity_decreased_count,
            net_finding_change=net_change,
            posture_change=posture_change,
            posture_explanation=posture_explanation,
            baseline_severity_breakdown=baseline_breakdown,
            comparison_severity_breakdown=comp_breakdown,
            comparison_items=all_comparison_items,
        )

    async def get_filter_applications(self, org_id: uuid.UUID) -> List[ApplicationFilterOption]:
        """Get applications for this org that have scans, with scan counts."""
        stmt = (
            select(
                Application.id,
                Application.name,
                Application.target_url,
                func.count(Scan.id).label("total_scans"),
            )
            .join(Scan, Application.id == Scan.application_id)
            .where(Scan.organization_id == org_id)
            .group_by(Application.id, Application.name, Application.target_url)
            .order_by(Application.name.asc())
        )
        res = await self.db.execute(stmt)
        rows = res.all()
        return [
            ApplicationFilterOption(
                id=r[0],
                name=r[1],
                target_url=r[2],
                total_scans=r[3],
            )
            for r in rows
        ]

import uuid
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
from fastapi import HTTPException, status

from app.models.application import Application
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability, Evidence
from app.models.vulnerability_report import VulnerabilityReport, VulnerabilityStatusHistory, ReportStatus
from app.models.time_travel import (
    SecurityBaseline,
    RegressionRecord,
    BaselineStatus,
    RegressionStatus,
    MatchQuality,
)
from app.features.security_operations.scan_history.service import make_vuln_fingerprint
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
)
from app.features.security_operations.time_travel.schemas import (
    SecurityBaselineResponse,
    BaselineVerifyResponse,
    BaselineListResponse,
    RegressionRecordResponse,
    RegressionListResponse,
    ScanEvaluationResponse,
    SecurityTimelineEvent,
    SecurityTimelineResponse,
    TimeTravelOverviewResponse,
)

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def normalize_endpoint(ep: str) -> str:
    """Normalize endpoint path by stripping trailing slashes and converting to lowercase."""
    return (ep or "").strip().lower().rstrip("/")


def clean_severity(sev: Any) -> str:
    """Normalize severity to uppercase string."""
    if hasattr(sev, "value"):
        return str(sev.value).upper()
    return str(sev or "INFO").upper()


def calculate_match_quality(
    baseline_fp: str,
    baseline_ep: str,
    baseline_cwe: Optional[str],
    baseline_title: str,
    vuln_ep: str,
    vuln_cwe: Optional[str],
    vuln_title: str,
) -> Tuple[MatchQuality, float]:
    """
    Evaluate similarity between a baseline finding and a discovered vulnerability.
    Prioritizes trustworthy regression detection over aggressive matching.
    """
    vuln_fp = make_vuln_fingerprint(vuln_ep, vuln_cwe, vuln_title)
    norm_base_ep = normalize_endpoint(baseline_ep)
    norm_vuln_ep = normalize_endpoint(vuln_ep)

    # 1. Exact Fingerprint Match
    if vuln_fp == baseline_fp or (norm_base_ep == norm_vuln_ep and baseline_cwe and vuln_cwe and baseline_cwe.upper() == vuln_cwe.upper()):
        return MatchQuality.EXACT_FINGERPRINT, 1.0

    # 2. High Confidence Match (Same endpoint with significant title overlap)
    if norm_base_ep == norm_vuln_ep:
        base_words = set(baseline_title.lower().split())
        vuln_words = set(vuln_title.lower().split())
        overlap = base_words.intersection(vuln_words)
        if len(overlap) >= 2 or (len(overlap) == 1 and any(w in overlap for w in ["sql", "xss", "idor", "csrf", "ssrf", "injection", "rce"])):
            return MatchQuality.HIGH_CONFIDENCE, 0.85

    # 3. Ambiguous Title Match (Identical or very similar title on DIFFERENT endpoint)
    if baseline_title.strip().lower() == vuln_title.strip().lower() and norm_base_ep != norm_vuln_ep:
        return MatchQuality.AMBIGUOUS_TITLE, 0.50

    # 4. Ambiguous Endpoint Match (Same endpoint, but completely different/unrelated title & null CWE)
    if norm_base_ep == norm_vuln_ep:
        return MatchQuality.AMBIGUOUS_ENDPOINT, 0.50

    # 5. No Match
    return MatchQuality.NO_MATCH, 0.0


class TimeTravelService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def verify_and_create_baseline(
        self,
        org_id: uuid.UUID,
        vulnerability_id: uuid.UUID,
        verification_scan_id: uuid.UUID,
        notes: Optional[str] = None,
        actor_id: Optional[uuid.UUID] = None,
    ) -> BaselineVerifyResponse:
        """
        Verify that a previously fixed vulnerability is truly absent in a subsequent successful verification scan.
        Creates or updates a verified SecurityBaseline if all criteria are satisfied.
        """
        # 1. Validate Vulnerability exists and belongs to authenticated organization
        vuln_q = select(Vulnerability).where(Vulnerability.id == vulnerability_id)
        vuln_res = await self.db.execute(vuln_q)
        vulnerability = vuln_res.scalars().first()
        if not vulnerability:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability finding not found")
        if vulnerability.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        # 2. Validate Verification Scan exists and belongs to authenticated organization
        scan_q = select(Scan).where(Scan.id == verification_scan_id)
        scan_res = await self.db.execute(scan_q)
        verification_scan = scan_res.scalars().first()
        if not verification_scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verification scan not found")
        if verification_scan.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        # 3. Validate Application consistency
        if vulnerability.application_id != verification_scan.application_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vulnerability and verification scan belong to different applications"
            )

        # 4. Validate Verification Scan completed successfully
        scan_status_str = verification_scan.status.value if hasattr(verification_scan.status, "value") else str(verification_scan.status)
        if scan_status_str.upper() != "COMPLETED":
            return BaselineVerifyResponse(
                baseline=None,
                verification_status="FAILED",
                reason=f"Verification scan status is '{scan_status_str}'. Scans must be fully COMPLETED to verify security baselines."
            )

        # 5. Check if the vulnerability is still detected in the verification scan
        target_fp = make_vuln_fingerprint(vulnerability.endpoint, vulnerability.cwe_id, vulnerability.title)
        scan_vulns_q = select(Vulnerability).where(Vulnerability.scan_id == verification_scan_id)
        scan_vulns_res = await self.db.execute(scan_vulns_q)
        scan_vulns = scan_vulns_res.scalars().all()

        for sv in scan_vulns:
            match_quality, conf = calculate_match_quality(
                target_fp,
                vulnerability.endpoint,
                vulnerability.cwe_id,
                vulnerability.title,
                sv.endpoint,
                sv.cwe_id,
                sv.title,
            )
            if match_quality in [MatchQuality.EXACT_FINGERPRINT, MatchQuality.HIGH_CONFIDENCE]:
                return BaselineVerifyResponse(
                    baseline=None,
                    verification_status="FAILED",
                    reason=f"Vulnerability remains detected in verification scan '{verification_scan.id}' at '{sv.endpoint}'."
                )

        # 6. Target finding is absent in verification scan -> Fix is verified!
        # Fetch Application for name
        app_q = select(Application).where(Application.id == vulnerability.application_id)
        app_res = await self.db.execute(app_q)
        application = app_res.scalars().first()
        app_name = application.name if application else "Unknown Application"

        # Evidence references
        ev_refs = {
            "original_vulnerability_id": str(vulnerability.id),
            "original_scan_id": str(vulnerability.scan_id) if vulnerability.scan_id else None,
            "verification_scan_id": str(verification_scan.id),
            "verification_scan_completed_at": verification_scan.completed_at.isoformat() if verification_scan.completed_at else None,
            "target_endpoint": vulnerability.endpoint,
            "target_fingerprint": target_fp,
        }

        # Check if baseline already exists for this (application_id, target_fp)
        base_q = select(SecurityBaseline).where(
            SecurityBaseline.application_id == vulnerability.application_id,
            SecurityBaseline.vulnerability_fingerprint == target_fp,
        )
        base_res = await self.db.execute(base_q)
        baseline = base_res.scalars().first()

        now = datetime.now(timezone.utc)
        if baseline:
            # Re-verification after remediation or update existing
            baseline.verification_scan_id = verification_scan.id
            baseline.verification_timestamp = now
            baseline.verification_status = "VERIFIED"
            baseline.status = BaselineStatus.VERIFIED.value
            baseline.verification_reason = f"Re-verified: Finding absent in verification scan '{verification_scan.id}'"
            baseline.evidence_references = ev_refs
            baseline.is_retired = False
            baseline.retired_at = None
            if notes:
                baseline.notes = notes
        else:
            baseline = SecurityBaseline(
                organization_id=org_id,
                application_id=vulnerability.application_id,
                source_scan_id=vulnerability.scan_id,
                verification_scan_id=verification_scan.id,
                original_vulnerability_id=vulnerability.id,
                vulnerability_fingerprint=target_fp,
                title=vulnerability.title,
                category=vulnerability.cwe_id or "General Security",
                cwe_id=vulnerability.cwe_id,
                endpoint=vulnerability.endpoint,
                http_method="GET",
                severity=clean_severity(vulnerability.severity),
                status=BaselineStatus.VERIFIED.value,
                verification_timestamp=now,
                verification_status="VERIFIED",
                verification_reason="Fix verified: finding absent in verification scan",
                evidence_references=ev_refs,
                notes=notes,
                is_retired=False,
            )
            self.db.add(baseline)

        await self.db.commit()
        await self.db.refresh(baseline)

        # Audit logging via Feature 25
        try:
            audit_ev = AuditEventCreate(
                category=AuditCategory.EXECUTION,
                event_type=AuditEventType.SCAN_COMPLETED,
                action=f"Security Baseline Verified: {baseline.title}",
                severity=AuditSeverity.LOW,
                status=AuditStatus.SUCCESS,
                user_id=actor_id,
                application_id=baseline.application_id,
                scan_id=verification_scan.id,
                details={
                    "baseline_id": str(baseline.id),
                    "fingerprint": baseline.vulnerability_fingerprint,
                    "endpoint": baseline.endpoint,
                    "severity": baseline.severity,
                    "verification_scan_id": str(verification_scan.id),
                },
            )
            await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
        except Exception:
            pass  # Non-blocking audit log integration

        baseline_resp = self._serialize_baseline(baseline, app_name)
        return BaselineVerifyResponse(
            baseline=baseline_resp,
            verification_status="VERIFIED",
            reason=f"Security baseline verified: issue '{baseline.title}' confirmed resolved in scan '{verification_scan.id}'."
        )

    async def retire_baseline(
        self,
        org_id: uuid.UUID,
        baseline_id: uuid.UUID,
        reason: Optional[str] = None,
        actor_id: Optional[uuid.UUID] = None,
    ) -> SecurityBaselineResponse:
        """
        Retire a security baseline without destroying historical records.
        """
        base_q = select(SecurityBaseline).where(SecurityBaseline.id == baseline_id)
        base_res = await self.db.execute(base_q)
        baseline = base_res.scalars().first()
        if not baseline:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security baseline not found")
        if baseline.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        now = datetime.now(timezone.utc)
        baseline.is_retired = True
        baseline.status = BaselineStatus.RETIRED.value
        baseline.retired_at = now
        baseline.retired_reason = reason or "Manually retired by security operator"

        await self.db.commit()
        await self.db.refresh(baseline)

        # Audit logging
        try:
            audit_ev = AuditEventCreate(
                category=AuditCategory.CONFIGURATION,
                event_type=AuditEventType.SAFETY_POLICY_UPDATE,
                action=f"Security Baseline Retired: {baseline.title}",
                severity=AuditSeverity.MEDIUM,
                status=AuditStatus.SUCCESS,
                user_id=actor_id,
                application_id=baseline.application_id,
                details={
                    "baseline_id": str(baseline.id),
                    "reason": baseline.retired_reason,
                },
            )
            await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
        except Exception:
            pass

        app_q = select(Application.name).where(Application.id == baseline.application_id)
        app_res = await self.db.execute(app_q)
        app_name = app_res.scalars().first() or "Application"
        return self._serialize_baseline(baseline, app_name)

    async def get_baseline(self, org_id: uuid.UUID, baseline_id: uuid.UUID) -> SecurityBaselineResponse:
        """Get baseline details by ID with tenant isolation."""
        base_q = select(SecurityBaseline).where(SecurityBaseline.id == baseline_id)
        base_res = await self.db.execute(base_q)
        baseline = base_res.scalars().first()
        if not baseline:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security baseline not found")
        if baseline.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        app_q = select(Application.name).where(Application.id == baseline.application_id)
        app_res = await self.db.execute(app_q)
        app_name = app_res.scalars().first() or "Application"
        return self._serialize_baseline(baseline, app_name)

    async def list_baselines(
        self,
        org_id: uuid.UUID,
        application_id: Optional[uuid.UUID] = None,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        is_retired: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> BaselineListResponse:
        """List security baselines with multi-criteria filtering and pagination."""
        conditions = [SecurityBaseline.organization_id == org_id]
        if application_id:
            conditions.append(SecurityBaseline.application_id == application_id)
        if status_filter:
            conditions.append(SecurityBaseline.status == status_filter)
        if severity_filter:
            conditions.append(SecurityBaseline.severity == severity_filter)
        if is_retired is not None:
            conditions.append(SecurityBaseline.is_retired == is_retired)
        if search:
            search_pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    SecurityBaseline.title.ilike(search_pattern),
                    SecurityBaseline.endpoint.ilike(search_pattern),
                    SecurityBaseline.cwe_id.ilike(search_pattern),
                )
            )

        count_q = select(func.count(SecurityBaseline.id)).where(and_(*conditions))
        count_res = await self.db.execute(count_q)
        total = count_res.scalar_one()

        offset = (page - 1) * limit
        data_q = (
            select(SecurityBaseline)
            .where(and_(*conditions))
            .order_by(SecurityBaseline.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        data_res = await self.db.execute(data_q)
        baselines = data_res.scalars().all()

        # Batch load application names
        app_ids = list({b.application_id for b in baselines})
        app_map: Dict[uuid.UUID, str] = {}
        if app_ids:
            apps_q = select(Application.id, Application.name).where(Application.id.in_(app_ids))
            apps_res = await self.db.execute(apps_q)
            app_map = {row[0]: row[1] for row in apps_res.all()}

        items = [self._serialize_baseline(b, app_map.get(b.application_id, "Application")) for b in baselines]
        return BaselineListResponse(items=items, total=total, page=page, limit=limit)

    async def evaluate_scan(
        self,
        org_id: uuid.UUID,
        scan_id: uuid.UUID,
        actor_id: Optional[uuid.UUID] = None,
    ) -> ScanEvaluationResponse:
        """
        Evaluate a completed scan against all active security baselines for that application.
        Detects regressions, severity escalations, and inconclusive matches with full idempotency.
        """
        # 1. Validate Scan
        scan_q = select(Scan).where(Scan.id == scan_id)
        scan_res = await self.db.execute(scan_q)
        scan = scan_res.scalars().first()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        if scan.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        scan_status_str = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        if scan_status_str.upper() != "COMPLETED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan status is '{scan_status_str}'. Only COMPLETED scans can be evaluated for regressions."
            )

        # Fetch Application
        app_q = select(Application).where(Application.id == scan.application_id)
        app_res = await self.db.execute(app_q)
        application = app_res.scalars().first()
        app_name = application.name if application else "Application"

        # 2. Fetch Active Baselines for this application
        base_q = select(SecurityBaseline).where(
            SecurityBaseline.application_id == scan.application_id,
            SecurityBaseline.is_retired == False,
        )
        base_res = await self.db.execute(base_q)
        baselines = base_res.scalars().all()

        if not baselines:
            return ScanEvaluationResponse(
                scan_id=scan.id,
                application_id=scan.application_id,
                application_name=app_name,
                baselines_evaluated=0,
                regressions_detected=0,
                still_protected=0,
                inconclusive=0,
                results=[],
            )

        # 3. Fetch Findings for this Scan
        vulns_q = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        vulns_res = await self.db.execute(vulns_q)
        scan_findings = vulns_res.scalars().all()

        # 4. Check existing evaluation records for idempotency
        existing_records_q = select(RegressionRecord).where(
            RegressionRecord.scan_id == scan_id,
            RegressionRecord.baseline_id.in_([b.id for b in baselines]),
        )
        existing_records_res = await self.db.execute(existing_records_q)
        existing_map: Dict[uuid.UUID, RegressionRecord] = {r.baseline_id: r for r in existing_records_res.scalars().all()}

        evaluation_results: List[RegressionRecordResponse] = []
        now = datetime.now(timezone.utc)
        scan_time = scan.completed_at or now

        regressions_count = 0
        still_protected_count = 0
        inconclusive_count = 0

        for baseline in baselines:
            # If already evaluated for this exact scan and baseline, reuse existing
            if baseline.id in existing_map:
                record = existing_map[baseline.id]
                if record.status == RegressionStatus.REGRESSION_DETECTED.value:
                    regressions_count += 1
                elif record.status == RegressionStatus.INCONCLUSIVE.value:
                    inconclusive_count += 1
                else:
                    still_protected_count += 1
                evaluation_results.append(self._serialize_regression(record, app_name, baseline.title, baseline.endpoint, scan.notes))
                continue

            # Evaluate baseline against all scan findings
            best_match: Optional[Vulnerability] = None
            best_quality = MatchQuality.NO_MATCH
            best_conf = 0.0

            for finding in scan_findings:
                quality, conf = calculate_match_quality(
                    baseline.vulnerability_fingerprint,
                    baseline.endpoint,
                    baseline.cwe_id,
                    baseline.title,
                    finding.endpoint,
                    finding.cwe_id,
                    finding.title,
                )
                if conf > best_conf:
                    best_conf = conf
                    best_quality = quality
                    best_match = finding

            # Determine classification
            if best_quality in [MatchQuality.EXACT_FINGERPRINT, MatchQuality.HIGH_CONFIDENCE]:
                # Regression confirmed!
                eval_status = RegressionStatus.REGRESSION_DETECTED.value
                regressions_count += 1
                baseline.status = BaselineStatus.REGRESSION_DETECTED.value

                reappeared_vuln = best_match
                new_sev = clean_severity(reappeared_vuln.severity)
                orig_sev = baseline.severity

                orig_rank = SEVERITY_ORDER.get(orig_sev, 0)
                new_rank = SEVERITY_ORDER.get(new_sev, 0)

                if new_rank > orig_rank:
                    sev_change = "INCREASED"
                elif new_rank < orig_rank:
                    sev_change = "DECREASED"
                else:
                    sev_change = "UNCHANGED"

                explanation = (
                    f"Security Regression Detected: Issue '{baseline.title}' (previously verified fixed) "
                    f"reappeared at endpoint '{reappeared_vuln.endpoint}' with severity {new_sev}."
                )
                ev_refs = {
                    "baseline_id": str(baseline.id),
                    "baseline_endpoint": baseline.endpoint,
                    "reappeared_vulnerability_id": str(reappeared_vuln.id),
                    "reappeared_endpoint": reappeared_vuln.endpoint,
                    "reappeared_severity": new_sev,
                    "cvss_score": reappeared_vuln.cvss_score,
                }

                record = RegressionRecord(
                    organization_id=org_id,
                    application_id=scan.application_id,
                    baseline_id=baseline.id,
                    scan_id=scan.id,
                    reappeared_vulnerability_id=reappeared_vuln.id,
                    status=eval_status,
                    match_quality=best_quality.value,
                    confidence_score=best_conf,
                    original_severity=orig_sev,
                    new_severity=new_sev,
                    severity_change=sev_change,
                    first_observed_at=scan_time,
                    evidence_references=ev_refs,
                    explanation=explanation,
                )
                self.db.add(record)

                # Audit log regression detection
                try:
                    audit_ev = AuditEventCreate(
                        category=AuditCategory.EXECUTION,
                        event_type=AuditEventType.VULNERABILITY_DISCOVERED,
                        action=f"Regression Detected: {baseline.title}",
                        severity=AuditSeverity.HIGH if new_rank >= 3 else AuditSeverity.MEDIUM,
                        status=AuditStatus.FAILURE,
                        user_id=actor_id,
                        application_id=scan.application_id,
                        scan_id=scan.id,
                        details={
                            "baseline_id": str(baseline.id),
                            "reappeared_vuln_id": str(reappeared_vuln.id),
                            "severity_change": sev_change,
                            "original_severity": orig_sev,
                            "new_severity": new_sev,
                        },
                    )
                    await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
                except Exception:
                    pass

            elif best_quality in [MatchQuality.AMBIGUOUS_ENDPOINT, MatchQuality.AMBIGUOUS_TITLE]:
                # Ambiguous / Inconclusive
                eval_status = RegressionStatus.INCONCLUSIVE.value
                inconclusive_count += 1
                matched_vuln = best_match
                new_sev = clean_severity(matched_vuln.severity)

                explanation = (
                    f"Inconclusive Finding: Potentially related finding '{matched_vuln.title}' discovered at '{matched_vuln.endpoint}'. "
                    f"Match confidence is {best_conf * 100:.0f}%; manual security verification is recommended to confirm regression."
                )
                ev_refs = {
                    "baseline_id": str(baseline.id),
                    "baseline_endpoint": baseline.endpoint,
                    "candidate_vulnerability_id": str(matched_vuln.id),
                    "candidate_endpoint": matched_vuln.endpoint,
                    "candidate_severity": new_sev,
                }

                record = RegressionRecord(
                    organization_id=org_id,
                    application_id=scan.application_id,
                    baseline_id=baseline.id,
                    scan_id=scan.id,
                    reappeared_vulnerability_id=matched_vuln.id,
                    status=eval_status,
                    match_quality=best_quality.value,
                    confidence_score=best_conf,
                    original_severity=baseline.severity,
                    new_severity=new_sev,
                    severity_change="NONE",
                    first_observed_at=scan_time,
                    evidence_references=ev_refs,
                    explanation=explanation,
                )
                self.db.add(record)

            else:
                # Still Protected
                eval_status = RegressionStatus.STILL_PROTECTED.value
                still_protected_count += 1

                explanation = f"Security Invariant Maintained: Verified condition '{baseline.title}' on '{baseline.endpoint}' remains protected."
                ev_refs = {
                    "baseline_id": str(baseline.id),
                    "baseline_endpoint": baseline.endpoint,
                    "evaluated_scan_id": str(scan.id),
                }

                record = RegressionRecord(
                    organization_id=org_id,
                    application_id=scan.application_id,
                    baseline_id=baseline.id,
                    scan_id=scan.id,
                    reappeared_vulnerability_id=None,
                    status=eval_status,
                    match_quality=MatchQuality.NO_MATCH.value,
                    confidence_score=0.0,
                    original_severity=baseline.severity,
                    new_severity=None,
                    severity_change="NONE",
                    first_observed_at=scan_time,
                    evidence_references=ev_refs,
                    explanation=explanation,
                )
                self.db.add(record)

            await self.db.commit()
            await self.db.refresh(record)
            evaluation_results.append(self._serialize_regression(record, app_name, baseline.title, baseline.endpoint, scan.notes))

        return ScanEvaluationResponse(
            scan_id=scan.id,
            application_id=scan.application_id,
            application_name=app_name,
            baselines_evaluated=len(baselines),
            regressions_detected=regressions_count,
            still_protected=still_protected_count,
            inconclusive=inconclusive_count,
            results=evaluation_results,
        )

    async def list_regressions(
        self,
        org_id: uuid.UUID,
        application_id: Optional[uuid.UUID] = None,
        status_filter: Optional[str] = None,
        baseline_id: Optional[uuid.UUID] = None,
        page: int = 1,
        limit: int = 20,
    ) -> RegressionListResponse:
        """List detected and inconclusive regressions with pagination and filtering."""
        conditions = [RegressionRecord.organization_id == org_id]
        if application_id:
            conditions.append(RegressionRecord.application_id == application_id)
        if status_filter:
            conditions.append(RegressionRecord.status == status_filter)
        if baseline_id:
            conditions.append(RegressionRecord.baseline_id == baseline_id)

        count_q = select(func.count(RegressionRecord.id)).where(and_(*conditions))
        count_res = await self.db.execute(count_q)
        total = count_res.scalar_one()

        offset = (page - 1) * limit
        data_q = (
            select(RegressionRecord)
            .where(and_(*conditions))
            .order_by(RegressionRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        data_res = await self.db.execute(data_q)
        records = data_res.scalars().all()

        # Batch resolve names
        base_ids = list({r.baseline_id for r in records})
        app_ids = list({r.application_id for r in records})
        scan_ids = list({r.scan_id for r in records})

        base_map: Dict[uuid.UUID, Tuple[str, str]] = {}
        if base_ids:
            bq = select(SecurityBaseline.id, SecurityBaseline.title, SecurityBaseline.endpoint).where(SecurityBaseline.id.in_(base_ids))
            bres = await self.db.execute(bq)
            base_map = {row[0]: (row[1], row[2]) for row in bres.all()}

        app_map: Dict[uuid.UUID, str] = {}
        if app_ids:
            aq = select(Application.id, Application.name).where(Application.id.in_(app_ids))
            ares = await self.db.execute(aq)
            app_map = {row[0]: row[1] for row in ares.all()}

        scan_map: Dict[uuid.UUID, str] = {}
        if scan_ids:
            sq = select(Scan.id, Scan.notes).where(Scan.id.in_(scan_ids))
            sres = await self.db.execute(sq)
            scan_map = {row[0]: (row[1] or "") for row in sres.all()}

        items = []
        for r in records:
            b_info = base_map.get(r.baseline_id, ("Baseline", ""))
            items.append(
                self._serialize_regression(
                    r,
                    app_map.get(r.application_id, "Application"),
                    b_info[0],
                    b_info[1],
                    scan_map.get(r.scan_id, ""),
                )
            )

        return RegressionListResponse(items=items, total=total, page=page, limit=limit)

    async def get_regression_details(self, org_id: uuid.UUID, regression_id: uuid.UUID) -> RegressionRecordResponse:
        """Get regression record details by ID."""
        rq = select(RegressionRecord).where(RegressionRecord.id == regression_id)
        rres = await self.db.execute(rq)
        record = rres.scalars().first()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regression record not found")
        if record.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        # Resolve names
        app_q = select(Application.name).where(Application.id == record.application_id)
        app_name = (await self.db.execute(app_q)).scalars().first() or "Application"

        base_q = select(SecurityBaseline.title, SecurityBaseline.endpoint).where(SecurityBaseline.id == record.baseline_id)
        base_res = (await self.db.execute(base_q)).first()
        base_title = base_res[0] if base_res else "Baseline"
        base_endpoint = base_res[1] if base_res else ""

        scan_q = select(Scan.notes).where(Scan.id == record.scan_id)
        scan_notes = (await self.db.execute(scan_q)).scalars().first() or ""

        return self._serialize_regression(record, app_name, base_title, base_endpoint, scan_notes)

    async def get_application_timeline(self, org_id: uuid.UUID, application_id: uuid.UUID) -> SecurityTimelineResponse:
        """
        Aggregate chronological historical security timeline for an application:
        - Vulnerability discovery
        - Report status changes & fix declarations
        - Verification scans
        - Baseline creation & verifications
        - Regression detections
        - Baseline retirements & re-verifications
        """
        # 1. Validate application
        app_q = select(Application).where(Application.id == application_id)
        app_res = await self.db.execute(app_q)
        application = app_res.scalars().first()
        if not application:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
        if application.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited")

        events: List[SecurityTimelineEvent] = []

        # A) Discoveries (Vulnerabilities)
        vulns_q = select(Vulnerability).where(Vulnerability.application_id == application_id)
        vulns_res = await self.db.execute(vulns_q)
        for v in vulns_res.scalars().all():
            events.append(
                SecurityTimelineEvent(
                    id=f"discovery-{v.id}",
                    event_type="DISCOVERY",
                    timestamp=v.created_at,
                    title=f"Vulnerability Discovered: {v.title}",
                    description=f"Initial discovery at endpoint '{v.endpoint}' with severity {clean_severity(v.severity)}.",
                    severity=clean_severity(v.severity),
                    status=clean_severity(v.status),
                    metadata={"vulnerability_id": str(v.id), "endpoint": v.endpoint, "cwe_id": v.cwe_id},
                )
            )

        # B) Report Status Changes & Fix Declarations
        reports_q = select(VulnerabilityReport).where(VulnerabilityReport.application_id == application_id)
        reports_res = await self.db.execute(reports_q)
        rep_ids = [r.id for r in reports_res.scalars().all()]
        if rep_ids:
            hist_q = select(VulnerabilityStatusHistory).where(VulnerabilityStatusHistory.report_id.in_(rep_ids))
            hist_res = await self.db.execute(hist_q)
            for h in hist_res.scalars().all():
                ev_type = "FIX_DECLARED" if h.to_status == "FIXED" else "REPORT_STATUS_CHANGE"
                events.append(
                    SecurityTimelineEvent(
                        id=f"status-{h.id}",
                        event_type=ev_type,
                        timestamp=h.created_at,
                        title=f"Report Status: {h.to_status}" if ev_type != "FIX_DECLARED" else "Vulnerability Fix Declared",
                        description=f"Status transitioned from '{h.from_status}' to '{h.to_status}'. Reason: {h.reason or 'Status update'}",
                        status=h.to_status,
                        metadata={"report_id": str(h.report_id), "from_status": h.from_status, "to_status": h.to_status},
                    )
                )

        # C) Completed Scans
        scans_q = select(Scan).where(Scan.application_id == application_id, Scan.completed_at != None)
        scans_res = await self.db.execute(scans_q)
        for s in scans_res.scalars().all():
            events.append(
                SecurityTimelineEvent(
                    id=f"scan-{s.id}",
                    event_type="VERIFICATION_SCAN",
                    timestamp=s.completed_at or s.created_at,
                    title=f"Scan Completed: {s.notes or 'Automated Security Assessment'}",
                    description=f"Execution completed with {s.findings_count} findings recorded.",
                    status="COMPLETED",
                    metadata={"scan_id": str(s.id), "findings_count": s.findings_count},
                )
            )

        # D) Baselines Created & Verified
        baselines_q = select(SecurityBaseline).where(SecurityBaseline.application_id == application_id)
        baselines_res = await self.db.execute(baselines_q)
        for b in baselines_res.scalars().all():
            if b.verification_timestamp:
                events.append(
                    SecurityTimelineEvent(
                        id=f"baseline-verified-{b.id}",
                        event_type="BASELINE_VERIFIED",
                        timestamp=b.verification_timestamp,
                        title=f"Security Baseline Verified: {b.title}",
                        description=f"Condition verified on endpoint '{b.endpoint}'. Fix confirmed resolved.",
                        severity=b.severity,
                        status=b.status,
                        metadata={"baseline_id": str(b.id), "fingerprint": b.vulnerability_fingerprint},
                    )
                )
            if b.is_retired and b.retired_at:
                events.append(
                    SecurityTimelineEvent(
                        id=f"baseline-retired-{b.id}",
                        event_type="BASELINE_RETIRED",
                        timestamp=b.retired_at,
                        title=f"Security Baseline Retired: {b.title}",
                        description=f"Baseline retired: {b.retired_reason or 'No reason provided'}",
                        status="RETIRED",
                        metadata={"baseline_id": str(b.id)},
                    )
                )

        # E) Regressions Detected
        regs_q = select(RegressionRecord).where(
            RegressionRecord.application_id == application_id,
            RegressionRecord.status == RegressionStatus.REGRESSION_DETECTED.value,
        )
        regs_res = await self.db.execute(regs_q)
        for r in regs_res.scalars().all():
            events.append(
                SecurityTimelineEvent(
                    id=f"regression-{r.id}",
                    event_type="REGRESSION_DETECTED",
                    timestamp=r.first_observed_at,
                    title=f"Security Regression Detected",
                    description=r.explanation,
                    severity=r.new_severity or r.original_severity,
                    status=r.status,
                    metadata={
                        "regression_id": str(r.id),
                        "baseline_id": str(r.baseline_id),
                        "scan_id": str(r.scan_id),
                        "severity_change": r.severity_change,
                    },
                )
            )

        # Sort chronologically, descending (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return SecurityTimelineResponse(
            application_id=application_id,
            application_name=application.name,
            events=events,
            total_events=len(events),
        )

    async def get_overview(self, org_id: uuid.UUID) -> TimeTravelOverviewResponse:
        """Provide aggregate overview metrics for dashboard headers and summaries."""
        # Total baselines
        tot_q = select(func.count(SecurityBaseline.id)).where(SecurityBaseline.organization_id == org_id)
        total_baselines = (await self.db.execute(tot_q)).scalar_one()

        # Verified baselines
        ver_q = select(func.count(SecurityBaseline.id)).where(
            SecurityBaseline.organization_id == org_id,
            SecurityBaseline.status == BaselineStatus.VERIFIED.value,
            SecurityBaseline.is_retired == False,
        )
        verified_baselines = (await self.db.execute(ver_q)).scalar_one()

        # Active baselines (not retired)
        act_q = select(func.count(SecurityBaseline.id)).where(
            SecurityBaseline.organization_id == org_id,
            SecurityBaseline.is_retired == False,
        )
        active_baselines = (await self.db.execute(act_q)).scalar_one()

        # Retired baselines
        ret_q = select(func.count(SecurityBaseline.id)).where(
            SecurityBaseline.organization_id == org_id,
            SecurityBaseline.is_retired == True,
        )
        retired_baselines = (await self.db.execute(ret_q)).scalar_one()

        # Regressions detected
        reg_q = select(func.count(RegressionRecord.id)).where(
            RegressionRecord.organization_id == org_id,
            RegressionRecord.status == RegressionStatus.REGRESSION_DETECTED.value,
        )
        regressions_detected = (await self.db.execute(reg_q)).scalar_one()

        # Inconclusive evaluations
        inc_q = select(func.count(RegressionRecord.id)).where(
            RegressionRecord.organization_id == org_id,
            RegressionRecord.status == RegressionStatus.INCONCLUSIVE.value,
        )
        inconclusive_evaluations = (await self.db.execute(inc_q)).scalar_one()

        # Affected applications
        aff_q = select(func.count(func.distinct(RegressionRecord.application_id))).where(
            RegressionRecord.organization_id == org_id,
            RegressionRecord.status == RegressionStatus.REGRESSION_DETECTED.value,
        )
        affected_applications = (await self.db.execute(aff_q)).scalar_one()

        # Recent 5 regressions
        rec_q = (
            select(RegressionRecord)
            .where(
                RegressionRecord.organization_id == org_id,
                RegressionRecord.status.in_([RegressionStatus.REGRESSION_DETECTED.value, RegressionStatus.INCONCLUSIVE.value]),
            )
            .order_by(RegressionRecord.created_at.desc())
            .limit(5)
        )
        rec_res = await self.db.execute(rec_q)
        recent_records = rec_res.scalars().all()

        recent_items = []
        for r in recent_records:
            app_name = (await self.db.execute(select(Application.name).where(Application.id == r.application_id))).scalars().first() or "App"
            b_info = (await self.db.execute(select(SecurityBaseline.title, SecurityBaseline.endpoint).where(SecurityBaseline.id == r.baseline_id))).first()
            recent_items.append(
                self._serialize_regression(
                    r,
                    app_name,
                    b_info[0] if b_info else "Baseline",
                    b_info[1] if b_info else "",
                    "",
                )
            )

        return TimeTravelOverviewResponse(
            total_baselines=total_baselines,
            verified_baselines=verified_baselines,
            active_baselines=active_baselines,
            retired_baselines=retired_baselines,
            regressions_detected=regressions_detected,
            inconclusive_evaluations=inconclusive_evaluations,
            affected_applications_count=affected_applications,
            recent_regressions=recent_items,
        )

    def _serialize_baseline(self, b: SecurityBaseline, app_name: str) -> SecurityBaselineResponse:
        return SecurityBaselineResponse(
            id=b.id,
            organization_id=b.organization_id,
            application_id=b.application_id,
            application_name=app_name,
            source_scan_id=b.source_scan_id,
            verification_scan_id=b.verification_scan_id,
            original_vulnerability_id=b.original_vulnerability_id,
            vulnerability_fingerprint=b.vulnerability_fingerprint,
            title=b.title,
            category=b.category,
            cwe_id=b.cwe_id,
            endpoint=b.endpoint,
            http_method=b.http_method,
            severity=b.severity,
            status=b.status,
            verification_timestamp=b.verification_timestamp,
            verification_status=b.verification_status,
            verification_reason=b.verification_reason,
            evidence_references=b.evidence_references or {},
            notes=b.notes,
            is_retired=b.is_retired,
            retired_at=b.retired_at,
            retired_reason=b.retired_reason,
            created_at=b.created_at,
            updated_at=b.updated_at,
        )

    def _serialize_regression(
        self,
        r: RegressionRecord,
        app_name: str,
        base_title: str,
        base_endpoint: str,
        scan_notes: str,
    ) -> RegressionRecordResponse:
        return RegressionRecordResponse(
            id=r.id,
            organization_id=r.organization_id,
            application_id=r.application_id,
            application_name=app_name,
            baseline_id=r.baseline_id,
            baseline_title=base_title,
            baseline_endpoint=base_endpoint,
            scan_id=r.scan_id,
            scan_notes=scan_notes,
            reappeared_vulnerability_id=r.reappeared_vulnerability_id,
            status=r.status,
            match_quality=r.match_quality,
            confidence_score=r.confidence_score,
            original_severity=r.original_severity,
            new_severity=r.new_severity,
            severity_change=r.severity_change,
            first_observed_at=r.first_observed_at,
            evidence_references=r.evidence_references or {},
            explanation=r.explanation,
            remediation_notes=r.remediation_notes,
            is_resolved=r.is_resolved,
            resolved_at=r.resolved_at,
            created_at=r.created_at,
        )


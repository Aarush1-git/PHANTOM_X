import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, asc, or_

from app.models.audit import AuditLog, ScanExecutionRecord
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
    AuditOverviewResponse,
    AuditIntegrityVerificationResponse,
    ScanExecutionRecordResponse,
)
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.integrity import verify_chain_integrity, scrub_secrets


class AuditLogService:
    """
    Service layer for querying audit event logs, calculating compliance metrics,
    verifying cryptographic integrity, and managing scan execution histories.
    """

    @classmethod
    async def list_events(
        cls,
        db: AsyncSession,
        org_id: Optional[uuid.UUID] = None,
        category: Optional[str] = None,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        application_id: Optional[uuid.UUID] = None,
        scan_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        sort_desc: bool = True
    ) -> List[AuditLog]:
        """Query audit log events with multi-field filtering and organization isolation."""
        query = select(AuditLog)

        if org_id:
            query = query.where(AuditLog.organization_id == org_id)
        if category:
            query = query.where(AuditLog.category == category.upper())
        if event_type:
            query = query.where(AuditLog.event_type == event_type.upper())
        if application_id:
            query = query.where(AuditLog.application_id == application_id)
        if scan_id:
            query = query.where(AuditLog.scan_id == scan_id)
        if status:
            query = query.where(AuditLog.status == status.upper())
        if severity:
            query = query.where(AuditLog.severity == severity.upper())
        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)

        if actor:
            actor_term = f"%{actor}%"
            query = query.where(
                or_(
                    AuditLog.actor_email.ilike(actor_term),
                    AuditLog.actor_role.ilike(actor_term)
                )
            )

        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    AuditLog.action.ilike(search_term),
                    AuditLog.event_type.ilike(search_term),
                    AuditLog.target_type.ilike(search_term),
                    AuditLog.target_id.ilike(search_term),
                    AuditLog.actor_email.ilike(search_term)
                )
            )

        if sort_desc:
            query = query.order_by(desc(AuditLog.sequence_number), desc(AuditLog.created_at), desc(AuditLog.id))
        else:
            query = query.order_by(asc(AuditLog.sequence_number), asc(AuditLog.created_at), asc(AuditLog.id))

        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def get_event(
        cls,
        db: AsyncSession,
        event_id: uuid.UUID,
        org_id: Optional[uuid.UUID] = None
    ) -> Optional[AuditLog]:
        """Fetch single audit event by ID with organization verification."""
        query = select(AuditLog).where(AuditLog.id == event_id)
        if org_id:
            query = query.where(AuditLog.organization_id == org_id)
        result = await db.execute(query)
        return result.scalars().first()

    @classmethod
    async def get_overview_metrics(
        cls,
        db: AsyncSession,
        org_id: Optional[uuid.UUID] = None
    ) -> AuditOverviewResponse:
        """Compute live compliance and audit metrics from actual backend records."""
        base_query = select(AuditLog)
        if org_id:
            base_query = base_query.where(AuditLog.organization_id == org_id)

        res = await db.execute(base_query)
        logs = res.scalars().all()

        total_events = len(logs)
        successful_events = sum(1 for l in logs if l.status == "SUCCESS")
        failed_events = sum(1 for l in logs if l.status == "FAILURE")
        blocked_events = sum(1 for l in logs if l.status == "BLOCKED")
        critical_events = sum(1 for l in logs if l.severity == "CRITICAL")

        breakdown: Dict[str, int] = {}
        for l in logs:
            breakdown[l.category] = breakdown.get(l.category, 0) + 1

        return AuditOverviewResponse(
            total_events=total_events,
            successful_events=successful_events,
            failed_events=failed_events,
            blocked_events=blocked_events,
            critical_events=critical_events,
            categories_breakdown=breakdown,
            generated_at=datetime.now(timezone.utc)
        )

    @classmethod
    async def verify_integrity(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        expected_final_hash: Optional[str] = None,
        expected_final_sequence: Optional[int] = None
    ) -> AuditIntegrityVerificationResponse:
        """Execute cryptographic SHA-256 chain verification for organization's log."""
        return await verify_chain_integrity(
            db=db,
            org_id=org_id,
            expected_final_hash=expected_final_hash,
            expected_final_sequence=expected_final_sequence
        )

    # =========================================================================
    # SCAN EXECUTION LIFECYCLE HISTORY
    # =========================================================================

    @classmethod
    async def record_scan_lifecycle(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        scan_id: uuid.UUID,
        application_id: uuid.UUID,
        status: str,
        note: Optional[str] = None,
        initiating_user_id: Optional[uuid.UUID] = None,
        initiating_user: Optional[str] = None,
        tests_executed: Optional[int] = None,
        tests_blocked: Optional[int] = None,
        verified_findings: Optional[int] = None,
        failure_reason: Optional[str] = None,
        commit: bool = True
    ) -> ScanExecutionRecord:
        """
        Record or transition scan lifecycle event in dedicated execution record
        and emit corresponding audit event into the immutable audit chain.
        """
        query = select(ScanExecutionRecord).where(ScanExecutionRecord.scan_id == scan_id)
        result = await db.execute(query)
        record = result.scalars().first()

        now = datetime.now(timezone.utc)
        norm_status = status.upper().strip()

        event_entry = {
            "status": norm_status,
            "timestamp": now.isoformat(),
            "note": note or f"Scan entered status {norm_status}",
        }

        if not record:
            record = ScanExecutionRecord(
                organization_id=org_id,
                scan_id=scan_id,
                application_id=application_id,
                initiating_user_id=initiating_user_id,
                initiating_user=initiating_user,
                start_time=now if norm_status in ["STARTED", "RUNNING"] else None,
                final_status=norm_status,
                tests_executed=tests_executed or 0,
                tests_blocked=tests_blocked or 0,
                verified_findings=verified_findings or 0,
                failure_reason=failure_reason,
                lifecycle_events=[event_entry]
            )
            db.add(record)
        else:
            record.final_status = norm_status
            events = list(record.lifecycle_events or [])
            events.append(event_entry)
            record.lifecycle_events = events

            if norm_status in ["STARTED", "RUNNING"] and not record.start_time:
                record.start_time = now
            elif norm_status in ["COMPLETED", "FAILED", "CANCELLED"]:
                record.end_time = now
                if record.start_time:
                    start_utc = record.start_time if record.start_time.tzinfo else record.start_time.replace(tzinfo=timezone.utc)
                    record.duration_seconds = max(0.0, (now - start_utc).total_seconds())

            if tests_executed is not None:
                record.tests_executed = tests_executed
            if tests_blocked is not None:
                record.tests_blocked = tests_blocked
            if verified_findings is not None:
                record.verified_findings = verified_findings
            if failure_reason is not None:
                record.failure_reason = failure_reason

        # Synchronously record in the immutable audit event log
        event_type_map = {
            "CREATED": AuditEventType.SCAN_CREATED.value,
            "STARTED": AuditEventType.SCAN_STARTED.value,
            "RUNNING": AuditEventType.SCAN_STARTED.value,
            "COMPLETED": AuditEventType.SCAN_COMPLETED.value,
            "FAILED": AuditEventType.SCAN_FAILED.value,
            "CANCELLED": AuditEventType.SCAN_CANCELLED.value,
        }
        mapped_event_type = event_type_map.get(norm_status, "SCAN_STATUS_UPDATE")

        await AuditEventRecorder.record_security_testing_event(
            db=db,
            org_id=org_id,
            event_type=mapped_event_type,
            action=f"Scan {scan_id} transition: {norm_status}",
            app_id=application_id,
            scan_id=scan_id,
            status=AuditStatus.FAILURE if norm_status == "FAILED" else AuditStatus.SUCCESS,
            severity=AuditSeverity.HIGH if norm_status == "FAILED" else AuditSeverity.INFO,
            source_module="SCAN_EXECUTION_LIFECYCLE",
            details={
                "scan_id": str(scan_id),
                "application_id": str(application_id),
                "final_status": norm_status,
                "tests_executed": record.tests_executed,
                "tests_blocked": record.tests_blocked,
                "verified_findings": record.verified_findings,
                "failure_reason": failure_reason,
                "note": note
            }
        )

        if commit:
            await db.commit()
            await db.refresh(record)

        return record

    @classmethod
    async def get_scan_execution_record(
        cls,
        db: AsyncSession,
        scan_id: uuid.UUID,
        org_id: Optional[uuid.UUID] = None
    ) -> Optional[ScanExecutionRecord]:
        """Fetch dedicated execution record and lifecycle history for a scan."""
        query = select(ScanExecutionRecord).where(ScanExecutionRecord.scan_id == scan_id)
        if org_id:
            query = query.where(ScanExecutionRecord.organization_id == org_id)
        result = await db.execute(query)
        return result.scalars().first()

    @classmethod
    async def list_execution_records(
        cls,
        db: AsyncSession,
        org_id: Optional[uuid.UUID] = None,
        application_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50
    ) -> List[ScanExecutionRecord]:
        """List scan execution history records with optional filters."""
        query = select(ScanExecutionRecord)
        if org_id:
            query = query.where(ScanExecutionRecord.organization_id == org_id)
        if application_id:
            query = query.where(ScanExecutionRecord.application_id == application_id)
        if status:
            query = query.where(ScanExecutionRecord.final_status == status.upper())

        query = query.order_by(desc(ScanExecutionRecord.created_at)).offset(skip).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def export_events(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Export sanitized audit events for compliance archives (secret scrubbed)."""
        events = await cls.list_events(db, org_id=org_id, limit=limit)
        exported = []
        for e in events:
            exported.append({
                "id": str(e.id),
                "sequence_number": e.sequence_number or 1,
                "timestamp": e.created_at.isoformat() if e.created_at else "",
                "category": e.category,
                "event_type": e.event_type,
                "action": e.action,
                "status": e.status,
                "severity": e.severity,
                "actor_email": e.actor_email,
                "actor_role": e.actor_role,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "application_id": str(e.application_id) if e.application_id else None,
                "scan_id": str(e.scan_id) if e.scan_id else None,
                "details": scrub_secrets(e.details),
                "event_hash": e.event_hash,
                "prev_event_hash": e.prev_event_hash
            })
        return exported


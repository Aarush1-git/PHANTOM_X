import uuid
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.models.audit import AuditLog
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
)
from app.features.security_operations.audit_logs.integrity import (
    GENESIS_HASH,
    scrub_secrets,
    compute_canonical_hash,
)


class AuditEventRecorder:
    """
    Central recorder for immutable, secret-scrubbed, tamper-evident audit events.
    Thread-safe and concurrency-safe across distributed asynchronous execution.
    """

    @classmethod
    def _get_org_lock(cls, org_id: str) -> asyncio.Lock:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        if not hasattr(loop, "_audit_org_locks"):
            loop._audit_org_locks = {}
        if org_id not in loop._audit_org_locks:
            loop._audit_org_locks[org_id] = asyncio.Lock()
        return loop._audit_org_locks[org_id]

    @classmethod
    async def record_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        event_in: AuditEventCreate,
        commit: bool = True
    ) -> AuditLog:
        """
        Record a structured audit event into the append-only log with
        secret scrubbing and tamper-evident cryptographic hash chain linkage.
        """
        org_key = str(org_id)
        lock = cls._get_org_lock(org_key)

        async with lock:
            # Multi-worker concurrency protection for PostgreSQL deployments
            bind = db.get_bind() if hasattr(db, "get_bind") else getattr(db, "bind", None)
            if bind and hasattr(bind, "dialect") and bind.dialect.name == "postgresql":
                from sqlalchemy import text
                try:
                    await db.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                        {"key": f"audit_chain_{org_key}"}
                    )
                except Exception as lock_err:
                    # Fail-closed: distributed audit lock acquisition failed.
                    # Never silently continue without the distributed lock.
                    await db.rollback()
                    raise RuntimeError(
                        f"PostgreSQL advisory lock acquisition failed for organization {org_key}: {lock_err}"
                    ) from lock_err

            # 1. Fetch latest event in organization's audit chain
            latest_query = (
                select(AuditLog)
                .where(AuditLog.organization_id == org_id)
                .order_by(desc(AuditLog.sequence_number), desc(AuditLog.created_at), desc(AuditLog.id))
                .limit(1)
            )
            latest_res = await db.execute(latest_query)
            latest_event = latest_res.scalars().first()

            prev_hash = latest_event.event_hash if latest_event and latest_event.event_hash else GENESIS_HASH
            next_seq = (latest_event.sequence_number + 1) if (latest_event and latest_event.sequence_number is not None) else 1

            # 2. Prepare event metadata and identifiers
            event_id = uuid.uuid4()
            now = datetime.now(timezone.utc)
            clean_details = scrub_secrets(event_in.details)

            # 3. Calculate canonical tamper-evident hash
            event_hash = compute_canonical_hash(
                event_id=str(event_id),
                org_id=str(org_id),
                timestamp_str=now.isoformat(),
                category=event_in.category.value,
                event_type=event_in.event_type,
                status=event_in.status.value,
                action=event_in.action,
                target_type=event_in.target_type,
                target_id=event_in.target_id,
                details=clean_details,
                prev_event_hash=prev_hash,
                sequence_number=next_seq
            )

            # 4. Construct AuditLog entity
            audit_entry = AuditLog(
                id=event_id,
                organization_id=org_id,
                sequence_number=next_seq,
                user_id=event_in.user_id,
                actor_email=event_in.actor_email,
                actor_role=event_in.actor_role,
                application_id=event_in.application_id,
                scan_id=event_in.scan_id,
                category=event_in.category.value,
                event_type=event_in.event_type,
                action=event_in.action,
                status=event_in.status.value,
                severity=event_in.severity.value,
                source_module=event_in.source_module,
                target_type=event_in.target_type,
                target_id=event_in.target_id,
                details=clean_details,
                ip_address=event_in.ip_address,
                correlation_id=event_in.correlation_id,
                event_hash=event_hash,
                prev_event_hash=prev_hash,
                created_at=now,
                updated_at=now
            )

            db.add(audit_entry)
            if commit:
                try:
                    await db.commit()
                    await db.refresh(audit_entry)
                except Exception:
                    await db.rollback()
                    raise

            return audit_entry

    # =========================================================================
    # CONVENIENCE DOMAIN LOGGING HELPERS
    # =========================================================================

    @classmethod
    async def record_authentication_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        event_type: str,
        action: str,
        user_id: Optional[uuid.UUID] = None,
        email: Optional[str] = None,
        status: AuditStatus = AuditStatus.SUCCESS,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.AUTHENTICATION,
                event_type=event_type,
                action=action,
                status=status,
                severity=AuditSeverity.HIGH if status == AuditStatus.FAILURE else AuditSeverity.INFO,
                source_module="AUTHENTICATION_SERVICE",
                target_type="User",
                target_id=str(user_id) if user_id else email,
                user_id=user_id,
                actor_email=email,
                details=details or {},
                ip_address=ip_address
            )
        )

    @classmethod
    async def record_application_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        app_id: uuid.UUID,
        event_type: str,
        action: str,
        user_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.APPLICATION_MANAGEMENT,
                event_type=event_type,
                action=action,
                status=AuditStatus.SUCCESS,
                severity=AuditSeverity.INFO,
                source_module="APPLICATION_REGISTRY",
                target_type="Application",
                target_id=str(app_id),
                application_id=app_id,
                user_id=user_id,
                actor_email=actor_email,
                details=details or {}
            )
        )

    @classmethod
    async def record_authorization_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        app_id: uuid.UUID,
        event_type: str,
        action: str,
        authorizer_email: Optional[str] = None,
        authorizer_role: Optional[str] = None,
        status: AuditStatus = AuditStatus.SUCCESS,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.AUTHORIZATION,
                event_type=event_type,
                action=action,
                status=status,
                severity=AuditSeverity.HIGH if event_type in ["AUTHZ_REVOKED", "AUTHZ_SUSPENDED"] else AuditSeverity.MEDIUM,
                source_module="SCOPE_GOVERNANCE",
                target_type="ApplicationScopePolicy",
                target_id=str(app_id),
                application_id=app_id,
                actor_email=authorizer_email,
                actor_role=authorizer_role,
                details=details or {}
            )
        )

    @classmethod
    async def record_security_testing_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        event_type: str,
        action: str,
        app_id: Optional[uuid.UUID] = None,
        scan_id: Optional[uuid.UUID] = None,
        status: AuditStatus = AuditStatus.SUCCESS,
        severity: AuditSeverity = AuditSeverity.INFO,
        source_module: str = "SECURITY_TESTING_ENGINE",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.SECURITY_TESTING,
                event_type=event_type,
                action=action,
                status=status,
                severity=severity,
                source_module=source_module,
                target_type="Scan" if scan_id else "SecurityTest",
                target_id=str(scan_id) if scan_id else str(app_id),
                application_id=app_id,
                scan_id=scan_id,
                details=details or {},
                ip_address=ip_address
            )
        )

    @classmethod
    async def record_vulnerability_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        vuln_id: uuid.UUID,
        event_type: str,
        title: str,
        app_id: Optional[uuid.UUID] = None,
        scan_id: Optional[uuid.UUID] = None,
        severity: AuditSeverity = AuditSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.VULNERABILITY,
                event_type=event_type,
                action=f"Vulnerability event: {title}",
                status=AuditStatus.SUCCESS,
                severity=severity,
                source_module="VULNERABILITY_MANAGEMENT",
                target_type="Vulnerability",
                target_id=str(vuln_id),
                application_id=app_id,
                scan_id=scan_id,
                details=details or {}
            )
        )

    @classmethod
    async def record_platform_event(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        event_type: str,
        action: str,
        user_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        return await cls.record_event(
            db=db,
            org_id=org_id,
            event_in=AuditEventCreate(
                category=AuditCategory.PLATFORM,
                event_type=event_type,
                action=action,
                status=AuditStatus.SUCCESS,
                severity=AuditSeverity.INFO,
                source_module="PLATFORM_CORE",
                target_type="Configuration",
                target_id=None,
                user_id=user_id,
                actor_email=actor_email,
                details=details or {}
            )
        )

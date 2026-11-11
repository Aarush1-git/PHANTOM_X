import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy import String, Integer, Boolean, ForeignKey, JSON, DateTime, Float, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID


class AuditLog(ModelBase):
    """
    Structured, tamper-evident audit event record.
    Append-only log for all authentication, authorization, scanning,
    vulnerability discovery, and governance actions.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        UniqueConstraint("organization_id", "sequence_number", name="uq_audit_logs_org_sequence"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    actor_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Scoping references
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="SET NULL"), index=True, nullable=True
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), index=True, nullable=True
    )

    # Sequence tracking for strict deterministic ordering and gap detection
    sequence_number: Mapped[int] = mapped_column(Integer, default=1, index=True, nullable=False)

    # Event Categorization & Type
    # Category: AUTHENTICATION, APPLICATION_MANAGEMENT, AUTHORIZATION, SECURITY_TESTING, VULNERABILITY, PLATFORM
    category: Mapped[str] = mapped_column(String(50), default="PLATFORM", index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), default="GENERAL_AUDIT", index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="SUCCESS", index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="INFO", index=True, nullable=False)

    # Source & Resource Targeting
    source_module: Mapped[str] = mapped_column(String(100), default="SECURITY_OPERATIONS", nullable=False)
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Structured metadata (secrets stripped)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Tamper-evident hash chain linkage
    event_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    prev_event_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class ScopePermission(ModelBase):
    __tablename__ = "scope_permissions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host_pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_methods: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    is_destructive_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ScanExecutionRecord(ModelBase):
    """
    Dedicated lifecycle history record for a security scan.
    Tracks execution transitions from QUEUED to COMPLETED/FAILED,
    timings, executed/blocked test counts, and verified findings.
    """
    __tablename__ = "scan_execution_records"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False
    )

    initiating_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    initiating_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    final_status: Mapped[str] = mapped_column(String(50), default="QUEUED", index=True, nullable=False)
    tests_executed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_blocked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    lifecycle_events: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

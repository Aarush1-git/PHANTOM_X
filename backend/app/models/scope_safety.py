import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, ForeignKey, JSON, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID


class ApplicationScopePolicy(ModelBase):
    """
    Application testing scope and safety configuration policy.
    Enforces authorization, rate limits, permitted/excluded paths,
    and destructive test prevention.
    """
    __tablename__ = "application_scope_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )

    # Scope definition
    target_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    permitted_paths: Mapped[List[str]] = mapped_column(JSON, default=lambda: ["/*"], nullable=False)
    excluded_paths: Mapped[List[str]] = mapped_column(
        JSON,
        default=lambda: ["/admin/*", "/logout", "/auth/reset-password"],
        nullable=False
    )

    # Status: DRAFT, ACTIVE, SUSPENDED, EXPIRED
    scope_status: Mapped[str] = mapped_column(String(50), default="DRAFT", index=True, nullable=False)

    # Permission / Authorization management
    # authorization_status: PENDING, AUTHORIZED, REVOKED, EXPIRED
    authorization_status: Mapped[str] = mapped_column(String(50), default="PENDING", index=True, nullable=False)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorizer_role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    authorization_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Safety limits & controls
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    max_scan_duration_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    allowed_methods: Mapped[List[str]] = mapped_column(
        JSON,
        default=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        nullable=False
    )
    restricted_endpoint_patterns: Mapped[List[str]] = mapped_column(
        JSON,
        default=lambda: ["*/delete-account*", "*/purge*", "*/reset*"],
        nullable=False
    )
    require_synthetic_auth: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allow_destructive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationship to application
    application: Mapped["Application"] = relationship("Application", backref="scope_policy", lazy="selectin")


class BlockedExecutionLog(ModelBase):
    """
    Log of security test executions or requests blocked by safety policy checks.
    Provides complete auditability of prohibited actions (both human and LLM-initiated).
    """
    __tablename__ = "blocked_execution_logs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="SET NULL"), index=True, nullable=True
    )

    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    http_method: Mapped[str] = mapped_column(String(20), nullable=False)
    violation_category: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    blocked_reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    payload_sample: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_agent: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

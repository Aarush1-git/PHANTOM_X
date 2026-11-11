import uuid
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import String, Float, ForeignKey, JSON, Text, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class SessionStatus(str, Enum):
    READY = "READY"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class SecurityResultClassification(str, Enum):
    VULNERABILITY_CONFIRMED = "VULNERABILITY_CONFIRMED"
    SECURE_BEHAVIOR_CONFIRMED = "SECURE_BEHAVIOR_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class TargetType(str, Enum):
    SYNTHETIC_TARGET = "SYNTHETIC_TARGET"
    AUTHORIZED_APPLICATION = "AUTHORIZED_APPLICATION"


class PlaygroundSession(ModelBase):
    __tablename__ = "playground_sessions"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    parent_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("playground_sessions.id", ondelete="SET NULL"), nullable=True)

    scenario_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    scenario_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scenario_category: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), default=TargetType.AUTHORIZED_APPLICATION.value, nullable=False)

    status: Mapped[str] = mapped_column(String(50), default=SessionStatus.AWAITING_AUTHORIZATION.value, index=True, nullable=False)
    security_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Explicit Authorization
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorizer_role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    authorized_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Execution Plan & Telemetry
    execution_plan: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    execution_results: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_references: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    safety_decisions: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    parent_session: Mapped[Optional["PlaygroundSession"]] = relationship("PlaygroundSession", remote_side="PlaygroundSession.id")

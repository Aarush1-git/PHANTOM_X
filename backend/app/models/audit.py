import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import ModelBase, GUID


class AuditLog(ModelBase):
    __tablename__ = "audit_logs"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)


class ScopePermission(ModelBase):
    __tablename__ = "scope_permissions"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    host_pattern: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "api.staging.example.com", "*.target.test"
    allowed_methods: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)  # ["GET", "POST"]
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    is_destructive_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


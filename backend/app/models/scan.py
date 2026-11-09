import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Float, Integer, ForeignKey, JSON, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID
from shared.enums.common import ScanStatus, ExecutionMode


class ScanConfiguration(ModelBase):
    __tablename__ = "scan_configurations"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    mode: Mapped[ExecutionMode] = mapped_column(SQLEnum(ExecutionMode), default=ExecutionMode.OBSERVE, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    concurrency: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    test_categories: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="configuration")


class Scan(ModelBase):
    __tablename__ = "scans"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    configuration_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("scan_configurations.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED, index=True, nullable=False)
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="scans")
    application: Mapped["Application"] = relationship("Application", back_populates="scans")
    configuration: Mapped[Optional["ScanConfiguration"]] = relationship("ScanConfiguration", back_populates="scans")
    attack_plans: Mapped[List["AttackPlan"]] = relationship("AttackPlan", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class ScanComparison(ModelBase):
    __tablename__ = "scan_comparisons"

    base_scan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    target_scan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    new_vulnerabilities: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    resolved_vulnerabilities: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    unchanged_vulnerabilities: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


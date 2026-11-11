import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import String, Float, ForeignKey, JSON, Text, DateTime, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class BaselineStatus(str, Enum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class RegressionStatus(str, Enum):
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    STILL_PROTECTED = "STILL_PROTECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class MatchQuality(str, Enum):
    EXACT_FINGERPRINT = "EXACT_FINGERPRINT"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    AMBIGUOUS_ENDPOINT = "AMBIGUOUS_ENDPOINT"
    AMBIGUOUS_TITLE = "AMBIGUOUS_TITLE"
    NO_MATCH = "NO_MATCH"


class SecurityBaseline(ModelBase):
    __tablename__ = "security_baselines"
    __table_args__ = (
        UniqueConstraint("application_id", "vulnerability_fingerprint", name="uq_baseline_app_fingerprint"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    source_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="SET NULL"), index=True, nullable=True)
    verification_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="SET NULL"), index=True, nullable=True)
    original_vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True, nullable=True)

    vulnerability_fingerprint: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    http_method: Mapped[str] = mapped_column(String(20), default="GET", nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: Mapped[str] = mapped_column(String(50), default=BaselineStatus.VERIFIED.value, nullable=False)

    verification_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(50), default="VERIFIED", nullable=False)
    verification_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    evidence_references: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    is_retired: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    retired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    source_scan: Mapped[Optional["Scan"]] = relationship("Scan", foreign_keys=[source_scan_id])
    verification_scan: Mapped[Optional["Scan"]] = relationship("Scan", foreign_keys=[verification_scan_id])
    original_vulnerability: Mapped[Optional["Vulnerability"]] = relationship("Vulnerability", foreign_keys=[original_vulnerability_id])
    regression_records: Mapped[List["RegressionRecord"]] = relationship(
        "RegressionRecord",
        back_populates="baseline",
        cascade="all, delete-orphan",
        order_by="desc(RegressionRecord.created_at)"
    )


class RegressionRecord(ModelBase):
    __tablename__ = "regression_records"
    __table_args__ = (
        UniqueConstraint("baseline_id", "scan_id", name="uq_baseline_scan_evaluation"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    baseline_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("security_baselines.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    reappeared_vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[str] = mapped_column(String(50), nullable=False)  # REGRESSION_DETECTED, STILL_PROTECTED, INCONCLUSIVE
    match_quality: Mapped[str] = mapped_column(String(50), nullable=False)  # EXACT_FINGERPRINT, HIGH_CONFIDENCE, AMBIGUOUS_ENDPOINT, AMBIGUOUS_TITLE, NO_MATCH
    confidence_score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    original_severity: Mapped[str] = mapped_column(String(50), nullable=False)
    new_severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity_change: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # INCREASED, DECREASED, UNCHANGED, NONE

    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    evidence_references: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    baseline: Mapped["SecurityBaseline"] = relationship("SecurityBaseline", back_populates="regression_records")
    scan: Mapped["Scan"] = relationship("Scan")
    application: Mapped["Application"] = relationship("Application")
    reappeared_vulnerability: Mapped[Optional["Vulnerability"]] = relationship("Vulnerability", foreign_keys=[reappeared_vulnerability_id])


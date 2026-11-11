import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import String, Float, ForeignKey, JSON, Text, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class RecommendationStatus(str, Enum):
    GENERATED = "GENERATED"
    REVIEWED = "REVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFIED = "VERIFIED"
    DEFERRED = "DEFERRED"


class RemediationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    PERSISTENT = "PERSISTENT"
    INCONCLUSIVE = "INCONCLUSIVE"


class RemediationRecommendation(ModelBase):
    __tablename__ = "remediation_recommendations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), index=True, nullable=True
    )

    # Core metadata
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    calculated_priority: Mapped[str] = mapped_column(
        String(50), default=RemediationPriority.MEDIUM.value, index=True, nullable=False
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), default=RecommendationStatus.GENERATED.value, index=True, nullable=False
    )

    endpoint: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(20), default="GET", nullable=True)

    # Decision rationale and reasoning
    priority_rationale: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, nullable=False)
    potential_business_impact: Mapped[str] = mapped_column(Text, nullable=False)

    # Actionable guidance
    remediation_steps: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    suggested_fix_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    validation_steps: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    suggested_playground_scenario_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    estimated_effort: Mapped[Optional[str]] = mapped_column(String(50), default="MEDIUM", nullable=True)
    missing_information_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Assignment & Lifecycle Details
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deferred_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Verification Telemetry
    verification_status: Mapped[str] = mapped_column(
        String(50), default=VerificationStatus.UNVERIFIED.value, nullable=False
    )
    verification_evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability")
    scan: Mapped[Optional["Scan"]] = relationship("Scan")
    history_records: Mapped[List["RecommendationHistory"]] = relationship(
        "RecommendationHistory",
        back_populates="recommendation",
        cascade="all, delete-orphan",
        order_by="desc(RecommendationHistory.created_at)"
    )


class RecommendationHistory(ModelBase):
    __tablename__ = "remediation_history"

    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("remediation_recommendations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )

    from_status: Mapped[str] = mapped_column(String(50), nullable=False)
    to_status: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    recommendation: Mapped["RemediationRecommendation"] = relationship(
        "RemediationRecommendation", back_populates="history_records"
    )


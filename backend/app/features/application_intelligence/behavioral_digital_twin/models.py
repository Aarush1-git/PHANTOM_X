import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    String,
    Integer,
    Float,
    ForeignKey,
    JSON,
    DateTime,
    UniqueConstraint,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class BaselineStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


class AnomalyStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AnomalyType(str, Enum):
    UNEXPECTED_STATUS_CODE = "UNEXPECTED_STATUS_CODE"
    SCHEMA_DRIFT = "SCHEMA_DRIFT"
    UNSEEN_SEQUENCE = "UNSEEN_SEQUENCE"
    UNAUTHORIZED_ROLE_HOP = "UNAUTHORIZED_ROLE_HOP"
    LATENCY_SPIKE = "LATENCY_SPIKE"


class AnomalySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BehavioralObservation(ModelBase):
    """
    Persistent log of observed API interactions.
    Strictly captures sanitized request/response schemas, paths, status codes, and latencies.
    Never stores raw credentials, authorization tokens, or sensitive customer PII.
    """
    __tablename__ = "behavioral_observations"
    __table_args__ = (
        Index("ix_obs_app_observed_at", "application_id", "observed_at"),
        Index("ix_obs_app_norm_path", "application_id", "normalized_path"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("applications.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
        nullable=True
    )

    method: Mapped[str] = mapped_column(String(20), nullable=False)
    normalized_path: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    sanitized_request_schema: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    sanitized_response_schema: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    session_token_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship("DiscoveredEndpoint")


class BehavioralBaseline(ModelBase):
    """
    A versioned behavioral baseline snapshot for an application.
    Contains aggregated endpoint profiles and Markov sequence transition matrices.
    """
    __tablename__ = "behavioral_baselines"
    __table_args__ = (
        UniqueConstraint("application_id", "version", name="uq_behavioral_baseline_app_version"),
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="chk_baseline_confidence"),
        Index("ix_baseline_app_status", "application_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("applications.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=BaselineStatus.DRAFT.value, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    endpoint_profiles: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    transition_matrix: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    transitions: Mapped[List["BehavioralTransition"]] = relationship(
        "BehavioralTransition",
        back_populates="baseline",
        cascade="all, delete-orphan"
    )
    anomalies: Mapped[List["BehavioralAnomaly"]] = relationship(
        "BehavioralAnomaly",
        back_populates="baseline"
    )


class BehavioralTransition(ModelBase):
    """
    A single directed transition edge between API endpoints within a Behavioral Baseline.
    Represents sequence flow probabilities (Markov chain state transitions).
    """
    __tablename__ = "behavioral_transitions"
    __table_args__ = (
        CheckConstraint("probability >= 0.0 AND probability <= 1.0", name="chk_transition_probability"),
        Index("ix_trans_baseline_endpoints", "baseline_id", "from_endpoint_id", "to_endpoint_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("applications.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    baseline_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("behavioral_baselines.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    from_endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
        nullable=True
    )
    to_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    probability: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Relationships
    baseline: Mapped["BehavioralBaseline"] = relationship("BehavioralBaseline", back_populates="transitions")
    from_endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship(
        "DiscoveredEndpoint",
        foreign_keys=[from_endpoint_id]
    )
    to_endpoint: Mapped["DiscoveredEndpoint"] = relationship(
        "DiscoveredEndpoint",
        foreign_keys=[to_endpoint_id]
    )


class BehavioralAnomaly(ModelBase):
    """
    Represents an observed deviation from an established Behavioral Baseline.
    Distinct from security vulnerabilities: captures behavioral drift, schema changes,
    and out-of-order sequence traversals with supporting forensic telemetry.
    """
    __tablename__ = "behavioral_anomalies"
    __table_args__ = (
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="chk_anomaly_confidence"),
        Index("ix_anomaly_app_status", "application_id", "status"),
        Index("ix_anomaly_detected_at", "detected_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("applications.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    baseline_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("behavioral_baselines.id", ondelete="SET NULL"),
        index=True,
        nullable=True
    )
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
        nullable=True
    )

    anomaly_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default=AnomalySeverity.MEDIUM.value, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)
    evidence_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=AnomalyStatus.OPEN.value, index=True, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    application: Mapped["Application"] = relationship("Application")
    baseline: Mapped[Optional["BehavioralBaseline"]] = relationship(
        "BehavioralBaseline",
        back_populates="anomalies"
    )
    endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship("DiscoveredEndpoint")

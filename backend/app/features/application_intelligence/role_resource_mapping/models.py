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
    CheckConstraint,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class SubjectType(str, Enum):
    ROLE = "ROLE"
    RESOURCE = "RESOURCE"
    IDENTITY = "IDENTITY"


class ObjectType(str, Enum):
    ENDPOINT = "ENDPOINT"
    RESOURCE = "RESOURCE"
    ROLE = "ROLE"


class RelationshipType(str, Enum):
    ROLE_ACCESSES_ENDPOINT = "ROLE_ACCESSES_ENDPOINT"
    ROLE_ACCESSES_RESOURCE = "ROLE_ACCESSES_RESOURCE"
    STRUCTURAL_CONTAINMENT = "STRUCTURAL_CONTAINMENT"
    RESOURCE_REFERENCES_RESOURCE = "RESOURCE_REFERENCES_RESOURCE"
    ROLE_DECLARED_INHERITANCE = "ROLE_DECLARED_INHERITANCE"
    OBSERVED_ACCESS_OVERLAP = "OBSERVED_ACCESS_OVERLAP"
    IDENTITY_ASSIGNED_ROLE = "IDENTITY_ASSIGNED_ROLE"


class EvidenceSource(str, Enum):
    DECLARED = "DECLARED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"


class MappingStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    CANDIDATE = "CANDIDATE"


class RoleResourceMapping(ModelBase):
    """
    Persistent mapping of access, structural relationship, and identity bindings
    between roles, endpoints, resources, and sanitized identities.
    Scoped strictly to organization_id and application_id with deterministic deduplication.
    """
    __tablename__ = "role_resource_mappings"
    __table_args__ = (
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="chk_mapping_confidence"),
        CheckConstraint("sample_count >= 0", name="chk_mapping_sample_count"),
        UniqueConstraint(
            "application_id",
            "subject_type",
            "subject_name",
            "relationship_type",
            "object_type",
            "object_name",
            name="uq_role_resource_mapping",
        ),
        Index("ix_rrm_app_type", "application_id", "relationship_type"),
        Index("ix_rrm_app_source", "application_id", "evidence_source"),
        Index("ix_rrm_app_confidence", "application_id", "confidence_score"),
        Index("ix_rrm_org_app", "organization_id", "application_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("applications.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    # Subject of relationship (ROLE, RESOURCE, or IDENTITY)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    subject_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Object of relationship (ENDPOINT, RESOURCE, or ROLE)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    object_name: Mapped[str] = mapped_column(String(200), nullable=False)

    # Semantics of relationship
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Evidence provenance (DECLARED, OBSERVED, INFERRED)
    evidence_source: Mapped[str] = mapped_column(
        String(50), default=EvidenceSource.OBSERVED.value, nullable=False
    )

    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Detailed access telemetry separating request outcomes from authorization claims
    access_telemetry: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Comparison of declared permissions vs observed reality
    declared_vs_observed: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Supporting sanitized observation IDs (strictly sanitized, zero credentials)
    evidence_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    status: Mapped[str] = mapped_column(
        String(50), default=MappingStatus.ACTIVE.value, nullable=False
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    application: Mapped["Application"] = relationship("Application")

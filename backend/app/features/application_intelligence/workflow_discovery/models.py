import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    ForeignKey,
    JSON,
    DateTime,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ModelBase, GUID


class WorkflowType(str, Enum):
    STANDARD = "STANDARD"
    BRANCHED = "BRANCHED"
    ABANDONED = "ABANDONED"
    CYCLIC = "CYCLIC"


class WorkflowStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class StepType(str, Enum):
    ENTRY = "ENTRY"
    INTERMEDIATE = "INTERMEDIATE"
    TERMINAL = "TERMINAL"
    DROPOUT = "DROPOUT"


class DiscoveredWorkflow(ModelBase):
    """
    Persistent representation of an application workflow discovered from observed user journeys.
    Captures ordered execution steps, branching paths, graph structure, and statistically
    grounded transition frequencies without persisting raw credentials or session tokens.
    """
    __tablename__ = "discovered_workflows"
    __table_args__ = (
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="chk_workflow_confidence"),
        CheckConstraint("sample_count >= 0", name="chk_workflow_sample_count"),
        Index("ix_dw_app_status", "application_id", "status"),
        Index("ix_dw_app_confidence", "application_id", "confidence_score"),
        Index("ix_dw_app_created", "application_id", "created_at"),
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

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    workflow_type: Mapped[str] = mapped_column(
        String(50), default=WorkflowType.STANDARD.value, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), default=WorkflowStatus.DISCOVERED.value, nullable=False
    )

    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    step_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    entry_endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    terminal_endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    is_incomplete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dropout_step_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Graph representation: {"nodes": [...], "edges": [...]}
    graph_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Ordered sequence of canonical steps: [{"step_index": 0, "method": "POST", "normalized_path": "/...", ...}]
    steps_sequence: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    # Alternative transitions, branching variants, or observed drop-off metadata
    variations: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

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
    entry_endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship(
        "DiscoveredEndpoint", foreign_keys=[entry_endpoint_id]
    )
    terminal_endpoint: Mapped[Optional["DiscoveredEndpoint"]] = relationship(
        "DiscoveredEndpoint", foreign_keys=[terminal_endpoint_id]
    )

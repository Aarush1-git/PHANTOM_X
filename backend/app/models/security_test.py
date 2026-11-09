import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import String, ForeignKey, JSON, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID
from shared.enums.common import SecurityTestStatus, SafetyClassification


class AttackPlan(ModelBase):
    __tablename__ = "attack_plans"

    scan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="DRAFT", nullable=False)  # DRAFT, APPROVED, EXECUTED
    scenarios: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="attack_plans")
    security_tests: Mapped[List["SecurityTest"]] = relationship("SecurityTest", back_populates="plan", cascade="all, delete-orphan")


class SecurityTest(ModelBase):
    __tablename__ = "security_tests"

    plan_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("attack_plans.id", ondelete="CASCADE"), index=True, nullable=False)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("discovered_endpoints.id", ondelete="CASCADE"), index=True, nullable=False)
    test_category: Mapped[str] = mapped_column(String(100), nullable=False)  # BOLA, IDOR, AUTH_BYPASS, INJECTION
    test_parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    safety_classification: Mapped[SafetyClassification] = mapped_column(
        SQLEnum(SafetyClassification),
        default=SafetyClassification.SAFE_READ_ONLY,
        nullable=False
    )
    status: Mapped[SecurityTestStatus] = mapped_column(
        SQLEnum(SecurityTestStatus),
        default=SecurityTestStatus.PENDING,
        index=True,
        nullable=False
    )
    result_summary: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    plan: Mapped["AttackPlan"] = relationship("AttackPlan", back_populates="security_tests")
    endpoint: Mapped["DiscoveredEndpoint"] = relationship("DiscoveredEndpoint", back_populates="security_tests")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="security_test")


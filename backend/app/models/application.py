import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Float, ForeignKey, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID


class Application(ModelBase):
    __tablename__ = "applications"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE", nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="applications")
    environments: Mapped[List["ApplicationEnvironment"]] = relationship("ApplicationEnvironment", back_populates="application", cascade="all, delete-orphan")
    endpoints: Mapped[List["DiscoveredEndpoint"]] = relationship("DiscoveredEndpoint", back_populates="application", cascade="all, delete-orphan")
    roles: Mapped[List["ApplicationRole"]] = relationship("ApplicationRole", back_populates="application", cascade="all, delete-orphan")
    relationships: Mapped[List["ResourceRelationship"]] = relationship("ResourceRelationship", back_populates="application", cascade="all, delete-orphan")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="application", cascade="all, delete-orphan")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship("Vulnerability", back_populates="application", cascade="all, delete-orphan")


class ApplicationEnvironment(ModelBase):
    __tablename__ = "application_environments"

    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(50), nullable=False)  # staging, dev, sandbox
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    env_type: Mapped[str] = mapped_column(String(50), default="staging", nullable=False)

    application: Mapped["Application"] = relationship("Application", back_populates="environments")


class ApplicationRole(ModelBase):
    __tablename__ = "application_roles"

    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    permissions: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    application: Mapped["Application"] = relationship("Application", back_populates="roles")


class ResourceRelationship(ModelBase):
    __tablename__ = "resource_relationships"

    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    source_resource: Mapped[str] = mapped_column(String(100), nullable=False)
    target_resource: Mapped[str] = mapped_column(String(100), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)  # OWNS, CONTAINS, REFERENCES
    is_bidirectional: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    application: Mapped["Application"] = relationship("Application", back_populates="relationships")


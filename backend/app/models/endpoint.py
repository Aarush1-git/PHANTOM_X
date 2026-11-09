import uuid
from typing import List, Dict, Any, Optional
from sqlalchemy import String, Boolean, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID
from shared.enums.common import HttpMethod, EndpointRiskLevel


class DiscoveredEndpoint(ModelBase):
    __tablename__ = "discovered_endpoints"

    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    path: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    method: Mapped[HttpMethod] = mapped_column(SQLEnum(HttpMethod), default=HttpMethod.GET, nullable=False)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    parameters: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    response_codes: Mapped[List[int]] = mapped_column(JSON, default=list, nullable=False)
    risk_level: Mapped[EndpointRiskLevel] = mapped_column(SQLEnum(EndpointRiskLevel), default=EndpointRiskLevel.UNASSESSED, nullable=False)
    raw_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    application: Mapped["Application"] = relationship("Application", back_populates="endpoints")
    security_tests: Mapped[List["SecurityTest"]] = relationship("SecurityTest", back_populates="endpoint", cascade="all, delete-orphan")


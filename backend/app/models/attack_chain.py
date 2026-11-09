import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Boolean, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID
from shared.enums.common import AttackChainSeverity


class AttackChain(ModelBase):
    __tablename__ = "attack_chains"

    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[AttackChainSeverity] = mapped_column(SQLEnum(AttackChainSeverity), default=AttackChainSeverity.HIGH, nullable=False)
    nodes: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    edges: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


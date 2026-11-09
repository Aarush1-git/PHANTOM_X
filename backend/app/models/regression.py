import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import ModelBase, GUID
from shared.enums.common import RegressionTestStatus


class RegressionTest(ModelBase):
    __tablename__ = "regression_tests"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False)
    previous_test_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), ForeignKey("security_tests.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[RegressionTestStatus] = mapped_column(SQLEnum(RegressionTestStatus), default=RegressionTestStatus.PASSED, nullable=False)
    last_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    result_summary: Mapped[str] = mapped_column(String(1000), nullable=False)

    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability", back_populates="regressions")


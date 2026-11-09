from enum import Enum
from typing import Dict, Any, List, Optional
from uuid import UUID
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    INITIALIZING = "INITIALIZING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class AgentContext(BaseModel):
    agent_name: str
    target_application_id: Optional[UUID] = None
    target_url: Optional[str] = None
    scan_id: Optional[UUID] = None
    session_id: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    discovered_artifacts: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 60
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentResult(BaseModel):
    agent_name: str
    status: AgentStatus
    output_data: Dict[str, Any] = Field(default_factory=dict)
    proposed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


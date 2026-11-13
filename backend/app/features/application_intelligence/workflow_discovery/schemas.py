import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.features.application_intelligence.workflow_discovery.models import (
    WorkflowType,
    WorkflowStatus,
    StepType,
)


class WorkflowStepSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    step_index: int = Field(..., ge=0)
    method: str
    normalized_path: str
    endpoint_id: Optional[uuid.UUID] = None
    step_type: str = StepType.INTERMEDIATE.value
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    sample_count: int = 1
    observation_ids: List[str] = Field(default_factory=list)


class WorkflowNodeSchema(BaseModel):
    id: str
    label: str
    method: str
    normalized_path: str
    step_type: str = StepType.INTERMEDIATE.value
    endpoint_id: Optional[str] = None
    observation_count: int = 0
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0


class WorkflowEdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    transition_count: int = 1
    probability: float = Field(0.0, ge=0.0, le=1.0)
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class WorkflowGraphSchema(BaseModel):
    nodes: List[WorkflowNodeSchema] = Field(default_factory=list)
    edges: List[WorkflowEdgeSchema] = Field(default_factory=list)


class DiscoveredWorkflowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    name: str
    description: Optional[str] = None
    workflow_type: str
    status: str
    confidence_score: float
    sample_count: int
    step_count: int
    is_incomplete: bool
    dropout_step_index: Optional[int] = None
    steps_sequence: List[WorkflowStepSchema] = Field(default_factory=list)
    discovered_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime


class DiscoveredWorkflowDetailResponse(DiscoveredWorkflowResponse):
    graph_data: WorkflowGraphSchema = Field(default_factory=WorkflowGraphSchema)
    variations: Dict[str, Any] = Field(default_factory=dict)


class DiscoveredWorkflowListResponse(BaseModel):
    items: List[DiscoveredWorkflowResponse]
    total: int
    page: int
    page_size: int


class WorkflowDiscoveryRequest(BaseModel):
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    min_sample_count: int = Field(1, ge=1)


class WorkflowDiscoveryResultResponse(BaseModel):
    application_id: uuid.UUID
    discovered_count: int
    analyzed_sessions_count: int
    analyzed_observations_count: int
    insufficient_data: bool
    insufficient_data_reason: Optional[str] = None
    workflows: List[DiscoveredWorkflowResponse] = Field(default_factory=list)


class WorkflowEvidenceItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    observation_id: uuid.UUID
    session_token_hash: Optional[str] = None
    method: str
    normalized_path: str
    status_code: int
    latency_ms: float
    observed_at: datetime
    sanitized_request_schema: Dict[str, Any] = Field(default_factory=dict)
    sanitized_response_schema: Dict[str, Any] = Field(default_factory=dict)


class WorkflowEvidenceListResponse(BaseModel):
    workflow_id: uuid.UUID
    step_index: Optional[int] = None
    total_evidence: int
    items: List[WorkflowEvidenceItemResponse] = Field(default_factory=list)


class WorkflowOverviewResponse(BaseModel):
    application_id: uuid.UUID
    total_workflows: int
    active_workflows: int
    incomplete_workflows: int
    branched_workflows: int
    average_steps: float
    high_confidence_count: int
    total_observed_sessions: int
    insufficient_data: bool

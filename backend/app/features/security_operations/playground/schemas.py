import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ScenarioInfo(BaseModel):
    id: str
    name: str
    category: str
    description: str
    security_objective: str
    preconditions: List[str] = Field(default_factory=list)
    required_authorization: str = "EXPLICIT_SECURITY_OPERATOR"
    expected_secure_behavior: str
    potential_vulnerability_indicators: List[str] = Field(default_factory=list)
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    execution_constraints: Dict[str, Any] = Field(default_factory=dict)
    target_endpoints: List[str] = Field(default_factory=list)
    sample_payload: Optional[Dict[str, Any]] = None
    is_synthetic_compatible: bool = True


class ScenarioListResponse(BaseModel):
    scenarios: List[ScenarioInfo]
    categories: List[str]
    total: int


class PlaygroundTargetInfo(BaseModel):
    id: uuid.UUID
    name: str
    target_url: str
    target_type: str  # SYNTHETIC_TARGET, AUTHORIZED_APPLICATION
    is_synthetic: bool = False
    scope_status: Optional[str] = None
    authorization_status: Optional[str] = None
    description: Optional[str] = None


class PlaygroundSessionCreate(BaseModel):
    application_id: uuid.UUID
    scenario_id: str
    notes: Optional[str] = None


class PlaygroundAuthorizeRequest(BaseModel):
    notes: Optional[str] = None


class PlaygroundExecutionPlan(BaseModel):
    target_url: str
    endpoint: str
    http_method: str = "GET"
    payload_preview: Dict[str, Any] = Field(default_factory=dict)
    safety_classification: str = "SAFE_READ_ONLY"
    rate_limit_rps: int = 5
    max_concurrency: int = 1
    is_synthetic: bool = False
    safety_restrictions: List[str] = Field(default_factory=list)


class PlaygroundSessionResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    application_name: Optional[str] = None
    parent_session_id: Optional[uuid.UUID] = None
    scenario_id: str
    scenario_name: str
    scenario_category: str
    target_type: str
    status: str
    security_result: Optional[str] = None
    is_authorized: bool = False
    authorized_by: Optional[str] = None
    authorizer_role: Optional[str] = None
    authorized_at: Optional[datetime] = None
    execution_plan: Dict[str, Any] = Field(default_factory=dict)
    execution_results: Dict[str, Any] = Field(default_factory=dict)
    evidence_references: Dict[str, Any] = Field(default_factory=dict)
    safety_decisions: Dict[str, Any] = Field(default_factory=dict)
    duration_seconds: Optional[float] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaygroundSessionListResponse(BaseModel):
    items: List[PlaygroundSessionResponse]
    total: int
    page: int
    limit: int


class PlaygroundResultResponse(BaseModel):
    session_id: uuid.UUID
    scenario_id: str
    scenario_name: str
    target_application: str
    target_url: str
    execution_status: str
    security_result: str
    vulnerability_category: str
    severity: Optional[str] = None
    expected_behavior: str
    observed_behavior: str
    evidence_references: Dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float
    safety_decisions: Dict[str, Any] = Field(default_factory=dict)
    recommended_next_step: str
    is_synthetic: bool = False
    previous_result_comparison: Optional[Dict[str, Any]] = None

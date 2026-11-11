import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.remediation import (
    RecommendationStatus,
    RemediationPriority,
    VerificationStatus,
)


class PriorityFactor(BaseModel):
    factor: str
    points: float
    reason: str


class RemediationRecommendationBase(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    vulnerability_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: str
    category: str
    cwe_id: Optional[str] = None
    severity: str
    calculated_priority: RemediationPriority
    risk_score: float
    status: RecommendationStatus
    endpoint: Optional[str] = None
    http_method: Optional[str] = "GET"
    estimated_effort: Optional[str] = "MEDIUM"
    suggested_playground_scenario_id: Optional[str] = None
    assigned_to: Optional[str] = None
    verification_status: VerificationStatus
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RemediationRecommendationListItem(RemediationRecommendationBase):
    why_it_matters_summary: Optional[str] = None


class RemediationRecommendationDetail(RemediationRecommendationBase):
    priority_rationale: List[Dict[str, Any]] = []
    why_it_matters: str
    potential_business_impact: str
    remediation_steps: List[str] = []
    suggested_fix_snippet: Optional[str] = None
    validation_steps: List[str] = []
    missing_information_notes: Optional[str] = None
    decision_notes: Optional[str] = None
    deferred_reason: Optional[str] = None
    verification_evidence: Dict[str, Any] = {}
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None


class RecommendationHistoryItem(BaseModel):
    id: uuid.UUID
    recommendation_id: uuid.UUID
    from_status: str
    to_status: str
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RecommendationListResponse(BaseModel):
    items: List[RemediationRecommendationListItem]
    total: int
    page: int
    size: int


class RecommendationGenerateRequest(BaseModel):
    application_id: uuid.UUID
    vulnerability_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None


class RecommendationGenerateResponse(BaseModel):
    generated_count: int
    updated_count: int
    recommendations: List[RemediationRecommendationListItem]


class RecommendationStatusUpdateRequest(BaseModel):
    status: RecommendationStatus
    notes: Optional[str] = None
    deferred_reason: Optional[str] = None
    assigned_to: Optional[str] = None


class RecommendationNotesUpdateRequest(BaseModel):
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


class RecommendationVerifyRequest(BaseModel):
    verification_scan_id: Optional[uuid.UUID] = None
    playground_session_id: Optional[uuid.UUID] = None
    notes: Optional[str] = None


class RecommendationVerifyResponse(BaseModel):
    recommendation_id: uuid.UUID
    previous_status: str
    new_status: str
    verification_status: VerificationStatus
    is_verified: bool
    message: str
    evidence_details: Dict[str, Any]
    verified_at: Optional[datetime] = None


class PriorityCountBreakdown(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0


class StatusCountBreakdown(BaseModel):
    GENERATED: int = 0
    REVIEWED: int = 0
    ACCEPTED: int = 0
    REJECTED: int = 0
    IN_PROGRESS: int = 0
    VERIFIED: int = 0
    DEFERRED: int = 0


class RemediationOverviewResponse(BaseModel):
    total_recommendations: int
    by_priority: PriorityCountBreakdown
    by_status: StatusCountBreakdown
    average_risk_score: float
    verified_count: int
    pending_verification_count: int
    in_progress_count: int


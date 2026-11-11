import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class BaselineVerifyRequest(BaseModel):
    vulnerability_id: uuid.UUID
    verification_scan_id: uuid.UUID
    notes: Optional[str] = None


class BaselineRetireRequest(BaseModel):
    reason: Optional[str] = None


class SecurityBaselineResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    application_name: Optional[str] = None
    source_scan_id: Optional[uuid.UUID] = None
    verification_scan_id: Optional[uuid.UUID] = None
    original_vulnerability_id: Optional[uuid.UUID] = None
    vulnerability_fingerprint: str
    title: str
    category: Optional[str] = None
    cwe_id: Optional[str] = None
    endpoint: str
    http_method: str = "GET"
    severity: str
    status: str
    verification_timestamp: Optional[datetime] = None
    verification_status: str
    verification_reason: Optional[str] = None
    evidence_references: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
    is_retired: bool = False
    retired_at: Optional[datetime] = None
    retired_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BaselineVerifyResponse(BaseModel):
    baseline: Optional[SecurityBaselineResponse] = None
    verification_status: str  # VERIFIED, FAILED
    reason: str


class BaselineListResponse(BaseModel):
    items: List[SecurityBaselineResponse]
    total: int
    page: int
    limit: int


class RegressionRecordResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    application_name: Optional[str] = None
    baseline_id: uuid.UUID
    baseline_title: Optional[str] = None
    baseline_endpoint: Optional[str] = None
    scan_id: uuid.UUID
    scan_notes: Optional[str] = None
    reappeared_vulnerability_id: Optional[uuid.UUID] = None
    status: str  # REGRESSION_DETECTED, STILL_PROTECTED, INCONCLUSIVE
    match_quality: str  # EXACT_FINGERPRINT, HIGH_CONFIDENCE, AMBIGUOUS_ENDPOINT, AMBIGUOUS_TITLE, NO_MATCH
    confidence_score: float
    original_severity: str
    new_severity: Optional[str] = None
    severity_change: Optional[str] = None  # INCREASED, DECREASED, UNCHANGED, NONE
    first_observed_at: datetime
    evidence_references: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    remediation_notes: Optional[str] = None
    is_resolved: bool = False
    resolved_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class RegressionListResponse(BaseModel):
    items: List[RegressionRecordResponse]
    total: int
    page: int
    limit: int


class ScanEvaluationResponse(BaseModel):
    scan_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    baselines_evaluated: int
    regressions_detected: int
    still_protected: int
    inconclusive: int
    results: List[RegressionRecordResponse]


class SecurityTimelineEvent(BaseModel):
    id: str
    event_type: str  # DISCOVERY, REPORT_STATUS_CHANGE, FIX_DECLARED, VERIFICATION_SCAN, BASELINE_CREATED, BASELINE_VERIFIED, REGRESSION_DETECTED, BASELINE_RETIRED, RE_VERIFIED
    timestamp: datetime
    title: str
    description: str
    severity: Optional[str] = None
    status: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityTimelineResponse(BaseModel):
    application_id: uuid.UUID
    application_name: str
    events: List[SecurityTimelineEvent]
    total_events: int


class TimeTravelOverviewResponse(BaseModel):
    total_baselines: int
    verified_baselines: int
    active_baselines: int
    retired_baselines: int
    regressions_detected: int
    inconclusive_evaluations: int
    affected_applications_count: int
    recent_regressions: List[RegressionRecordResponse]


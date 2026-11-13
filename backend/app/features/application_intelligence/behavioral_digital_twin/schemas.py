import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BaselineStatus,
    AnomalyStatus,
    AnomalyType,
    AnomalySeverity,
)
from app.features.application_intelligence.behavioral_digital_twin.sanitization import (
    hash_session_identifier,
    sanitize_payload_recursively,
    sanitize_headers,
    extract_structural_schema,
)

# Standard allowed HTTP methods
VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ==============================================================================
# 1. OBSERVATION SCHEMAS
# ==============================================================================

class ObservationIngestRequest(BaseSchema):
    """
    Schema for ingesting raw application interaction traces.
    Strictly sanitizes payloads and headers to prevent storing sensitive credentials or PII.
    """
    application_id: uuid.UUID
    endpoint_id: Optional[uuid.UUID] = None
    method: str = Field(..., max_length=20, description="HTTP method")
    path: str = Field(..., max_length=500, description="Observed endpoint path")
    status_code: int = Field(..., ge=100, le=599, description="Observed HTTP status code")
    request_headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Request headers to sanitize")
    response_headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Response headers to sanitize")
    request_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw request body to be sanitized")
    response_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw response body to be sanitized")
    latency_ms: float = Field(default=0.0, ge=0.0, le=300000.0, description="Request duration in milliseconds")
    session_identifier: Optional[str] = Field(None, max_length=500, description="Raw session cookie/token (will be hashed, never stored)")

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        upper = v.strip().upper()
        if upper not in VALID_HTTP_METHODS:
            raise ValueError(f"Invalid HTTP method: '{v}'. Must be one of {sorted(VALID_HTTP_METHODS)}")
        return upper

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Path cannot be empty.")
        if not clean.startswith("/"):
            clean = "/" + clean
        return clean

    @field_validator("request_headers", "response_headers")
    @classmethod
    def clean_headers(cls, v: Optional[Dict[str, str]]) -> Dict[str, str]:
        if not v:
            return {}
        if len(v) > 50:
            raise ValueError("Exceeded maximum header count (50).")
        return sanitize_headers(v)

    @field_validator("request_payload", "response_payload")
    @classmethod
    def sanitize_bodies(cls, v: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not v:
            return {}
        # Protect against payload explosion
        if len(str(v)) > 200000:
            raise ValueError("Payload exceeds maximum permissible size (200KB).")
        return sanitize_payload_recursively(v)


class ObservationBatchIngestRequest(BaseSchema):
    """Batch ingestion of up to 200 observations (e.g. from HAR logs or crawler traces)."""
    application_id: uuid.UUID
    observations: List[ObservationIngestRequest] = Field(..., min_length=1, max_length=200)


class ObservationResponse(BaseSchema):
    """Sanitized behavioral observation representation."""
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    endpoint_id: Optional[uuid.UUID] = None
    method: str
    normalized_path: str
    status_code: int
    sanitized_request_schema: Dict[str, Any]
    sanitized_response_schema: Dict[str, Any]
    latency_ms: float
    session_token_hash: Optional[str] = None
    observed_at: datetime
    created_at: datetime


# ==============================================================================
# 2. BASELINE SCHEMAS
# ==============================================================================

class BaselineCreateRequest(BaseSchema):
    """Request to create a new behavioral baseline snapshot."""
    application_id: uuid.UUID
    version: str = Field(..., min_length=1, max_length=50, description="Semantic version or label, e.g. 'v1.0'")
    sample_count: int = Field(default=0, ge=0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    endpoint_profiles: Dict[str, Any] = Field(default_factory=dict, description="Aggregated endpoint profile maps")
    transition_matrix: Dict[str, Any] = Field(default_factory=dict, description="Markov sequence transition probabilities")

    @field_validator("confidence_score")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("Confidence score must be strictly between 0.0 and 1.0.")
        return round(v, 4)

    @field_validator("endpoint_profiles", "transition_matrix")
    @classmethod
    def validate_json_bounds(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if len(str(v)) > 500000:
            raise ValueError("Baseline metadata exceeds maximum permissible size (500KB).")
        return v


class BaselineActivateRequest(BaseSchema):
    """Promotes a baseline from DRAFT to ACTIVE, superseding prior active baselines."""
    activation_notes: Optional[str] = Field(None, max_length=1000)


class BaselineTransitionResponse(BaseSchema):
    id: uuid.UUID
    baseline_id: uuid.UUID
    from_endpoint_id: Optional[uuid.UUID] = None
    to_endpoint_id: uuid.UUID
    probability: float
    observation_count: int


class BaselineResponse(BaseSchema):
    """Versioned behavioral baseline snapshot."""
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    version: str
    status: BaselineStatus
    sample_count: int
    confidence_score: float
    endpoint_profiles: Dict[str, Any]
    transition_matrix: Dict[str, Any]
    created_at: datetime
    activated_at: Optional[datetime] = None


# ==============================================================================
# 3. ANOMALY SCHEMAS
# ==============================================================================

class AnomalyCreateRequest(BaseSchema):
    """Direct anomaly recording with validated evidence payload."""
    application_id: uuid.UUID
    baseline_id: Optional[uuid.UUID] = None
    endpoint_id: Optional[uuid.UUID] = None
    anomaly_type: str = Field(..., max_length=100)
    severity: str = Field(default=AnomalySeverity.MEDIUM.value, max_length=50)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("Confidence must be strictly between 0.0 and 1.0.")
        return round(v, 4)

    @field_validator("evidence_data")
    @classmethod
    def sanitize_evidence(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not v:
            return {}
        if len(str(v)) > 200000:
            raise ValueError("Evidence payload exceeds maximum permissible size (200KB).")
        return sanitize_payload_recursively(v)


class AnomalyStatusUpdateRequest(BaseSchema):
    """Update anomaly review status."""
    status: AnomalyStatus
    resolution_notes: Optional[str] = Field(None, max_length=1000)


class AnomalyResponse(BaseSchema):
    """Behavioral anomaly deviation event."""
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    baseline_id: Optional[uuid.UUID] = None
    endpoint_id: Optional[uuid.UUID] = None
    anomaly_type: str
    severity: str
    confidence: float
    evidence_data: Dict[str, Any]
    status: AnomalyStatus
    detected_at: datetime
    resolved_at: Optional[datetime] = None


# ==============================================================================
# 4. DIGITAL TWIN OVERVIEW SCHEMA
# ==============================================================================

class DigitalTwinOverviewResponse(BaseSchema):
    """High-level summary of the Behavioral Digital Twin state for an application."""
    application_id: uuid.UUID
    organization_id: uuid.UUID
    total_observations: int
    active_baseline_id: Optional[uuid.UUID] = None
    active_baseline_version: Optional[str] = None
    active_baseline_confidence: float = 0.0
    total_transitions_tracked: int = 0
    open_anomalies_count: int = 0
    last_observed_at: Optional[datetime] = None
    endpoint_profiles: Dict[str, Any] = Field(default_factory=dict)
    latest_anomalies: List[AnomalyResponse] = Field(default_factory=list)


# ==============================================================================
# 5. REST API REQUEST / RESPONSE SCHEMAS
# ==============================================================================

class BaselineCompileRequest(BaseSchema):
    """Request to compile observations into a new draft baseline snapshot."""
    application_id: uuid.UUID
    version: Optional[str] = Field(None, max_length=50, description="Optional version label, e.g. 'v1.0'")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    min_samples: int = Field(default=1, ge=1, le=10000, description="Minimum observations required")


class HarIngestRequest(BaseSchema):
    """Request to ingest HTTP interaction traces from a HAR archive string."""
    application_id: uuid.UUID
    har_content: str = Field(..., min_length=10, max_length=15000000, description="Raw HAR JSON content")


class BatchIngestResponse(BaseSchema):
    """Response returned upon batch or HAR observation ingestion."""
    application_id: uuid.UUID
    ingested_count: int
    failed_count: int
    observations: List[ObservationResponse] = Field(default_factory=list)


class DriftEvaluateRequest(BaseSchema):
    """Trigger drift evaluation across observations for an application."""
    application_id: uuid.UUID
    baseline_id: Optional[uuid.UUID] = None
    max_observations: int = Field(default=50, ge=1, le=500, description="Maximum recent observations to evaluate")


class DriftEvaluationResponse(BaseSchema):
    """Response reporting detected drift deviations."""
    application_id: uuid.UUID
    baseline_id: Optional[uuid.UUID] = None
    evaluated_observations_count: int
    new_anomalies_detected: int
    anomalies: List[AnomalyResponse] = Field(default_factory=list)


class BaselineListResponse(BaseSchema):
    """List of baseline snapshots for an application."""
    items: List[BaselineResponse]
    total: int


class AnomalyListResponse(BaseSchema):
    """Paginated list of detected behavioral anomalies."""
    items: List[AnomalyResponse]
    total: int
    page: int
    limit: int


class ObservationListResponse(BaseSchema):
    """Paginated list of sanitized behavioral observations."""
    items: List[ObservationResponse]
    total: int
    page: int
    limit: int

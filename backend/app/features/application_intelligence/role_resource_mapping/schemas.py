import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from app.features.application_intelligence.role_resource_mapping.models import (
    SubjectType,
    ObjectType,
    RelationshipType,
    EvidenceSource,
    MappingStatus,
)


class AccessTelemetrySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    request_outcomes: Dict[str, int] = Field(default_factory=lambda: {"2xx": 0, "4xx": 0, "5xx": 0})
    authentication_status: str = "UNKNOWN"  # AUTHENTICATED, UNAUTHENTICATED, UNKNOWN
    authorization_status: str = "UNSPECIFIED"  # EXPLICIT_ALLOW, EXPLICIT_DENY, UNSPECIFIED
    authorization_scope: Optional[str] = "REQUEST_SCOPED"
    authorization_note: Optional[str] = None
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None


class DeclaredVsObservedSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    declared_in_spec: bool = False
    observed_in_traffic: bool = False
    discrepancy_category: str = "NONE"  # ALIGNED, DECLARED_NOT_OBSERVED, OBSERVED_NOT_DECLARED, EVIDENCE_INSUFFICIENT
    notes: Optional[str] = None


class RoleResourceMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    subject_type: str
    subject_id: Optional[str] = None
    subject_name: str
    object_type: str
    object_id: Optional[str] = None
    object_name: str
    relationship_type: str
    evidence_source: str
    confidence_score: float
    sample_count: int
    access_telemetry: Dict[str, Any] = Field(default_factory=dict)
    declared_vs_observed: Dict[str, Any] = Field(default_factory=dict)
    status: str
    discovered_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime


class RoleResourceMappingListResponse(BaseModel):
    items: List[RoleResourceMappingResponse]
    total: int
    page: int
    page_size: int


class MappingDiscoveryRequest(BaseModel):
    mode: Optional[str] = Field("ALL", description="Discovery mode: ALL, DECLARED_ONLY, OBSERVED_ONLY, STRUCTURAL_ONLY, OVERLAP_ONLY")
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    min_sample_count: int = Field(1, ge=1)
    include_declared: bool = True
    include_observed: bool = True
    include_inferred: bool = True


class MappingDiscoveryResultResponse(BaseModel):
    application_id: uuid.UUID
    discovered_mappings_count: int
    declared_mappings_count: int
    observed_mappings_count: int
    inferred_mappings_count: int
    discrepancies_count: int
    insufficient_evidence: bool
    insufficient_evidence_reason: Optional[str] = None
    mappings: List[RoleResourceMappingResponse] = Field(default_factory=list)


class MappingEvidenceItemResponse(BaseModel):
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


class MappingEvidenceListResponse(BaseModel):
    mapping_id: uuid.UUID
    total_evidence: int
    items: List[MappingEvidenceItemResponse] = Field(default_factory=list)


class RoleResourceOverviewResponse(BaseModel):
    application_id: uuid.UUID
    total_roles: int
    total_resources: int
    total_mappings: int
    declared_count: int
    observed_count: int
    inferred_count: int
    discrepancies_count: int
    high_confidence_count: int
    insufficient_evidence: bool
    insufficient_evidence_reason: Optional[str] = None


class DiscrepancyListResponse(BaseModel):
    application_id: uuid.UUID
    total_discrepancies: int
    category_filter: Optional[str] = None
    breakdown: Dict[str, int] = Field(default_factory=dict)
    items: List[RoleResourceMappingResponse] = Field(default_factory=list)
    evidence_limitations_note: str = (
        "Discrepancies represent empirical differences between declared specifications and observed traffic telemetry. "
        "They do NOT constitute verified security vulnerabilities, and unexercised permissions must not be assumed absent."
    )


class ApplicationRoleMappingResponse(BaseModel):
    role_id: Optional[str] = None
    role_name: str
    description: Optional[str] = None
    declared_permissions: Dict[str, Any] = Field(default_factory=dict)
    discovered_endpoints: List[str] = Field(default_factory=list)
    discovered_resources: List[str] = Field(default_factory=list)
    mappings: List[RoleResourceMappingResponse] = Field(default_factory=list)


class ApplicationRoleMappingListResponse(BaseModel):
    application_id: uuid.UUID
    total_roles: int
    items: List[ApplicationRoleMappingResponse] = Field(default_factory=list)


class ApplicationResourceMappingResponse(BaseModel):
    resource_name: str
    structural_parents: List[str] = Field(default_factory=list)
    structural_children: List[str] = Field(default_factory=list)
    accessing_roles: List[str] = Field(default_factory=list)
    mappings: List[RoleResourceMappingResponse] = Field(default_factory=list)


class ApplicationResourceMappingListResponse(BaseModel):
    application_id: uuid.UUID
    total_resources: int
    items: List[ApplicationResourceMappingResponse] = Field(default_factory=list)

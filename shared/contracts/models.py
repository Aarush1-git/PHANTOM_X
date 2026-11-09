from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, HttpUrl, ConfigDict

from shared.enums.common import (
    ScanStatus,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    SecurityTestStatus,
    SafetyClassification,
    ExecutionMode,
    HttpMethod,
    EndpointRiskLevel,
    AttackChainSeverity,
    RegressionTestStatus,
    UserRole,
)


class BaseContract(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ==============================================================================
# 1. APPLICATION CONTRACTS
# ==============================================================================

class ApplicationCreate(BaseContract):
    name: str = Field(..., min_length=2, max_length=100, description="Application display name")
    description: Optional[str] = Field(None, max_length=1000)
    target_url: str = Field(..., description="Base target URL for authorized testing")
    environment_name: str = Field(default="staging", description="e.g. staging, dev, sandbox")
    organization_id: Optional[UUID] = None


class ApplicationUpdate(BaseContract):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    target_url: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    status: Optional[str] = None


class ApplicationResponse(BaseContract):
    id: UUID
    organization_id: UUID
    name: str
    description: Optional[str] = None
    target_url: str
    risk_score: float = 0.0
    status: str = "ACTIVE"
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 2. SCAN CONTRACTS
# ==============================================================================

class ScanConfigurationCreate(BaseContract):
    name: str
    mode: ExecutionMode = ExecutionMode.OBSERVE
    max_depth: int = Field(default=3, ge=1, le=10)
    concurrency: int = Field(default=3, ge=1, le=20)
    rate_limit_rps: int = Field(default=10, ge=1, le=100)
    test_categories: List[str] = Field(default_factory=lambda: ["AUTH", "IDOR", "BOLA", "API_SECURITY"])


class ScanCreate(BaseContract):
    application_id: UUID
    configuration_id: Optional[UUID] = None
    mode: ExecutionMode = ExecutionMode.OBSERVE
    notes: Optional[str] = None


class ScanProgress(BaseContract):
    scan_id: UUID
    status: ScanStatus
    percent_complete: float = Field(ge=0.0, le=100.0)
    current_phase: str
    discovered_endpoints_count: int = 0
    executed_tests_count: int = 0
    findings_count: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanResponse(BaseContract):
    id: UUID
    organization_id: UUID
    application_id: UUID
    configuration_id: Optional[UUID] = None
    status: ScanStatus
    progress: float = 0.0
    findings_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 3. DISCOVERED ENDPOINT CONTRACTS
# ==============================================================================

class EndpointParameter(BaseContract):
    name: str
    location: str = "query"  # query, path, header, body
    param_type: str = "string"
    required: bool = False
    example: Optional[Any] = None


class EndpointAuthentication(BaseContract):
    auth_type: str = "BEARER"  # NONE, BEARER, BASIC, COOKIE, API_KEY
    header_name: Optional[str] = "Authorization"
    roles_permitted: List[str] = Field(default_factory=list)


class EndpointCreate(BaseContract):
    application_id: UUID
    path: str
    method: HttpMethod = HttpMethod.GET
    auth_required: bool = True
    parameters: List[EndpointParameter] = Field(default_factory=list)
    authentication: Optional[EndpointAuthentication] = None
    response_codes: List[int] = Field(default_factory=lambda: [200])
    risk_level: EndpointRiskLevel = EndpointRiskLevel.UNASSESSED


class EndpointResponse(BaseContract):
    id: UUID
    application_id: UUID
    path: str
    method: HttpMethod
    auth_required: bool
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    response_codes: List[int] = Field(default_factory=list)
    risk_level: EndpointRiskLevel
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 4. ATTACK PLAN CONTRACTS
# ==============================================================================

class AttackScenario(BaseContract):
    scenario_id: str
    name: str
    category: str
    target_endpoint: str
    method: HttpMethod
    hypothesis: str
    safety_classification: SafetyClassification
    preconditions: List[str] = Field(default_factory=list)


class AttackPlanRequest(BaseContract):
    scan_id: UUID
    application_id: UUID
    risk_appetite: str = "LOW"  # LOW, MEDIUM, HIGH


class AttackPlanResponse(BaseContract):
    id: UUID
    scan_id: UUID
    application_id: UUID
    status: str = "DRAFT"  # DRAFT, APPROVED, REJECTED, EXECUTED
    scenarios: List[AttackScenario] = Field(default_factory=list)
    approved_by: Optional[UUID] = None
    approved_at: Optional[datetime] = None
    created_at: datetime


# ==============================================================================
# 5. SECURITY TEST CONTRACTS
# ==============================================================================

class SecurityTestRequest(BaseContract):
    plan_id: UUID
    endpoint_id: UUID
    test_category: str
    test_parameters: Dict[str, Any] = Field(default_factory=dict)
    safety_classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY


class SecurityTestResponse(BaseContract):
    id: UUID
    plan_id: UUID
    endpoint_id: UUID
    test_category: str
    test_parameters: Dict[str, Any]
    safety_classification: SafetyClassification
    status: SecurityTestStatus
    result_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 6. EVIDENCE CONTRACTS
# ==============================================================================

class EvidenceCreate(BaseContract):
    vulnerability_id: Optional[UUID] = None
    test_id: Optional[UUID] = None
    request_dump: str
    response_dump: str
    proof_data: Dict[str, Any] = Field(default_factory=dict)
    screenshot_url: Optional[str] = None
    har_entry: Optional[Dict[str, Any]] = None


class EvidenceResponse(BaseContract):
    id: UUID
    vulnerability_id: Optional[UUID] = None
    test_id: Optional[UUID] = None
    request_dump: str
    response_dump: str
    proof_data: Dict[str, Any] = Field(default_factory=dict)
    screenshot_url: Optional[str] = None
    created_at: datetime


# ==============================================================================
# 7. VULNERABILITY CONTRACTS
# ==============================================================================

class VulnerabilityCreate(BaseContract):
    application_id: UUID
    scan_id: Optional[UUID] = None
    test_id: Optional[UUID] = None
    title: str
    severity: VulnerabilitySeverity
    status: VulnerabilityStatus = VulnerabilityStatus.DISCOVERED
    endpoint: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)


class VulnerabilityResponse(BaseContract):
    id: UUID
    organization_id: UUID
    application_id: UUID
    scan_id: Optional[UUID] = None
    test_id: Optional[UUID] = None
    title: str
    severity: VulnerabilitySeverity
    status: VulnerabilityStatus
    endpoint: str
    confidence: float
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: List[EvidenceResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 8. ATTACK CHAIN CONTRACTS
# ==============================================================================

class AttackChainNode(BaseContract):
    id: str
    label: str
    step_type: str  # e.g., "DISCOVERY", "AUTH_BYPASS", "IDOR_READ", "PRIVILEGE_ESCALATION"
    endpoint: Optional[str] = None
    vulnerability_id: Optional[UUID] = None
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM


class AttackChainEdge(BaseContract):
    id: str
    source: str
    target: str
    description: str


class AttackChainResponse(BaseContract):
    id: UUID
    application_id: UUID
    scan_id: Optional[UUID] = None
    title: str
    description: str
    severity: AttackChainSeverity
    nodes: List[AttackChainNode]
    edges: List[AttackChainEdge]
    is_verified: bool = False
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 9. REGRESSION CONTRACTS
# ==============================================================================

class RegressionTestRequest(BaseContract):
    vulnerability_id: UUID
    application_id: UUID
    trigger_reason: str = "APPLICATION_UPDATE"


class RegressionResult(BaseContract):
    id: UUID
    vulnerability_id: UUID
    application_id: UUID
    status: RegressionTestStatus
    last_run_at: datetime
    result_summary: str
    is_reintroduced: bool = False
    created_at: datetime


# ==============================================================================
# 10. AUDIT & SAFETY CONTRACTS
# ==============================================================================

class AuditLogResponse(BaseContract):
    id: UUID
    organization_id: UUID
    user_id: Optional[UUID] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    created_at: datetime


class ScopePermissionCreate(BaseContract):
    application_id: UUID
    host_pattern: str
    allowed_methods: List[HttpMethod] = Field(default_factory=lambda: [HttpMethod.GET, HttpMethod.POST])
    rate_limit_rps: int = Field(default=10, ge=1, le=100)
    is_destructive_allowed: bool = False


class ScopePermissionResponse(BaseContract):
    id: UUID
    organization_id: UUID
    application_id: UUID
    host_pattern: str
    allowed_methods: List[str]
    rate_limit_rps: int
    is_destructive_allowed: bool
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# 11. AUTHENTICATION & USER CONTRACTS
# ==============================================================================

class UserLogin(BaseContract):
    email: str
    password: str


class TokenResponse(BaseContract):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: UUID
    email: str
    role: UserRole


class UserResponse(BaseContract):
    id: UUID
    organization_id: UUID
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime


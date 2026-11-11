import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class AuditCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    APPLICATION_MANAGEMENT = "APPLICATION_MANAGEMENT"
    AUTHORIZATION = "AUTHORIZATION"
    SECURITY_TESTING = "SECURITY_TESTING"
    VULNERABILITY = "VULNERABILITY"
    PLATFORM = "PLATFORM"


class AuditEventType(str, Enum):
    # Authentication
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
    AUTH_PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"

    # Application Management
    APP_REGISTERED = "APP_REGISTERED"
    APP_UPDATED = "APP_UPDATED"
    APP_DELETED = "APP_DELETED"
    APP_SCOPE_CONFIGURED = "APP_SCOPE_CONFIGURED"

    # Authorization
    AUTHZ_REQUESTED = "AUTHZ_REQUESTED"
    AUTHZ_GRANTED = "AUTHZ_GRANTED"
    AUTHZ_REJECTED = "AUTHZ_REJECTED"
    AUTHZ_SUSPENDED = "AUTHZ_SUSPENDED"
    AUTHZ_REVOKED = "AUTHZ_REVOKED"
    AUTHZ_EXPIRED = "AUTHZ_EXPIRED"

    # Security Testing
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    TEST_EXECUTED = "TEST_EXECUTED"
    TEST_BLOCKED = "TEST_BLOCKED"
    SAFETY_POLICY_VIOLATION = "SAFETY_POLICY_VIOLATION"

    # Vulnerability & Reports
    VULN_DISCOVERED = "VULN_DISCOVERED"
    VULN_VERIFIED = "VULN_VERIFIED"
    VULN_FALSE_POSITIVE = "VULN_FALSE_POSITIVE"
    VULN_STATUS_CHANGED = "VULN_STATUS_CHANGED"
    VULN_RESOLVED = "VULN_RESOLVED"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_VIEWED = "REPORT_VIEWED"
    REPORT_STATUS_CHANGED = "REPORT_STATUS_CHANGED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    REPORT_REOPENED = "REPORT_REOPENED"

    # Platform
    CONFIG_CHANGED = "CONFIG_CHANGED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    ADMIN_ACTION = "ADMIN_ACTION"
    GENERAL_AUDIT = "GENERAL_AUDIT"


class AuditSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuditStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"
    CANCELLED = "CANCELLED"


class AuditEventCreate(BaseModel):
    category: AuditCategory
    event_type: str = Field(..., description="Unique event identifier string")
    action: str = Field(..., description="Action description")
    status: AuditStatus = Field(AuditStatus.SUCCESS, description="Resulting action status")
    severity: AuditSeverity = Field(AuditSeverity.INFO, description="Event severity classification")
    source_module: str = Field("SECURITY_OPERATIONS", description="Origin module emitting the event")
    target_type: str = Field(..., description="Resource entity type (e.g. Application, Scan, User)")
    target_id: Optional[str] = Field(None, description="Resource identifier")
    user_id: Optional[uuid.UUID] = None
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    application_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata payload")
    ip_address: Optional[str] = None
    correlation_id: Optional[str] = None


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    application_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    category: str
    event_type: str
    action: str
    status: str
    severity: str
    source_module: str
    target_type: str
    target_id: Optional[str] = None
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    correlation_id: Optional[str] = None
    sequence_number: Optional[int] = Field(default=1, description="Sequential per-organization event counter")
    event_hash: Optional[str] = None
    prev_event_hash: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditOverviewResponse(BaseModel):
    total_events: int
    successful_events: int
    failed_events: int
    blocked_events: int
    critical_events: int
    categories_breakdown: Dict[str, int]
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class AuditIntegrityVerificationResponse(BaseModel):
    is_intact: bool
    records_checked: int
    anomalies: List[str]
    broken_event_ids: List[str]
    verified_at: datetime
    genesis_event_id: Optional[str] = None
    latest_event_id: Optional[str] = None
    chain_head_hash: Optional[str] = None


class ScanLifecycleEvent(BaseModel):
    status: str
    timestamp: str
    note: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ScanExecutionRecordCreate(BaseModel):
    scan_id: uuid.UUID
    application_id: uuid.UUID
    initiating_user_id: Optional[uuid.UUID] = None
    initiating_user: Optional[str] = None
    final_status: str = "QUEUED"
    tests_executed: int = 0
    tests_blocked: int = 0
    verified_findings: int = 0
    failure_reason: Optional[str] = None
    lifecycle_events: List[Dict[str, Any]] = Field(default_factory=list)


class ScanExecutionRecordResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_id: uuid.UUID
    application_id: uuid.UUID
    initiating_user_id: Optional[uuid.UUID] = None
    initiating_user: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    final_status: str
    tests_executed: int
    tests_blocked: int
    verified_findings: int
    failure_reason: Optional[str] = None
    lifecycle_events: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


import uuid
from typing import List, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, ConfigDict


class ScopeStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"


class AuthorizationStatus(str, Enum):
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ViolationCategory(str, Enum):
    UNREGISTERED_TARGET = "UNREGISTERED_TARGET"
    UNAUTHORIZED_DOMAIN = "UNAUTHORIZED_DOMAIN"
    SCOPE_NOT_ACTIVE = "SCOPE_NOT_ACTIVE"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    EXCLUDED_PATH = "EXCLUDED_PATH"
    PATH_NOT_PERMITTED = "PATH_NOT_PERMITTED"
    RESTRICTED_ENDPOINT = "RESTRICTED_ENDPOINT"
    PROHIBITED_METHOD = "PROHIBITED_METHOD"
    DESTRUCTIVE_ACTION_PROHIBITED = "DESTRUCTIVE_ACTION_PROHIBITED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    CONCURRENCY_EXCEEDED = "CONCURRENCY_EXCEEDED"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"


class ScopePolicyBase(BaseModel):
    target_domain: str = Field(..., description="Target domain or host (e.g. staging.target.internal)")
    base_url: str = Field(..., description="API Base URL (e.g. https://staging.target.internal/api)")
    permitted_paths: List[str] = Field(
        default_factory=lambda: ["/*"],
        description="Glob or path patterns permitted for security testing"
    )
    excluded_paths: List[str] = Field(
        default_factory=lambda: ["/admin/*", "/logout", "/auth/reset-password"],
        description="Path patterns strictly forbidden from testing"
    )
    rate_limit_rps: int = Field(10, ge=1, le=100, description="Max requests per second")
    max_concurrency: int = Field(2, ge=1, le=20, description="Max concurrent scans/requests")
    max_scan_duration_minutes: int = Field(60, ge=5, le=720, description="Max scan duration in minutes")
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        description="Allowed HTTP methods"
    )
    restricted_endpoint_patterns: List[str] = Field(
        default_factory=lambda: ["*/delete-account*", "*/purge*", "*/reset*"],
        description="High-risk endpoint patterns requiring explicit protection"
    )
    require_synthetic_auth: bool = Field(True, description="Strictly require dedicated synthetic test credentials")
    allow_destructive: bool = Field(False, description="Whether destructive tests are permitted (default: False)")


class ScopePolicyCreate(ScopePolicyBase):
    application_id: Optional[uuid.UUID] = None


class ScopePolicyUpdate(BaseModel):
    target_domain: Optional[str] = None
    base_url: Optional[str] = None
    permitted_paths: Optional[List[str]] = None
    excluded_paths: Optional[List[str]] = None
    rate_limit_rps: Optional[int] = Field(None, ge=1, le=100)
    max_concurrency: Optional[int] = Field(None, ge=1, le=20)
    max_scan_duration_minutes: Optional[int] = Field(None, ge=5, le=720)
    allowed_methods: Optional[List[str]] = None
    restricted_endpoint_patterns: Optional[List[str]] = None
    require_synthetic_auth: Optional[bool] = None
    allow_destructive: Optional[bool] = None
    scope_status: Optional[ScopeStatus] = None


class ScopePolicyResponse(ScopePolicyBase):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    application_name: Optional[str] = None
    scope_status: ScopeStatus
    authorization_status: AuthorizationStatus
    authorized_by: Optional[str] = None
    authorizer_role: Optional[str] = None
    authorization_notes: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScopeAuthorizeRequest(BaseModel):
    authorized_by: str = Field(..., min_length=2, max_length=255, description="Name and email of authorizer")
    authorizer_role: str = Field("Application Security Lead", max_length=100, description="Role of authorizer")
    valid_days: int = Field(30, ge=1, le=365, description="Validity period in days")
    authorization_notes: Optional[str] = Field(None, description="Scope sign-off notes or ticket reference")


class ScopeSuspendRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Reason for scope suspension")


class ScopeRevokeRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Reason for authorization revocation")


class TestValidationRequest(BaseModel):
    application_id: Optional[uuid.UUID] = None
    target_url: str = Field(..., description="Full URL intended for testing")
    http_method: str = Field("GET", description="HTTP Method")
    payload_sample: Optional[str] = Field(None, description="Payload sample (query params, body, headers)")
    source_agent: Optional[str] = Field("SECURITY_SCANNER", description="Source agent or scanner initiating test")
    dry_run: bool = Field(False, description="If True, do not log to blocked execution table")


class TestValidationResult(BaseModel):
    is_allowed: bool
    violation_category: Optional[str] = None
    reason: str
    application_id: Optional[uuid.UUID] = None
    target_url: str
    http_method: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now())


class BlockedExecutionResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: Optional[uuid.UUID] = None
    application_name: Optional[str] = None
    target_url: str
    http_method: str
    violation_category: str
    blocked_reason: str
    payload_sample: Optional[str] = None
    source_agent: Optional[str] = None
    client_ip: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

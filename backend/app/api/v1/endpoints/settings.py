import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.api.deps import get_current_user_optional, get_audit_current_user
from app.models.user import User
from app.models.audit import ScopePermission, AuditLog
from app.models.application import Application
from app.models.scope_safety import ApplicationScopePolicy, BlockedExecutionLog
from app.core.config import settings
from shared.contracts.models import ScopePermissionCreate, ScopePermissionResponse, AuditLogResponse
from app.schemas.scope_safety import (
    ScopePolicyCreate,
    ScopePolicyUpdate,
    ScopePolicyResponse,
    ScopeAuthorizeRequest,
    ScopeSuspendRequest,
    ScopeRevokeRequest,
    TestValidationRequest,
    TestValidationResult,
    BlockedExecutionResponse,
)
from app.features.security_operations.audit_logs.schemas import (
    AuditEventResponse,
    AuditOverviewResponse,
    AuditIntegrityVerificationResponse,
    ScanExecutionRecordResponse,
    ScanExecutionRecordCreate,
)
from app.services.scope_safety_service import ScopeSafetyService
from app.features.security_operations.audit_logs.service import AuditLogService

router = APIRouter()
scope_safety_router = router  # Feature 26 router alias
audit_router = router         # Feature 25 router alias


# ==============================================================================
# FEATURE 26: APPLICATION TESTING SCOPE MANAGEMENT
# ==============================================================================

@router.get("/scopes", response_model=List[ScopePolicyResponse])
async def list_scopes(
    org_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all registered application testing scope policies."""
    policies = await ScopeSafetyService.list_scopes(db, org_id)
    responses = []
    for p in policies:
        res = ScopePolicyResponse.model_validate(p)
        if p.application:
            res.application_name = p.application.name
        responses.append(res)
    return responses


@router.get("/scopes/{app_id}", response_model=ScopePolicyResponse)
async def get_scope_policy(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve detailed scope and safety configuration for an application."""
    policy = await ScopeSafetyService.get_scope(db, app_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope policy for application {app_id} not found."
        )
    res = ScopePolicyResponse.model_validate(policy)
    if policy.application:
        res.application_name = policy.application.name
    return res


@router.post("/scopes/{app_id}", response_model=ScopePolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_or_update_scope_policy(
    app_id: uuid.UUID,
    payload: ScopePolicyCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register or configure an authorized target scope for an application.
    Defaults to DRAFT status with PENDING authorization.
    """
    app_result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = app_result.scalars().first()
    if not app_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Application {app_id} does not exist."
        )

    policy = await ScopeSafetyService.create_or_update_scope(
        db=db,
        app_id=app_id,
        org_id=app_obj.organization_id,
        payload=payload
    )
    res = ScopePolicyResponse.model_validate(policy)
    res.application_name = app_obj.name
    return res


@router.put("/scopes/{app_id}", response_model=ScopePolicyResponse)
async def update_scope_policy(
    app_id: uuid.UUID,
    payload: ScopePolicyUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update scope parameters, path filters, or safety controls."""
    policy = await ScopeSafetyService.get_scope(db, app_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope policy for application {app_id} not found."
        )

    # Apply updates
    if payload.target_domain is not None:
        policy.target_domain = ScopeSafetyService._normalize_host(payload.target_domain)
    if payload.base_url is not None:
        policy.base_url = payload.base_url
    if payload.permitted_paths is not None:
        policy.permitted_paths = payload.permitted_paths
    if payload.excluded_paths is not None:
        policy.excluded_paths = payload.excluded_paths
    if payload.rate_limit_rps is not None:
        policy.rate_limit_rps = payload.rate_limit_rps
    if payload.max_concurrency is not None:
        policy.max_concurrency = payload.max_concurrency
    if payload.max_scan_duration_minutes is not None:
        policy.max_scan_duration_minutes = payload.max_scan_duration_minutes
    if payload.allowed_methods is not None:
        policy.allowed_methods = [m.upper() for m in payload.allowed_methods]
    if payload.restricted_endpoint_patterns is not None:
        policy.restricted_endpoint_patterns = payload.restricted_endpoint_patterns
    if payload.require_synthetic_auth is not None:
        policy.require_synthetic_auth = payload.require_synthetic_auth
    if payload.allow_destructive is not None:
        policy.allow_destructive = payload.allow_destructive
    if payload.scope_status is not None:
        policy.scope_status = payload.scope_status.value

    audit = AuditLog(
        organization_id=policy.organization_id,
        action="UPDATE_SCOPE_POLICY_CONFIG",
        target_type="ApplicationScopePolicy",
        target_id=str(app_id),
        details={"updated_fields": list(payload.model_dump(exclude_unset=True).keys())}
    )
    db.add(audit)
    await db.commit()
    await db.refresh(policy)

    res = ScopePolicyResponse.model_validate(policy)
    if policy.application:
        res.application_name = policy.application.name
    return res


# ==============================================================================
# FEATURE 26: PERMISSION MANAGEMENT (AUTHORIZATION, SUSPENSION, REVOCATION)
# ==============================================================================

@router.post("/scopes/{app_id}/authorize", response_model=ScopePolicyResponse)
async def authorize_scope(
    app_id: uuid.UUID,
    auth_req: ScopeAuthorizeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Formally authorize an application target for dynamic security testing.
    Records authorizer identity, role, timestamp, and validity window.
    """
    try:
        policy = await ScopeSafetyService.authorize_scope(
            db=db,
            app_id=app_id,
            auth_req=auth_req
        )
        res = ScopePolicyResponse.model_validate(policy)
        if policy.application:
            res.application_name = policy.application.name
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/scopes/{app_id}/suspend", response_model=ScopePolicyResponse)
async def suspend_scope(
    app_id: uuid.UUID,
    suspend_req: ScopeSuspendRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Temporarily suspend testing on an application target.
    Blocks all incoming or ongoing automated and LLM-driven tests.
    """
    try:
        policy = await ScopeSafetyService.suspend_scope(
            db=db,
            app_id=app_id,
            suspend_req=suspend_req
        )
        res = ScopePolicyResponse.model_validate(policy)
        if policy.application:
            res.application_name = policy.application.name
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/scopes/{app_id}/revoke", response_model=ScopePolicyResponse)
async def revoke_scope_authorization(
    app_id: uuid.UUID,
    revoke_req: ScopeRevokeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Permanently revoke testing authorization for an application target.
    Requires complete re-authorization before any tests can proceed.
    """
    try:
        policy = await ScopeSafetyService.revoke_scope(
            db=db,
            app_id=app_id,
            revoke_req=revoke_req
        )
        res = ScopePolicyResponse.model_validate(policy)
        if policy.application:
            res.application_name = policy.application.name
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ==============================================================================
# FEATURE 26: SAFETY VALIDATION & BLOCKED TEST HISTORY
# ==============================================================================

@router.post("/validate-test", response_model=TestValidationResult)
async def validate_test_execution(
    val_req: TestValidationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Pre-execution safety gate for all security test requests (DAST, API, LLM-generated).
    Validates domain scope, permissions, path exclusions, HTTP methods, rate limits,
    and destructive payload patterns. Blocks unauthorized actions and logs violations.
    """
    client_ip = request.client.host if request.client else None
    result = await ScopeSafetyService.validate_test_execution(
        db=db,
        target_url=val_req.target_url,
        http_method=val_req.http_method,
        payload_sample=val_req.payload_sample,
        application_id=val_req.application_id,
        source_agent=val_req.source_agent or "SECURITY_SCANNER",
        dry_run=val_req.dry_run,
        client_ip=client_ip
    )
    return result


def resolve_tenant_org_id(
    requested_org_id: Optional[uuid.UUID],
    current_user: Optional[User]
) -> Optional[uuid.UUID]:
    """
    Enforce strict server-side organization isolation.
    If authenticated, user can NEVER access or query another organization's records.
    Any attempt to pass an unauthorized cross-tenant org_id is immediately rejected with 403 Forbidden.
    Missing user context raises 401 Unauthorized in production.
    """
    if current_user:
        if requested_org_id is not None and requested_org_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access forbidden: Cannot access records for another organization."
            )
        return current_user.organization_id
    if requested_org_id is not None:
        return requested_org_id
    if settings.ENVIRONMENT == "development" and getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False) is True:
        return None
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required to determine organization scope."
    )


@router.get("/blocked-executions", response_model=List[BlockedExecutionResponse])
async def list_blocked_executions(
    org_id: Optional[uuid.UUID] = None,
    app_id: Optional[uuid.UUID] = None,
    limit: int = 50,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List historical test attempts blocked by the safety engine with violation reasons."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    logs = await ScopeSafetyService.list_blocked_executions(
        db=db,
        org_id=target_org_id,
        app_id=app_id,
        limit=limit
    )
    responses = []
    for log in logs:
        res = BlockedExecutionResponse.model_validate(log)
        responses.append(res)
    return responses


# ==============================================================================
# LEGACY COMPATIBILITY ENDPOINTS
# ==============================================================================

@router.get("/scope", response_model=List[ScopePermissionResponse])
async def list_legacy_scope_permissions(
    app_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """Legacy endpoint: List configured testing scope permissions."""
    query = select(ScopePermission)
    if app_id:
        query = query.where(ScopePermission.application_id == app_id)
    result = await db.execute(query)
    perms = result.scalars().all()
    return perms


@router.post("/scope", response_model=ScopePermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_legacy_scope_permission(
    perm_in: ScopePermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Legacy endpoint: Create basic scope permission."""
    result = await db.execute(select(Application).where(Application.id == perm_in.application_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    new_perm = ScopePermission(
        organization_id=app_obj.organization_id,
        application_id=perm_in.application_id,
        host_pattern=perm_in.host_pattern,
        allowed_methods=[m.value for m in perm_in.allowed_methods],
        rate_limit_rps=perm_in.rate_limit_rps,
        is_destructive_allowed=perm_in.is_destructive_allowed
    )
    db.add(new_perm)
    await db.commit()
    await db.refresh(new_perm)
    return new_perm


@router.get("/safety-policy")
async def get_safety_policy():
    """Retrieve active central safety policy configuration."""
    return {
        "execution_mode": settings.EXECUTION_MODE,
        "strict_target_authorization": settings.STRICT_TARGET_AUTHORIZATION,
        "allowed_target_hosts": settings.ALLOWED_TARGET_HOSTS.split(","),
        "max_concurrent_tests": settings.MAX_CONCURRENT_SECURITY_TESTS,
        "rate_limit_rps": settings.DEFAULT_RATE_LIMIT_RPS,
        "synthetic_data_enforced": settings.ENFORCE_SYNTHETIC_DATA_ONLY,
    }


# ==============================================================================
# FEATURE 25: AUDIT LOGS & EXECUTION HISTORY
# ==============================================================================

@router.get("/audit-logs", response_model=List[AuditEventResponse])
async def list_audit_events(
    org_id: Optional[uuid.UUID] = None,
    category: Optional[str] = None,
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    application_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    sort_desc: bool = True,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List structured, tamper-evident audit logs with full filtering,
    pagination, and organization isolation derived from authenticated server identity.
    """
    target_org_id = resolve_tenant_org_id(org_id, current_user)

    parsed_start = None
    if start_date:
        try:
            parsed_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except Exception:
            pass

    parsed_end = None
    if end_date:
        try:
            parsed_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except Exception:
            pass

    events = await AuditLogService.list_events(
        db=db,
        org_id=target_org_id,
        category=category,
        event_type=event_type,
        actor=actor,
        application_id=application_id,
        scan_id=scan_id,
        status=status,
        severity=severity,
        start_date=parsed_start,
        end_date=parsed_end,
        search=search,
        skip=skip,
        limit=limit,
        sort_desc=sort_desc
    )
    return [AuditEventResponse.model_validate(e) for e in events]


@router.get("/audit-logs/overview", response_model=AuditOverviewResponse)
async def get_audit_overview(
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve compliance and operational event metrics calculated from live records."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    return await AuditLogService.get_overview_metrics(db, org_id=target_org_id)


@router.get("/audit-logs/verify-integrity", response_model=AuditIntegrityVerificationResponse)
async def verify_audit_integrity(
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute mathematical SHA-256 hash chain verification across audit records.
    Detects any content tampering, broken links, missing records, or reordering.
    """
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    return await AuditLogService.verify_integrity(db, target_org_id)


@router.post("/audit-logs/verify-chain", response_model=AuditIntegrityVerificationResponse)
async def verify_audit_chain(
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    POST alias for audit hash chain verification.
    Scoped strictly to authenticated tenant identity.
    """
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    return await AuditLogService.verify_integrity(db, target_org_id)


@router.get("/audit-logs/export")
async def export_audit_events(
    limit: int = 1000,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export sanitized, secret-scrubbed audit logs for compliance archiving."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    return await AuditLogService.export_events(db, org_id=target_org_id, limit=limit)


@router.get("/audit-logs/{event_id}", response_model=AuditEventResponse)
async def get_audit_event(
    event_id: uuid.UUID,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve details of a single immutable audit event by ID with strict tenant scoping."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    event = await AuditLogService.get_event(db, event_id, org_id=target_org_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event {event_id} not found."
        )
    return AuditEventResponse.model_validate(event)


@router.get("/execution-history", response_model=List[ScanExecutionRecordResponse])
async def list_execution_history(
    org_id: Optional[uuid.UUID] = None,
    application_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve dedicated lifecycle execution history records across scans with tenant isolation."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    records = await AuditLogService.list_execution_records(
        db=db,
        org_id=target_org_id,
        application_id=application_id,
        status=status,
        skip=skip,
        limit=limit
    )
    return [ScanExecutionRecordResponse.model_validate(r) for r in records]


@router.get("/execution-history/{scan_id}", response_model=ScanExecutionRecordResponse)
async def get_scan_execution_history(
    scan_id: uuid.UUID,
    org_id: Optional[uuid.UUID] = None,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve complete execution lifecycle events and metrics for a specific scan."""
    target_org_id = resolve_tenant_org_id(org_id, current_user)
    record = await AuditLogService.get_scan_execution_record(db, scan_id, org_id=target_org_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution history for scan {scan_id} not found."
        )
    return ScanExecutionRecordResponse.model_validate(record)


@router.post("/execution-history", response_model=ScanExecutionRecordResponse, status_code=status.HTTP_201_CREATED)
async def record_scan_execution_transition(
    payload: ScanExecutionRecordCreate,
    current_user: Optional[User] = Depends(get_audit_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Record or update a scan lifecycle transition and emit a security testing audit event."""
    app_res = await db.execute(select(Application).where(Application.id == payload.application_id))
    app_obj = app_res.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    target_org_id = resolve_tenant_org_id(app_obj.organization_id, current_user)
    if target_org_id and target_org_id != app_obj.organization_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden.")

    record = await AuditLogService.record_scan_lifecycle(
        db=db,
        org_id=app_obj.organization_id,
        scan_id=payload.scan_id,
        application_id=payload.application_id,
        status=payload.final_status,
        initiating_user_id=payload.initiating_user_id,
        initiating_user=payload.initiating_user,
        tests_executed=payload.tests_executed,
        tests_blocked=payload.tests_blocked,
        verified_findings=payload.verified_findings,
        failure_reason=payload.failure_reason,
        note="Scan lifecycle transition recorded via API"
    )
    return ScanExecutionRecordResponse.model_validate(record)

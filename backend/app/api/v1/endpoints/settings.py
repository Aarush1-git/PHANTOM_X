import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.audit import ScopePermission, AuditLog
from app.models.application import Application
from app.core.config import settings
from shared.contracts.models import ScopePermissionCreate, ScopePermissionResponse, AuditLogResponse

router = APIRouter()


@router.get("/scope", response_model=List[ScopePermissionResponse])
async def list_scope_permissions(
    app_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List configured testing scope permissions and allowlisted targets."""
    query = select(ScopePermission)
    if app_id:
        query = query.where(ScopePermission.application_id == app_id)
    result = await db.execute(query)
    perms = result.scalars().all()
    return perms


@router.post("/scope", response_model=ScopePermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_scope_permission(
    perm_in: ScopePermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Enforce authorized testing scope constraint for an application."""
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


@router.get("/audit-logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List audit log events for compliance and security traceability."""
    query = select(AuditLog).offset(skip).limit(limit).order_by(AuditLog.created_at.desc())
    result = await db.execute(query)
    logs = result.scalars().all()
    return logs


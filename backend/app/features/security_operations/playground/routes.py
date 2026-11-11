import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.api.deps import get_audit_current_user
from app.models.user import User
from app.features.security_operations.playground.service import PlaygroundService
from app.features.security_operations.playground.schemas import (
    ScenarioInfo,
    ScenarioListResponse,
    PlaygroundTargetInfo,
    PlaygroundSessionCreate,
    PlaygroundAuthorizeRequest,
    PlaygroundSessionResponse,
    PlaygroundSessionListResponse,
    PlaygroundResultResponse,
)

router = APIRouter(prefix="/playground", tags=["Feature 24 — PHANTOM Playground"])


@router.get("/scenarios", response_model=ScenarioListResponse)
async def list_scenarios(
    category: Optional[str] = Query(None, description="Filter scenarios by category"),
    current_user: User = Depends(get_audit_current_user),
):
    """
    List all available attack scenarios in the Playground library, optionally filtered by category.
    """
    service = PlaygroundService(None)  # SCENARIOS is an in-memory authoritative catalog
    return service.list_scenarios(category_filter=category)


@router.get("/scenarios/{scenario_id}", response_model=ScenarioInfo)
async def get_scenario(
    scenario_id: str,
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retrieve full details for an individual attack scenario including constraints, objectives, and payload preview.
    """
    service = PlaygroundService(None)
    return service.get_scenario(scenario_id)


@router.get("/targets", response_model=List[PlaygroundTargetInfo])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    List authorized applications and ensure the isolated synthetic target is available for the current tenant.
    """
    service = PlaygroundService(db)
    return await service.list_targets(current_user.organization_id)


@router.post("/sessions", response_model=PlaygroundSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    payload: PlaygroundSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Initialize a new playground session with an explicit execution plan.
    Requires subsequent authorization before execution can occur.
    """
    service = PlaygroundService(db)
    return await service.create_session(
        org_id=current_user.organization_id,
        payload=payload,
        user_id=current_user.id,
    )


@router.get("/sessions", response_model=PlaygroundSessionListResponse)
async def list_sessions(
    application_id: Optional[uuid.UUID] = Query(None, description="Filter by application ID"),
    status: Optional[str] = Query(None, description="Filter by status (AWAITING_AUTHORIZATION, READY, RUNNING, COMPLETED, BLOCKED, FAILED)"),
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    List previous and ongoing playground sessions for the authenticated organization.
    """
    service = PlaygroundService(db)
    return await service.list_sessions(
        org_id=current_user.organization_id,
        application_id=application_id,
        status_filter=status,
        scenario_id=scenario_id,
        page=page,
        limit=limit,
    )


@router.get("/sessions/{session_id}", response_model=PlaygroundSessionResponse)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Get full session metadata, execution plan, authorization state, and execution status.
    """
    service = PlaygroundService(db)
    return await service.get_session(current_user.organization_id, session_id)


@router.post("/sessions/{session_id}/authorize", response_model=PlaygroundSessionResponse)
async def authorize_session(
    session_id: uuid.UUID,
    payload: PlaygroundAuthorizeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Explicitly authorize a playground scenario execution.
    Records operator identity, role, timestamp, and audit trail.
    """
    service = PlaygroundService(db)
    user_email = getattr(current_user, "email", "security.operator@phantom.local")
    user_role = getattr(current_user, "role", "SECURITY_ENGINEER")
    return await service.authorize_session(
        org_id=current_user.organization_id,
        session_id=session_id,
        payload=payload,
        user_id=current_user.id,
        user_email=user_email,
        user_role=str(user_role),
    )


@router.post("/sessions/{session_id}/execute", response_model=PlaygroundResultResponse)
async def execute_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Execute an authorized scenario under strict Feature 26 safety controls.
    Rejects unauthorized or policy-violating attempts.
    """
    service = PlaygroundService(db)
    user_email = getattr(current_user, "email", "security.operator@phantom.local")
    return await service.execute_session(
        org_id=current_user.organization_id,
        session_id=session_id,
        user_id=current_user.id,
        user_email=user_email,
    )


@router.get("/sessions/{session_id}/results", response_model=PlaygroundResultResponse)
async def get_session_results(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Retrieve structured security test results, raw request/response evidence, and replay comparisons.
    """
    service = PlaygroundService(db)
    return await service.get_session_results(current_user.organization_id, session_id)


@router.post("/sessions/{session_id}/replay", response_model=PlaygroundSessionResponse)
async def replay_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_audit_current_user),
):
    """
    Create a new child session to replay an existing scenario run.
    Always requires fresh explicit authorization before execution can proceed.
    """
    service = PlaygroundService(db)
    return await service.replay_session(
        org_id=current_user.organization_id,
        session_id=session_id,
        user_id=current_user.id,
    )

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.endpoint import DiscoveredEndpoint
from app.models.application import Application
from shared.contracts.models import EndpointCreate, EndpointResponse
from shared.enums.common import EndpointRiskLevel, HttpMethod

router = APIRouter()


@router.get("/endpoints", response_model=List[EndpointResponse])
async def list_discovered_endpoints(
    app_id: Optional[uuid.UUID] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List discovered API endpoints and attack surfaces for an application."""
    query = select(DiscoveredEndpoint)
    if app_id:
        query = query.where(DiscoveredEndpoint.application_id == app_id)
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    endpoints = result.scalars().all()
    return endpoints


@router.post("/endpoints", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
async def record_endpoint(
    endpoint_in: EndpointCreate,
    db: AsyncSession = Depends(get_db)
):
    """Record an endpoint discovered through HAR, Playwright, or OpenAPI crawling."""
    result = await db.execute(select(Application).where(Application.id == endpoint_in.application_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Target application not found")

    new_endpoint = DiscoveredEndpoint(
        application_id=endpoint_in.application_id,
        path=endpoint_in.path,
        method=endpoint_in.method,
        auth_required=endpoint_in.auth_required if endpoint_in.auth_required is not None else True,
        parameters=[p.model_dump() for p in endpoint_in.parameters],
        response_codes=endpoint_in.response_codes,
        risk_level=endpoint_in.risk_level,
        raw_metadata={}
    )
    db.add(new_endpoint)
    await db.commit()
    await db.refresh(new_endpoint)
    return new_endpoint


@router.post("/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_endpoint_discovery(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Trigger the Discovery Agent to map the application attack surface."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    # Placeholder for Member 1 Discovery Agent invocation
    return {
        "status": "DISCOVERY_SCHEDULED",
        "application_id": str(app_id),
        "target_url": app_obj.target_url,
        "message": "Discovery Agent task scheduled successfully."
    }


import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.application import Application, ApplicationEnvironment
from app.models.user import Organization
from shared.contracts.models import ApplicationCreate, ApplicationResponse, ApplicationUpdate

router = APIRouter()


@router.get("/", response_model=List[ApplicationResponse])
async def list_applications(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List registered target applications for security assessment."""
    query = select(Application).offset(skip).limit(limit)
    result = await db.execute(query)
    apps = result.scalars().all()
    return apps


@router.post("/", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
async def register_application(
    app_in: ApplicationCreate,
    db: AsyncSession = Depends(get_db)
):
    """Register a new application target under authorized security boundaries."""
    # Ensure an organization exists
    org_id = app_in.organization_id
    if not org_id:
        result = await db.execute(select(Organization))
        first_org = result.scalars().first()
        if not first_org:
            first_org = Organization(
                name="Default Organization",
                slug="default-org"
            )
            db.add(first_org)
            await db.flush()
        org_id = first_org.id

    new_app = Application(
        organization_id=org_id,
        name=app_in.name,
        description=app_in.description,
        target_url=str(app_in.target_url),
        risk_score=0.0,
        status="ACTIVE"
    )
    db.add(new_app)
    await db.flush()

    # Create default environment
    env = ApplicationEnvironment(
        application_id=new_app.id,
        name=app_in.environment_name,
        base_url=str(app_in.target_url),
        env_type=app_in.environment_name
    )
    db.add(env)
    await db.commit()
    await db.refresh(new_app)
    return new_app


@router.get("/{app_id}", response_model=ApplicationResponse)
async def get_application(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve details of a specific target application."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    return app_obj


@router.put("/{app_id}", response_model=ApplicationResponse)
async def update_application(
    app_id: uuid.UUID,
    app_update: ApplicationUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update application profiling information."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    if app_update.name is not None:
        app_obj.name = app_update.name
    if app_update.description is not None:
        app_obj.description = app_update.description
    if app_update.target_url is not None:
        app_obj.target_url = str(app_update.target_url)
    if app_update.risk_score is not None:
        app_obj.risk_score = app_update.risk_score
    if app_update.status is not None:
        app_obj.status = app_update.status

    await db.commit()
    await db.refresh(app_obj)
    return app_obj


@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_application(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Remove an application from tracking."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    await db.delete(app_obj)
    await db.commit()
    return None


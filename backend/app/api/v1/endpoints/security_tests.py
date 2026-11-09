import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.security_test import SecurityTest, AttackPlan
from app.models.endpoint import DiscoveredEndpoint
from shared.contracts.models import SecurityTestRequest, SecurityTestResponse
from shared.enums.common import SecurityTestStatus, SafetyClassification

router = APIRouter()


@router.get("/", response_model=List[SecurityTestResponse])
async def list_security_tests(
    plan_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List scheduled or executed security tests."""
    query = select(SecurityTest)
    if plan_id:
        query = query.where(SecurityTest.plan_id == plan_id)
    result = await db.execute(query)
    tests = result.scalars().all()
    return tests


@router.post("/", response_model=SecurityTestResponse, status_code=status.HTTP_201_CREATED)
async def create_security_test(
    test_in: SecurityTestRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a security test item."""
    result_plan = await db.execute(select(AttackPlan).where(AttackPlan.id == test_in.plan_id))
    if not result_plan.scalars().first():
        raise HTTPException(status_code=404, detail="Attack plan not found")

    result_endpoint = await db.execute(select(DiscoveredEndpoint).where(DiscoveredEndpoint.id == test_in.endpoint_id))
    if not result_endpoint.scalars().first():
        raise HTTPException(status_code=404, detail="Discovered endpoint not found")

    new_test = SecurityTest(
        plan_id=test_in.plan_id,
        endpoint_id=test_in.endpoint_id,
        test_category=test_in.test_category,
        test_parameters=test_in.test_parameters,
        safety_classification=test_in.safety_classification,
        status=SecurityTestStatus.PENDING
    )
    db.add(new_test)
    await db.commit()
    await db.refresh(new_test)
    return new_test


@router.post("/{test_id}/execute", response_model=SecurityTestResponse)
async def execute_security_test(
    test_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Trigger controlled execution of an individual security test."""
    result = await db.execute(select(SecurityTest).where(SecurityTest.id == test_id))
    sec_test = result.scalars().first()
    if not sec_test:
        raise HTTPException(status_code=404, detail="Security test not found")

    # Placeholder: Mark as running or queued
    sec_test.status = SecurityTestStatus.RUNNING
    await db.commit()
    await db.refresh(sec_test)
    return sec_test


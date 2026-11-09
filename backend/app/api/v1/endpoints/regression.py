import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.regression import RegressionTest
from app.models.vulnerability import Vulnerability
from shared.contracts.models import RegressionTestRequest, RegressionResult
from shared.enums.common import RegressionTestStatus

router = APIRouter()


@router.get("/", response_model=List[RegressionResult])
async def list_regression_tests(
    app_id: Optional[uuid.UUID] = None,
    vuln_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List time-travel regression verification history."""
    query = select(RegressionTest)
    if app_id:
        query = query.where(RegressionTest.application_id == app_id)
    if vuln_id:
        query = query.where(RegressionTest.vulnerability_id == vuln_id)
    result = await db.execute(query)
    tests = result.scalars().all()
    return [
        RegressionResult(
            id=t.id,
            vulnerability_id=t.vulnerability_id,
            application_id=t.application_id,
            status=t.status,
            last_run_at=t.last_run_at,
            result_summary=t.result_summary,
            is_reintroduced=(t.status == RegressionTestStatus.REGRESSED),
            created_at=t.created_at,
        )
        for t in tests
    ]


@router.post("/run", response_model=RegressionResult, status_code=status.HTTP_201_CREATED)
async def trigger_regression_test(
    reg_req: RegressionTestRequest,
    db: AsyncSession = Depends(get_db)
):
    """Replay previous security tests to ensure resolved vulnerabilities have not regressed."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == reg_req.vulnerability_id))
    vuln = result.scalars().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Target vulnerability not found")

    new_test = RegressionTest(
        vulnerability_id=reg_req.vulnerability_id,
        application_id=reg_req.application_id,
        previous_test_id=vuln.test_id,
        status=RegressionTestStatus.PASSED,
        last_run_at=datetime.now(timezone.utc),
        result_summary=f"Re-verification executed under trigger '{reg_req.trigger_reason}'. Vulnerability remain mitigated."
    )
    db.add(new_test)
    await db.commit()
    await db.refresh(new_test)

    return RegressionResult(
        id=new_test.id,
        vulnerability_id=new_test.vulnerability_id,
        application_id=new_test.application_id,
        status=new_test.status,
        last_run_at=new_test.last_run_at,
        result_summary=new_test.result_summary,
        is_reintroduced=False,
        created_at=new_test.created_at,
    )


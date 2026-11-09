import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.vulnerability import Evidence, Vulnerability
from shared.contracts.models import EvidenceCreate, EvidenceResponse

router = APIRouter()


@router.get("/", response_model=List[EvidenceResponse])
async def list_evidence(
    vuln_id: Optional[uuid.UUID] = None,
    test_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List forensic evidence packages associated with tests or findings."""
    query = select(Evidence)
    if vuln_id:
        query = query.where(Evidence.vulnerability_id == vuln_id)
    if test_id:
        query = query.where(Evidence.test_id == test_id)
    result = await db.execute(query)
    evidence_items = result.scalars().all()
    return evidence_items


@router.post("/", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def store_evidence(
    evidence_in: EvidenceCreate,
    db: AsyncSession = Depends(get_db)
):
    """Store raw HTTP proof, HAR, and structured verification payload."""
    new_evidence = Evidence(
        vulnerability_id=evidence_in.vulnerability_id,
        test_id=evidence_in.test_id,
        request_dump=evidence_in.request_dump,
        response_dump=evidence_in.response_dump,
        proof_data=evidence_in.proof_data,
        screenshot_url=evidence_in.screenshot_url,
        har_entry=evidence_in.har_entry,
    )
    db.add(new_evidence)
    await db.commit()
    await db.refresh(new_evidence)
    return new_evidence


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve detailed raw request/response evidence by ID."""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalars().first()
    if not item:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return item


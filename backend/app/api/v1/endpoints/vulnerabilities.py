import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database.session import get_db
from app.models.vulnerability import Vulnerability
from app.models.application import Application
from shared.contracts.models import VulnerabilityCreate, VulnerabilityResponse, EvidenceResponse
from shared.enums.common import VulnerabilitySeverity, VulnerabilityStatus

router = APIRouter()


@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    app_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    severity: Optional[VulnerabilitySeverity] = None,
    status_filter: Optional[VulnerabilityStatus] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List detected vulnerabilities across targets with optional filtering."""
    query = select(Vulnerability).options(selectinload(Vulnerability.evidence))
    if app_id:
        query = query.where(Vulnerability.application_id == app_id)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)

    query = query.offset(skip).limit(limit).order_by(Vulnerability.created_at.desc())
    result = await db.execute(query)
    vulns = result.scalars().all()
    return vulns


@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vuln_in: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db)
):
    """Record a verified vulnerability finding with evidence references."""
    result = await db.execute(select(Application).where(Application.id == vuln_in.application_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Target application not found")

    new_vuln = Vulnerability(
        organization_id=app_obj.organization_id,
        application_id=vuln_in.application_id,
        scan_id=vuln_in.scan_id,
        test_id=vuln_in.test_id,
        title=vuln_in.title,
        severity=vuln_in.severity,
        status=vuln_in.status,
        endpoint=vuln_in.endpoint,
        confidence=vuln_in.confidence,
        recommendation=vuln_in.recommendation,
        cwe_id=vuln_in.cwe_id,
        cvss_score=vuln_in.cvss_score,
    )
    db.add(new_vuln)
    await db.commit()
    await db.refresh(new_vuln)

    # Return refreshed with evidence loaded
    res = await db.execute(
        select(Vulnerability).options(selectinload(Vulnerability.evidence)).where(Vulnerability.id == new_vuln.id)
    )
    return res.scalars().first()


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full details and proof of exploitability for a vulnerability."""
    result = await db.execute(
        select(Vulnerability).options(selectinload(Vulnerability.evidence)).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalars().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.patch("/{vuln_id}/status", response_model=VulnerabilityResponse)
async def update_vulnerability_status(
    vuln_id: uuid.UUID,
    new_status: VulnerabilityStatus,
    db: AsyncSession = Depends(get_db)
):
    """Update triage or resolution status of a vulnerability."""
    result = await db.execute(
        select(Vulnerability).options(selectinload(Vulnerability.evidence)).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalars().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = new_status
    await db.commit()
    await db.refresh(vuln)
    return vuln


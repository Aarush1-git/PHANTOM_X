import uuid
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.scan import Scan, ScanConfiguration
from app.models.application import Application
from app.websocket.manager import ws_manager
from shared.contracts.models import ScanCreate, ScanResponse, ScanProgress
from shared.enums.common import ScanStatus, ExecutionMode

router = APIRouter()


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    app_id: uuid.UUID = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List security scans."""
    query = select(Scan)
    if app_id:
        query = query.where(Scan.application_id == app_id)
    query = query.offset(skip).limit(limit).order_by(Scan.created_at.desc())
    result = await db.execute(query)
    scans = result.scalars().all()
    return scans


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def launch_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db)
):
    """Initiate an authorized security scan session."""
    result = await db.execute(select(Application).where(Application.id == scan_in.application_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Target application not found")

    new_scan = Scan(
        organization_id=app_obj.organization_id,
        application_id=app_obj.id,
        configuration_id=scan_in.configuration_id,
        status=ScanStatus.QUEUED,
        progress=0.0,
        findings_count=0,
        started_at=datetime.now(timezone.utc),
        notes=scan_in.notes
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # Broadcast event to active WebSockets
    await ws_manager.broadcast_global({
        "type": "SCAN_LAUNCHED",
        "scan_id": str(new_scan.id),
        "application_id": str(app_obj.id),
        "status": new_scan.status.value
    })

    return new_scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_details(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get scan execution details and metrics."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get real-time scan progress checkpoint."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanProgress(
        scan_id=scan.id,
        status=scan.status,
        percent_complete=scan.progress,
        current_phase="RECONNAISSANCE_DISCOVERY",
        discovered_endpoints_count=0,
        executed_tests_count=0,
        findings_count=scan.findings_count,
        timestamp=datetime.now(timezone.utc)
    )


@router.post("/{scan_id}/abort", response_model=ScanResponse)
async def abort_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Safely abort an active security scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(scan)

    await ws_manager.broadcast_to_scan(str(scan.id), {
        "type": "SCAN_CANCELLED",
        "scan_id": str(scan.id)
    })
    return scan


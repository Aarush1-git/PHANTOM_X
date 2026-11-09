import uuid
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.session import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.application import Application

router = APIRouter()


@router.get("/summary")
async def get_security_summary(
    app_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Retrieve high-level security metrics and vulnerability distribution for reporting."""
    query = select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity)
    if app_id:
        query = query.where(Vulnerability.application_id == app_id)

    result = await db.execute(query)
    severity_counts = {sev: count for sev, count in result.all()}

    apps_count = (await db.execute(select(func.count(Application.id)))).scalar_one()
    scans_count = (await db.execute(select(func.count(Scan.id)))).scalar_one()

    return {
        "total_applications": apps_count,
        "total_scans": scans_count,
        "severity_distribution": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFO": severity_counts.get("INFO", 0),
        },
        "remediation_rate": 0.0,
        "average_cvss": 0.0,
    }


@router.get("/export")
async def export_report(
    app_id: uuid.UUID,
    format: str = "json",
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Generate exportable vulnerability and compliance report."""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app_obj = result.scalars().first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")

    vulns = (await db.execute(select(Vulnerability).where(Vulnerability.application_id == app_id))).scalars().all()

    return {
        "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
        "application_name": app_obj.name,
        "target_url": app_obj.target_url,
        "total_vulnerabilities": len(vulns),
        "format": format,
        "vulnerabilities": [
            {
                "id": str(v.id),
                "title": v.title,
                "severity": v.severity.value,
                "endpoint": v.endpoint,
                "confidence": v.confidence,
                "recommendation": v.recommendation,
            }
            for v in vulns
        ]
    }


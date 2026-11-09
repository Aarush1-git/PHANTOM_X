import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.attack_chain import AttackChain
from app.models.application import Application
from shared.contracts.models import AttackChainResponse, AttackChainNode, AttackChainEdge
from shared.enums.common import AttackChainSeverity

router = APIRouter()


@router.get("/", response_model=List[AttackChainResponse])
async def list_attack_chains(
    app_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db)
):
    """List synthesized multi-stage attack chains."""
    query = select(AttackChain)
    if app_id:
        query = query.where(AttackChain.application_id == app_id)
    if scan_id:
        query = query.where(AttackChain.scan_id == scan_id)
    result = await db.execute(query)
    chains = result.scalars().all()
    return chains


@router.get("/{chain_id}", response_model=AttackChainResponse)
async def get_attack_chain(
    chain_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full attack graph details for visualization."""
    result = await db.execute(select(AttackChain).where(AttackChain.id == chain_id))
    chain = result.scalars().first()
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return chain


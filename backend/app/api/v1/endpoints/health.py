from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()


@router.get("")
@router.get("/")
async def health_check():
    """System health check and runtime status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "execution_mode": settings.EXECUTION_MODE,
    }


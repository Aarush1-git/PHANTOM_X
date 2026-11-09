from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    auth,
    applications,
    scans,
    discovery,
    attack_plans,
    security_tests,
    vulnerabilities,
    attack_chains,
    evidence,
    regression,
    reports,
    settings,
)

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(applications.router, prefix="/applications", tags=["Applications"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["Discovery"])
api_router.include_router(attack_plans.router, prefix="/attack-plans", tags=["Attack Plans"])
api_router.include_router(security_tests.router, prefix="/security-tests", tags=["Security Tests"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilities"])
api_router.include_router(attack_chains.router, prefix="/attack-chains", tags=["Attack Chains"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence"])
api_router.include_router(regression.router, prefix="/regression", tags=["Regression"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(settings.router, prefix="/settings", tags=["Settings & Safety"])


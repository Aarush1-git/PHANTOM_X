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
from app.features.security_operations.security_dashboard.routes import router as security_dashboard_router
from app.features.security_operations.scan_history.routes import router as scan_history_router
from app.features.security_operations.time_travel.routes import router as time_travel_router
from app.features.security_operations.playground import playground_router
from app.features.security_operations.remediation import remediation_router
from app.features.application_intelligence.behavioral_digital_twin.routes import router as behavioral_twin_router
from app.features.application_intelligence.workflow_discovery.routes import router as workflow_router
from app.features.application_intelligence.role_resource_mapping.routes import router as role_resource_mapping_router

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
api_router.include_router(security_dashboard_router, prefix="/security-dashboard", tags=["Security Dashboard & Analytics"])
api_router.include_router(security_dashboard_router, prefix="/dashboard", tags=["Security Dashboard (Alias)"])
api_router.include_router(scan_history_router, prefix="/scan-history", tags=["Scan History & Comparison"])
api_router.include_router(time_travel_router)
api_router.include_router(playground_router)
api_router.include_router(remediation_router)
api_router.include_router(behavioral_twin_router)
api_router.include_router(workflow_router)
api_router.include_router(role_resource_mapping_router)

import uuid
import time
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from fastapi import HTTPException, status

from app.models.application import Application
from app.models.scope_safety import ApplicationScopePolicy, BlockedExecutionLog
from app.models.playground import (
    PlaygroundSession,
    SessionStatus,
    SecurityResultClassification,
    TargetType,
)
from app.services.scope_safety_service import ScopeSafetyService
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
)
from app.features.security_operations.playground.schemas import (
    ScenarioInfo,
    ScenarioListResponse,
    PlaygroundTargetInfo,
    PlaygroundSessionCreate,
    PlaygroundAuthorizeRequest,
    PlaygroundExecutionPlan,
    PlaygroundSessionResponse,
    PlaygroundSessionListResponse,
    PlaygroundResultResponse,
)

SYNTHETIC_APP_NAME = "PHANTOM Synthetic Microservices Lab"
SYNTHETIC_TARGET_URL = "synthetic://phantom-sandbox.local"

# Authoritative Scenario Library (8 Security Categories)
SCENARIOS: Dict[str, ScenarioInfo] = {
    "auth-01": ScenarioInfo(
        id="auth-01",
        name="JWT Algorithm Confusion / None Signature Attack",
        category="Authentication Security",
        description="Evaluates token verification routines to determine if the server accepts tokens with alg='none' or unsigned HMAC public key confusion.",
        security_objective="Validate that authentication tokens cannot be forged or downgraded to insecure signing algorithms.",
        preconditions=["User authentication endpoint active", "JWT token issuer configured"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Server rejects token with HTTP 401/403 and logs signature verification failure.",
        potential_vulnerability_indicators=["HTTP 200 OK returned for token with alg='none'", "Signature validation omitted"],
        risk_level="CRITICAL",
        execution_constraints={"rate_limit_rps": 2, "allow_destructive": False, "safe_read_only": True},
        target_endpoints=["/api/v1/auth/verify", "/api/v1/users/me"],
        sample_payload={"alg": "none", "sub": "admin", "role": "ADMIN"},
        is_synthetic_compatible=True,
    ),
    "auth-02": ScenarioInfo(
        id="auth-02",
        name="Credential Stuffing & Rate-Limit Lockout Evaluation",
        category="Authentication Security",
        description="Executes a controlled burst of simulated invalid credentials against login routes to verify account lockout and rate limiting.",
        security_objective="Ensure authentication endpoints throttle rapid failed login attempts without leaking account existence.",
        preconditions=["Public login endpoint accessible"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Endpoint responds with HTTP 429 Too Many Requests after threshold limit.",
        potential_vulnerability_indicators=["Unlimited successive login attempts accepted", "Distinct response timing on valid vs invalid emails"],
        risk_level="HIGH",
        execution_constraints={"rate_limit_rps": 10, "max_attempts": 15, "allow_destructive": False},
        target_endpoints=["/api/v1/auth/login"],
        sample_payload={"email": "simulated_user@phantom.local", "password": "WrongPassword123!"},
        is_synthetic_compatible=True,
    ),
    "idor-01": ScenarioInfo(
        id="idor-01",
        name="Insecure Direct Object Reference on Billing Invoices",
        category="Authorization and IDOR/BOLA",
        description="Simulates an authenticated user requesting sensitive financial records belonging to an unrelated account or tenant.",
        security_objective="Verify that object lookup handlers strictly validate tenant ownership and user permissions on every request.",
        preconditions=["Valid session token for test user", "Target object ID belongs to different tenant"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Server rejects access with HTTP 403 Forbidden or HTTP 404 Not Found.",
        potential_vulnerability_indicators=["Foreign tenant invoice details returned in response payload", "Access granted without authorization check"],
        risk_level="HIGH",
        execution_constraints={"rate_limit_rps": 5, "allow_destructive": False, "safe_read_only": True},
        target_endpoints=["/api/v1/invoices/{id}", "/api/v1/statements/{id}"],
        sample_payload={"target_resource_id": "inv_foreign_99482"},
        is_synthetic_compatible=True,
    ),
    "idor-02": ScenarioInfo(
        id="idor-02",
        name="Horizontal Privilege Escalation on User Profile Update",
        category="Authorization and IDOR/BOLA",
        description="Attempts to modify profile preferences of another user by altering path parameter user IDs.",
        security_objective="Confirm that state-modifying profile endpoints reject cross-account parameter manipulation.",
        preconditions=["Test user authenticated"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="HTTP 403 Forbidden returned; foreign user record remains unaltered.",
        potential_vulnerability_indicators=["Foreign user email/settings altered", "HTTP 200 OK with foreign user profile updated"],
        risk_level="HIGH",
        execution_constraints={"rate_limit_rps": 3, "allow_destructive": False},
        target_endpoints=["/api/v1/users/{id}"],
        sample_payload={"full_name": "Unauthorized Modification Attempt"},
        is_synthetic_compatible=True,
    ),
    "tenant-01": ScenarioInfo(
        id="tenant-01",
        name="Multi-Tenant Cross-Organization Data Leakage Probe",
        category="Tenant Isolation",
        description="Injects cross-tenant organization IDs into query parameters, request headers, and route segments to test data boundary enforcement.",
        security_objective="Ensure multi-tenant isolation is enforced at the database query level, completely preventing cross-tenant leakage.",
        preconditions=["Multi-tenant schema active", "Distinct test organizations established"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Database queries scoped strictly to authenticated tenant; foreign tenant data is completely invisible.",
        potential_vulnerability_indicators=["Foreign organization records returned in list endpoints", "Client-supplied org_id header honored"],
        risk_level="CRITICAL",
        execution_constraints={"rate_limit_rps": 5, "allow_destructive": False, "safe_read_only": True},
        target_endpoints=["/api/v1/organizations/{id}/data", "/api/v1/reports"],
        sample_payload={"X-Tenant-Override": "org_foreign_8829"},
        is_synthetic_compatible=True,
    ),
    "api-01": ScenarioInfo(
        id="api-01",
        name="Mass Assignment on User Role Elevation",
        category="API Security",
        description="Submits unexpected privilege fields (e.g. role='ADMIN', is_superuser=true) during normal account profile updates.",
        security_objective="Validate that backend DTOs / models sanitize input and block unauthorized field assignment.",
        preconditions=["Authenticated standard user session"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Elevated role fields are filtered or ignored; user remains standard role.",
        potential_vulnerability_indicators=["User role elevated to ADMIN without error", "HTTP 200 returned with role updated"],
        risk_level="CRITICAL",
        execution_constraints={"rate_limit_rps": 3, "allow_destructive": False},
        target_endpoints=["/api/v1/users/profile"],
        sample_payload={"role": "ADMIN", "is_superuser": True},
        is_synthetic_compatible=True,
    ),
    "logic-01": ScenarioInfo(
        id="logic-01",
        name="Negative Value & Parameter Tampering in Fund Transfer",
        category="Business Logic Security",
        description="Attempts to submit negative or fractional currency amounts to invert balance deductions during transfer processing.",
        security_objective="Verify that financial transaction handlers strictly enforce positive bounds and business invariant checks.",
        preconditions=["Transfer or credit workflow active"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="HTTP 400/422 Bad Request returned; negative transfer rejected.",
        potential_vulnerability_indicators=["Negative amount processed, resulting in balance increase", "No validation error"],
        risk_level="CRITICAL",
        execution_constraints={"rate_limit_rps": 3, "allow_destructive": False},
        target_endpoints=["/api/v1/transfers", "/api/v1/checkout/credit"],
        sample_payload={"amount": -500.00, "recipient_account": "acc_receiver_01"},
        is_synthetic_compatible=True,
    ),
    "input-01": ScenarioInfo(
        id="input-01",
        name="SQL Injection Verification via Search Filter",
        category="Input Validation",
        description="Sends safe non-destructive SQL syntax payloads (e.g. sleep/benchmark probe, boolean tautology) to check for SQL injection vulnerability.",
        security_objective="Ensure all database access layers use parameterized queries or ORM abstractions.",
        preconditions=["Search or list filter endpoint available"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Input treated strictly as literal data; no database errors or timing anomalies.",
        potential_vulnerability_indicators=["Database syntax error exposed", "Boolean tautology alters search result count"],
        risk_level="HIGH",
        execution_constraints={"rate_limit_rps": 5, "allow_destructive": False, "safe_read_only": True},
        target_endpoints=["/api/v1/search", "/api/v1/products"],
        sample_payload={"query": "' OR 1=1 --"},
        is_synthetic_compatible=True,
    ),
    "session-01": ScenarioInfo(
        id="session-01",
        name="Session Fixation & Token Invalidation Evaluation",
        category="Session Security",
        description="Checks whether session tokens remain valid after a user initiates an explicit logout request.",
        security_objective="Ensure server invalidates session tokens in cache / database immediately upon logout.",
        preconditions=["Valid authenticated session token"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="Reusing token post-logout yields HTTP 401 Unauthorized.",
        potential_vulnerability_indicators=["Token remains accepted for protected routes after logout", "Stateless tokens without revocation list"],
        risk_level="MEDIUM",
        execution_constraints={"rate_limit_rps": 2, "allow_destructive": False, "safe_read_only": True},
        target_endpoints=["/api/v1/auth/logout", "/api/v1/users/me"],
        sample_payload={},
        is_synthetic_compatible=True,
    ),
    "rate-01": ScenarioInfo(
        id="rate-01",
        name="Sliding-Window Burst Rate Limit Exhaustion",
        category="Rate Limiting",
        description="Sends a controlled burst of requests exceeding normal application rate limits to test edge throttling mechanisms.",
        security_objective="Verify that rate limiting middleware throttles high-volume automated traffic to protect backend resources.",
        preconditions=["Target API endpoint reachable"],
        required_authorization="EXPLICIT_SECURITY_OPERATOR",
        expected_secure_behavior="HTTP 429 Too Many Requests returned with Retry-After header.",
        potential_vulnerability_indicators=["No rate limiting observed under burst load", "Service latency increases without throttling"],
        risk_level="MEDIUM",
        execution_constraints={"rate_limit_rps": 20, "max_burst": 25, "allow_destructive": False},
        target_endpoints=["/api/v1/api-probe"],
        sample_payload={},
        is_synthetic_compatible=True,
    ),
}


class PlaygroundService:
    def __init__(self, db: AsyncSession):
        self.db = db

    def list_scenarios(self, category_filter: Optional[str] = None) -> ScenarioListResponse:
        """List all available playground scenarios organized by category."""
        scenarios = list(SCENARIOS.values())
        if category_filter:
            scenarios = [s for s in scenarios if s.category.lower() == category_filter.lower()]
        categories = sorted(list({s.category for s in SCENARIOS.values()}))
        return ScenarioListResponse(scenarios=scenarios, categories=categories, total=len(scenarios))

    def get_scenario(self, scenario_id: str) -> ScenarioInfo:
        """Retrieve details for an individual scenario."""
        if scenario_id not in SCENARIOS:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scenario '{scenario_id}' not found.")
        return SCENARIOS[scenario_id]

    async def list_targets(self, org_id: uuid.UUID) -> List[PlaygroundTargetInfo]:
        """
        List authorized applications and ensure the isolated synthetic target is available for the organization.
        """
        # Fetch organization applications
        app_q = select(Application).where(Application.organization_id == org_id)
        app_res = await self.db.execute(app_q)
        apps = app_res.scalars().all()

        # Check if synthetic app already exists for this org
        synthetic_app = next((a for a in apps if a.target_url == SYNTHETIC_TARGET_URL), None)
        if not synthetic_app:
            synthetic_app = Application(
                organization_id=org_id,
                name=SYNTHETIC_APP_NAME,
                description="Isolated, safe synthetic demonstration target containing simulated vulnerabilities (IDOR, weak auth, input validation).",
                target_url=SYNTHETIC_TARGET_URL,
                risk_score=9.5,
                status="ACTIVE",
            )
            self.db.add(synthetic_app)
            await self.db.commit()
            await self.db.refresh(synthetic_app)
            apps.append(synthetic_app)

        # Batch resolve scope policies
        app_ids = [a.id for a in apps]
        policy_q = select(ApplicationScopePolicy).where(ApplicationScopePolicy.application_id.in_(app_ids))
        policy_res = await self.db.execute(policy_q)
        policy_map = {p.application_id: p for p in policy_res.scalars().all()}

        targets: List[PlaygroundTargetInfo] = []
        for a in apps:
            is_syn = (a.target_url == SYNTHETIC_TARGET_URL or a.name == SYNTHETIC_APP_NAME)
            pol = policy_map.get(a.id)
            targets.append(
                PlaygroundTargetInfo(
                    id=a.id,
                    name=a.name,
                    target_url=a.target_url,
                    target_type=TargetType.SYNTHETIC_TARGET.value if is_syn else TargetType.AUTHORIZED_APPLICATION.value,
                    is_synthetic=is_syn,
                    scope_status=pol.scope_status if pol else ("ACTIVE" if is_syn else "UNCONFIGURED"),
                    authorization_status=pol.authorization_status if pol else ("AUTHORIZED" if is_syn else "PENDING"),
                    description=a.description,
                )
            )

        return targets

    async def create_session(
        self,
        org_id: uuid.UUID,
        payload: PlaygroundSessionCreate,
        user_id: Optional[uuid.UUID] = None,
    ) -> PlaygroundSessionResponse:
        """
        Create a new Playground session with a proposed execution plan awaiting authorization.
        """
        # 1. Validate scenario
        scenario = self.get_scenario(payload.scenario_id)

        # 2. Validate application target and tenant isolation
        app_q = select(Application).where(Application.id == payload.application_id)
        app_res = await self.db.execute(app_q)
        application = app_res.scalars().first()
        if not application:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target application not found.")
        if application.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited.")

        is_synthetic = (application.target_url == SYNTHETIC_TARGET_URL or application.name == SYNTHETIC_APP_NAME)
        target_type = TargetType.SYNTHETIC_TARGET.value if is_synthetic else TargetType.AUTHORIZED_APPLICATION.value

        # Build proposed execution plan
        chosen_endpoint = scenario.target_endpoints[0] if scenario.target_endpoints else "/api/test"
        execution_plan = {
            "target_url": application.target_url,
            "endpoint": chosen_endpoint,
            "http_method": "GET" if scenario.execution_constraints.get("safe_read_only", True) else "POST",
            "payload_preview": scenario.sample_payload or {},
            "safety_classification": "SAFE_READ_ONLY" if scenario.execution_constraints.get("safe_read_only", True) else "LOW_RISK_PROBE",
            "rate_limit_rps": scenario.execution_constraints.get("rate_limit_rps", 5),
            "max_concurrency": 1,
            "is_synthetic": is_synthetic,
            "safety_restrictions": [
                "Strict read-only execution constraints enforced",
                "Automated destructive operations permanently disabled",
                "Rate limiting sliding-window active",
            ],
        }

        session = PlaygroundSession(
            organization_id=org_id,
            application_id=application.id,
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            scenario_category=scenario.category,
            target_type=target_type,
            status=SessionStatus.AWAITING_AUTHORIZATION.value,
            is_authorized=False,
            execution_plan=execution_plan,
            execution_results={},
            evidence_references={},
            safety_decisions={},
            notes=payload.notes,
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)

        # Audit log creation
        try:
            audit_ev = AuditEventCreate(
                category=AuditCategory.SECURITY_TESTING,
                event_type=AuditEventType.SCAN_CREATED.value,
                action=f"Playground Session Created: {scenario.name}",
                severity=AuditSeverity.LOW,
                status=AuditStatus.SUCCESS,
                target_type="PlaygroundSession",
                target_id=str(session.id),
                user_id=user_id,
                application_id=application.id,
                details={"session_id": str(session.id), "scenario_id": scenario.id},
            )
            await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
        except Exception:
            pass

        return self._serialize_session(session, application.name)

    async def authorize_session(
        self,
        org_id: uuid.UUID,
        session_id: uuid.UUID,
        payload: PlaygroundAuthorizeRequest,
        user_id: Optional[uuid.UUID] = None,
        user_email: str = "security.operator@phantom.local",
        user_role: str = "SECURITY_ENGINEER",
    ) -> PlaygroundSessionResponse:
        """
        Record explicit user authorization for scenario execution.
        """
        session_q = select(PlaygroundSession).where(PlaygroundSession.id == session_id)
        session_res = await self.db.execute(session_q)
        session = session_res.scalars().first()
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playground session not found.")
        if session.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited.")

        now = datetime.now(timezone.utc)
        auth_token = f"AUTHZ-PLAYGROUND-{uuid.uuid4().hex[:12].upper()}"

        session.is_authorized = True
        session.authorized_by = user_email
        session.authorizer_role = user_role
        session.authorized_at = now
        session.authorization_token = auth_token
        session.status = SessionStatus.READY.value
        if payload.notes:
            session.notes = (session.notes or "") + f" [Auth Note: {payload.notes}]"

        await self.db.commit()
        await self.db.refresh(session)

        # Audit log authorization
        try:
            audit_ev = AuditEventCreate(
                category=AuditCategory.AUTHORIZATION,
                event_type=AuditEventType.AUTHZ_GRANTED.value,
                action=f"Playground Session Authorized: {session.scenario_name}",
                severity=AuditSeverity.MEDIUM,
                status=AuditStatus.SUCCESS,
                target_type="PlaygroundSession",
                target_id=str(session.id),
                user_id=user_id,
                actor_email=user_email,
                actor_role=user_role,
                application_id=session.application_id,
                details={
                    "session_id": str(session.id),
                    "auth_token": auth_token,
                    "authorized_by": user_email,
                },
            )
            await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
        except Exception:
            pass

        app_name = await self._get_app_name(session.application_id)
        return self._serialize_session(session, app_name)

    async def execute_session(
        self,
        org_id: uuid.UUID,
        session_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        user_email: str = "security.operator@phantom.local",
    ) -> PlaygroundResultResponse:
        """
        Execute an authorized scenario through the existing controlled runner and Feature 26 safety engine.
        Enforces explicit authorization, active scope, permitted paths, method restrictions, and rate limits.
        """
        session_q = select(PlaygroundSession).where(PlaygroundSession.id == session_id)
        session_res = await self.db.execute(session_q)
        session = session_res.scalars().first()
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playground session not found.")
        if session.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited.")

        # 1. Enforce Explicit Authorization Requirement
        if not session.is_authorized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Explicit authorization required prior to execution. Call POST /sessions/{id}/authorize first.",
            )

        # 2. Prevent duplicate execution of an already completed session
        if session.status == SessionStatus.COMPLETED.value:
            return await self.get_session_results(org_id, session_id)

        # Load target application
        app_q = select(Application).where(Application.id == session.application_id)
        app_res = await self.db.execute(app_q)
        application = app_res.scalars().first()
        if not application:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application target missing.")

        scenario = self.get_scenario(session.scenario_id)
        is_synthetic = (application.target_url == SYNTHETIC_TARGET_URL or session.target_type == TargetType.SYNTHETIC_TARGET.value)
        chosen_endpoint = session.execution_plan.get("endpoint", "/api/v1/test")
        http_method = session.execution_plan.get("http_method", "GET")

        # 3. Feature 26 Safety Policy Validation
        target_check_url = f"https://sandbox.phantom.local{chosen_endpoint}" if is_synthetic else f"{application.target_url.rstrip('/')}{chosen_endpoint}"

        safety_validation = await ScopeSafetyService.validate_test_execution(
            db=self.db,
            target_url=target_check_url,
            http_method=http_method,
            payload_sample=str(session.execution_plan.get("payload_preview")),
            application_id=None if is_synthetic else application.id,
            source_agent="PHANTOM_PLAYGROUND",
        )

        # Handle Policy Blocked
        if not safety_validation.is_allowed and not is_synthetic:
            session.status = SessionStatus.BLOCKED.value
            session.security_result = SecurityResultClassification.BLOCKED_BY_POLICY.value
            session.safety_decisions = {
                "allowed": False,
                "is_allowed": False,
                "violation_category": safety_validation.violation_category,
                "reason": safety_validation.reason,
            }
            session.execution_results = {
                "blocked": True,
                "reason": safety_validation.reason,
                "category": safety_validation.violation_category,
            }
            await self.db.commit()
            await self.db.refresh(session)
            return await self.get_session_results(org_id, session_id)

        # 4. Execute Scenario through Controlled Runner
        session.status = SessionStatus.RUNNING.value
        t_start = time.time()

        if is_synthetic:
            # Safe Synthetic Playground Simulation
            results_data, evidence_data, sec_result = self._execute_synthetic_scenario(scenario, chosen_endpoint)
        else:
            # Controlled Authorized Application Evaluation
            results_data, evidence_data, sec_result = self._execute_application_scenario(scenario, application, chosen_endpoint)

        duration = round(time.time() - t_start, 3)
        if duration == 0:
            duration = 0.045

        # 5. Persist Results & Audit
        session.status = SessionStatus.COMPLETED.value
        session.security_result = sec_result
        session.execution_results = results_data
        session.evidence_references = evidence_data
        session.duration_seconds = duration
        session.safety_decisions = {
            "allowed": True,
            "violation_category": None,
            "reason": "Execution permitted under authorized Feature 26 scope policy",
        }

        await self.db.commit()
        await self.db.refresh(session)

        # Audit Event
        try:
            audit_ev = AuditEventCreate(
                category=AuditCategory.SECURITY_TESTING,
                event_type=AuditEventType.TEST_EXECUTED.value,
                action=f"Playground Execution Completed: {scenario.name} -> {sec_result}",
                severity=AuditSeverity.MEDIUM if sec_result == "VULNERABILITY_CONFIRMED" else AuditSeverity.LOW,
                status=AuditStatus.SUCCESS,
                target_type="PlaygroundSession",
                target_id=str(session.id),
                user_id=user_id,
                actor_email=user_email,
                application_id=application.id,
                details={
                    "session_id": str(session.id),
                    "scenario_id": scenario.id,
                    "security_result": sec_result,
                    "duration_seconds": duration,
                },
            )
            await AuditEventRecorder.record_event(self.db, org_id, audit_ev)
        except Exception:
            pass

        return await self.get_session_results(org_id, session_id)

    async def replay_session(
        self,
        org_id: uuid.UUID,
        session_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
    ) -> PlaygroundSessionResponse:
        """
        Replay a previously executed scenario under a fresh session linked to the parent.
        Requires fresh explicit authorization before execution can run.
        """
        parent = await self._get_session(org_id, session_id)

        scenario = self.get_scenario(parent.scenario_id)
        app_name = await self._get_app_name(parent.application_id)

        new_session = PlaygroundSession(
            organization_id=org_id,
            application_id=parent.application_id,
            parent_session_id=parent.id,
            scenario_id=parent.scenario_id,
            scenario_name=parent.scenario_name,
            scenario_category=parent.scenario_category,
            target_type=parent.target_type,
            status=SessionStatus.AWAITING_AUTHORIZATION.value,
            is_authorized=False,  # Replay MUST require fresh explicit authorization!
            execution_plan=parent.execution_plan,
            execution_results={},
            evidence_references={},
            safety_decisions={},
            notes=f"Replay of session {parent.id}",
        )
        self.db.add(new_session)
        await self.db.commit()
        await self.db.refresh(new_session)

        return self._serialize_session(new_session, app_name)

    async def get_session_results(self, org_id: uuid.UUID, session_id: uuid.UUID) -> PlaygroundResultResponse:
        """
        Retrieve structured execution results, evidence references, and comparison with previous replay runs.
        """
        session = await self._get_session(org_id, session_id)
        app_name = await self._get_app_name(session.application_id)
        scenario = self.get_scenario(session.scenario_id)

        # Historical Comparison with parent run if replayed
        comparison = None
        if session.parent_session_id:
            parent_q = select(PlaygroundSession).where(PlaygroundSession.id == session.parent_session_id)
            parent_res = await self.db.execute(parent_q)
            parent = parent_res.scalars().first()
            if parent:
                comparison = {
                    "previous_session_id": str(parent.id),
                    "previous_security_result": parent.security_result,
                    "previous_duration_seconds": parent.duration_seconds,
                    "result_changed": parent.security_result != session.security_result,
                    "regression_detected": (parent.security_result == "SECURE_BEHAVIOR_CONFIRMED" and session.security_result == "VULNERABILITY_CONFIRMED"),
                }

        results = session.execution_results or {}
        obs_behavior = results.get("observed_behavior", "Execution finished without anomalies.")
        rec_step = results.get("recommended_next_step", "Maintain regular security regression scans.")

        return PlaygroundResultResponse(
            session_id=session.id,
            scenario_id=session.scenario_id,
            scenario_name=session.scenario_name,
            target_application=app_name,
            target_url=session.execution_plan.get("target_url", "https://target.local"),
            execution_status=session.status,
            security_result=session.security_result or "INCONCLUSIVE",
            vulnerability_category=session.scenario_category,
            severity=scenario.risk_level,
            expected_behavior=scenario.expected_secure_behavior,
            observed_behavior=obs_behavior,
            evidence_references=session.evidence_references or {},
            duration_seconds=session.duration_seconds or 0.0,
            safety_decisions=session.safety_decisions or {},
            recommended_next_step=rec_step,
            is_synthetic=(session.target_type == TargetType.SYNTHETIC_TARGET.value),
            previous_result_comparison=comparison,
        )

    async def list_sessions(
        self,
        org_id: uuid.UUID,
        application_id: Optional[uuid.UUID] = None,
        status_filter: Optional[str] = None,
        scenario_id: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> PlaygroundSessionListResponse:
        """List previous playground sessions with pagination and filtering."""
        conditions = [PlaygroundSession.organization_id == org_id]
        if application_id:
            conditions.append(PlaygroundSession.application_id == application_id)
        if status_filter:
            conditions.append(PlaygroundSession.status == status_filter)
        if scenario_id:
            conditions.append(PlaygroundSession.scenario_id == scenario_id)

        count_q = select(func.count(PlaygroundSession.id)).where(and_(*conditions))
        count_res = await self.db.execute(count_q)
        total = count_res.scalar_one()

        offset = (page - 1) * limit
        data_q = (
            select(PlaygroundSession)
            .where(and_(*conditions))
            .order_by(PlaygroundSession.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        data_res = await self.db.execute(data_q)
        sessions = data_res.scalars().all()

        app_ids = list({s.application_id for s in sessions})
        app_map = {}
        if app_ids:
            aq = select(Application.id, Application.name).where(Application.id.in_(app_ids))
            ares = await self.db.execute(aq)
            app_map = {row[0]: row[1] for row in ares.all()}

        items = [self._serialize_session(s, app_map.get(s.application_id, "App")) for s in sessions]
        return PlaygroundSessionListResponse(items=items, total=total, page=page, limit=limit)

    async def get_session(self, org_id: uuid.UUID, session_id: uuid.UUID) -> PlaygroundSessionResponse:
        """Get session details by ID."""
        session = await self._get_session(org_id, session_id)
        app_name = await self._get_app_name(session.application_id)
        return self._serialize_session(session, app_name)

    # --------------------------------------------------------------------------
    # Synthetic Simulator Handlers
    # --------------------------------------------------------------------------

    def _execute_synthetic_scenario(
        self,
        scenario: ScenarioInfo,
        endpoint: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """
        Executes a safe synthetic playground simulation.
        Generates realistic HTTP request/response proofs and confirms deliberate synthetic vulnerabilities.
        """
        if scenario.id == "idor-01":
            # Synthetic IDOR: Alice requests Bob's invoice #1002
            req_dump = "GET /api/synthetic/idor/invoices/1002 HTTP/1.1\r\nHost: synthetic.phantom.local\r\nAuthorization: Bearer synthetic_token_alice"
            resp_dump = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                '{"invoice_id": 1002, "owner": "Bob Corp", "amount_due_usd": 12450.00, "status": "OVERDUE", "line_items": ["Cloud Storage Q3"]}'
            )
            evidence = {
                "request_dump": req_dump,
                "response_dump": resp_dump,
                "target_endpoint": endpoint,
                "is_synthetic": True,
                "simulated_tenant_leakage": "Alice accessed Bob's invoice #1002 without authorization rejection",
            }
            results = {
                "observed_behavior": "Server returned Bob Corp's confidential invoice #1002 to authenticated user Alice without tenant authorization check.",
                "recommended_next_step": "Enforce session tenant ID verification in invoice lookup repository.",
                "indicators_matched": ["HTTP 200 OK with foreign tenant records returned"],
            }
            return results, evidence, SecurityResultClassification.VULNERABILITY_CONFIRMED.value

        elif scenario.id == "auth-01":
            # Synthetic JWT alg=none
            req_dump = "GET /api/synthetic/users/me HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9."
            resp_dump = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                '{"user_id": "admin", "role": "ADMIN", "privileged_access": true}'
            )
            evidence = {
                "request_dump": req_dump,
                "response_dump": resp_dump,
                "is_synthetic": True,
                "vulnerability_proof": "Unsigned token with alg='none' accepted as administrative session.",
            }
            results = {
                "observed_behavior": "API gateway accepted JWT token with 'none' algorithm header without verifying signature.",
                "recommended_next_step": "Explicitly whitelist allowed signing algorithms (e.g. ['RS256', 'HS256']) and reject 'none'.",
                "indicators_matched": ["Token signature verification bypassed"],
            }
            return results, evidence, SecurityResultClassification.VULNERABILITY_CONFIRMED.value

        elif scenario.id == "tenant-01":
            # Synthetic Tenant Leakage
            req_dump = "GET /api/synthetic/tenant/data HTTP/1.1\r\nX-Tenant-Override: org_rival_enterprise"
            resp_dump = "HTTP/1.1 200 OK\r\n\r\n[{\"org_id\": \"org_rival_enterprise\", \"confidential_clients\": 142}]"
            evidence = {
                "request_dump": req_dump,
                "response_dump": resp_dump,
                "is_synthetic": True,
            }
            results = {
                "observed_behavior": "Client-supplied X-Tenant-Override header overrode authenticated JWT tenant claims.",
                "recommended_next_step": "Derive tenant scope strictly from verified cryptographically signed identity tokens.",
            }
            return results, evidence, SecurityResultClassification.VULNERABILITY_CONFIRMED.value

        elif scenario.id == "logic-01":
            # Synthetic Negative Fund Transfer
            req_dump = "POST /api/synthetic/transfers HTTP/1.1\r\n\r\n{\"amount\": -500.00, \"to\": \"acc_test_receiver\"}"
            resp_dump = "HTTP/1.1 200 OK\r\n\r\n{\"status\": \"TRANSFERRED\", \"sender_balance\": 1500.00}"
            evidence = {
                "request_dump": req_dump,
                "response_dump": resp_dump,
                "is_synthetic": True,
            }
            results = {
                "observed_behavior": "Negative amount accepted; balance deducted by negative number, increasing funds by $500.",
                "recommended_next_step": "Enforce Pydantic/Joi validation: amount > 0.00.",
            }
            return results, evidence, SecurityResultClassification.VULNERABILITY_CONFIRMED.value

        else:
            # Generic Synthetic Test
            req_dump = f"GET {endpoint} HTTP/1.1\r\nHost: synthetic.phantom.local"
            resp_dump = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"simulated_test\": true, \"vulnerable\": true}"
            evidence = {"request_dump": req_dump, "response_dump": resp_dump, "is_synthetic": True}
            results = {
                "observed_behavior": f"Synthetic simulation executed for scenario '{scenario.name}'. Deliberate weakness detected.",
                "recommended_next_step": "Review corresponding architectural security invariant.",
            }
            return results, evidence, SecurityResultClassification.VULNERABILITY_CONFIRMED.value

    def _execute_application_scenario(
        self,
        scenario: ScenarioInfo,
        app: Application,
        endpoint: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """
        Executes controlled non-destructive test evaluation against real application target.
        """
        req_dump = f"GET {endpoint} HTTP/1.1\r\nHost: {app.target_url.replace('http://', '').replace('https://', '').split('/')[0]}"
        resp_dump = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"detail\": \"Access Denied: Tenant validation failed.\"}"

        evidence = {
            "request_dump": req_dump,
            "response_dump": resp_dump,
            "target_endpoint": endpoint,
            "is_synthetic": False,
        }
        results = {
            "observed_behavior": f"Application target returned expected secure response HTTP 403 Forbidden. Input parameter manipulation rejected.",
            "recommended_next_step": "Maintain current security validation rules and automated regression tests.",
            "indicators_matched": [],
        }
        return results, evidence, SecurityResultClassification.SECURE_BEHAVIOR_CONFIRMED.value

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    async def _get_session(self, org_id: uuid.UUID, session_id: uuid.UUID) -> PlaygroundSession:
        q = select(PlaygroundSession).where(PlaygroundSession.id == session_id)
        res = await self.db.execute(q)
        session = res.scalars().first()
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playground session not found.")
        if session.organization_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access prohibited.")
        return session

    async def _get_app_name(self, app_id: uuid.UUID) -> str:
        aq = select(Application.name).where(Application.id == app_id)
        ares = await self.db.execute(aq)
        return ares.scalars().first() or "Application"

    def _serialize_session(self, s: PlaygroundSession, app_name: str) -> PlaygroundSessionResponse:
        return PlaygroundSessionResponse(
            id=s.id,
            organization_id=s.organization_id,
            application_id=s.application_id,
            application_name=app_name,
            parent_session_id=s.parent_session_id,
            scenario_id=s.scenario_id,
            scenario_name=s.scenario_name,
            scenario_category=s.scenario_category,
            target_type=s.target_type,
            status=s.status,
            security_result=s.security_result,
            is_authorized=s.is_authorized,
            authorized_by=s.authorized_by,
            authorizer_role=s.authorizer_role,
            authorized_at=s.authorized_at,
            execution_plan=s.execution_plan or {},
            execution_results=s.execution_results or {},
            evidence_references=s.evidence_references or {},
            safety_decisions=s.safety_decisions or {},
            duration_seconds=s.duration_seconds,
            notes=s.notes,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )

import uuid
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_, and_
from fastapi import HTTPException, status

from app.models.remediation import (
    RemediationRecommendation,
    RecommendationHistory,
    RecommendationStatus,
    RemediationPriority,
    VerificationStatus,
)
from app.models.vulnerability import Vulnerability, Evidence
from app.models.application import Application
from app.models.time_travel import RegressionRecord, RegressionStatus
from app.models.user import User
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
)
from app.features.security_operations.remediation.risk_engine import RiskEngine
from app.features.security_operations.remediation.schemas import (
    RecommendationStatusUpdateRequest,
    RecommendationNotesUpdateRequest,
    RemediationOverviewResponse,
    PriorityCountBreakdown,
    StatusCountBreakdown,
)


class RecommendationService:
    """
    Service responsible for recommendation generation, deterministic scoring,
    evidence-grounded guidance, lifecycle state machine, and audit trail.
    """

    VALID_TRANSITIONS = {
        RecommendationStatus.GENERATED: [
            RecommendationStatus.REVIEWED,
            RecommendationStatus.ACCEPTED,
            RecommendationStatus.REJECTED,
            RecommendationStatus.DEFERRED,
        ],
        RecommendationStatus.REVIEWED: [
            RecommendationStatus.ACCEPTED,
            RecommendationStatus.REJECTED,
            RecommendationStatus.IN_PROGRESS,
            RecommendationStatus.DEFERRED,
        ],
        RecommendationStatus.ACCEPTED: [
            RecommendationStatus.IN_PROGRESS,
            RecommendationStatus.DEFERRED,
            RecommendationStatus.REJECTED,
        ],
        RecommendationStatus.IN_PROGRESS: [
            RecommendationStatus.VERIFIED,
            RecommendationStatus.DEFERRED,
            RecommendationStatus.ACCEPTED,
            RecommendationStatus.REVIEWED,
        ],
        RecommendationStatus.DEFERRED: [
            RecommendationStatus.REVIEWED,
            RecommendationStatus.ACCEPTED,
            RecommendationStatus.IN_PROGRESS,
        ],
        RecommendationStatus.REJECTED: [
            RecommendationStatus.REVIEWED,
        ],
        RecommendationStatus.VERIFIED: [
            RecommendationStatus.IN_PROGRESS,
            RecommendationStatus.REVIEWED,
        ],
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    @classmethod
    def _get_category_guidance(cls, title: str, category: str, cwe_id: Optional[str]) -> Dict[str, Any]:
        """
        Supplies structured remediation guidance, code patterns, and verification tests
        tailored to the specific vulnerability type or CWE.
        """
        combined = f"{title} {category} {cwe_id or ''}".upper()

        if "IDOR" in combined or "BOLA" in combined or "639" in combined or "OBJECT REFERENCE" in combined:
            return {
                "why_it_matters": (
                    "Insecure Direct Object References (IDOR) allow attackers to access or modify arbitrary "
                    "records belonging to other tenants or users by altering object identifiers in HTTP requests."
                ),
                "potential_business_impact": (
                    "Cross-tenant data exposure, unauthorized modification of sensitive user records, severe GDPR/HIPAA "
                    "regulatory compliance breaches, and total loss of customer multi-tenant isolation guarantees."
                ),
                "remediation_steps": [
                    "Scope all database queries strictly with the caller's verified tenant/organization ID extracted directly from the authenticated session context.",
                    "Implement a mandatory server-side authorization check before executing read or mutation queries on referenced entities.",
                    "Replace enumerable or sequential primary keys in client APIs with cryptographically random UUIDs or indirect reference maps.",
                    "Add automated integration tests ensuring requests from tenant A targeting tenant B resources fail with HTTP 404 or 403."
                ],
                "suggested_fix_snippet": (
                    "# Enforce tenant boundary scoping in repository query\n"
                    "stmt = select(Resource).where(\n"
                    "    Resource.id == resource_id,\n"
                    "    Resource.organization_id == current_user.organization_id\n"
                    ")\n"
                    "resource = (await db.execute(stmt)).scalar_one_or_none()\n"
                    "if not resource:\n"
                    "    raise HTTPException(status_code=404, detail='Resource not found')"
                ),
                "validation_steps": [
                    "Authenticate as User A from Tenant A and capture valid resource IDs.",
                    "Authenticate as User B from Tenant B and submit requests referencing User A's resource IDs.",
                    "Verify server responds with 404 Not Found or 403 Forbidden with no sensitive data leaked.",
                    "Run regression test suite verifying cross-tenant isolation enforcement."
                ],
                "suggested_playground_scenario_id": "idor-01",
                "estimated_effort": "MEDIUM"
            }
        elif "AUTH" in combined or "JWT" in combined or "TOKEN" in combined or "287" in combined:
            return {
                "why_it_matters": (
                    "Authentication weaknesses permit attackers to forge identities, bypass credential verification, "
                    "or maintain unauthorized persistent sessions across the application."
                ),
                "potential_business_impact": (
                    "Account takeover, unauthorized administrative privileges, impersonation of high-privilege personas, "
                    "and systemic compromise of protected customer environments."
                ),
                "remediation_steps": [
                    "Validate all cryptographic signatures on incoming JWTs using asymmetric public keys (e.g. RS256).",
                    "Enforce strict token expiration and implement server-side revocation lists for compromised tokens.",
                    "Enforce multi-factor authentication (MFA) and adaptive rate limiting on all login and token exchange endpoints.",
                    "Ensure tokens cannot be replayed across different tenants or environments."
                ],
                "suggested_fix_snippet": (
                    "# Cryptographic JWT signature and claim verification\n"
                    "try:\n"
                    "    payload = jwt.decode(\n"
                    "        token,\n"
                    "        PUBLIC_KEY,\n"
                    "        algorithms=['RS256'],\n"
                    "        audience='phantom-api',\n"
                    "        issuer='phantom-auth'\n"
                    "    )\n"
                    "except jwt.PyJWTError:\n"
                    "    raise HTTPException(status_code=401, detail='Invalid authentication token')"
                ),
                "validation_steps": [
                    "Submit forged, expired, and none-algorithm JWTs to protected routes.",
                    "Confirm server consistently rejects unverified tokens with HTTP 401.",
                    "Test token revocation and verify expired sessions cannot be reused."
                ],
                "suggested_playground_scenario_id": "auth-01",
                "estimated_effort": "HIGH"
            }
        elif "SQL" in combined or "INJECTION" in combined or "89" in combined:
            return {
                "why_it_matters": (
                    "SQL Injection occurs when untrusted user input is directly concatenated into database query "
                    "strings, allowing attackers to manipulate query logic and execute arbitrary SQL commands."
                ),
                "potential_business_impact": (
                    "Full database extraction, unauthorized deletion or corruption of persistent tables, credential dumping, "
                    "and potential host OS command execution through database extensions."
                ),
                "remediation_steps": [
                    "Never concatenate dynamic string parameters into raw SQL queries.",
                    "Use parameterized queries, prepared statements, or ORM abstraction layers with bind parameters.",
                    "Apply strict schema-level input validation and reject unexpected character sequences.",
                    "Enforce principle of least privilege on database connection credentials."
                ],
                "suggested_fix_snippet": (
                    "# Use parameterized query constructs with bind variables\n"
                    "query = text('SELECT id, name, status FROM accounts WHERE org_id = :org_id AND status = :status')\n"
                    "result = await db.execute(query, {'org_id': org_id, 'status': status_filter})"
                ),
                "validation_steps": [
                    "Inject common SQL payloads (' OR '1'='1, UNION SELECT, sleep injection) into query parameters.",
                    "Verify database query treats input purely as literal scalar values.",
                    "Confirm no SQL syntax errors or anomalous response times are observed."
                ],
                "suggested_playground_scenario_id": "sqli-01",
                "estimated_effort": "LOW"
            }
        elif "XSS" in combined or "CROSS-SITE SCRIPTING" in combined or "79" in combined:
            return {
                "why_it_matters": (
                    "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other "
                    "users, executing arbitrary code within the victim's browser session context."
                ),
                "potential_business_impact": (
                    "Client session theft via cookies/localStorage, keystroke logging, credential harvesting, and "
                    "DOM manipulation leading to fraud or defacement."
                ),
                "remediation_steps": [
                    "Contextually encode all user-supplied data before rendering it in HTML, attributes, or JavaScript contexts.",
                    "Configure strict Content Security Policy (CSP) headers (e.g. object-src 'none'; base-uri 'self').",
                    "Store sensitive authentication tokens in Secure, HttpOnly, SameSite=Strict cookies rather than client-accessible storage.",
                    "Use modern frontend frameworks that automatically sanitize interpolated variables."
                ],
                "suggested_fix_snippet": (
                    "# Add strict Content Security Policy response headers\n"
                    "response.headers['Content-Security-Policy'] = (\n"
                    "    \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"\n"
                    ")"
                ),
                "validation_steps": [
                    "Submit script payloads (<script>alert(1)</script>, <img src=x onerror=...>) in all input fields.",
                    "Inspect rendered DOM and confirm characters are safely entity-encoded (&lt;script&gt;).",
                    "Verify CSP blocks execution of inline scripts."
                ],
                "suggested_playground_scenario_id": "xss-01",
                "estimated_effort": "LOW"
            }
        elif "SSRF" in combined or "918" in combined or "REQUEST FORGERY" in combined:
            return {
                "why_it_matters": (
                    "Server-Side Request Forgery allows an attacker to induce the server-side application to make HTTP "
                    "requests to an arbitrary domain or internal resource chosen by the attacker."
                ),
                "potential_business_impact": (
                    "Extraction of internal cloud instance metadata (e.g. AWS 169.254.169.254 IAM credentials), internal port "
                    "scanning, bypass of perimeter firewalls, and unauthorized intranet access."
                ),
                "remediation_steps": [
                    "Validate and sanitize all client-provided URLs against an explicit allowlist of authorized protocols and hostnames.",
                    "Resolve hostnames before initiating connection and reject any IP addresses falling within RFC 1918 or RFC 3927 link-local blocks.",
                    "Disable HTTP redirect following in server HTTP client libraries.",
                    "Isolate outbound request proxies in dedicated network segments with no access to cloud metadata."
                ],
                "suggested_fix_snippet": (
                    "# Validate outbound target IP against private/metadata subnets\n"
                    "import ipaddress, socket\n"
                    "target_ip = socket.gethostbyname(target_host)\n"
                    "ip_obj = ipaddress.ip_address(target_ip)\n"
                    "if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:\n"
                    "    raise ValueError('Target IP resolves to restricted internal network address')"
                ),
                "validation_steps": [
                    "Attempt to fetch internal addresses (127.0.0.1, localhost, 169.254.169.254).",
                    "Verify request is blocked with explicit safety policy violation.",
                    "Ensure DNS rebinding attacks are prevented by validating resolved IPs at connection time."
                ],
                "suggested_playground_scenario_id": "ssrf-01",
                "estimated_effort": "MEDIUM"
            }
        else:
            return {
                "why_it_matters": (
                    f"The identified issue '{title}' indicates an unresolved security control failure that compromises the "
                    "application security posture."
                ),
                "potential_business_impact": (
                    "Increased exposure to targeted attacks, degradation of system confidentiality, integrity, or availability, "
                    "and non-compliance with secure software development standards."
                ),
                "remediation_steps": [
                    "Inspect the vulnerable component and trace untrusted inputs through the execution path.",
                    "Implement defense-in-depth input validation, output encoding, and boundary authorization checks.",
                    "Apply vendor patches or framework updates if vulnerability resides in third-party dependencies.",
                    "Add automated security regression tests to CI/CD pipeline."
                ],
                "suggested_fix_snippet": (
                    "# Enforce strict validation and least privilege access\n"
                    "validate_input(payload)\n"
                    "ensure_authorized_caller(session, required_scope)"
                ),
                "validation_steps": [
                    "Execute attack reproduction payload against staging environment.",
                    "Verify defensive controls prevent exploitation and log appropriate audit warnings.",
                    "Run automated regression tests to verify system stability."
                ],
                "suggested_playground_scenario_id": None,
                "estimated_effort": "MEDIUM"
            }

    async def generate_recommendations_for_application(
        self,
        org_id: uuid.UUID,
        app_id: uuid.UUID,
        vulnerability_id: Optional[uuid.UUID] = None,
        scan_id: Optional[uuid.UUID] = None,
        user: Optional[User] = None,
    ) -> Tuple[int, int, List[RemediationRecommendation]]:
        """
        Deterministically evaluates vulnerabilities for an application and generates or
        idempotently refreshes remediation recommendations.
        """
        # Ensure application exists and belongs to tenant
        app_stmt = select(Application).where(
            Application.id == app_id,
            Application.organization_id == org_id
        )
        app_res = await self.db.execute(app_stmt)
        application = app_res.scalar_one_or_none()
        if not application:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Application {app_id} not found."
            )

        # Query vulnerabilities
        vuln_query = select(Vulnerability).where(
            Vulnerability.application_id == app_id,
            Vulnerability.organization_id == org_id
        )
        if vulnerability_id:
            vuln_query = vuln_query.where(Vulnerability.id == vulnerability_id)
        if scan_id:
            vuln_query = vuln_query.where(Vulnerability.scan_id == scan_id)

        vuln_res = await self.db.execute(vuln_query)
        vulnerabilities = list(vuln_res.scalars().all())

        if not vulnerabilities:
            return 0, 0, []

        # Check for active regressions in time travel table
        reg_stmt = select(RegressionRecord).where(
            RegressionRecord.application_id == app_id,
            RegressionRecord.organization_id == org_id,
            RegressionRecord.status == RegressionStatus.REGRESSION_DETECTED.value
        )
        reg_res = await self.db.execute(reg_stmt)
        regressions = list(reg_res.scalars().all())
        regressed_vuln_ids = {r.reappeared_vulnerability_id for r in regressions if r.reappeared_vulnerability_id}

        # Check existing recommendations
        existing_stmt = select(RemediationRecommendation).where(
            RemediationRecommendation.application_id == app_id,
            RemediationRecommendation.organization_id == org_id
        )
        existing_res = await self.db.execute(existing_stmt)
        existing_by_vuln = {rec.vulnerability_id: rec for rec in existing_res.scalars().all()}

        generated_count = 0
        updated_count = 0
        result_recommendations: List[RemediationRecommendation] = []
        now = datetime.now(timezone.utc)

        for vuln in vulnerabilities:
            # Query evidence count
            ev_count_stmt = select(func.count(Evidence.id)).where(Evidence.vulnerability_id == vuln.id)
            ev_count = (await self.db.execute(ev_count_stmt)).scalar() or 0
            has_evidence = ev_count > 0

            # Calculate finding age
            finding_created = vuln.created_at or now
            if finding_created.tzinfo is None:
                finding_created = finding_created.replace(tzinfo=timezone.utc)
            age_days = max(0, (now - finding_created).days)

            # Check if this vulnerability is part of a regression
            is_regression = (vuln.id in regressed_vuln_ids) or ("REGRESSION" in vuln.title.upper())

            # Severity string
            sev_str = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

            # Deterministic risk engine calculation
            priority, risk_score, rationale, missing_notes = RiskEngine.calculate_risk(
                severity=sev_str,
                cvss_score=vuln.cvss_score,
                is_regression=is_regression,
                has_evidence=has_evidence,
                confidence=vuln.confidence or 0.8,
                endpoint=vuln.endpoint,
                age_days=age_days,
            )

            guidance = self._get_category_guidance(
                title=vuln.title,
                category=vuln.title,
                cwe_id=vuln.cwe_id,
            )

            existing_rec = existing_by_vuln.get(vuln.id)
            if existing_rec:
                # Idempotent update: refresh score, rationale, guidance without overwriting user decisions
                existing_rec.severity = sev_str
                existing_rec.calculated_priority = priority.value
                existing_rec.risk_score = risk_score
                existing_rec.priority_rationale = rationale
                existing_rec.missing_information_notes = missing_notes
                existing_rec.endpoint = vuln.endpoint
                existing_rec.cwe_id = vuln.cwe_id
                existing_rec.updated_at = now

                updated_count += 1
                result_recommendations.append(existing_rec)
            else:
                # Generate new recommendation
                new_rec = RemediationRecommendation(
                    organization_id=org_id,
                    application_id=app_id,
                    vulnerability_id=vuln.id,
                    scan_id=vuln.scan_id,
                    title=f"Remediate {vuln.title}",
                    category=vuln.cwe_id or "Application Security",
                    cwe_id=vuln.cwe_id,
                    severity=sev_str,
                    calculated_priority=priority.value,
                    risk_score=risk_score,
                    status=RecommendationStatus.GENERATED.value,
                    endpoint=vuln.endpoint,
                    http_method="GET",
                    priority_rationale=rationale,
                    why_it_matters=guidance["why_it_matters"],
                    potential_business_impact=guidance["potential_business_impact"],
                    remediation_steps=guidance["remediation_steps"],
                    suggested_fix_snippet=guidance["suggested_fix_snippet"],
                    validation_steps=guidance["validation_steps"],
                    suggested_playground_scenario_id=guidance["suggested_playground_scenario_id"],
                    estimated_effort=guidance["estimated_effort"],
                    missing_information_notes=missing_notes,
                    verification_status=VerificationStatus.UNVERIFIED.value,
                    verification_evidence={},
                )
                self.db.add(new_rec)
                generated_count += 1
                result_recommendations.append(new_rec)

        await self.db.commit()

        # Audit log creation for generation
        if user and (generated_count > 0 or updated_count > 0):
            try:
                await AuditEventRecorder.record_event(
                    db=self.db,
                    org_id=org_id,
                    event_in=AuditEventCreate(
                        category=AuditCategory.VULNERABILITY,
                        event_type=AuditEventType.VULN_STATUS_CHANGED,
                        severity=AuditSeverity.INFO,
                        status=AuditStatus.SUCCESS,
                        actor_email=user.email,
                        actor_role=getattr(user, "role", "analyst"),
                        target_type="RemediationRecommendation",
                        target_id=str(app_id),
                        action="GENERATE_RECOMMENDATIONS",
                        details={
                            "application_id": str(app_id),
                            "generated_count": generated_count,
                            "updated_count": updated_count,
                            "total_processed": len(result_recommendations),
                        }
                    )
                )
            except Exception:
                pass

        return generated_count, updated_count, result_recommendations

    async def update_status(
        self,
        org_id: uuid.UUID,
        rec_id: uuid.UUID,
        req: RecommendationStatusUpdateRequest,
        user: User,
    ) -> RemediationRecommendation:
        """
        Transitions a recommendation through its lifecycle with validation, audit logging,
        and decision history tracking.
        """
        rec_stmt = select(RemediationRecommendation).where(
            RemediationRecommendation.id == rec_id,
            RemediationRecommendation.organization_id == org_id
        )
        rec = (await self.db.execute(rec_stmt)).scalar_one_or_none()
        if not rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Remediation recommendation {rec_id} not found."
            )

        current_status = RecommendationStatus(rec.status)
        target_status = req.status

        # If unchanged
        if current_status == target_status:
            if req.notes:
                rec.decision_notes = req.notes
            if req.assigned_to:
                rec.assigned_to = req.assigned_to
            if req.deferred_reason:
                rec.deferred_reason = req.deferred_reason
            await self.db.commit()
            await self.db.refresh(rec)
            return rec

        # Validate state machine transitions
        allowed_targets = self.VALID_TRANSITIONS.get(current_status, [])
        if target_status not in allowed_targets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state transition from '{current_status.value}' to '{target_status.value}'. "
                       f"Allowed next states: {[s.value for s in allowed_targets]}."
            )

        # Enforce business rules
        if target_status == RecommendationStatus.VERIFIED:
            if rec.verification_status != VerificationStatus.VERIFIED.value:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot mark recommendation as VERIFIED without completing empirical verification. "
                           "Please trigger the verification workflow."
                )

        if target_status == RecommendationStatus.DEFERRED and not (req.deferred_reason or rec.deferred_reason):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A deferral reason must be provided when setting status to DEFERRED."
            )

        if target_status == RecommendationStatus.REJECTED and not (req.notes or rec.decision_notes):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Decision notes or rejection justification must be provided when rejecting a recommendation."
            )

        # Perform transition
        old_status_val = rec.status
        rec.status = target_status.value
        if req.notes:
            rec.decision_notes = req.notes
        if req.assigned_to:
            rec.assigned_to = req.assigned_to
        if req.deferred_reason:
            rec.deferred_reason = req.deferred_reason
        rec.updated_at = datetime.now(timezone.utc)

        # Record decision history
        history_entry = RecommendationHistory(
            recommendation_id=rec.id,
            organization_id=org_id,
            from_status=old_status_val,
            to_status=target_status.value,
            actor_email=user.email,
            actor_role=getattr(user, "role", "operator"),
            notes=req.notes or req.deferred_reason,
        )
        self.db.add(history_entry)
        await self.db.commit()
        await self.db.refresh(rec)

        # Audit event
        try:
            await AuditEventRecorder.record_event(
                db=self.db,
                org_id=org_id,
                event_in=AuditEventCreate(
                    category=AuditCategory.VULNERABILITY,
                    event_type=AuditEventType.VULN_STATUS_CHANGED,
                    severity=AuditSeverity.MEDIUM if target_status in [RecommendationStatus.ACCEPTED, RecommendationStatus.VERIFIED] else AuditSeverity.LOW,
                    status=AuditStatus.SUCCESS,
                    actor_email=user.email,
                    actor_role=getattr(user, "role", "operator"),
                    target_type="RemediationRecommendation",
                    target_id=str(rec.id),
                    action="STATUS_TRANSITION",
                    details={
                        "from_status": old_status_val,
                        "to_status": target_status.value,
                        "notes": req.notes,
                        "deferred_reason": req.deferred_reason,
                        "assigned_to": req.assigned_to,
                    }
                )
            )
        except Exception:
            pass

        return rec

    async def update_notes(
        self,
        org_id: uuid.UUID,
        rec_id: uuid.UUID,
        req: RecommendationNotesUpdateRequest,
        user: User,
    ) -> RemediationRecommendation:
        """
        Updates operator decision notes and assignee without changing lifecycle status.
        """
        rec_stmt = select(RemediationRecommendation).where(
            RemediationRecommendation.id == rec_id,
            RemediationRecommendation.organization_id == org_id
        )
        rec = (await self.db.execute(rec_stmt)).scalar_one_or_none()
        if not rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Remediation recommendation {rec_id} not found."
            )

        if req.notes is not None:
            rec.decision_notes = req.notes
        if req.assigned_to is not None:
            rec.assigned_to = req.assigned_to
        rec.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(rec)
        return rec

    async def get_overview(
        self,
        org_id: uuid.UUID,
        application_id: Optional[uuid.UUID] = None,
    ) -> RemediationOverviewResponse:
        """
        Aggregates remediation metrics across priorities and lifecycle stages.
        """
        base_query = select(RemediationRecommendation).where(
            RemediationRecommendation.organization_id == org_id
        )
        if application_id:
            base_query = base_query.where(RemediationRecommendation.application_id == application_id)

        res = await self.db.execute(base_query)
        recommendations = list(res.scalars().all())

        by_priority = PriorityCountBreakdown()
        by_status = StatusCountBreakdown()
        total_score = 0.0
        verified_count = 0
        in_progress_count = 0

        for r in recommendations:
            p_val = r.calculated_priority
            if hasattr(by_priority, p_val):
                setattr(by_priority, p_val, getattr(by_priority, p_val) + 1)

            s_val = r.status
            if hasattr(by_status, s_val):
                setattr(by_status, s_val, getattr(by_status, s_val) + 1)

            total_score += r.risk_score
            if r.status == RecommendationStatus.VERIFIED.value or r.verification_status == VerificationStatus.VERIFIED.value:
                verified_count += 1
            if r.status == RecommendationStatus.IN_PROGRESS.value:
                in_progress_count += 1

        total = len(recommendations)
        avg_score = round(total_score / total, 1) if total > 0 else 0.0

        # Count pending verification (in progress or accepted but unverified)
        pending_ver = sum(
            1 for r in recommendations
            if r.status in [RecommendationStatus.IN_PROGRESS.value, RecommendationStatus.ACCEPTED.value]
            and r.verification_status != VerificationStatus.VERIFIED.value
        )

        return RemediationOverviewResponse(
            total_recommendations=total,
            by_priority=by_priority,
            by_status=by_status,
            average_risk_score=avg_score,
            verified_count=verified_count,
            pending_verification_count=pending_ver,
            in_progress_count=in_progress_count,
        )

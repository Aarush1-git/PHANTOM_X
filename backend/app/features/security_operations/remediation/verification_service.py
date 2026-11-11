import uuid
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from fastapi import HTTPException, status

from app.models.remediation import (
    RemediationRecommendation,
    RecommendationHistory,
    RecommendationStatus,
    VerificationStatus,
)
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.playground import PlaygroundSession, SecurityResultClassification
from app.models.user import User
from app.services.scope_safety_service import ScopeSafetyService
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import (
    AuditCategory,
    AuditEventType,
    AuditSeverity,
    AuditStatus,
    AuditEventCreate,
)
from app.features.security_operations.remediation.schemas import (
    RecommendationVerifyRequest,
    RecommendationVerifyResponse,
)


class VerificationService:
    """
    Evidence-grounded verification workflow.
    Validates remediation effectiveness using real empirical scans or Playground sessions.
    Strictly verifies Feature 26 scope policies before authorizing verification activities.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def verify_recommendation(
        self,
        org_id: uuid.UUID,
        rec_id: uuid.UUID,
        req: RecommendationVerifyRequest,
        user: User,
    ) -> RecommendationVerifyResponse:
        """
        Executes verification workflow against a recommendation.
        Returns detailed verification outcome and records audit evidence.
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

        # 1. Feature 26 Scope Safety Validation
        # Construct full target URL using application target_url
        from app.models.application import Application
        app_stmt = select(Application).where(Application.id == rec.application_id)
        app = (await self.db.execute(app_stmt)).scalar_one_or_none()
        base_url = (app.target_url if app and app.target_url else "https://localhost").rstrip("/")
        endpoint_path = (rec.endpoint or "/api/v1/health").strip()
        if endpoint_path.startswith("http://") or endpoint_path.startswith("https://"):
            full_target_url = endpoint_path
        else:
            full_target_url = f"{base_url}/{endpoint_path.lstrip('/')}"

        safety_validation = await ScopeSafetyService.validate_test_execution(
            db=self.db,
            target_url=full_target_url,
            http_method=rec.http_method or "GET",
            application_id=rec.application_id,
            source_agent="Feature27_RemediationVerifier",
            payload_sample="Verification payload simulation",
            dry_run=False,
        )

        if not safety_validation.is_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Verification execution blocked by Scope Safety Policy: {safety_validation.reason}"
            )

        # 2. Evidence Grounding Evaluation
        outcome_status = VerificationStatus.INCONCLUSIVE
        is_verified = False
        message = ""
        evidence_details: Dict[str, Any] = {
            "verified_by": user.email,
            "verification_method": "empirical_evidence",
            "safety_validation": {
                "allowed": safety_validation.is_allowed,
                "reason": safety_validation.reason,
            }
        }

        # Check Option A: Verification Scan
        if req.verification_scan_id:
            scan_stmt = select(Scan).where(
                Scan.id == req.verification_scan_id,
                Scan.organization_id == org_id,
                Scan.application_id == rec.application_id
            )
            verif_scan = (await self.db.execute(scan_stmt)).scalar_one_or_none()
            if not verif_scan:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Verification scan {req.verification_scan_id} does not exist for this application."
                )

            # Check if original vulnerability or same endpoint & title persists in verification scan
            vuln_stmt = select(Vulnerability).where(
                Vulnerability.scan_id == req.verification_scan_id,
                Vulnerability.organization_id == org_id,
                Vulnerability.application_id == rec.application_id
            )
            scan_vulns = list((await self.db.execute(vuln_stmt)).scalars().all())

            # Check for matches
            original_vuln_stmt = select(Vulnerability).where(Vulnerability.id == rec.vulnerability_id)
            orig_vuln = (await self.db.execute(original_vuln_stmt)).scalar_one_or_none()

            persistent_match = None
            for sv in scan_vulns:
                if orig_vuln and sv.title == orig_vuln.title and sv.endpoint == orig_vuln.endpoint:
                    persistent_match = sv
                    break

            if persistent_match:
                outcome_status = VerificationStatus.PERSISTENT
                is_verified = False
                message = f"Vulnerability remains PERSISTENT in verification scan {req.verification_scan_id}."
                evidence_details.update({
                    "evidence_type": "SCAN_VERIFICATION",
                    "scan_id": str(req.verification_scan_id),
                    "finding_detected": True,
                    "persistent_vulnerability_id": str(persistent_match.id),
                    "notes": req.notes,
                })
            else:
                outcome_status = VerificationStatus.VERIFIED
                is_verified = True
                message = f"Vulnerability confirmed RESOLVED in clean verification scan {req.verification_scan_id}."
                evidence_details.update({
                    "evidence_type": "SCAN_VERIFICATION",
                    "scan_id": str(req.verification_scan_id),
                    "finding_detected": False,
                    "notes": req.notes,
                })

        # Check Option B: Playground Session
        elif req.playground_session_id:
            ps_stmt = select(PlaygroundSession).where(
                PlaygroundSession.id == req.playground_session_id,
                PlaygroundSession.organization_id == org_id,
                PlaygroundSession.application_id == rec.application_id
            )
            playground_session = (await self.db.execute(ps_stmt)).scalar_one_or_none()
            if not playground_session:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Playground session {req.playground_session_id} does not exist for this application."
                )

            evidence_details.update({
                "evidence_type": "PLAYGROUND_VERIFICATION",
                "session_id": str(req.playground_session_id),
                "scenario_id": playground_session.scenario_id,
                "security_result": playground_session.security_result,
                "notes": req.notes,
            })

            if playground_session.security_result == SecurityResultClassification.SECURE_BEHAVIOR_CONFIRMED.value:
                outcome_status = VerificationStatus.VERIFIED
                is_verified = True
                message = f"Playground simulation '{playground_session.scenario_name}' confirmed secure defensive controls."
            elif playground_session.security_result == SecurityResultClassification.VULNERABILITY_CONFIRMED.value:
                outcome_status = VerificationStatus.PERSISTENT
                is_verified = False
                message = f"Playground simulation '{playground_session.scenario_name}' confirmed vulnerability is still exploitable."
            else:
                outcome_status = VerificationStatus.INCONCLUSIVE
                is_verified = False
                message = f"Playground simulation outcome was inconclusive ({playground_session.security_result})."

        # Option C: Inconclusive / Missing evidence
        else:
            outcome_status = VerificationStatus.INCONCLUSIVE
            is_verified = False
            message = "Verification inconclusive: no valid verification scan or completed Playground simulation provided."
            evidence_details.update({
                "evidence_type": "NONE_PROVIDED",
                "notes": req.notes,
            })

        # 3. Update Recommendation Record
        now = datetime.now(timezone.utc)
        prev_status = rec.status
        rec.verification_status = outcome_status.value
        rec.verification_evidence = evidence_details

        if is_verified:
            rec.status = RecommendationStatus.VERIFIED.value
            rec.verified_at = now
            rec.verified_by = user.email
        else:
            # If persistent or inconclusive, ensure it is NOT marked VERIFIED
            if rec.status == RecommendationStatus.VERIFIED.value:
                rec.status = RecommendationStatus.IN_PROGRESS.value
            rec.verified_at = None
            rec.verified_by = None

        rec.updated_at = now

        # Add history record
        hist = RecommendationHistory(
            recommendation_id=rec.id,
            organization_id=org_id,
            from_status=prev_status,
            to_status=rec.status,
            actor_email=user.email,
            actor_role=getattr(user, "role", "verifier"),
            notes=f"Verification result: {outcome_status.value}. {message}"
        )
        self.db.add(hist)
        await self.db.commit()
        await self.db.refresh(rec)

        # Audit Event Logging
        try:
            await AuditEventRecorder.record_event(
                db=self.db,
                org_id=org_id,
                event_in=AuditEventCreate(
                    category=AuditCategory.VULNERABILITY,
                    event_type=AuditEventType.VULN_VERIFIED if is_verified else AuditEventType.VULN_STATUS_CHANGED,
                    severity=AuditSeverity.HIGH if is_verified else AuditSeverity.MEDIUM,
                    status=AuditStatus.SUCCESS,
                    actor_email=user.email,
                    actor_role=getattr(user, "role", "verifier"),
                    target_type="RemediationRecommendation",
                    target_id=str(rec.id),
                    action="VERIFY_REMEDIATION",
                    details={
                        "verification_status": outcome_status.value,
                        "is_verified": is_verified,
                        "previous_status": prev_status,
                        "new_status": rec.status,
                        "evidence_details": evidence_details,
                    }
                )
            )
        except Exception:
            pass

        return RecommendationVerifyResponse(
            recommendation_id=rec.id,
            previous_status=prev_status,
            new_status=rec.status,
            verification_status=outcome_status,
            is_verified=is_verified,
            message=message,
            evidence_details=evidence_details,
            verified_at=rec.verified_at,
        )

"""
Verification pipeline: bridges authorization check results with the
SelfChallengingProofEngine and EvidenceCollector.

Provides two entry-points:
  verify_and_record()  - runs the proof engine and packages evidence for
                         both CONFIRMED and NEEDS_HUMAN_REVIEW outcomes,
                         returning a comprehensive VerificationRecord.
  verify_and_package() - backward-compatible thin wrapper returning an
                         EvidencePackage only when outcome is CONFIRMED.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from checks.base import SecurityCheckContext, SecurityCheckResult
from evidence.collector import EvidenceCollector, EvidencePackage
from evidence.redact import redact_obj, redact_text
from verification.proof_engine import (
    SelfChallengingProofEngine,
    VerificationOutcome,
    to_vulnerability_status,
)

logger = logging.getLogger("phantom_x.pipeline")


class VerificationRecord(BaseModel):
    outcome: str
    reason: str
    independent: bool
    reproducibility_rate: float
    confidence: float
    verification_status: str
    package: Optional[EvidencePackage] = None


async def verify_and_record(
    result: SecurityCheckResult,
    context: SecurityCheckContext,
    engine: SelfChallengingProofEngine,
    collector: EvidenceCollector,
) -> Optional[VerificationRecord]:
    """
    Execute verification for a finding and return a VerificationRecord.

    Outcomes:
      CONFIRMED          - independently reproduced across all challenges
      REJECTED           - disproved by negative controls or not reproducible
      INCONCLUSIVE       - baseline/control errors, rate limits, or cached responses
      NEEDS_HUMAN_REVIEW - auth bypass suspected, intermittent rate, or state artifact

    Packages forensic evidence for CONFIRMED and NEEDS_HUMAN_REVIEW.
    """
    if not result.is_vulnerable:
        return None

    # Self-verified path (e.g. collection-level check that already ran 3/3 reproducible trials)
    if result.proof_data.get("self_verified") is True:
        outcome = VerificationOutcome.CONFIRMED.value
        independent = False
        reason = "self-verified: reproduced 3/3 by the originating check; not independently verified"
        reproducibility_rate = 1.0
        confidence = float(result.confidence)
        verification_status = to_vulnerability_status(outcome).value
        reproduction_steps = "Originating check confirmed finding through 3/3 internal replays."
        cache_suspected = False
        verdict_dict = {"self_verified": True}
    else:
        extra_attacker = result.proof_data.get("extra_attacker_headers", {})
        effective_attacker_headers = {**context.secondary_auth_headers, **extra_attacker}
        evidence = {
            "attack_url": result.proof_data.get("attack_url", context.target_url + context.endpoint_path),
            "victim_headers": context.auth_headers,
            "attacker_headers": effective_attacker_headers,
            "baseline_body": context.parameters.get("_baseline_body", ""),
            "ignore_fields": result.proof_data.get("ignore_fields", []),
        }

        verdict = await engine.verify_finding(
            finding_title=result.title,
            evidence=evidence,
        )
        independent = True
        outcome = verdict.outcome.value if hasattr(verdict.outcome, "value") else str(verdict.outcome)
        reason = verdict.reason
        reproducibility_rate = float(verdict.reproducibility_rate)
        confidence = float(verdict.confidence)
        verification_status = to_vulnerability_status(verdict.outcome).value
        reproduction_steps = verdict.reproduction_steps
        cache_suspected = verdict.cache_suspected
        verdict_dict = verdict.model_dump(mode="json")

    # Log every non-CONFIRMED outcome with safe redacted reason
    if outcome != VerificationOutcome.CONFIRMED.value:
        logger.warning(
            "Finding %r outcome %s (test_id=%s): %s",
            result.title, outcome, context.test_id, redact_text(reason),
        )

    # Package is built for CONFIRMED and NEEDS_HUMAN_REVIEW; None for REJECTED and INCONCLUSIVE
    package: Optional[EvidencePackage] = None
    if outcome in (VerificationOutcome.CONFIRMED.value, VerificationOutcome.NEEDS_HUMAN_REVIEW.value):
        request_dump = redact_text(result.evidence_request)
        response_dump = redact_text(result.evidence_response)
        evidence_sha256 = hashlib.sha256(f"{request_dump}\n{response_dump}".encode("utf-8")).hexdigest()

        severity_val = result.severity.value if hasattr(result.severity, "value") else str(result.severity)
        expected = result.proof_data.get("expected", "access denied (HTTP 401/403/404) for the attacker identity")
        actual = result.proof_data.get("actual", f"HTTP {result.proof_data.get('attack_status', 0)}")

        package_proof_data = {
            **result.proof_data,
            "finding": {
                "title": result.title,
                "check_name": result.check_name,
                "severity": severity_val,
                "confidence": float(result.confidence),
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "recommendation": result.recommendation,
            },
            "verification": {
                "outcome": outcome,
                "reason": reason,
                "verification_status": verification_status,
                "independent": independent,
                "reproducibility_rate": reproducibility_rate,
                "confidence": confidence,
                "reproduction_steps": reproduction_steps,
                "cache_suspected": cache_suspected,
            },
            "expected_vs_actual": {
                "expected": expected,
                "actual": actual,
            },
            "timestamps": {
                "detected_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            "redaction": {
                "applied": True,
                "layers": 2,
            },
            "evidence_sha256": evidence_sha256,
            "verdict": verdict_dict,
        }

        package = collector.package_evidence(
            request_dump=request_dump,
            response_dump=response_dump,
            proof_data=redact_obj(package_proof_data),
            test_id=context.test_id,
        )

    return VerificationRecord(
        outcome=outcome,
        reason=reason,
        independent=independent,
        reproducibility_rate=reproducibility_rate,
        confidence=confidence,
        verification_status=verification_status,
        package=package,
    )


async def verify_and_package(
    result: SecurityCheckResult,
    context: SecurityCheckContext,
    engine: SelfChallengingProofEngine,
    collector: EvidenceCollector,
) -> Optional[EvidencePackage]:
    """
    Confirm a suspected vulnerability finding and, if confirmed, package the evidence.

    Returns an EvidencePackage on CONFIRMED, or None when the result is
    not vulnerable or when the outcome is REJECTED, INCONCLUSIVE, or NEEDS_HUMAN_REVIEW.
    """
    record = await verify_and_record(result, context, engine, collector)
    if record and record.outcome == VerificationOutcome.CONFIRMED.value:
        return record.package
    return None

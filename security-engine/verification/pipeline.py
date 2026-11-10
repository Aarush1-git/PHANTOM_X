"""
Verification pipeline: bridges BOLAOwnershipCheck results with the
SelfChallengingProofEngine and EvidenceCollector.

verify_and_package() is the single entry-point used by the scan orchestrator:

  1. If the check result is not vulnerable -> immediately return None (nothing
     to confirm).
  2. Build an evidence dict from SecurityCheckResult.proof_data and the
     SecurityCheckContext (victim / attacker headers, baseline body extracted
     from the evidence_response, ignore_fields).
  3. Run SelfChallengingProofEngine.verify_finding().
  4. If the engine cannot confirm the finding -> return None (false positive,
     suppressed from the final report).
  5. If confirmed -> delegate to EvidenceCollector.package_evidence() and
     return the resulting EvidencePackage.

No raw HTTP is performed here; that responsibility belongs to the engine.
"""

import logging
from typing import Optional

from checks.base import SecurityCheckContext, SecurityCheckResult
from evidence.collector import EvidenceCollector, EvidencePackage
from evidence.redact import redact_obj, redact_text
from verification.proof_engine import SelfChallengingProofEngine

logger = logging.getLogger("phantom_x.pipeline")


async def verify_and_package(
    result: SecurityCheckResult,
    context: SecurityCheckContext,
    engine: SelfChallengingProofEngine,
    collector: EvidenceCollector,
) -> Optional[EvidencePackage]:
    """
    Confirm a suspected BOLA finding and, if confirmed, package the evidence.

    Returns an EvidencePackage on confirmation, or None when the result is
    not vulnerable or when the proof engine rejects it as a false positive.

    Parameters
    ----------
    result:    Output of BOLAOwnershipCheck.run().
    context:   The same SecurityCheckContext passed to the check.
    engine:    A configured SelfChallengingProofEngine instance.
    collector: An EvidenceCollector used to create the final package.
    """
    if not result.is_vulnerable:
        return None

    # Self-verified findings (e.g. list-mode tenant check with 3/3 reproducibility)
    # have already proven themselves; skip the external proof engine.
    if result.proof_data.get("self_verified") is True:
        return collector.package_evidence(
            request_dump=redact_text(result.evidence_request),
            response_dump=redact_text(result.evidence_response),
            proof_data=redact_obj({**result.proof_data, "verdict": {"self_verified": True}}),
            test_id=context.test_id,
        )

    # Merge any extra attacker headers recorded in proof_data (e.g. spoofed tenant header).
    extra_attacker = result.proof_data.get("extra_attacker_headers", {})
    effective_attacker_headers = {**context.secondary_auth_headers, **extra_attacker}

    # Build the evidence dict from proof_data + context.
    # The baseline body is NOT stored in proof_data (it may contain credentials);
    # the engine re-fetches it as the owner using victim_headers.
    evidence = {
        "attack_url": result.proof_data.get("attack_url", context.target_url + context.endpoint_path),
        "victim_headers": context.auth_headers,
        "attacker_headers": effective_attacker_headers,
        # Optional pre-fetched baseline; empty -> engine re-fetches, and refuses
        # to confirm if it cannot (fail-safe).
        "baseline_body": context.parameters.get("_baseline_body", ""),
        "ignore_fields": result.proof_data.get("ignore_fields", []),
    }

    verdict = await engine.verify_finding(
        finding_title=result.title,
        evidence=evidence,
    )

    if not verdict.is_confirmed:
        # Safe reason only (no exception text); redacted again for defence in depth.
        logger.warning(
            "Finding %r not confirmed (test_id=%s): %s",
            result.title, context.test_id, redact_text(verdict.counter_evidence),
        )
        return None

    return collector.package_evidence(
        # Second redaction layer: defence in depth before anything is stored.
        request_dump=redact_text(result.evidence_request),
        response_dump=redact_text(result.evidence_response),
        proof_data=redact_obj({**result.proof_data, "verdict": verdict.model_dump()}),
        test_id=context.test_id,
    )
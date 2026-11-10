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

from typing import Optional

from checks.base import SecurityCheckContext, SecurityCheckResult
from evidence.collector import EvidenceCollector, EvidencePackage
from evidence.redact import redact_obj, redact_text
from verification.proof_engine import SelfChallengingProofEngine


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

    # Build the evidence dict from proof_data + context
    # The baseline body is NOT stored in proof_data (it may contain credentials);
    # the engine re-fetches it as the owner using victim_headers.
    evidence = {
        "attack_url": result.proof_data.get("attack_url", context.target_url + context.endpoint_path),
        "victim_headers": context.auth_headers,
        "attacker_headers": context.secondary_auth_headers,
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
        return None

    return collector.package_evidence(
        # Second redaction layer: defence in depth before anything is stored.
        request_dump=redact_text(result.evidence_request),
        response_dump=redact_text(result.evidence_response),
        proof_data=redact_obj({**result.proof_data, "verdict": verdict.model_dump()}),
        test_id=context.test_id,
    )
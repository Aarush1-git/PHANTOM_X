"""
Self-Challenging Proof Engine for BOLA findings.

After BOLAOwnershipCheck flags a potential vulnerability, this engine attempts to
*disprove* the finding through four independent negative-control tests:

  a) Reproducibility  - replay the attacker GET `replays` times; require a 100%
     hit rate (2xx + body matches baseline_body) to rule out flakiness.
  b) Negative control - unauthenticated GET must NOT return baseline_body; if it
     does, the data is public and the BOLA label is incorrect.
  c) Invalid-token    - a deliberately corrupted attacker token must NOT return
     baseline_body; if it does, authentication is not being enforced at all
     (a different class of bug, not BOLA).
  d) Fresh-request    - one additional attacker-only GET (no cookies carried from
     earlier calls) confirms the result is not an artifact of session state.

is_confirmed=True only when ALL four disproof tests fail to disprove the finding
(i.e., the finding survives every challenge). confidence drops to 0.2 when any
disproof test succeeds.
"""

import json
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from execution.http_runner import ControlledHttpRunner
from shared.enums.common import SafetyClassification

# Headers whose values we corrupt to simulate an invalid token
_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "cookie", "proxy-authorization", "x-auth-token"}


def _corrupt_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of *headers* with Bearer / API-key values appended with 'x'."""
    corrupted = {}
    for k, v in headers.items():
        if k.lower() in _AUTH_HEADER_NAMES:
            corrupted[k] = v + "x"
        else:
            corrupted[k] = v
    return corrupted


def _bodies_equal(body: str, baseline: str, ignore_fields: list) -> bool:
    """JSON-aware body comparison with field stripping; falls back to string compare."""
    def _strip(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _strip(v) for k, v in obj.items() if k not in ignore_fields}
        if isinstance(obj, list):
            return [_strip(i) for i in obj]
        return obj

    try:
        return _strip(json.loads(body)) == _strip(json.loads(baseline))
    except (json.JSONDecodeError, ValueError):
        return body == baseline


class _SkipControl(Exception):
    """Internal: control test not applicable."""


class VerificationVerdict(BaseModel):
    is_confirmed: bool
    reproducibility_rate: float
    confidence: float
    counter_evidence: str
    reproduction_steps: str


class SelfChallengingProofEngine:
    """
    Challenges suspected BOLA findings with four disproof tests to prevent
    false-positive reporting.  Requires a ControlledHttpRunner for all HTTP
    traffic so the central safety policy is always enforced.
    """

    def __init__(
        self,
        runner: Optional[ControlledHttpRunner] = None,
        replays: int = 3,
    ) -> None:
        self.runner = runner or ControlledHttpRunner()
        self.replays = replays

    async def verify_finding(
        self, finding_title: str, evidence: Dict[str, Any]
    ) -> VerificationVerdict:
        """
        Execute the four counter-hypothesis tests against *evidence* and return
        a VerificationVerdict.

        evidence keys:
          attack_url      (str)  - full URL that was probed
          victim_headers  (dict) - User A's auth headers (may be empty)
          attacker_headers(dict) - User B's auth headers (may be empty)
          baseline_body   (str)  - body User A received (the reference)
          ignore_fields   (list) - JSON keys to drop before comparing
        """
        attack_url: str = evidence["attack_url"]
        attacker_headers: Dict[str, str] = evidence.get("attacker_headers", {})
        baseline_body: str = evidence.get("baseline_body", "")
        ignore_fields: list = evidence.get("ignore_fields", [])

        if not baseline_body:
            return VerificationVerdict(
                is_confirmed=False,
                reproducibility_rate=0.0,
                confidence=0.0,
                counter_evidence="No baseline body supplied; cannot verify finding.",
                reproduction_steps=f"1. GET {attack_url} as attacker.\n2. Not run: no baseline to compare against.",
            )

        failed_disproof: List[str] = []  # tests that could NOT disprove the finding
        disproved_by: List[str] = []     # tests that DID disprove the finding

        # ── (a) Reproducibility ───────────────────────────────────────────────
        hits = 0
        last_attack_status = 0
        last_attack_body = ""
        for _ in range(self.replays):
            try:
                resp = await self.runner.execute_request(
                    method="GET",
                    url=attack_url,
                    headers=attacker_headers or None,
                    safety_classification=SafetyClassification.SAFE_READ_ONLY,
                )
                last_attack_status = resp.status_code
                last_attack_body = resp.body
                if 200 <= resp.status_code < 300 and _bodies_equal(
                    resp.body, baseline_body, ignore_fields
                ):
                    hits += 1
            except Exception:
                pass  # network error counts as a miss

        reproducibility_rate = hits / self.replays if self.replays > 0 else 0.0
        if reproducibility_rate < 1.0:
            disproved_by.append(
                f"reproducibility ({hits}/{self.replays} hits; "
                f"rate={reproducibility_rate:.2f} < 1.0 required)"
            )
        else:
            failed_disproof.append("reproducibility")

        # ── (b) Negative control (no auth) ───────────────────────────────────
        try:
            no_auth_resp = await self.runner.execute_request(
                method="GET",
                url=attack_url,
                headers=None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
            if 200 <= no_auth_resp.status_code < 300 and _bodies_equal(
                no_auth_resp.body, baseline_body, ignore_fields
            ):
                disproved_by.append(
                    f"negative_control (unauthenticated GET returned HTTP "
                    f"{no_auth_resp.status_code} with matching body -> public endpoint)"
                )
            else:
                failed_disproof.append("negative_control")
        except Exception as exc:
            disproved_by.append(f"negative_control (inconclusive, request failed: {exc})")

        # ── (c) Invalid-token control ─────────────────────────────────────────
        corrupted = _corrupt_headers(attacker_headers)
        if corrupted == attacker_headers:
            # Nothing corruptible (no credential header): control not applicable.
            failed_disproof.append("invalid_token_control (skipped: no credential header)")
            corrupted = None
        try:
            if corrupted is None:
                raise _SkipControl()
            bad_tok_resp = await self.runner.execute_request(
                method="GET",
                url=attack_url,
                headers=corrupted or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
            if 200 <= bad_tok_resp.status_code < 300 and _bodies_equal(
                bad_tok_resp.body, baseline_body, ignore_fields
            ):
                disproved_by.append(
                    f"invalid_token_control (corrupted token HTTP "
                    f"{bad_tok_resp.status_code} returned matching body -> "
                    "auth not enforced at all, different bug class)"
                )
            else:
                failed_disproof.append("invalid_token_control")
        except _SkipControl:
            pass
        except Exception as exc:
            disproved_by.append(f"invalid_token_control (inconclusive, request failed: {exc})")

        # ── (d) Fresh-request check ───────────────────────────────────────────
        try:
            fresh_resp = await self.runner.execute_request(
                method="GET",
                url=attack_url,
                headers=attacker_headers or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
            if 200 <= fresh_resp.status_code < 300 and _bodies_equal(
                fresh_resp.body, baseline_body, ignore_fields
            ):
                failed_disproof.append("fresh_request")
            else:
                disproved_by.append(
                    f"fresh_request (independent attacker GET returned "
                    f"HTTP {fresh_resp.status_code}; body did not match baseline)"
                )
        except Exception as exc:
            disproved_by.append(f"fresh_request (inconclusive, request failed: {exc})")

        # ── Verdict ───────────────────────────────────────────────────────────
        is_confirmed = len(disproved_by) == 0

        if is_confirmed:
            counter_evidence_str = (
                "All disproof tests failed to refute the finding: "
                + ", ".join(failed_disproof)
            )
            confidence = 0.95
        else:
            counter_evidence_str = (
                "Finding disproved by: " + "; ".join(disproved_by)
            )
            confidence = 0.2

        reproduction_steps = (
            f"1. Send GET {attack_url} with attacker credentials.\n"
            f"2. Observed HTTP {last_attack_status} on final replay.\n"
            f"3. Reproducibility rate: {reproducibility_rate:.0%} "
            f"({hits}/{self.replays} successful replays).\n"
            f"4. Negative control (no auth): {'body matched' if any('negative_control' in d for d in disproved_by) else 'access denied as expected'}.\n"
            f"5. Invalid-token control: {'body matched (auth bypass suspected)' if any('invalid_token' in d for d in disproved_by) else 'access denied as expected'}.\n"
            f"6. Fresh-request: {'body did not match' if any('fresh_request' in d for d in disproved_by) else 'body matched baseline — confirmed'}."
        )

        return VerificationVerdict(
            is_confirmed=is_confirmed,
            reproducibility_rate=reproducibility_rate,
            confidence=confidence,
            counter_evidence=counter_evidence_str,
            reproduction_steps=reproduction_steps,
        )
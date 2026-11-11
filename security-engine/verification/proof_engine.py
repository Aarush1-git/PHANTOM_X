"""
Self-Challenging Proof Engine for BOLA and authorization findings.

After an authorization check flags a potential vulnerability, this engine
attempts to *disprove* the finding through four independent negative-control
tests:

  a) Reproducibility  - replay the attacker GET `replays` times; require a 100%
     hit rate (2xx + body matches baseline_body) to rule out flakiness.
  b) Negative control - unauthenticated GET must NOT return baseline_body; if it
     does, the data is public and the finding is REJECTED.
  c) Invalid-token    - a deliberately corrupted attacker token must NOT return
     baseline_body; if it does, authentication is not being enforced at all
     (a different class of bug, requires human review).
  d) Fresh-request    - one additional attacker-only GET (no cookies carried from
     earlier calls) confirms the result is not an artifact of session state.

Outcomes (evaluated in strict priority order):
  1. baseline unavailable                                   -> INCONCLUSIVE
  2. negative control (no auth) returned the baseline body  -> REJECTED ("public endpoint")
  3. any control/fresh request raised or hit safety policy,
     or a 429 was seen, or cache_suspected                  -> INCONCLUSIVE
  4. attacker replay hits == 0                              -> REJECTED ("not reproducible: 0/N")
  5. invalid-token control returned the baseline body,
     OR 0 < hits < replays, OR fresh request mismatched    -> NEEDS_HUMAN_REVIEW
  6. otherwise                                              -> CONFIRMED
"""

import json
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from execution.http_runner import ControlledHttpRunner
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilityStatus


class VerificationOutcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


def to_vulnerability_status(outcome: VerificationOutcome | str) -> VulnerabilityStatus:
    """
    Map VerificationOutcome to VulnerabilityStatus.

    PROPOSED mapping (pending team agreement):
      CONFIRMED          -> VERIFIED
      REJECTED           -> FALSE_POSITIVE
      INCONCLUSIVE       -> VERIFYING
      NEEDS_HUMAN_REVIEW -> VERIFYING
    """
    val = outcome.value if isinstance(outcome, VerificationOutcome) else str(outcome)
    if val == VerificationOutcome.CONFIRMED.value:
        return VulnerabilityStatus.VERIFIED
    if val == VerificationOutcome.REJECTED.value:
        return VulnerabilityStatus.FALSE_POSITIVE
    return VulnerabilityStatus.VERIFYING


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


def _is_cache_suspect(headers: Optional[Dict[str, str]]) -> bool:
    """
    Check if response headers indicate it may have been served from a cache.
    Case-insensitive header lookup:
      - Age is an int > 0
      - X-Cache, X-Cache-Status, or CF-Cache-Status contains 'HIT'
    """
    if not headers:
        return False
    lower = {k.lower(): str(v) for k, v in headers.items()}
    if "age" in lower:
        try:
            if int(lower["age"]) > 0:
                return True
        except ValueError:
            pass
    for h in ("x-cache", "x-cache-status", "cf-cache-status"):
        if h in lower and "HIT" in lower[h].upper():
            return True
    return False


class _SkipControl(Exception):
    """Internal: control test not applicable."""


class VerificationVerdict(BaseModel):
    is_confirmed: bool
    reproducibility_rate: float
    confidence: float
    counter_evidence: str
    reproduction_steps: str
    outcome: VerificationOutcome = VerificationOutcome.INCONCLUSIVE
    reason: str = ""
    cache_suspected: bool = False


class SelfChallengingProofEngine:
    """
    Challenges suspected BOLA findings with four disproof tests to prevent
    false-positive reporting. Requires a ControlledHttpRunner for all HTTP
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

        seen_429 = False
        cache_suspected = False
        negative_control_matched = False
        invalid_token_control_matched = False
        fresh_request_mismatched = False
        control_or_fresh_safety = None
        control_or_fresh_exception = None

        # The baseline is never stored in findings/evidence (it may hold credentials),
        # so re-fetch it as the legitimate owner when not supplied.
        victim_headers: Dict[str, str] = evidence.get("victim_headers", {})
        baseline_failure = "not supplied and no owner credentials to re-fetch"
        if not baseline_body and victim_headers:
            try:
                base_resp = await self.runner.execute_request(
                    method="GET",
                    url=attack_url,
                    headers=victim_headers,
                    safety_classification=SafetyClassification.SAFE_READ_ONLY,
                )
                if base_resp.status_code == 429:
                    seen_429 = True
                if not (200 <= base_resp.status_code < 300):
                    baseline_failure = f"owner re-fetch returned HTTP {base_resp.status_code}"
                elif not base_resp.body:
                    baseline_failure = "owner re-fetch returned an empty body"
                else:
                    baseline_body = base_resp.body
            except SafetyViolationError:
                baseline_failure = "owner re-fetch blocked by safety policy"
            except Exception as exc:  # reason only: exception text may hold credentials
                baseline_failure = f"owner re-fetch failed ({type(exc).__name__})"

        # Rule 1: baseline unavailable -> INCONCLUSIVE
        if not baseline_body:
            reason = f"No baseline body available ({baseline_failure}); cannot verify finding."
            return VerificationVerdict(
                is_confirmed=False,
                reproducibility_rate=0.0,
                confidence=0.0,
                counter_evidence=reason,
                reproduction_steps=f"1. GET {attack_url} as attacker.\n2. Not run: no baseline to compare against.",
                outcome=VerificationOutcome.INCONCLUSIVE,
                reason=reason,
                cache_suspected=False,
            )

        failed_disproof: List[str] = []  # tests that could NOT disprove the finding
        disproved_by: List[str] = []     # tests that DID disprove the finding

        # ── (a) Reproducibility ───────────────────────────────────────────────
        hits = 0
        last_attack_status = 0
        last_attack_body = ""
        replay_safety = None
        replay_exception = None
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
                if resp.status_code == 429:
                    seen_429 = True
                if 200 <= resp.status_code < 300 and _bodies_equal(
                    resp.body, baseline_body, ignore_fields
                ):
                    hits += 1
                    if _is_cache_suspect(resp.headers):
                        cache_suspected = True
            except SafetyViolationError:
                replay_safety = "attacker replay blocked by safety policy"
            except Exception as exc:
                replay_exception = f"attacker replay failed ({type(exc).__name__})"

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
            if no_auth_resp.status_code == 429:
                seen_429 = True
            if 200 <= no_auth_resp.status_code < 300 and _bodies_equal(
                no_auth_resp.body, baseline_body, ignore_fields
            ):
                negative_control_matched = True
                disproved_by.append(
                    f"negative_control (unauthenticated GET returned HTTP "
                    f"{no_auth_resp.status_code} with matching body -> public endpoint)"
                )
            else:
                failed_disproof.append("negative_control")
        except SafetyViolationError:
            control_or_fresh_safety = "negative control blocked by safety policy"
            disproved_by.append("negative_control (blocked by safety policy)")
        except Exception as exc:
            control_or_fresh_exception = f"negative control failed ({type(exc).__name__})"
            disproved_by.append(f"negative_control (inconclusive, request failed: {type(exc).__name__})")

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
            if bad_tok_resp.status_code == 429:
                seen_429 = True
            if 200 <= bad_tok_resp.status_code < 300 and _bodies_equal(
                bad_tok_resp.body, baseline_body, ignore_fields
            ):
                invalid_token_control_matched = True
                disproved_by.append(
                    f"invalid_token_control (corrupted token HTTP "
                    f"{bad_tok_resp.status_code} returned matching body -> "
                    "auth not enforced at all, different bug class)"
                )
            else:
                failed_disproof.append("invalid_token_control")
        except _SkipControl:
            pass
        except SafetyViolationError:
            control_or_fresh_safety = "invalid-token control blocked by safety policy"
            disproved_by.append("invalid_token_control (blocked by safety policy)")
        except Exception as exc:
            control_or_fresh_exception = f"invalid-token control failed ({type(exc).__name__})"
            disproved_by.append(f"invalid_token_control (inconclusive, request failed: {type(exc).__name__})")

        # ── (d) Fresh-request check ───────────────────────────────────────────
        fresh_status = 0
        try:
            fresh_resp = await self.runner.execute_request(
                method="GET",
                url=attack_url,
                headers=attacker_headers or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
            fresh_status = fresh_resp.status_code
            if fresh_resp.status_code == 429:
                seen_429 = True
            if 200 <= fresh_resp.status_code < 300 and _bodies_equal(
                fresh_resp.body, baseline_body, ignore_fields
            ):
                if _is_cache_suspect(fresh_resp.headers):
                    cache_suspected = True
                failed_disproof.append("fresh_request")
            else:
                fresh_request_mismatched = True
                disproved_by.append(
                    f"fresh_request (independent attacker GET returned "
                    f"HTTP {fresh_resp.status_code}; body did not match baseline)"
                )
        except SafetyViolationError:
            control_or_fresh_safety = "fresh request blocked by safety policy"
            disproved_by.append("fresh_request (blocked by safety policy)")
        except Exception as exc:
            control_or_fresh_exception = f"fresh request failed ({type(exc).__name__})"
            disproved_by.append(f"fresh_request (inconclusive, request failed: {type(exc).__name__})")

        # ── Outcome rules (evaluated in strict priority order) ─────────────────
        # 1. baseline unavailable -> handled above
        # 2. negative control returned baseline body -> REJECTED ("public endpoint")
        if negative_control_matched:
            outcome = VerificationOutcome.REJECTED
            reason = "Negative control (unauthenticated GET) returned the baseline body; public endpoint, not a vulnerability."
            confidence = 0.2
        # 3. any control/fresh request raised or hit safety policy, or a 429 was seen, or cache_suspected -> INCONCLUSIVE
        elif control_or_fresh_safety or replay_safety:
            outcome = VerificationOutcome.INCONCLUSIVE
            reason = f"Request blocked by safety policy ({control_or_fresh_safety or replay_safety}); verification inconclusive."
            confidence = 0.2
        elif control_or_fresh_exception or replay_exception:
            outcome = VerificationOutcome.INCONCLUSIVE
            reason = f"Request raised network error ({control_or_fresh_exception or replay_exception}); verification inconclusive."
            confidence = 0.2
        elif seen_429:
            outcome = VerificationOutcome.INCONCLUSIVE
            reason = "Rate limit (HTTP 429) encountered during verification; verification inconclusive."
            confidence = 0.2
        elif cache_suspected:
            outcome = VerificationOutcome.INCONCLUSIVE
            reason = "response may be served from cache; replay not independent"
            confidence = 0.2
        # 4. attacker replay hits == 0 -> REJECTED ("not reproducible: 0/N")
        elif hits == 0:
            outcome = VerificationOutcome.REJECTED
            reason = f"Finding is not reproducible: 0/{self.replays} attacker replays succeeded."
            confidence = 0.2
        # 5. invalid-token control returned baseline body, OR 0 < hits < replays, OR fresh request mismatched -> NEEDS_HUMAN_REVIEW
        elif invalid_token_control_matched:
            outcome = VerificationOutcome.NEEDS_HUMAN_REVIEW
            reason = "authentication not enforced at all - likely a different bug class (corrupted token returned baseline data)"
            confidence = 0.2
        elif 0 < hits < self.replays:
            outcome = VerificationOutcome.NEEDS_HUMAN_REVIEW
            reason = f"intermittent: {hits}/{self.replays} attacker replays succeeded (reproducibility rate {reproducibility_rate:.2f} < 1.0)"
            confidence = 0.2
        elif fresh_request_mismatched:
            outcome = VerificationOutcome.NEEDS_HUMAN_REVIEW
            reason = f"fresh request did not reproduce finding (HTTP {fresh_status}; body did not match baseline)"
            confidence = 0.2
        # 6. otherwise -> CONFIRMED
        else:
            outcome = VerificationOutcome.CONFIRMED
            reason = f"Finding confirmed: all {self.replays}/{self.replays} replays succeeded and all negative controls passed."
            confidence = 0.95

        is_confirmed = (outcome == VerificationOutcome.CONFIRMED)

        if is_confirmed:
            counter_evidence_str = (
                "All disproof tests failed to refute the finding: "
                + ", ".join(failed_disproof)
            )
        else:
            counter_evidence_str = (
                "Finding disproved by: " + "; ".join(disproved_by)
            )

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
            outcome=outcome,
            reason=reason,
            cache_suspected=cache_suspected,
        )

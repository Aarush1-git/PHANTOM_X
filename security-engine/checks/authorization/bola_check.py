"""
BOLA (Broken Object Level Authorization) detection check - API1:2023.

Algorithm:
  1. Baseline GET as User A: establishes the expected resource body.
     If non-2xx -> inconclusive (endpoint may require different preconditions).
  2. Control GET with no auth: if 2xx and body matches baseline -> public endpoint,
     not a BOLA finding.
  3. Attack GET as User B: the cross-tenant/cross-user access attempt.
  4. Compare bodies (JSON-aware, ignore_fields stripped): decide verdict.

All HTTP traffic flows through self.runner.execute_request (never raw httpx).
Sensitive header values (Authorization, Cookie, X-API-Key) are REDACTED in
evidence_request and proof_data - only presence booleans are stored.
SafetyViolationError from an out-of-scope host is caught and returned as
is_vulnerable=False with the safety policy message.
"""

import json
import re
from typing import Any, Dict, Optional

from checks.authorization.access_probe import describe_expected_actual
from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

# Headers whose values must never appear in evidence / proof_data
_SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key"}

_REDACT = "[REDACTED]"


def _redact_headers(headers: Optional[Dict[str, str]]) -> str:
    """Return a string representation of *headers* with sensitive values replaced."""
    if not headers:
        return "{}"
    safe: Dict[str, str] = {}
    for k, v in headers.items():
        safe[k] = _REDACT if k.lower() in _SENSITIVE_HEADERS else v
    return str(safe)


def _strip_fields(obj: Any, ignore_fields: list) -> Any:
    """Recursively remove *ignore_fields* keys from a parsed JSON object."""
    if isinstance(obj, dict):
        return {k: _strip_fields(v, ignore_fields) for k, v in obj.items() if k not in ignore_fields}
    if isinstance(obj, list):
        return [_strip_fields(item, ignore_fields) for item in obj]
    return obj


def _bodies_equal(body_a: str, body_b: str, ignore_fields: list) -> bool:
    """
    Compare two response bodies.

    Attempts JSON parse + field-stripping first; falls back to exact string
    comparison when either body is not valid JSON.
    """
    try:
        parsed_a = _strip_fields(json.loads(body_a), ignore_fields)
        parsed_b = _strip_fields(json.loads(body_b), ignore_fields)
        return parsed_a == parsed_b
    except (json.JSONDecodeError, ValueError):
        return body_a == body_b


class BOLAOwnershipCheck(BaseSecurityCheck):
    """
    Detects Broken Object Level Authorization (BOLA / IDOR) by issuing three
    GET requests to the same resource:

      baseline  - as the legitimate owner (User A)
      control   - with no authentication (public-endpoint detection)
      attack    - as an unrelated user (User B)

    The finding is HIGH-severity CWE-639 only when the attack response is 2xx
    **and** its (field-stripped) body is identical to the baseline body,
    proving that User B received User A's private data.
    """

    def __init__(self, runner=None):
        super().__init__(check_name="BOLAOwnershipCheck", runner=runner)

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:  # noqa: C901
        url = context.target_url.rstrip("/") + context.endpoint_path
        ignore_fields: list = context.parameters.get("ignore_fields", [])
        owner_label = context.parameters.get("owner_label", "owner")
        attacker_label = context.parameters.get("attacker_label", "attacker")
        identity_labels = {"owner": owner_label, "attacker": attacker_label}

        def _not_vuln(
            title: str,
            description: str,
            confidence: float,
            severity: VulnerabilitySeverity = VulnerabilitySeverity.INFO,
            attack_resp=None,
            baseline_status: int = 0,
            attack_status: int = 0,
            control_status: int = 0,
        ) -> SecurityCheckResult:
            evidence_req = ""
            evidence_resp = ""
            attempted = attack_resp is not None
            if attack_resp is not None:
                evidence_req = (
                    f"GET {url}\n"
                    f"Headers: {_redact_headers(context.secondary_auth_headers)}\n"
                    f"Body: None"
                )
                evidence_resp = build_response_dump(attack_resp.status_code, attack_resp.headers, attack_resp.body)

            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                recommendation=(
                    "Implement server-side ownership validation: verify that the "
                    "authenticated user's ID/org matches the resource's owner before "
                    "returning any data."
                ),
                cwe_id=None,
                cvss_score=None,
                evidence_request=evidence_req,
                evidence_response=evidence_resp,
                proof_data={
                    "baseline_status": baseline_status,
                    "attack_status": attack_status,
                    "control_status": control_status,
                    "body_match": False,
                    "attack_url": url,
                    "user_a_headers_present": bool(context.auth_headers),
                    "user_b_headers_present": bool(context.secondary_auth_headers),
                    "ignore_fields": ignore_fields,
                    **describe_expected_actual(attack_status, False, attempted=attempted),
                    "identity_labels": identity_labels,
                },
            )

        # ── Step 1: Baseline (User A) ─────────────────────────────────────────
        try:
            baseline = await self.runner.execute_request(
                method="GET",
                url=url,
                headers=context.auth_headers or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
        except SafetyViolationError as exc:
            return _not_vuln(
                title="BOLA check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                confidence=0.0,
            )
        except Exception as exc:
            return _not_vuln(
                title="BOLA check inconclusive",
                description=f"Network error during baseline request: {exc}",
                confidence=0.0,
            )

        if not (200 <= baseline.status_code < 300):
            return _not_vuln(
                title="BOLA check inconclusive",
                description=(
                    f"Baseline request as User A returned HTTP {baseline.status_code}; "
                    "cannot establish an expected body to compare against."
                ),
                confidence=0.0,
                baseline_status=baseline.status_code,
            )

        # ── Step 2: Control (no auth) ─────────────────────────────────────────
        try:
            control = await self.runner.execute_request(
                method="GET",
                url=url,
                headers=None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
        except SafetyViolationError as exc:
            return _not_vuln(
                title="BOLA check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                confidence=0.0,
                baseline_status=baseline.status_code,
            )
        except Exception as exc:
            return _not_vuln(
                title="BOLA check inconclusive",
                description=f"Network error during control request: {exc}",
                confidence=0.0,
                baseline_status=baseline.status_code,
            )

        if 200 <= control.status_code < 300 and _bodies_equal(
            control.body, baseline.body, ignore_fields
        ):
            return _not_vuln(
                title="BOLA check - public endpoint",
                description="Endpoint is publicly readable (no auth required); not a BOLA finding.",
                confidence=0.9,
                baseline_status=baseline.status_code,
                control_status=control.status_code,
            )

        # ── Step 3: Attack (User B) ───────────────────────────────────────────
        try:
            attack = await self.runner.execute_request(
                method="GET",
                url=url,
                headers=context.secondary_auth_headers or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
        except SafetyViolationError as exc:
            return _not_vuln(
                title="BOLA check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                confidence=0.0,
                baseline_status=baseline.status_code,
                control_status=control.status_code,
            )
        except Exception as exc:
            return _not_vuln(
                title="BOLA check inconclusive",
                description=f"Network error during attack request: {exc}",
                confidence=0.0,
                baseline_status=baseline.status_code,
                control_status=control.status_code,
            )

        # ── Step 4: Verdict ───────────────────────────────────────────────────
        body_match = _bodies_equal(attack.body, baseline.body, ignore_fields)

        evidence_request = (
            f"GET {url}\n"
            f"Headers: {_redact_headers(context.secondary_auth_headers)}\n"
            f"Body: None"
        )
        evidence_response = build_response_dump(attack.status_code, attack.headers, attack.body)

        proof_data: Dict[str, Any] = {
            "baseline_status": baseline.status_code,
            "attack_status": attack.status_code,
            "control_status": control.status_code,
            "body_match": body_match,
            "attack_url": url,
            "user_a_headers_present": bool(context.auth_headers),
            "user_b_headers_present": bool(context.secondary_auth_headers),
            "ignore_fields": ignore_fields,
            **describe_expected_actual(attack.status_code, body_match, attempted=True),
            "identity_labels": identity_labels,
        }

        if 200 <= attack.status_code < 300 and body_match:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.HIGH,
                confidence=0.9,
                title="Broken Object Level Authorization (BOLA)",
                description=(
                    f"User B successfully accessed resource at {url} owned by User A. "
                    f"Attack response HTTP {attack.status_code} body matches the owner's "
                    "baseline response, confirming unauthorized cross-user data exposure."
                ),
                recommendation=(
                    "Implement server-side ownership validation: verify that the "
                    "authenticated user's ID/org matches the resource's owner before "
                    "returning any data."
                ),
                cwe_id="CWE-639",
                cvss_score=8.6,
                evidence_request=evidence_request,
                evidence_response=evidence_response,
                proof_data=proof_data,
            )

        if attack.status_code in (401, 403, 404):
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.9,
                title="BOLA check passed - access denied",
                description=(
                    f"User B was correctly denied access to the resource: "
                    f"HTTP {attack.status_code} returned."
                ),
                recommendation="No action required; authorization is enforced correctly.",
                cwe_id=None,
                cvss_score=None,
                evidence_request=evidence_request,
                evidence_response=evidence_response,
                proof_data=proof_data,
            )

        if 200 <= attack.status_code < 300 and not body_match:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.6,
                title="BOLA check passed - body differs",
                description=(
                    f"User B received HTTP {attack.status_code} but the response body "
                    "does not match User A's resource. The endpoint may serve per-user "
                    "data correctly, or returns a different resource."
                ),
                recommendation="Review whether the differing body represents a separate scoped resource.",
                cwe_id=None,
                cvss_score=None,
                evidence_request=evidence_request,
                evidence_response=evidence_response,
                proof_data=proof_data,
            )

        # Any other status code (5xx, 3xx not followed, etc.)
        return SecurityCheckResult(
            check_name=self.check_name,
            is_vulnerable=False,
            severity=VulnerabilitySeverity.INFO,
            confidence=0.3,
            title="BOLA check inconclusive",
            description=(
                f"Unexpected HTTP {attack.status_code} from attack request; "
                "result is inconclusive."
            ),
            recommendation="Investigate the unexpected response and re-run the check.",
            cwe_id=None,
            cvss_score=None,
            evidence_request=evidence_request,
            evidence_response=evidence_response,
            proof_data=proof_data,
        )
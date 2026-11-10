"""
RBAC (Role-Based Access Control) check — detects Broken Function Level
Authorization (OWASP API5:2023 / CWE-285).

Algorithm:
  1. Only GET / HEAD / OPTIONS are supported. Any other method is refused up front
     with no request sent, because the owner baseline request would itself perform
     the privileged action (and could modify data) in a permissive policy mode.
  2. Use probe_access to issue three requests:
       baseline  : as the privileged role (admin / auth_headers)
       control   : no auth
       attack    : as the lower-privilege role (agent / customer / secondary_auth_headers)
  3. Verdict from AccessDecision:
       ACCESS_GRANTED → vulnerable: HIGH, CWE-285, cvss 8.1
       BLOCKED        → not vulnerable, description "Blocked by safety policy: ..."
       others         → not vulnerable, INFO, confidence per decision table

Severity of non-vulnerable results follows the same confidence table as
TenantIsolationCheck: DENIED 0.9, PUBLIC 0.9, BODY_DIFFERS 0.6, rest 0.0–0.3.
"""

from typing import Any, Dict, Optional

from checks.authorization.access_probe import AccessDecision, probe_access
from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump, redact_headers
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

_RECOMMENDATION = (
    "Enforce function-level access control server-side: validate the caller's "
    "role or permission before processing any privileged operation, regardless "
    "of the HTTP method or URL structure."
)


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class RBACCheck(BaseSecurityCheck):
    """
    Tests whether a lower-privileged role can invoke a privileged endpoint.

    Uses probe_access (baseline=admin, attack=lower-role) and maps the
    AccessDecision to a vulnerability verdict.
    """

    def __init__(self, runner=None):
        super().__init__(check_name="RBACCheck", runner=runner)

    @staticmethod
    def _classification(method: str) -> SafetyClassification:
        if method.upper() in {"GET", "HEAD", "OPTIONS"}:
            return SafetyClassification.SAFE_READ_ONLY
        return SafetyClassification.STATE_MODIFYING

    @staticmethod
    def _conf(decision: AccessDecision) -> float:
        return {
            AccessDecision.DENIED: 0.9,
            AccessDecision.PUBLIC: 0.9,
            AccessDecision.BODY_DIFFERS: 0.6,
            AccessDecision.INCONCLUSIVE: 0.0,
            AccessDecision.BLOCKED: 0.0,
        }.get(decision, 0.3)

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        url = context.target_url.rstrip("/") + context.endpoint_path
        method = (context.http_method or "GET").upper()
        ignore_fields: list = context.parameters.get("ignore_fields", [])
        role_label: str = context.parameters.get("role_label", "lower-privilege role")

        if method not in _SAFE_METHODS:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="RBAC check skipped - state-changing method not supported",
                description=(
                    f"Method {method} is not supported: the owner baseline request would "
                    "perform the privileged action itself. Use GET, HEAD or OPTIONS. "
                    "No request was sent."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id=None,
                cvss_score=None,
                evidence_request="",
                evidence_response="",
                proof_data={"attack_url": url, "skipped": "state_changing_method", "method": method},
            )
        classification = self._classification(method)

        pr = await probe_access(
            self.runner, url,
            owner_headers=context.auth_headers,
            attacker_headers=context.secondary_auth_headers,
            method=method,
            classification=classification,
            ignore_fields=ignore_fields,
        )

        # Build evidence from attack response
        attack_resp = pr.attack
        evidence_request = (
            f"{method} {url}\n"
            f"Headers: {redact_headers(context.secondary_auth_headers)}\n"
            f"Body: None"
        )
        evidence_response = (
            build_response_dump(attack_resp.status_code, attack_resp.headers, attack_resp.body)
            if attack_resp else ""
        )

        proof_data: Dict[str, Any] = {
            "baseline_status": pr.baseline.status_code if pr.baseline else 0,
            "attack_status": attack_resp.status_code if attack_resp else 0,
            "control_status": pr.control.status_code if pr.control else 0,
            "body_match": pr.body_match,
            "attack_url": url,
            "user_a_headers_present": bool(context.auth_headers),
            "user_b_headers_present": bool(context.secondary_auth_headers),
            "ignore_fields": ignore_fields,
        }

        def _not_vuln(title: str, description: str, confidence: float) -> SecurityCheckResult:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=confidence,
                title=title,
                description=description,
                recommendation=_RECOMMENDATION,
                cwe_id=None,
                cvss_score=None,
                evidence_request=evidence_request,
                evidence_response=evidence_response,
                proof_data=proof_data,
            )

        if pr.decision == AccessDecision.ACCESS_GRANTED:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.HIGH,
                confidence=0.9,
                title="Broken Function Level Authorization (RBAC bypass)",
                description=(
                    f"The {role_label} successfully invoked the privileged endpoint "
                    f"{method} {url} (HTTP {attack_resp.status_code if attack_resp else '?'}). "
                    "Response body matches the admin baseline, confirming unauthorized "
                    "function-level access."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id="CWE-285",
                cvss_score=8.1,
                evidence_request=evidence_request,
                evidence_response=evidence_response,
                proof_data=proof_data,
            )

        if pr.decision == AccessDecision.BLOCKED:
            return _not_vuln(
                title="RBAC check blocked by safety policy",
                description=f"Blocked by safety policy: {pr.detail}",
                confidence=0.0,
            )

        descs = {
            AccessDecision.PUBLIC: "Endpoint is publicly readable; not an RBAC finding.",
            AccessDecision.DENIED: (
                f"The {role_label} was correctly denied access "
                f"(HTTP {attack_resp.status_code if attack_resp else '?'})."
            ),
            AccessDecision.BODY_DIFFERS: (
                f"The {role_label} received a 2xx response but with a different body; "
                "access may be scoped correctly."
            ),
            AccessDecision.INCONCLUSIVE: (
                f"RBAC check inconclusive: {pr.detail or 'unexpected response'}"
            ),
        }
        return _not_vuln(
            title=f"RBAC check — {pr.decision.value.lower().replace('_', ' ')}",
            description=descs.get(pr.decision, pr.detail),
            confidence=self._conf(pr.decision),
        )
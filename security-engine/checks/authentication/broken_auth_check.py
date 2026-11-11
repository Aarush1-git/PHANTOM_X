"""
Broken Authentication Check (Feature 17, Check 1).

Verifies authentication enforcement on sensitive endpoints by probing:
  1. Valid baseline request as the owner.
  2. Five unauthenticated or malformed-credential variants:
     - no_credentials (no headers)
     - empty_bearer   ("Bearer ")
     - bearer_null    ("Bearer null")
     - garbage_token  ("Bearer invalid.invalid.invalid")
     - unsigned_jwt   ("Bearer <b64({"alg":"none","typ":"JWT"})>.<b64({"sub":"1"})>.")
  3. 3/3 reproducibility confirmation for any accepted variant (2xx + body equals baseline).

Request budget: default max 40 requests; stops immediately on budget limit or HTTP 429.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional, Tuple

from checks.authorization.access_probe import bodies_equal
from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump, redact_headers
from execution.http_runner import ControlledHttpResponse
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

_EXPECTED_SENTENCE = "authentication required: requests without valid credentials are rejected (HTTP 401/403)"
_RECOMMENDATION_MISSING = "Enforce mandatory authentication on all protected endpoints."
_RECOMMENDATION_INVALID = "Validate authentication tokens strictly; reject unsigned tokens, empty tokens, and malformed credentials."


def _make_unsigned_jwt() -> str:
    """Generate an alg=none unsigned JWT with an empty signature component."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("ascii").rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').decode("ascii").rstrip("=")
    return f"{header}.{payload}."


class BrokenAuthenticationCheck(BaseSecurityCheck):
    """Verifies that sensitive endpoints enforce authentication against unauthenticated and malformed requests."""

    def __init__(self, runner=None):
        super().__init__(check_name="BrokenAuthenticationCheck", runner=runner)

    def _build_evidence(
        self,
        url: str,
        sent_headers: Optional[Dict[str, str]],
        resp: Optional[ControlledHttpResponse],
    ) -> Tuple[str, str]:
        if resp is None:
            return "", ""
        headers_to_redact = sent_headers if sent_headers is not None else {}
        evidence_request = f"GET {url}\nHeaders: {redact_headers(headers_to_redact)}\nBody: None"
        evidence_response = build_response_dump(resp.status_code, resp.headers, resp.body)
        return evidence_request, evidence_response

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        url = context.target_url.rstrip("/") + context.endpoint_path
        params = context.parameters or {}
        expect_auth = params.get("expect_auth", True)
        auth_header_name = params.get("auth_header_name", "Authorization")
        ignore_fields = params.get("ignore_fields", [])
        max_requests = params.get("max_requests", 40)
        owner_label = params.get("owner_label", "owner")
        identity_labels = {"owner": owner_label}

        # Step 0: If endpoint is explicitly declared public, send no requests
        if not expect_auth:
            proof_data = {
                "baseline_status": 0,
                "variants": {},
                "accepted_variants": [],
                "reproducibility": {},
                "attack_url": url,
                "self_verified": False,
                "ignore_fields": list(ignore_fields),
                "expected": _EXPECTED_SENTENCE,
                "actual": "all unauthenticated and invalid-credential variants rejected",
                "identity_labels": identity_labels,
            }
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.9,
                title="Broken authentication check — declared public",
                description="Endpoint is declared public; skipping authentication check.",
                recommendation="Ensure that public endpoints do not expose sensitive user or tenant data.",
                cwe_id=None,
                cvss_score=None,
                proof_data=proof_data,
            )

        request_count = 0

        async def _execute(headers: Optional[Dict[str, str]]) -> ControlledHttpResponse:
            nonlocal request_count
            if request_count >= max_requests:
                raise RuntimeError("Request budget exceeded")
            request_count += 1
            return await self.runner.execute_request(
                method="GET",
                url=url,
                headers=headers,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )

        # Step 1: Baseline request with valid owner credentials
        try:
            baseline_resp = await _execute(context.auth_headers)
        except SafetyViolationError as exc:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Broken authentication check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                recommendation="Verify safety policy host allowlist.",
                proof_data={
                    "baseline_status": 0,
                    "variants": {},
                    "accepted_variants": [],
                    "reproducibility": {},
                    "attack_url": url,
                    "self_verified": False,
                    "ignore_fields": list(ignore_fields),
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "all unauthenticated and invalid-credential variants rejected",
                    "identity_labels": identity_labels,
                },
            )
        except Exception as exc:
            desc = "rate limited, backed off" if "rate limit" in str(exc).lower() else f"request error ({type(exc).__name__})"
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Broken authentication check inconclusive",
                description=desc,
                recommendation="Investigate baseline endpoint connectivity.",
                proof_data={
                    "baseline_status": 0,
                    "variants": {},
                    "accepted_variants": [],
                    "reproducibility": {},
                    "attack_url": url,
                    "self_verified": False,
                    "ignore_fields": list(ignore_fields),
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "all unauthenticated and invalid-credential variants rejected",
                    "identity_labels": identity_labels,
                },
            )

        if baseline_resp.status_code == 429:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Broken authentication check inconclusive",
                description="rate limited, backed off",
                recommendation="Throttle request rate or configure higher rate limits.",
                proof_data={
                    "baseline_status": 429,
                    "variants": {},
                    "accepted_variants": [],
                    "reproducibility": {},
                    "attack_url": url,
                    "self_verified": False,
                    "ignore_fields": list(ignore_fields),
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "all unauthenticated and invalid-credential variants rejected",
                    "identity_labels": identity_labels,
                },
            )

        if not (200 <= baseline_resp.status_code < 300):
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Broken authentication check inconclusive",
                description=f"Baseline request failed with HTTP {baseline_resp.status_code}",
                recommendation="Ensure the baseline request is valid and returns a 2xx response.",
                proof_data={
                    "baseline_status": baseline_resp.status_code,
                    "variants": {},
                    "accepted_variants": [],
                    "reproducibility": {},
                    "attack_url": url,
                    "self_verified": False,
                    "ignore_fields": list(ignore_fields),
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "all unauthenticated and invalid-credential variants rejected",
                    "identity_labels": identity_labels,
                },
            )

        baseline_body = baseline_resp.body
        baseline_status = baseline_resp.status_code

        # Step 2: Probing variants
        unsigned_jwt_val = f"Bearer {_make_unsigned_jwt()}"
        variant_specs: List[Tuple[str, Optional[Dict[str, str]]]] = [
            ("no_credentials", None),
            ("empty_bearer", {auth_header_name: "Bearer"}),
            ("bearer_null", {auth_header_name: "Bearer null"}),
            ("garbage_token", {auth_header_name: "Bearer invalid.invalid.invalid"}),
            ("unsigned_jwt", {auth_header_name: unsigned_jwt_val}),
        ]

        variants_data: Dict[str, Dict[str, Any]] = {}
        accepted_variants: List[str] = []
        variant_resps: Dict[str, Tuple[Optional[Dict[str, str]], ControlledHttpResponse]] = {}
        first_accepted_pair: Optional[Tuple[Optional[Dict[str, str]], ControlledHttpResponse]] = None
        no_credentials_pair: Optional[Tuple[Optional[Dict[str, str]], ControlledHttpResponse]] = None

        for var_name, var_headers in variant_specs:
            try:
                resp = await _execute(var_headers)
            except SafetyViolationError as exc:
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="Broken authentication check blocked by safety policy",
                    description=f"Blocked by safety policy: {exc}",
                    recommendation="Verify safety policy host allowlist.",
                    proof_data={
                        "baseline_status": baseline_status,
                        "variants": variants_data,
                        "accepted_variants": accepted_variants,
                        "reproducibility": {},
                        "attack_url": url,
                        "self_verified": False,
                        "ignore_fields": list(ignore_fields),
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "all unauthenticated and invalid-credential variants rejected",
                        "identity_labels": identity_labels,
                    },
                )
            except Exception as exc:
                desc = "rate limited, backed off" if "rate limit" in str(exc).lower() else f"request error ({type(exc).__name__})"
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="Broken authentication check inconclusive",
                    description=desc,
                    recommendation="Investigate endpoint error during probe execution.",
                    proof_data={
                        "baseline_status": baseline_status,
                        "variants": variants_data,
                        "accepted_variants": accepted_variants,
                        "reproducibility": {},
                        "attack_url": url,
                        "self_verified": False,
                        "ignore_fields": list(ignore_fields),
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "all unauthenticated and invalid-credential variants rejected",
                        "identity_labels": identity_labels,
                    },
                )

            if resp.status_code == 429:
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="Broken authentication check inconclusive",
                    description="rate limited, backed off",
                    recommendation="Throttle request rate or configure higher rate limits.",
                    proof_data={
                        "baseline_status": baseline_status,
                        "variants": variants_data,
                        "accepted_variants": accepted_variants,
                        "reproducibility": {},
                        "attack_url": url,
                        "self_verified": False,
                        "ignore_fields": list(ignore_fields),
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "all unauthenticated and invalid-credential variants rejected",
                        "identity_labels": identity_labels,
                    },
                )

            is_2xx = 200 <= resp.status_code < 300
            body_match = is_2xx and bodies_equal(resp.body, baseline_body, ignore_fields=ignore_fields)
            is_accepted = bool(is_2xx and body_match)

            variants_data[var_name] = {
                "status": resp.status_code,
                "accepted": is_accepted,
            }
            variant_resps[var_name] = (var_headers, resp)

            if var_name == "no_credentials":
                no_credentials_pair = (var_headers, resp)

            if is_accepted:
                accepted_variants.append(var_name)
                if first_accepted_pair is None:
                    first_accepted_pair = (var_headers, resp)

        # Step 3: Replay accepted variants 2 more times (total 3 trials)
        reproducibility: Dict[str, str] = {}
        confirmed_variants: List[str] = []

        for var_name in accepted_variants:
            hits = 1  # Initial accepted trial
            var_headers = None
            for s_name, s_headers in variant_specs:
                if s_name == var_name:
                    var_headers = s_headers
                    break

            for _ in range(2):
                try:
                    rep_resp = await _execute(var_headers)
                except Exception:
                    break

                if rep_resp.status_code == 429:
                    return SecurityCheckResult(
                        check_name=self.check_name,
                        is_vulnerable=False,
                        severity=VulnerabilitySeverity.INFO,
                        confidence=0.0,
                        title="Broken authentication check inconclusive",
                        description="rate limited, backed off",
                        recommendation="Throttle request rate or configure higher rate limits.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "variants": variants_data,
                            "accepted_variants": accepted_variants,
                            "reproducibility": reproducibility,
                            "attack_url": url,
                            "self_verified": False,
                            "ignore_fields": list(ignore_fields),
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "all unauthenticated and invalid-credential variants rejected",
                            "identity_labels": identity_labels,
                        },
                    )

                if (200 <= rep_resp.status_code < 300) and bodies_equal(
                    rep_resp.body, baseline_body, ignore_fields=ignore_fields
                ):
                    hits += 1

            reproducibility[var_name] = f"{hits}/3"
            if hits == 3:
                confirmed_variants.append(var_name)

        # Step 4: Determine verdict
        is_vuln = False
        evidence_pair = first_accepted_pair or no_credentials_pair

        if "no_credentials" in confirmed_variants:
            is_vuln = True
            severity = VulnerabilitySeverity.CRITICAL
            cvss_score = 9.1
            cwe_id = "CWE-306"
            title = "Missing authentication"
            description = "Endpoint does not enforce authentication; unauthenticated requests returned owner's data."
            recommendation = _RECOMMENDATION_MISSING
            confidence = 0.9
        elif confirmed_variants:
            is_vuln = True
            severity = VulnerabilitySeverity.CRITICAL
            cvss_score = 9.1
            cwe_id = "CWE-347" if "unsigned_jwt" in confirmed_variants else "CWE-287"
            title = f"Broken authentication ({', '.join(confirmed_variants)})"
            description = f"Endpoint accepted invalid authentication credentials: {', '.join(confirmed_variants)}."
            recommendation = _RECOMMENDATION_INVALID
            confidence = 0.9
        elif accepted_variants:
            # Accepted initially but failed 3/3 reproducibility
            is_vuln = False
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "Broken authentication check — not reproducible"
            description = "Variant accepted initially but failed to reproduce 3/3 times (not reproducible)."
            recommendation = "Investigate intermittent authentication authorization checks."
            confidence = 0.6
        elif all(v["status"] in (401, 403) for v in variants_data.values()):
            is_vuln = False
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "Authentication properly enforced"
            description = "All unauthenticated and invalid-credential variants rejected with 401/403."
            recommendation = "Continue enforcing authentication middleware on all protected endpoints."
            confidence = 0.9
        else:
            is_vuln = False
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "Broken authentication check — inconclusive"
            description = "Variants were not accepted with owner data (received different bodies or non-auth error status codes)."
            recommendation = "Verify endpoint error responses and authentication handling."
            confidence = 0.6

        # Step 5: Construct actual sentence and proof data
        if confirmed_variants:
            actual_sentence = f"variants accepted with the owner's data: {', '.join(confirmed_variants)}"
        elif accepted_variants:
            actual_sentence = f"variants accepted with the owner's data: {', '.join(accepted_variants)}"
        else:
            actual_sentence = "all unauthenticated and invalid-credential variants rejected"

        proof_data = {
            "baseline_status": baseline_status,
            "variants": variants_data,
            "accepted_variants": accepted_variants,
            "reproducibility": reproducibility,
            "attack_url": url,
            "self_verified": is_vuln,
            "ignore_fields": list(ignore_fields),
            "expected": _EXPECTED_SENTENCE,
            "actual": actual_sentence,
            "identity_labels": identity_labels,
        }

        # Step 6: Construct evidence dumps
        evidence_request = ""
        evidence_response = ""
        if evidence_pair is not None:
            ev_headers, ev_resp = evidence_pair
            evidence_request, evidence_response = self._build_evidence(url, ev_headers, ev_resp)

        return SecurityCheckResult(
            check_name=self.check_name,
            is_vulnerable=is_vuln,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            recommendation=recommendation,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            evidence_request=evidence_request,
            evidence_response=evidence_response,
            proof_data=proof_data,
        )

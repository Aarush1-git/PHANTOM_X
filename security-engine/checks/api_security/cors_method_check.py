"""
CORS and Method Check (Feature 17, Check 3).

Verifies Cross-Origin Resource Sharing (CORS) and enabled HTTP methods:
  A. Untrusted origin reflection:
     Probes Origin "https://evil.example" and "null" with GET.
     Verifies 3/3 reproducibility for reflected origins.
     - Reflected + Access-Control-Allow-Credentials: true -> MEDIUM (CWE-942)
     - Reflected without credentials -> LOW (CWE-942)
  B. Unexpected HTTP methods:
     Probes OPTIONS to parse Allow and Access-Control-Allow-Methods headers.
     - Unexpected methods enabled (or TRACE enabled) -> LOW (CWE-16)

Reports the most severe finding and lists all detected findings in proof_data.
Request budget: default max 40 requests; stops immediately on budget limit or HTTP 429.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump, redact_headers
from execution.http_runner import ControlledHttpResponse
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

_EXPECTED_SENTENCE = "untrusted origins are not reflected and only expected HTTP methods are enabled"


class CorsAndMethodCheck(BaseSecurityCheck):
    """Detects overly permissive CORS origin reflection and enabled dangerous or unexpected HTTP methods."""

    def __init__(self, runner=None):
        super().__init__(check_name="CorsAndMethodCheck", runner=runner)

    def _build_evidence(
        self,
        method: str,
        url: str,
        sent_headers: Optional[Dict[str, str]],
        resp: Optional[ControlledHttpResponse],
    ) -> Tuple[str, str]:
        if resp is None:
            return "", ""
        headers_to_redact = sent_headers if sent_headers is not None else {}
        evidence_request = f"{method} {url}\nHeaders: {redact_headers(headers_to_redact)}\nBody: None"
        evidence_response = build_response_dump(resp.status_code, resp.headers, resp.body)
        return evidence_request, evidence_response

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        url = context.target_url.rstrip("/") + context.endpoint_path
        params = context.parameters or {}
        expected_methods = [
            m.strip().upper()
            for m in params.get("expected_methods", ["GET", "HEAD", "OPTIONS"])
        ]
        allowed_methods_set = set(expected_methods)
        max_requests = params.get("max_requests", 40)
        owner_label = params.get("owner_label", "owner")
        identity_labels = {"owner": owner_label}

        request_count = 0
        statuses: Dict[str, int] = {}

        async def _execute(
            method: str, headers: Optional[Dict[str, str]]
        ) -> ControlledHttpResponse:
            nonlocal request_count
            if request_count >= max_requests:
                raise RuntimeError("Request budget exceeded")
            request_count += 1
            return await self.runner.execute_request(
                method=method,
                url=url,
                headers=headers,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )

        findings: List[Dict[str, Any]] = []
        last_pair: Optional[Tuple[str, Optional[Dict[str, str]], ControlledHttpResponse]] = None

        # ── Step A: Origin Reflection Probes ─────────────────────────────────
        test_origins = ["https://evil.example", "null"]

        for origin in test_origins:
            origin_headers = {**(context.auth_headers or {}), "Origin": origin}
            try:
                resp = await _execute("GET", origin_headers)
            except SafetyViolationError as exc:
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="CORS check blocked by safety policy",
                    description=f"Blocked by safety policy: {exc}",
                    recommendation="Verify safety policy host allowlist.",
                    proof_data={
                        "statuses": statuses,
                        "findings": [],
                        "reproducible": False,
                        "attack_url": url,
                        "self_verified": False,
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "no issue found",
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
                    title="CORS and method check inconclusive",
                    description=desc,
                    recommendation="Investigate origin reflection probe error.",
                    proof_data={
                        "statuses": statuses,
                        "findings": [],
                        "reproducible": False,
                        "attack_url": url,
                        "self_verified": False,
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "no issue found",
                        "identity_labels": identity_labels,
                    },
                )

            statuses[f"origin_{origin}"] = resp.status_code
            last_pair = ("GET", origin_headers, resp)

            if resp.status_code == 429:
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="CORS and method check inconclusive",
                    description="rate limited, backed off",
                    recommendation="Throttle request rate or configure higher rate limits.",
                    proof_data={
                        "statuses": statuses,
                        "findings": [],
                        "reproducible": False,
                        "attack_url": url,
                        "self_verified": False,
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "no issue found",
                        "identity_labels": identity_labels,
                    },
                )

            # Check for reflection
            resp_headers_lower = {k.lower(): str(v) for k, v in (resp.headers or {}).items()}
            acao = resp_headers_lower.get("access-control-allow-origin")
            acac = resp_headers_lower.get("access-control-allow-credentials", "").lower()

            if acao and acao.strip().lower() == origin.lower():
                # Replay 2 more times to confirm 3/3
                hits = 1
                for _ in range(2):
                    try:
                        rep_resp = await _execute("GET", origin_headers)
                    except Exception:
                        break
                    rep_headers_lower = {k.lower(): str(v) for k, v in (rep_resp.headers or {}).items()}
                    rep_acao = rep_headers_lower.get("access-control-allow-origin")
                    if rep_acao and rep_acao.strip().lower() == origin.lower():
                        hits += 1

                if hits == 3:
                    has_creds = acac.strip() == "true"
                    if has_creds:
                        findings.append({
                            "short_name": "cors_origin_reflected_with_credentials",
                            "severity": VulnerabilitySeverity.MEDIUM,
                            "cvss_score": 6.5,
                            "cwe_id": "CWE-942",
                            "title": "CORS misconfiguration (origin reflected with credentials)",
                            "description": f"Endpoint reflects untrusted Origin '{origin}' with Access-Control-Allow-Credentials enabled.",
                            "recommendation": "Configure a whitelist of trusted origins and avoid reflecting arbitrary origins with credentials enabled.",
                            "actual": f"origin {origin} reflected with credentials allowed",
                            "pair": ("GET", origin_headers, resp),
                        })
                    else:
                        findings.append({
                            "short_name": "cors_origin_reflected",
                            "severity": VulnerabilitySeverity.LOW,
                            "cvss_score": 3.7,
                            "cwe_id": "CWE-942",
                            "title": "CORS misconfiguration (origin reflected)",
                            "description": f"Endpoint reflects untrusted Origin '{origin}' in Access-Control-Allow-Origin.",
                            "recommendation": "Avoid reflecting arbitrary origins; explicitly declare allowed origins or public access.",
                            "actual": f"origin {origin} reflected without credentials",
                            "pair": ("GET", origin_headers, resp),
                        })

        # ── Step B: HTTP Methods Probe ───────────────────────────────────────
        options_headers = context.auth_headers or {}
        try:
            opt_resp = await _execute("OPTIONS", options_headers)
            statuses["options"] = opt_resp.status_code
            last_pair = ("OPTIONS", options_headers, opt_resp)
        except SafetyViolationError as exc:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Method check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                recommendation="Verify safety policy host allowlist.",
                proof_data={
                    "statuses": statuses,
                    "findings": [f["short_name"] for f in findings],
                    "reproducible": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no issue found",
                    "identity_labels": identity_labels,
                },
            )
        except Exception as exc:
            # If options probe fails with an exception, check if origin findings exist
            if not findings:
                desc = "rate limited, backed off" if "rate limit" in str(exc).lower() else f"request error ({type(exc).__name__})"
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="CORS and method check inconclusive",
                    description=desc,
                    recommendation="Investigate OPTIONS probe connectivity.",
                    proof_data={
                        "statuses": statuses,
                        "findings": [],
                        "reproducible": False,
                        "attack_url": url,
                        "self_verified": False,
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "no issue found",
                        "identity_labels": identity_labels,
                    },
                )
            opt_resp = None

        if opt_resp is not None and opt_resp.status_code == 429 and not findings:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="CORS and method check inconclusive",
                description="rate limited, backed off",
                recommendation="Throttle request rate or configure higher rate limits.",
                proof_data={
                    "statuses": statuses,
                    "findings": [],
                    "reproducible": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no issue found",
                    "identity_labels": identity_labels,
                },
            )

        if opt_resp is not None:
            opt_headers_lower = {k.lower(): str(v) for k, v in (opt_resp.headers or {}).items()}
            methods_declared: Set[str] = set()

            for h_key in ("allow", "access-control-allow-methods"):
                h_val = opt_headers_lower.get(h_key)
                if h_val:
                    for m in h_val.split(","):
                        clean_m = m.strip().upper()
                        if clean_m:
                            methods_declared.add(clean_m)

            unexpected = sorted(
                m for m in methods_declared if m not in allowed_methods_set or m == "TRACE"
            )

            if unexpected:
                findings.append({
                    "short_name": "unexpected_methods_enabled",
                    "severity": VulnerabilitySeverity.LOW,
                    "cvss_score": 3.1,
                    "cwe_id": "CWE-16",
                    "title": "Unexpected HTTP methods enabled",
                    "description": f"Endpoint enables unexpected or risky HTTP methods: {', '.join(unexpected)}.",
                    "recommendation": "Disable unused and risky HTTP methods such as TRACE and state-modifying verbs where not required.",
                    "actual": f"unexpected methods enabled: {', '.join(unexpected)}",
                    "unexpected_methods": unexpected,
                    "pair": ("OPTIONS", options_headers, opt_resp),
                })

        # ── Step C: Select most severe finding ────────────────────────────────
        is_vuln = len(findings) > 0
        severity_rank = {
            VulnerabilitySeverity.CRITICAL: 4,
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 1,
            VulnerabilitySeverity.INFO: 0,
        }

        if is_vuln:
            # Sort findings by severity descending
            findings.sort(key=lambda f: severity_rank.get(f["severity"], 0), reverse=True)
            primary = findings[0]

            severity = primary["severity"]
            cvss_score = primary["cvss_score"]
            cwe_id = primary["cwe_id"]
            title = primary["title"]
            description = primary["description"]
            recommendation = primary["recommendation"]
            confidence = 0.9
            actual_sentence = primary["actual"]
            evidence_pair = primary["pair"]
        else:
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "CORS and HTTP methods properly configured"
            description = "Untrusted origins are not reflected and only expected HTTP methods are enabled."
            recommendation = "Maintain restrictive CORS policy and minimal enabled HTTP methods."
            confidence = 0.9
            actual_sentence = "no issue found"
            evidence_pair = last_pair

        finding_names = [f["short_name"] for f in findings]
        for f in findings:
            if "unexpected_methods" in f:
                for m in f["unexpected_methods"]:
                    if m not in finding_names:
                        finding_names.append(m)

        proof_data: Dict[str, Any] = {
            "statuses": statuses,
            "findings": finding_names,
            "reproducible": is_vuln,
            "attack_url": url,
            "self_verified": is_vuln,
            "expected": _EXPECTED_SENTENCE,
            "actual": actual_sentence,
            "identity_labels": identity_labels,
        }

        # Include unexpected_methods list if present
        for f in findings:
            if "unexpected_methods" in f:
                proof_data["unexpected_methods"] = f["unexpected_methods"]
                break

        # Step D: Construct evidence
        evidence_request = ""
        evidence_response = ""
        if evidence_pair is not None:
            ev_m, ev_h, ev_r = evidence_pair
            evidence_request, evidence_response = self._build_evidence(ev_m, url, ev_h, ev_r)

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

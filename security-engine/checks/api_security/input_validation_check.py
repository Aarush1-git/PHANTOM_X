"""
Input Validation Check (Feature 17, Check 2).

Probes input parameter validation on endpoints by injecting benign malformed
values (quotes, length boundaries, negative numbers, path traversals) and observing:
  - Unhandled 5xx server errors
  - Verbose internal exception / stack trace disclosures

Request budget: default max 40 requests; stops immediately on budget limit or HTTP 429.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump, redact_headers
from execution.http_runner import ControlledHttpResponse
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

_EXPECTED_SENTENCE = "malformed input is rejected with a 4xx validation error and no internal details"

MALFORMED_PROBES: List[Tuple[str, str]] = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("long_string", "A" * 5000),
    ("negative", "-1"),
    ("non_numeric", "abc"),
    ("path_traversal", "../"),
]

DISCLOSURE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"SQLSTATE", re.IGNORECASE),
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"psycopg2", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"at java\.", re.IGNORECASE),
    re.compile(r"System\.NullReferenceException", re.IGNORECASE),
]


def _has_disclosure(body: str) -> bool:
    """Returns True if the response body contains any known internal disclosure pattern."""
    if not body:
        return False
    return any(p.search(body) for p in DISCLOSURE_PATTERNS)


class InputValidationCheck(BaseSecurityCheck):
    """Detects missing input validation and verbose error / stack trace disclosure."""

    def __init__(self, runner=None):
        super().__init__(check_name="InputValidationCheck", runner=runner)

    def _build_evidence(
        self,
        full_url: str,
        sent_headers: Optional[Dict[str, str]],
        resp: Optional[ControlledHttpResponse],
    ) -> Tuple[str, str]:
        if resp is None:
            return "", ""
        headers_to_redact = sent_headers if sent_headers is not None else {}
        evidence_request = f"GET {full_url}\nHeaders: {redact_headers(headers_to_redact)}\nBody: None"
        evidence_response = build_response_dump(resp.status_code, resp.headers, resp.body)
        return evidence_request, evidence_response

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        url = context.target_url.rstrip("/") + context.endpoint_path
        params = context.parameters or {}
        probe_params = params.get("probe_params")
        max_requests = params.get("max_requests", 40)
        owner_label = params.get("owner_label", "owner")
        identity_labels = {"owner": owner_label}

        # Step 0: probe_params is required and non-empty
        if not probe_params or not isinstance(probe_params, dict):
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Input validation check inconclusive",
                description="probe_params is required",
                recommendation="Provide valid probe_params dictionary in check parameters.",
                proof_data={
                    "baseline_status": 0,
                    "probes_sent": 0,
                    "failing_probes": [],
                    "reproducible": False,
                    "disclosure_matched": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no malformed probe caused a failure",
                    "identity_labels": identity_labels,
                },
            )

        request_count = 0

        async def _execute(
            query_params: Optional[Dict[str, Any]]
        ) -> ControlledHttpResponse:
            nonlocal request_count
            if request_count >= max_requests:
                raise RuntimeError("Request budget exceeded")
            request_count += 1
            return await self.runner.execute_request(
                method="GET",
                url=url,
                headers=context.auth_headers,
                params=query_params,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )

        # Step 1: Baseline GET with all valid probe_params
        try:
            baseline_resp = await _execute(probe_params)
        except SafetyViolationError as exc:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Input validation check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                recommendation="Verify safety policy host allowlist.",
                proof_data={
                    "baseline_status": 0,
                    "probes_sent": 0,
                    "failing_probes": [],
                    "reproducible": False,
                    "disclosure_matched": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no malformed probe caused a failure",
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
                title="Input validation check inconclusive",
                description=desc,
                recommendation="Ensure the baseline request succeeds with valid parameters.",
                proof_data={
                    "baseline_status": 0,
                    "probes_sent": 0,
                    "failing_probes": [],
                    "reproducible": False,
                    "disclosure_matched": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no malformed probe caused a failure",
                    "identity_labels": identity_labels,
                },
            )

        if baseline_resp.status_code == 429:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Input validation check inconclusive",
                description="rate limited, backed off",
                recommendation="Throttle request rate or configure higher rate limits.",
                proof_data={
                    "baseline_status": 429,
                    "probes_sent": 0,
                    "failing_probes": [],
                    "reproducible": False,
                    "disclosure_matched": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no malformed probe caused a failure",
                    "identity_labels": identity_labels,
                },
            )

        if not (200 <= baseline_resp.status_code < 300):
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                confidence=0.0,
                title="Input validation check inconclusive",
                description=f"Baseline request failed with HTTP {baseline_resp.status_code}",
                recommendation="Ensure the baseline request with probe_params returns a 2xx response.",
                proof_data={
                    "baseline_status": baseline_resp.status_code,
                    "probes_sent": 0,
                    "failing_probes": [],
                    "reproducible": False,
                    "disclosure_matched": False,
                    "attack_url": url,
                    "self_verified": False,
                    "expected": _EXPECTED_SENTENCE,
                    "actual": "no malformed probe caused a failure",
                    "identity_labels": identity_labels,
                },
            )

        baseline_status = baseline_resp.status_code

        # Step 2: For each param and each benign malformed value, send GET
        probes_sent = 0
        failing_probes_info: List[Dict[str, Any]] = []
        failing_probes_labels: List[Dict[str, str]] = []

        for p_name in probe_params.keys():
            for label, malformed_val in MALFORMED_PROBES:
                test_params = {**probe_params, p_name: malformed_val}
                probes_sent += 1

                try:
                    p_resp = await _execute(test_params)
                except SafetyViolationError as exc:
                    return SecurityCheckResult(
                        check_name=self.check_name,
                        is_vulnerable=False,
                        severity=VulnerabilitySeverity.INFO,
                        confidence=0.0,
                        title="Input validation check blocked by safety policy",
                        description=f"Blocked by safety policy: {exc}",
                        recommendation="Verify safety policy host allowlist.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "probes_sent": probes_sent,
                            "failing_probes": failing_probes_labels,
                            "reproducible": False,
                            "disclosure_matched": False,
                            "attack_url": url,
                            "self_verified": False,
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "no malformed probe caused a failure",
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
                        title="Input validation check inconclusive",
                        description=desc,
                        recommendation="Investigate server errors during input validation probes.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "probes_sent": probes_sent,
                            "failing_probes": failing_probes_labels,
                            "reproducible": False,
                            "disclosure_matched": False,
                            "attack_url": url,
                            "self_verified": False,
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "no malformed probe caused a failure",
                            "identity_labels": identity_labels,
                        },
                    )

                if p_resp.status_code == 429:
                    return SecurityCheckResult(
                        check_name=self.check_name,
                        is_vulnerable=False,
                        severity=VulnerabilitySeverity.INFO,
                        confidence=0.0,
                        title="Input validation check inconclusive",
                        description="rate limited, backed off",
                        recommendation="Throttle request rate or configure higher rate limits.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "probes_sent": probes_sent,
                            "failing_probes": failing_probes_labels,
                            "reproducible": False,
                            "disclosure_matched": False,
                            "attack_url": url,
                            "self_verified": False,
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "no malformed probe caused a failure",
                            "identity_labels": identity_labels,
                        },
                    )

                is_5xx = 500 <= p_resp.status_code <= 599
                has_disc = _has_disclosure(p_resp.body)

                if is_5xx or has_disc:
                    failing_probes_labels.append({"param": p_name, "value_label": label})
                    failing_probes_info.append({
                        "param": p_name,
                        "value_label": label,
                        "test_params": test_params,
                        "initial_resp": p_resp,
                        "initial_has_disc": has_disc,
                        "initial_is_5xx": is_5xx,
                    })

        # Step 3: Replay each failing probe 2 more times (must fail 3/3)
        confirmed_failing_probes: List[Dict[str, Any]] = []

        for item in failing_probes_info:
            test_params = item["test_params"]
            hits = 1
            has_disc_replays = item["initial_has_disc"]
            all_5xx = item["initial_is_5xx"]

            for _ in range(2):
                try:
                    rep_resp = await _execute(test_params)
                except Exception:
                    break

                if rep_resp.status_code == 429:
                    return SecurityCheckResult(
                        check_name=self.check_name,
                        is_vulnerable=False,
                        severity=VulnerabilitySeverity.INFO,
                        confidence=0.0,
                        title="Input validation check inconclusive",
                        description="rate limited, backed off",
                        recommendation="Throttle request rate or configure higher rate limits.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "probes_sent": probes_sent,
                            "failing_probes": failing_probes_labels,
                            "reproducible": False,
                            "disclosure_matched": False,
                            "attack_url": url,
                            "self_verified": False,
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "no malformed probe caused a failure",
                            "identity_labels": identity_labels,
                        },
                    )

                is_5xx_rep = 500 <= rep_resp.status_code <= 599
                has_disc_rep = _has_disclosure(rep_resp.body)

                if is_5xx_rep or has_disc_rep:
                    hits += 1
                    if has_disc_rep:
                        has_disc_replays = True
                    if not is_5xx_rep:
                        all_5xx = False

            if hits == 3:
                confirmed_failing_probes.append({
                    **item,
                    "has_disclosure": has_disc_replays,
                    "is_5xx_only": all_5xx and not has_disc_replays,
                })

        # Step 4: If any probe failed, repeat valid baseline request once
        if failing_probes_info:
            try:
                check_base = await _execute(probe_params)
                if not (200 <= check_base.status_code < 300):
                    return SecurityCheckResult(
                        check_name=self.check_name,
                        is_vulnerable=False,
                        severity=VulnerabilitySeverity.INFO,
                        confidence=0.0,
                        title="Input validation check inconclusive",
                        description="server unstable after probes",
                        recommendation="Ensure the server remains stable under malformed parameter testing.",
                        proof_data={
                            "baseline_status": baseline_status,
                            "probes_sent": probes_sent,
                            "failing_probes": failing_probes_labels,
                            "reproducible": False,
                            "disclosure_matched": False,
                            "attack_url": url,
                            "self_verified": False,
                            "expected": _EXPECTED_SENTENCE,
                            "actual": "no malformed probe caused a failure",
                            "identity_labels": identity_labels,
                        },
                    )
            except Exception as exc:
                return SecurityCheckResult(
                    check_name=self.check_name,
                    is_vulnerable=False,
                    severity=VulnerabilitySeverity.INFO,
                    confidence=0.0,
                    title="Input validation check inconclusive",
                    description=f"server unstable after probes ({type(exc).__name__})",
                    recommendation="Ensure the server remains stable under malformed parameter testing.",
                    proof_data={
                        "baseline_status": baseline_status,
                        "probes_sent": probes_sent,
                        "failing_probes": failing_probes_labels,
                        "reproducible": False,
                        "disclosure_matched": False,
                        "attack_url": url,
                        "self_verified": False,
                        "expected": _EXPECTED_SENTENCE,
                        "actual": "no malformed probe caused a failure",
                        "identity_labels": identity_labels,
                    },
                )

        # Step 5: Verdict
        reproducible = len(confirmed_failing_probes) > 0
        disclosure_matched = any(p["has_disclosure"] for p in confirmed_failing_probes)
        is_vuln = False
        evidence_item: Optional[Dict[str, Any]] = None

        if confirmed_failing_probes:
            is_vuln = True
            evidence_item = confirmed_failing_probes[0]
            if disclosure_matched:
                severity = VulnerabilitySeverity.MEDIUM
                cvss_score = 5.3
                cwe_id = "CWE-209"
                title = "Verbose error disclosure"
                description = "Endpoint discloses internal error details / stack traces upon receiving malformed input."
                recommendation = "Sanitize and validate input; disable verbose error messages and stack traces in production."
                confidence = 0.9
            else:
                severity = VulnerabilitySeverity.LOW
                cvss_score = 3.7
                cwe_id = "CWE-20"
                title = "Improper input validation (server error)"
                description = "Endpoint triggered an unhandled server error (5xx) upon receiving malformed input."
                recommendation = "Validate and sanitize input; return HTTP 4xx client errors instead of unhandled 5xx errors."
                confidence = 0.9
        elif failing_probes_info:
            is_vuln = False
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "Input validation check — not reproducible"
            description = "Malformed probe failed initially but was not reproducible across 3/3 attempts (not reproducible)."
            recommendation = "Investigate intermittent input validation error handling."
            confidence = 0.6
            evidence_item = failing_probes_info[0]
        else:
            is_vuln = False
            severity = VulnerabilitySeverity.INFO
            cvss_score = None
            cwe_id = None
            title = "Input validation properly enforced"
            description = "All malformed probes were rejected or handled safely without internal error disclosure."
            recommendation = "Continue validating input parameters against expected schemas."
            confidence = 0.9

        # Step 6: Expected vs Actual
        if is_vuln and evidence_item is not None:
            ev_status = evidence_item["initial_resp"].status_code
            actual_sentence = f"HTTP {ev_status}; internal error details disclosed: {'yes' if disclosure_matched else 'no'}"
        elif failing_probes_info and evidence_item is not None:
            ev_status = evidence_item["initial_resp"].status_code
            disc_flag = "yes" if evidence_item["initial_has_disc"] else "no"
            actual_sentence = f"HTTP {ev_status}; internal error details disclosed: {disc_flag}"
        else:
            actual_sentence = "no malformed probe caused a failure"

        proof_data = {
            "baseline_status": baseline_status,
            "probes_sent": probes_sent,
            "failing_probes": failing_probes_labels,
            "reproducible": reproducible,
            "disclosure_matched": disclosure_matched,
            "attack_url": url,
            "self_verified": is_vuln,
            "expected": _EXPECTED_SENTENCE,
            "actual": actual_sentence,
            "identity_labels": identity_labels,
        }

        # Step 7: Build evidence
        evidence_request = ""
        evidence_response = ""
        if evidence_item is not None:
            query_str = urlencode(evidence_item["test_params"])
            full_url = f"{url}?{query_str}" if query_str else url
            evidence_request, evidence_response = self._build_evidence(
                full_url, context.auth_headers, evidence_item["initial_resp"]
            )

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


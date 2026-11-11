"""
Tenant Isolation Check — detects cross-tenant data exposure (API1:2023 / CWE-639).

Three modes, selected via context.parameters["mode"]:

  object (default)
    Probes a single tenant-A resource using probe_access.  ACCESS_GRANTED
    means tenant B can read tenant A's object → vulnerable (CRITICAL, CWE-639).

  list
    Probes a collection endpoint.  Baseline (tenant A) must return ≥1 item whose
    tenant_field equals tenant_a_id; otherwise INCONCLUSIVE ("nothing to leak").
    Attack (tenant B) is replayed 3 times; vulnerable only when ALL 3 responses
    contain at least one item with tenant_field == tenant_a_id.
    A no-auth control that also leaks the item → PUBLIC, not a vulnerability.
    Self-verified findings skip the external proof engine (proof_data["self_verified"]=True,
    proof_data["leaked_item_count"] set).

  spoof
    First does a plain object probe.  If tenant B already gets tenant A's data
    without any spoofed header → report as an object-level finding and stop.
    Otherwise attack as tenant B with an extra {tenant_header: tenant_a_id} header;
    ACCESS_GRANTED → vulnerable (proof_data["extra_attacker_headers"] set).

Severity / CWE:
  object / spoof : CRITICAL, CWE-639, cvss 9.1
  list           : CRITICAL, CWE-200, cvss 9.1
  not vulnerable : INFO, confidence per decision, no CWE/CVSS
"""

import json
from typing import Any, Dict, List, Optional

from checks.authorization.access_probe import (
    AccessDecision, AccessProbeResult, bodies_equal, describe_expected_actual, probe_access,
)
from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from evidence.redact import build_response_dump, redact_headers
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification, VulnerabilitySeverity

_RECOMMENDATION = (
    "Enforce strict server-side tenant isolation: derive the tenant scope "
    "from the authenticated token, never from request headers or parameters "
    "that the caller can control."
)


def _extract_items(body: str) -> List[Any]:
    """Return the top-level list from a JSON body, checking common envelope keys."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _has_tenant_item(items: List[Any], tenant_field: str, tenant_id: str) -> bool:
    return any(
        isinstance(item, dict) and str(item.get(tenant_field, "")) == str(tenant_id)
        for item in items
    )


class TenantIsolationCheck(BaseSecurityCheck):
    """
    Tests cross-tenant data isolation in three modes (object / list / spoof).
    Uses the shared probe_access helper for all individual probes.
    """

    def __init__(self, runner=None):
        super().__init__(check_name="TenantIsolationCheck", runner=runner)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _base_proof(
        self,
        mode: str,
        url: str,
        pr: AccessProbeResult,
        context: SecurityCheckContext,
        ignore_fields: list,
        **extra,
    ) -> Dict[str, Any]:
        attempted = pr.attack is not None
        attack_status = pr.attack.status_code if pr.attack else 0
        owner_label = context.parameters.get("owner_label", "owner")
        attacker_label = context.parameters.get("attacker_label", "attacker")
        return {
            "mode": mode,
            "baseline_status": pr.baseline.status_code if pr.baseline else 0,
            "attack_status": attack_status,
            "control_status": pr.control.status_code if pr.control else 0,
            "body_match": pr.body_match,
            "attack_url": url,
            "user_a_headers_present": bool(context.auth_headers),
            "user_b_headers_present": bool(context.secondary_auth_headers),
            "ignore_fields": ignore_fields,
            **describe_expected_actual(attack_status, pr.body_match, attempted=attempted),
            "identity_labels": {"owner": owner_label, "attacker": attacker_label},
            **extra,
        }

    def _evidence_pair(self, url: str, attacker_headers: dict, attack_resp) -> tuple[str, str]:
        """Return (evidence_request, evidence_response) for the attack request."""
        req = (
            f"GET {url}\n"
            f"Headers: {redact_headers(attacker_headers)}\n"
            f"Body: None"
        )
        resp = build_response_dump(
            attack_resp.status_code, attack_resp.headers, attack_resp.body
        ) if attack_resp else ""
        return req, resp

    def _not_vuln(
        self,
        title: str,
        description: str,
        confidence: float,
        proof_data: dict,
        evidence_request: str = "",
        evidence_response: str = "",
    ) -> SecurityCheckResult:
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

    def _conf(self, decision: AccessDecision) -> float:
        return {
            AccessDecision.DENIED: 0.9,
            AccessDecision.PUBLIC: 0.9,
            AccessDecision.BODY_DIFFERS: 0.6,
            AccessDecision.INCONCLUSIVE: 0.0,
            AccessDecision.BLOCKED: 0.0,
        }.get(decision, 0.3)

    # ── object mode ───────────────────────────────────────────────────────────

    async def _run_object(
        self, context: SecurityCheckContext, url: str, ignore_fields: list
    ) -> SecurityCheckResult:
        pr = await probe_access(
            self.runner, url,
            owner_headers=context.auth_headers,
            attacker_headers=context.secondary_auth_headers,
            ignore_fields=ignore_fields,
        )
        proof = self._base_proof("object", url, pr, context, ignore_fields)
        req, resp = self._evidence_pair(url, context.secondary_auth_headers, pr.attack)

        if pr.decision == AccessDecision.ACCESS_GRANTED:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.CRITICAL,
                confidence=0.9,
                title="Tenant Isolation Violation — object-level cross-tenant access",
                description=(
                    f"Tenant B successfully read a resource owned by Tenant A at {url}. "
                    f"Attack response HTTP {pr.attack.status_code} body matches the "
                    "owner's baseline, confirming cross-tenant data exposure."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id="CWE-639",
                cvss_score=9.1,
                evidence_request=req,
                evidence_response=resp,
                proof_data=proof,
            )

        if pr.decision == AccessDecision.BLOCKED:
            return self._not_vuln(
                title="Tenant isolation check blocked by safety policy",
                description=f"Blocked by safety policy: {pr.detail}",
                confidence=0.0,
                proof_data=proof,
            )

        descs = {
            AccessDecision.PUBLIC: "Endpoint is publicly readable (no auth required); not a tenant isolation finding.",
            AccessDecision.DENIED: f"Tenant B was correctly denied access (HTTP {pr.attack.status_code if pr.attack else '?'}).",
            AccessDecision.BODY_DIFFERS: "Tenant B received a different body — may be their own scoped data.",
            AccessDecision.INCONCLUSIVE: f"Check inconclusive: {pr.detail or 'unexpected response'}",
        }
        return self._not_vuln(
            title=f"Tenant isolation check — {pr.decision.value.lower().replace('_', ' ')}",
            description=descs.get(pr.decision, pr.detail),
            confidence=self._conf(pr.decision),
            proof_data=proof,
            evidence_request=req,
            evidence_response=resp,
        )

    # ── list mode ─────────────────────────────────────────────────────────────

    async def _run_list(
        self, context: SecurityCheckContext, url: str, ignore_fields: list
    ) -> SecurityCheckResult:
        tenant_a_id: str = str(context.parameters.get("tenant_a_id", ""))
        tenant_field: str = context.parameters.get("tenant_field", "tenant_id")
        owner_label = context.parameters.get("owner_label", "owner")
        attacker_label = context.parameters.get("attacker_label", "attacker")
        identity_labels = {"owner": owner_label, "attacker": attacker_label}

        def _empty_proof(extra=None):
            p = {
                "mode": "list",
                "baseline_status": 0, "attack_status": 0, "control_status": 0,
                "body_match": False, "attack_url": url,
                "user_a_headers_present": bool(context.auth_headers),
                "user_b_headers_present": bool(context.secondary_auth_headers),
                "ignore_fields": ignore_fields,
                **describe_expected_actual(0, False, attempted=False),
                "identity_labels": identity_labels,
            }
            if extra:
                p.update(extra)
            return p

        if not tenant_a_id:
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description="Inconclusive: parameters['tenant_a_id'] is required for list mode.",
                confidence=0.0,
                proof_data=_empty_proof(),
            )

        # Baseline
        try:
            base_resp = await self.runner.execute_request(
                method="GET", url=url,
                headers=context.auth_headers or None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
        except SafetyViolationError as exc:
            return self._not_vuln(
                title="Tenant isolation check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                confidence=0.0,
                proof_data=_empty_proof(),
            )
        except Exception as exc:
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description=f"request error ({type(exc).__name__})",
                confidence=0.0,
                proof_data=_empty_proof(),
            )

        if not (200 <= base_resp.status_code < 300):
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description=f"Baseline returned HTTP {base_resp.status_code}; nothing to compare.",
                confidence=0.0,
                proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
            )

        base_items = _extract_items(base_resp.body)
        if not _has_tenant_item(base_items, tenant_field, tenant_a_id):
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description=(
                    f"Baseline response contains no item with "
                    f"{tenant_field}=={tenant_a_id!r}; nothing to leak."
                ),
                confidence=0.0,
                proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
            )

        # Control (no auth)
        try:
            ctrl_resp = await self.runner.execute_request(
                method="GET", url=url, headers=None,
                safety_classification=SafetyClassification.SAFE_READ_ONLY,
            )
        except SafetyViolationError as exc:
            return self._not_vuln(
                title="Tenant isolation check blocked by safety policy",
                description=f"Blocked by safety policy: {exc}",
                confidence=0.0,
                proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
            )
        except Exception as exc:
            # Cannot rule out a public endpoint -> do not report a finding.
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description=f"request error ({type(exc).__name__}) on the no-auth control request",
                confidence=0.0,
                proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
            )

        ctrl_leaks = (
            ctrl_resp is not None
            and 200 <= ctrl_resp.status_code < 300
            and _has_tenant_item(_extract_items(ctrl_resp.body), tenant_field, tenant_a_id)
        )
        ctrl_status = ctrl_resp.status_code if ctrl_resp else 0

        if ctrl_leaks:
            proof = _empty_proof({
                "baseline_status": base_resp.status_code,
                "control_status": ctrl_status,
            })
            return self._not_vuln(
                title="Tenant isolation check — public endpoint",
                description="Endpoint is publicly readable (no auth required); not a tenant isolation finding.",
                confidence=0.9,
                proof_data=proof,
            )

        # Attack (tenant B) × 3
        attack_hits = 0
        last_attack_resp = None
        last_attack_status = 0
        for _ in range(3):
            try:
                atk = await self.runner.execute_request(
                    method="GET", url=url,
                    headers=context.secondary_auth_headers or None,
                    safety_classification=SafetyClassification.SAFE_READ_ONLY,
                )
                last_attack_resp = atk
                last_attack_status = atk.status_code
                if (200 <= atk.status_code < 300
                        and _has_tenant_item(_extract_items(atk.body), tenant_field, tenant_a_id)):
                    attack_hits += 1
            except SafetyViolationError as exc:
                return self._not_vuln(
                    title="Tenant isolation check blocked by safety policy",
                    description=f"Blocked by safety policy: {exc}",
                    confidence=0.0,
                    proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
                )
            except Exception as exc:
                return self._not_vuln(
                    title="Tenant isolation check inconclusive",
                    description=f"request error ({type(exc).__name__})",
                    confidence=0.0,
                    proof_data=_empty_proof({"baseline_status": base_resp.status_code}),
                )

        req, resp = self._evidence_pair(url, context.secondary_auth_headers, last_attack_resp)
        proof = _empty_proof({
            "baseline_status": base_resp.status_code,
            "attack_status": last_attack_status,
            "control_status": ctrl_status,
            "body_match": attack_hits == 3,
            **describe_expected_actual(last_attack_status, attack_hits == 3, attempted=bool(last_attack_resp)),
        })

        if attack_hits == 3:
            proof["self_verified"] = True
            proof["leaked_item_count"] = sum(
                1 for item in _extract_items(last_attack_resp.body if last_attack_resp else "[]")
                if isinstance(item, dict) and str(item.get(tenant_field, "")) == str(tenant_a_id)
            )
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.CRITICAL,
                confidence=0.9,
                title="Tenant Isolation Violation — collection-level cross-tenant data leak",
                description=(
                    f"Tenant B retrieved items belonging to Tenant A ({tenant_a_id!r}) "
                    f"from {url} on 3/3 consecutive requests, confirming a reproducible "
                    "cross-tenant collection leak."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id="CWE-200",
                cvss_score=9.1,
                evidence_request=req,
                evidence_response=resp,
                proof_data=proof,
            )

        return self._not_vuln(
            title="Tenant isolation check — list access denied or incomplete",
            description=(
                f"Tenant B obtained tenant-A items in {attack_hits}/3 requests "
                f"(attack status {last_attack_status}); not consistently reproducible."
            ),
            confidence=0.6 if attack_hits > 0 else 0.9,
            proof_data=proof,
            evidence_request=req,
            evidence_response=resp,
        )

    # ── spoof mode ────────────────────────────────────────────────────────────

    async def _run_spoof(
        self, context: SecurityCheckContext, url: str, ignore_fields: list
    ) -> SecurityCheckResult:
        tenant_header: str = context.parameters.get("tenant_header", "X-Tenant-ID")
        tenant_a_id: str = str(context.parameters.get("tenant_a_id", ""))

        if not tenant_a_id:
            return self._not_vuln(
                title="Tenant isolation check inconclusive",
                description="Inconclusive: parameters['tenant_a_id'] is required for spoof mode.",
                confidence=0.0,
                proof_data={
                    "mode": "spoof", "attack_url": url,
                    "user_a_headers_present": bool(context.auth_headers),
                    "user_b_headers_present": bool(context.secondary_auth_headers),
                    "ignore_fields": ignore_fields,
                },
            )

        # Step 1: plain object probe (without spoofed header)
        plain_pr = await probe_access(
            self.runner, url,
            owner_headers=context.auth_headers,
            attacker_headers=context.secondary_auth_headers,
            ignore_fields=ignore_fields,
        )
        proof_plain = self._base_proof("spoof", url, plain_pr, context, ignore_fields)
        req_plain, resp_plain = self._evidence_pair(
            url, context.secondary_auth_headers, plain_pr.attack
        )

        if plain_pr.decision == AccessDecision.BLOCKED:
            return self._not_vuln(
                title="Tenant isolation check blocked by safety policy",
                description=f"Blocked by safety policy: {plain_pr.detail}",
                confidence=0.0,
                proof_data=proof_plain,
            )

        if plain_pr.decision == AccessDecision.ACCESS_GRANTED:
            # B already has access without spoofed header — object-level finding
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.CRITICAL,
                confidence=0.9,
                title="Tenant Isolation Violation — object-level access (found during spoof probe)",
                description=(
                    f"Tenant B could already read Tenant A's resource at {url} without "
                    f"any spoofed header. This is an object-level BOLA/IDOR, not a "
                    "header-spoofing issue."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id="CWE-639",
                cvss_score=9.1,
                evidence_request=req_plain,
                evidence_response=resp_plain,
                proof_data=proof_plain,
            )

        # Step 2: spoof probe (tenant B + spoofed tenant header)
        spoofed_headers = {**context.secondary_auth_headers, tenant_header: tenant_a_id}
        spoof_pr = await probe_access(
            self.runner, url,
            owner_headers=context.auth_headers,
            attacker_headers=spoofed_headers,
            ignore_fields=ignore_fields,
        )
        proof_spoof = self._base_proof("spoof", url, spoof_pr, context, ignore_fields,
                                       extra_attacker_headers={tenant_header: tenant_a_id})
        req_spoof, resp_spoof = self._evidence_pair(url, spoofed_headers, spoof_pr.attack)

        if spoof_pr.decision == AccessDecision.BLOCKED:
            return self._not_vuln(
                title="Tenant isolation check blocked by safety policy",
                description=f"Blocked by safety policy: {spoof_pr.detail}",
                confidence=0.0,
                proof_data=proof_spoof,
            )

        if spoof_pr.decision == AccessDecision.ACCESS_GRANTED:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=True,
                severity=VulnerabilitySeverity.CRITICAL,
                confidence=0.9,
                title="Tenant Isolation Violation — tenant-header spoofing",
                description=(
                    f"The server accepted a forged '{tenant_header}: {tenant_a_id}' header "
                    f"from Tenant B and returned Tenant A's resource at {url}. "
                    "Tenant identity must be derived from the authenticated token, "
                    "not from caller-controlled headers."
                ),
                recommendation=_RECOMMENDATION,
                cwe_id="CWE-639",
                cvss_score=9.1,
                evidence_request=req_spoof,
                evidence_response=resp_spoof,
                proof_data=proof_spoof,
            )

        descs = {
            AccessDecision.PUBLIC: "Endpoint is publicly readable; not a tenant isolation finding.",
            AccessDecision.DENIED: (
                f"Server rejected the spoofed '{tenant_header}' header "
                f"(HTTP {spoof_pr.attack.status_code if spoof_pr.attack else '?'}); isolation is enforced."
            ),
            AccessDecision.BODY_DIFFERS: "Spoofed request received a different body.",
            AccessDecision.INCONCLUSIVE: f"Spoof probe inconclusive: {spoof_pr.detail}",
        }
        return self._not_vuln(
            title=f"Tenant isolation check (spoof) — {spoof_pr.decision.value.lower().replace('_', ' ')}",
            description=descs.get(spoof_pr.decision, spoof_pr.detail),
            confidence=self._conf(spoof_pr.decision),
            proof_data=proof_spoof,
            evidence_request=req_spoof,
            evidence_response=resp_spoof,
        )

    # ── entry-point ───────────────────────────────────────────────────────────

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        url = context.target_url.rstrip("/") + context.endpoint_path
        ignore_fields: list = context.parameters.get("ignore_fields", [])
        mode: str = context.parameters.get("mode", "object")

        if mode == "list":
            return await self._run_list(context, url, ignore_fields)
        if mode == "spoof":
            return await self._run_spoof(context, url, ignore_fields)
        return await self._run_object(context, url, ignore_fields)
"""
Benchmark Execution Engine.

Orchestrates ground-truth case evaluation through ControlledHttpRunner,
checks, and the self-challenging proof engine. Captures forensic request logs
without storing credentials, tokens, headers, or response payloads.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel

from checks.base import SecurityCheckContext, SecurityCheckResult
from evidence.collector import EvidenceCollector
from execution.http_runner import ControlledHttpResponse, ControlledHttpRunner
from safety.policy import SafetyViolationError, SecuritySafetyPolicy
from shared.enums.common import SafetyClassification
from benchmark.metrics import CaseResult
from benchmark.schema import BenchmarkCase, Manifest
from verification.pipeline import verify_and_record
from verification.proof_engine import SelfChallengingProofEngine


class BenchmarkRun(BaseModel):
    """Aggregate benchmark results, network audit log, and execution metadata."""
    results: List[CaseResult]
    request_log: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class RecordingRunner(ControlledHttpRunner):
    """
    Subclass of ControlledHttpRunner that records sanitized request telemetry.

    Logs case_id, method, host, path_with_query, status, blocked flag, and elapsed_ms.
    NEVER logs headers, authorization tokens, or request/response bodies.
    """

    def __init__(self, safety_policy: Optional[SecuritySafetyPolicy] = None):
        super().__init__(safety_policy=safety_policy)
        self.request_log: List[Dict[str, Any]] = []
        self.current_case_id: str = ""

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        safety_classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY,
    ) -> ControlledHttpResponse:
        parsed = urlparse(url)
        host = (parsed.hostname or url).lower()
        path_with_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        t0 = time.perf_counter()
        try:
            resp = await super().execute_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json_body=json_body,
                safety_classification=safety_classification,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.request_log.append({
                "case_id": self.current_case_id,
                "method": method.upper(),
                "host": host,
                "path_with_query": path_with_query,
                "status": resp.status_code,
                "blocked": False,
                "elapsed_ms": elapsed_ms,
            })
            return resp
        except SafetyViolationError:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.request_log.append({
                "case_id": self.current_case_id,
                "method": method.upper(),
                "host": host,
                "path_with_query": path_with_query,
                "status": None,
                "blocked": True,
                "elapsed_ms": elapsed_ms,
            })
            raise
        except Exception:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.request_log.append({
                "case_id": self.current_case_id,
                "method": method.upper(),
                "host": host,
                "path_with_query": path_with_query,
                "status": None,
                "blocked": False,
                "elapsed_ms": elapsed_ms,
            })
            raise


def _get_git_commit() -> str:
    """Retrieve git short commit hash if available, else 'unknown'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _resolve_check_class(check_name: str) -> Any:
    """Dynamically resolve security check class by name."""
    check_map = {
        "BOLAOwnershipCheck": ("checks.authorization.bola_check", "BOLAOwnershipCheck"),
        "TenantIsolationCheck": ("checks.authorization.tenant_isolation_check", "TenantIsolationCheck"),
        "RBACCheck": ("checks.authorization.rbac_check", "RBACCheck"),
    }
    if check_name in check_map:
        mod_name, cls_name = check_map[check_name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, cls_name)
    raise ImportError(f"Check '{check_name}' not available")


async def run_benchmark(
    manifest: Manifest,
    base_url: str,
    *,
    rps: int = 50,
    replays: int = 3,
    reset: Optional[Callable[[], None]] = None,
    skip_stateful: bool = False,
    allowed_hosts: Optional[List[str]] = None,
    manifest_sha256: str = "",
) -> BenchmarkRun:
    """
    Execute all benchmark cases in the manifest against the target service.

    Args:
        manifest: Loaded Manifest model
        base_url: Base HTTP URL of the target mock service
        rps: Rate limit (requests per second) for the central safety policy
        replays: Replay count for the proof engine
        reset: Optional callback to reset stateful mock app counters
        skip_stateful: If True, marks stateful cases as SKIPPED
        allowed_hosts: Explicit host allowlist (defaults to loopback + base_url host)
        manifest_sha256: Hash of the manifest file for metadata tracking
    """
    parsed_base = urlparse(base_url)
    base_host = (parsed_base.hostname or "127.0.0.1").lower()
    all_allowed = list({"127.0.0.1", "localhost", base_host} | set(allowed_hosts or []))

    policy = SecuritySafetyPolicy(allowed_hosts=all_allowed, max_rate_rps=rps)
    runner = RecordingRunner(safety_policy=policy)
    engine = SelfChallengingProofEngine(runner=runner, replays=replays)
    collector = EvidenceCollector()

    results: List[CaseResult] = []
    skipped_count = 0
    error_count = 0

    for case in manifest.cases:
        if not case.enabled:
            continue

        if skip_stateful and case.stateful:
            results.append(CaseResult(
                case_id=case.id,
                category=case.category,
                scenario=case.scenario,
                ground_truth=case.ground_truth,
                expected_outcome=case.expected_outcome,
                observed_outcome="SKIPPED",
                raw_flagged=False,
                independent=None,
                requests_sent=0,
                requests_blocked=0,
                duration_ms=0.0,
                reason="Stateful test skipped via --skip-stateful",
            ))
            skipped_count += 1
            continue

        # Reset counters before stateful/intermittent endpoints run
        if reset is not None:
            reset()

        runner.current_case_id = case.id
        start_req_count = len(runner.request_log)
        t0 = time.perf_counter()

        try:
            check_cls = _resolve_check_class(case.check)
            check_instance = check_cls(runner=runner)

            target_url = case.target_url_override or base_url
            owner_headers = manifest.identities[case.owner].headers
            attacker_headers = manifest.identities[case.attacker].headers

            ctx = SecurityCheckContext(
                test_id=f"bench-{case.id}",
                target_url=target_url,
                endpoint_path=case.path,
                http_method=case.method,
                auth_headers=owner_headers,
                secondary_auth_headers=attacker_headers,
                parameters={
                    **case.params,
                    "owner_label": case.owner,
                    "attacker_label": case.attacker,
                },
            )

            result: SecurityCheckResult = await check_instance.run(ctx)

            if result.is_vulnerable:
                raw_flagged = True
                record = await verify_and_record(result, ctx, engine, collector)
                if record is not None:
                    observed_outcome = record.outcome
                    independent = record.independent
                    reason = record.reason
                else:
                    observed_outcome = "REJECTED"
                    independent = True
                    reason = "Verification pipeline returned no record"
            else:
                raw_flagged = False
                independent = None
                desc_lower = result.description.lower()
                title_lower = result.title.lower()

                if "blocked by safety policy" in desc_lower:
                    observed_outcome = "BLOCKED"
                elif "not supported" in desc_lower and "skipped" in title_lower:
                    observed_outcome = "REFUSED"
                elif "inconclusive" in title_lower:
                    observed_outcome = "CHECK_INCONCLUSIVE"
                else:
                    observed_outcome = "NOT_FLAGGED"
                reason = result.description

        except Exception as exc:
            error_count += 1
            observed_outcome = "ERROR"
            raw_flagged = False
            independent = None
            # Store type name only, no exception details
            if isinstance(exc, ImportError) and "not available" in str(exc):
                reason = "check not available"
            else:
                reason = f"Execution error ({type(exc).__name__})"

        duration_ms = (time.perf_counter() - t0) * 1000.0

        # Calculate requests for this case
        case_reqs = runner.request_log[start_req_count:]
        reqs_sent = sum(1 for r in case_reqs if not r.get("blocked", False))
        reqs_blocked = sum(1 for r in case_reqs if r.get("blocked", False))

        results.append(CaseResult(
            case_id=case.id,
            category=case.category,
            scenario=case.scenario,
            check=case.check,
            ground_truth=case.ground_truth,
            expected_outcome=case.expected_outcome,
            observed_outcome=observed_outcome,
            raw_flagged=raw_flagged,
            independent=independent,
            requests_sent=reqs_sent,
            requests_blocked=reqs_blocked,
            duration_ms=duration_ms,
            reason=reason,
        ))

    metadata = {
        "manifest_name": manifest.name,
        "manifest_version": manifest.version,
        "manifest_sha256": manifest_sha256,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "replays": replays,
        "rps": rps,
        "base_url": base_url,
        "git_commit": _get_git_commit(),
        "enabled_count": len([c for c in manifest.cases if c.enabled]),
        "skipped_count": skipped_count,
        "error_count": error_count,
        "total_executed": len(results),
    }

    return BenchmarkRun(
        results=results,
        request_log=runner.request_log,
        metadata=metadata,
    )


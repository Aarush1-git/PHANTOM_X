"""
Shared access-probe helper used by TenantIsolationCheck and RBACCheck.

Algorithm (probe_access):
  1. Baseline  – request as owner (owner_headers).  Non-2xx → INCONCLUSIVE.
  2. Control   – request with NO headers.  2xx + body matches baseline → PUBLIC.
  3. Attack    – request as attacker (attacker_headers).
       ACCESS_GRANTED  : 2xx AND body equals baseline (field-stripped).
       DENIED          : 401 / 403 / 404.
       BODY_DIFFERS    : 2xx but body differs.
       INCONCLUSIVE    : anything else.
  SafetyViolationError at any step → BLOCKED, detail set.
  Any other exception → INCONCLUSIVE, detail "request error (<TypeName>)".

bodies_equal: JSON-aware comparison with ignore_fields stripping; falls back to
exact string comparison when either body is not valid JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import auto
from typing import Optional, Sequence

from execution.http_runner import ControlledHttpResponse, ControlledHttpRunner
from safety.policy import SafetyViolationError
from shared.enums.common import SafetyClassification

try:
    from enum import StrEnum  # Python 3.11+
except ImportError:          # pragma: no cover
    from enum import Enum as _Enum
    class StrEnum(str, _Enum):  # type: ignore[no-redef]
        pass


class AccessDecision(StrEnum):
    INCONCLUSIVE  = "INCONCLUSIVE"
    PUBLIC        = "PUBLIC"
    DENIED        = "DENIED"
    BODY_DIFFERS  = "BODY_DIFFERS"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    BLOCKED       = "BLOCKED"


@dataclass
class AccessProbeResult:
    decision: AccessDecision
    baseline: Optional[ControlledHttpResponse]
    control:  Optional[ControlledHttpResponse]
    attack:   Optional[ControlledHttpResponse]
    body_match: bool
    detail: str = ""


def bodies_equal(a: str, b: str, ignore_fields: Sequence[str] = ()) -> bool:
    """
    JSON-aware body comparison.

    Strips ignore_fields from both parsed objects before comparing; falls
    back to exact string comparison when either body is not valid JSON.
    """
    def _strip(obj: object) -> object:
        if isinstance(obj, dict):
            return {k: _strip(v) for k, v in obj.items() if k not in ignore_fields}
        if isinstance(obj, list):
            return [_strip(i) for i in obj]
        return obj

    try:
        return _strip(json.loads(a)) == _strip(json.loads(b))
    except (json.JSONDecodeError, ValueError):
        return a == b


async def probe_access(
    runner: ControlledHttpRunner,
    url: str,
    owner_headers: Optional[dict],
    attacker_headers: Optional[dict],
    *,
    method: str = "GET",
    classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY,
    ignore_fields: Sequence[str] = (),
) -> AccessProbeResult:
    """
    Issue baseline / control / attack requests and return an AccessProbeResult.

    Parameters
    ----------
    runner           : ControlledHttpRunner (all HTTP flows through it).
    url              : Full URL of the resource to probe.
    owner_headers    : Headers for the legitimate owner (User A / tenant A).
    attacker_headers : Headers for the cross-tenant / lower-privilege attacker.
    method           : HTTP method (default GET; safety policy may block others).
    classification   : SafetyClassification passed to every execute_request call.
    ignore_fields    : JSON keys stripped before body comparison.
    """

    # ── Baseline (owner) ──────────────────────────────────────────────────────
    try:
        baseline = await runner.execute_request(
            method=method, url=url,
            headers=owner_headers or None,
            safety_classification=classification,
        )
    except SafetyViolationError as exc:
        return AccessProbeResult(
            decision=AccessDecision.BLOCKED,
            baseline=None, control=None, attack=None,
            body_match=False,
            detail=f"Blocked by safety policy: {exc}",
        )
    except Exception as exc:
        return AccessProbeResult(
            decision=AccessDecision.INCONCLUSIVE,
            baseline=None, control=None, attack=None,
            body_match=False,
            detail=f"request error ({type(exc).__name__})",
        )

    if not (200 <= baseline.status_code < 300):
        return AccessProbeResult(
            decision=AccessDecision.INCONCLUSIVE,
            baseline=baseline, control=None, attack=None,
            body_match=False,
            detail=f"Baseline returned HTTP {baseline.status_code}",
        )

    # ── Control (no auth) ─────────────────────────────────────────────────────
    try:
        control = await runner.execute_request(
            method=method, url=url,
            headers=None,
            safety_classification=classification,
        )
    except SafetyViolationError as exc:
        return AccessProbeResult(
            decision=AccessDecision.BLOCKED,
            baseline=baseline, control=None, attack=None,
            body_match=False,
            detail=f"Blocked by safety policy: {exc}",
        )
    except Exception as exc:
        return AccessProbeResult(
            decision=AccessDecision.INCONCLUSIVE,
            baseline=baseline, control=None, attack=None,
            body_match=False,
            detail=f"request error ({type(exc).__name__})",
        )

    if 200 <= control.status_code < 300 and bodies_equal(
        control.body, baseline.body, ignore_fields
    ):
        return AccessProbeResult(
            decision=AccessDecision.PUBLIC,
            baseline=baseline, control=control, attack=None,
            body_match=True,
            detail="Unauthenticated request returned identical body — endpoint is public.",
        )

    # ── Attack (attacker) ─────────────────────────────────────────────────────
    try:
        attack = await runner.execute_request(
            method=method, url=url,
            headers=attacker_headers or None,
            safety_classification=classification,
        )
    except SafetyViolationError as exc:
        return AccessProbeResult(
            decision=AccessDecision.BLOCKED,
            baseline=baseline, control=control, attack=None,
            body_match=False,
            detail=f"Blocked by safety policy: {exc}",
        )
    except Exception as exc:
        return AccessProbeResult(
            decision=AccessDecision.INCONCLUSIVE,
            baseline=baseline, control=control, attack=None,
            body_match=False,
            detail=f"request error ({type(exc).__name__})",
        )

    bm = bodies_equal(attack.body, baseline.body, ignore_fields)

    if 200 <= attack.status_code < 300 and bm:
        decision = AccessDecision.ACCESS_GRANTED
    elif attack.status_code in (401, 403, 404):
        decision = AccessDecision.DENIED
    elif 200 <= attack.status_code < 300 and not bm:
        decision = AccessDecision.BODY_DIFFERS
    else:
        decision = AccessDecision.INCONCLUSIVE

    return AccessProbeResult(
        decision=decision,
        baseline=baseline, control=control, attack=attack,
        body_match=bm,
        detail="",
    )


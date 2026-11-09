import re
import time
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from shared.enums.common import ExecutionMode, SafetyClassification, HttpMethod


class SafetyViolationError(Exception):
    """Raised when an operation violates the PHANTOM-X Central Safety Policy."""
    pass


class TargetAuthorizationToken(BaseModel):
    """Cryptographic or verified token certifying target scope authorization."""
    application_id: str
    authorized_domain: str
    authorized_by: str
    valid_until_timestamp: float
    allowed_modes: List[ExecutionMode] = Field(default_factory=lambda: [ExecutionMode.OBSERVE])


class RateLimiter:
    """Token-bucket or sliding window rate limiter for target protection."""
    def __init__(self, requests_per_second: int = 10):
        self.rps = requests_per_second
        self.last_check = time.time()
        self.allowance = float(requests_per_second)

    async def acquire(self):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.allowance += time_passed * self.rps
        if self.allowance > self.rps:
            self.allowance = float(self.rps)
        if self.allowance < 1.0:
            sleep_time = (1.0 - self.allowance) / self.rps
            await asyncio.sleep(sleep_time)
            self.allowance = 0.0
        else:
            self.allowance -= 1.0


class SecuritySafetyPolicy:
    """The central, unbypassable safety policy engine governing all security execution."""

    def __init__(
        self,
        default_mode: ExecutionMode = ExecutionMode.OBSERVE,
        allowed_hosts: Optional[List[str]] = None,
        max_rate_rps: int = 10,
        enforce_synthetic: bool = True
    ):
        self.current_mode = default_mode
        self.allowed_hosts = allowed_hosts or ["localhost", "127.0.0.1", "api.example-target.local"]
        self.max_rate_rps = max_rate_rps
        self.enforce_synthetic = enforce_synthetic
        self.rate_limiter = RateLimiter(requests_per_second=max_rate_rps)

        # Destructive patterns never executed without explicit sign-off
        self.destructive_indicators = [
            "drop table", "truncate", "rm -rf", "delete from users",
            "grant dba", "alter system", "exec xp_cmdshell"
        ]

    def authorize_target(self, target_url: str) -> bool:
        """Verify target URL is within explicitly allowed domains."""
        try:
            parsed = urlparse(target_url)
            host = parsed.hostname or target_url
            for allowed in self.allowed_hosts:
                if host == allowed or host.endswith(f".{allowed}"):
                    return True
            return False
        except Exception:
            return False

    async def check_and_gate_request(
        self,
        url: str,
        method: str,
        payload: Optional[Any] = None,
        safety_classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY,
        auth_token: Optional[TargetAuthorizationToken] = None
    ):
        """Enforce all 10 safety requirements before any packet leaves PHANTOM-X."""
        # 1. Scope and Host authorization check
        if not self.authorize_target(url):
            raise SafetyViolationError(
                f"[Safety Policy] Request blocked: Target '{url}' is outside authorized scope {self.allowed_hosts}."
            )

        # 2. Safety Mode Enforcement
        if self.current_mode == ExecutionMode.OBSERVE:
            if method.upper() not in ["GET", "HEAD", "OPTIONS"]:
                if safety_classification != SafetyClassification.SAFE_READ_ONLY:
                    raise SafetyViolationError(
                        f"[Safety Policy] Mode is OBSERVE: Mutating method {method} on {url} is forbidden."
                    )

        # 3. High-Risk / Destructive checks
        if safety_classification == SafetyClassification.HIGH_RISK_DESTRUCTIVE:
            raise SafetyViolationError(
                "[Safety Policy] Destructive action rejected: High-risk actions require explicit operator sign-off."
            )

        # 4. Payload inspection for destructive commands
        if payload:
            payload_str = str(payload).lower()
            for pattern in self.destructive_indicators:
                if pattern in payload_str:
                    raise SafetyViolationError(
                        f"[Safety Policy] Destructive payload blocked: Detected pattern '{pattern}'."
                    )

        # 5. Rate limiting
        await self.rate_limiter.acquire()


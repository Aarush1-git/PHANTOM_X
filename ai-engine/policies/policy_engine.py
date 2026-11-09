import re
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field
from shared.enums.common import SafetyClassification, HttpMethod


class PolicyValidationResult(BaseModel):
    is_allowed: bool
    violations: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    approved_actions: List[Dict[str, Any]] = Field(default_factory=list)


class DeterministicPolicyEngine:
    """Central deterministic policy validation layer.
    The AI proposes; the deterministic policy strictly validates and constrains.
    """

    def __init__(
        self,
        allowed_hosts: List[str] = None,
        allow_destructive: bool = False,
        max_rate_rps: int = 10,
    ):
        self.allowed_hosts = allowed_hosts or ["localhost", "127.0.0.1", "api.example-target.local"]
        self.allow_destructive = allow_destructive
        self.max_rate_rps = max_rate_rps

        # Unsafe destructive patterns strictly prohibited by default
        self.prohibited_sql_patterns = [
            r"\bDROP\s+TABLE\b",
            r"\bTRUNCATE\b",
            r"\bDELETE\s+FROM\b",
            r"\bALTER\s+SYSTEM\b",
            r"\bSHUTDOWN\b",
        ]
        self.prohibited_system_commands = [
            r"\brm\s+-rf\b",
            r"\bformat\b",
            r"\bmkfs\b",
            r"\b:\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
        ]

    def validate_scenario(self, scenario: Dict[str, Any], target_host: str) -> Tuple[bool, List[str]]:
        """Validate an individual proposed test scenario."""
        violations = []

        # 1. Host allowlist check
        if not any(target_host.endswith(allowed) or target_host == allowed for allowed in self.allowed_hosts):
            violations.append(f"Target host '{target_host}' is outside authorized scope allowlist: {self.allowed_hosts}")

        # 2. Safety classification check
        safety_class = scenario.get("safety_classification", "SAFE_READ_ONLY")
        if safety_class == SafetyClassification.HIGH_RISK_DESTRUCTIVE and not self.allow_destructive:
            violations.append("Destructive test action rejected: High-risk actions require explicit operator sign-off.")

        # 3. Payload inspection for destructive commands
        payload_str = str(scenario.get("parameters", ""))
        for pattern in self.prohibited_sql_patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                violations.append(f"Prohibited destructive SQL pattern detected: {pattern}")

        for pattern in self.prohibited_system_commands:
            if re.search(pattern, payload_str, re.IGNORECASE):
                violations.append(f"Prohibited destructive system command pattern detected: {pattern}")

        return (len(violations) == 0, violations)

    def validate_plan(self, proposed_plan: List[Dict[str, Any]], target_host: str) -> PolicyValidationResult:
        """Validate entire LLM proposed attack plan before execution authorization."""
        all_violations = []
        approved = []

        for scenario in proposed_plan:
            is_valid, violations = self.validate_scenario(scenario, target_host)
            if is_valid:
                approved.append(scenario)
            else:
                all_violations.extend(violations)

        is_allowed = len(all_violations) == 0
        return PolicyValidationResult(
            is_allowed=is_allowed,
            violations=all_violations,
            reasons=["Plan passed all deterministic safety assertions."] if is_allowed else all_violations,
            approved_actions=approved
        )


"""
Benchmark Ground-Truth Schema and Manifest Loader.

Defines Pydantic models for benchmark identities, cases, and manifests,
along with strict validation ensuring ground truth integrity:
  - Unique case IDs
  - All referenced identities exist in the manifest
  - Allowed expected outcomes
  - Ground truth 'n/a' is restricted to safety cases
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field, field_validator, model_validator

VALID_CATEGORIES = {
    "bola",
    "tenant_isolation",
    "rbac",
    "safety",
    "authentication",
    "api_security",
}

VALID_CHECKS = {
    "BOLAOwnershipCheck",
    "TenantIsolationCheck",
    "RBACCheck",
    "BrokenAuthenticationCheck",
    "InputValidationCheck",
    "CorsAndMethodCheck",
}

VALID_EXPECTED_OUTCOMES = {
    "CONFIRMED",
    "REJECTED",
    "NEEDS_HUMAN_REVIEW",
    "INCONCLUSIVE",
    "NOT_FLAGGED",
    "CHECK_INCONCLUSIVE",
    "BLOCKED",
    "REFUSED",
}


class Identity(BaseModel):
    """Synthetic test credentials for an actor in a benchmark scenario."""
    headers: Dict[str, str] = Field(default_factory=dict)


class BenchmarkCase(BaseModel):
    """A single deterministic security benchmark test case."""
    id: str
    scenario: str
    category: Literal[
        "bola",
        "tenant_isolation",
        "rbac",
        "safety",
        "authentication",
        "api_security",
    ]
    check: str
    path: str
    method: str = "GET"
    owner: str
    attacker: str
    params: Dict[str, Any] = Field(default_factory=dict)
    ground_truth: Literal["vulnerable", "secure", "n/a"]
    expected_outcome: str
    stateful: bool = False
    enabled: bool = True
    target_url_override: Optional[str] = None
    notes: str = ""

    @field_validator("expected_outcome")
    @classmethod
    def validate_expected_outcome(cls, v: str) -> str:
        if v not in VALID_EXPECTED_OUTCOMES:
            raise ValueError(
                f"Invalid expected_outcome '{v}'. Must be one of: {sorted(VALID_EXPECTED_OUTCOMES)}"
            )
        return v

    @model_validator(mode="after")
    def validate_ground_truth_alignment(self) -> BenchmarkCase:
        if self.category == "safety":
            if self.ground_truth != "n/a":
                raise ValueError(
                    f"Safety case '{self.id}' must have ground_truth 'n/a', got '{self.ground_truth}'."
                )
        else:
            if self.ground_truth not in {"vulnerable", "secure"}:
                raise ValueError(
                    f"Case '{self.id}' in category '{self.category}' must have ground_truth "
                    f"'vulnerable' or 'secure', got '{self.ground_truth}'."
                )
        return self


class Manifest(BaseModel):
    """Complete ground-truth benchmark suite manifest."""
    name: str
    version: str
    description: str
    identities: Dict[str, Identity]
    plan_scenarios: List[str]
    cases: List[BenchmarkCase]

    @model_validator(mode="after")
    def validate_manifest_integrity(self) -> Manifest:
        seen_ids: Set[str] = set()
        for case in self.cases:
            if case.id in seen_ids:
                raise ValueError(f"Duplicate benchmark case ID: '{case.id}'.")
            seen_ids.add(case.id)

            if case.owner not in self.identities:
                raise ValueError(
                    f"Case '{case.id}' references undefined owner identity: '{case.owner}'."
                )
            if case.attacker not in self.identities:
                raise ValueError(
                    f"Case '{case.id}' references undefined attacker identity: '{case.attacker}'."
                )
        return self


def load_manifest(path: Path | str) -> tuple[Manifest, str]:
    """
    Load and validate a ground-truth manifest file.

    Returns:
        (manifest, sha256_hex)
    """
    p = Path(path).resolve()
    raw_bytes = p.read_bytes()
    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
    data = json.loads(raw_bytes.decode("utf-8"))
    manifest = Manifest.model_validate(data)
    return manifest, sha256_hex


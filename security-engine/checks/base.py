from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from shared.enums.common import VulnerabilitySeverity, SafetyClassification


class SecurityCheckContext(BaseModel):
    test_id: str
    target_url: str
    endpoint_path: str
    http_method: str
    auth_headers: Dict[str, str] = Field(default_factory=dict)
    secondary_auth_headers: Dict[str, str] = Field(default_factory=dict)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class SecurityCheckResult(BaseModel):
    check_name: str
    is_vulnerable: bool
    severity: VulnerabilitySeverity = VulnerabilitySeverity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    title: str = ""
    description: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence_request: str = ""
    evidence_response: str = ""
    proof_data: Dict[str, Any] = Field(default_factory=dict)


class BaseSecurityCheck(ABC):
    """Abstract base class for all custom security checks."""

    def __init__(self, check_name: str, runner: Optional[ControlledHttpRunner] = None):
        self.check_name = check_name
        self.runner = runner or ControlledHttpRunner()

    @abstractmethod
    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        """Execute the security check within controlled parameters."""
        raise NotImplementedError

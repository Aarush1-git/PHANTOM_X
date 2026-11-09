import uuid
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EvidencePackage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_id: Optional[str] = None
    test_id: Optional[str] = None
    request_dump: str
    response_dump: str
    proof_data: Dict[str, Any] = Field(default_factory=dict)
    screenshot_url: Optional[str] = None


class EvidenceCollector:
    """Collects and standardizes forensic evidence artifacts for verified vulnerabilities."""

    @staticmethod
    def package_evidence(
        request_dump: str,
        response_dump: str,
        proof_data: Dict[str, Any],
        vulnerability_id: Optional[str] = None,
        test_id: Optional[str] = None,
        screenshot_url: Optional[str] = None
    ) -> EvidencePackage:
        return EvidencePackage(
            vulnerability_id=vulnerability_id,
            test_id=test_id,
            request_dump=request_dump,
            response_dump=response_dump,
            proof_data=proof_data,
            screenshot_url=screenshot_url
        )


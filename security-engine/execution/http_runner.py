import httpx
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel

from safety.policy import SecuritySafetyPolicy, SafetyViolationError
from shared.enums.common import SafetyClassification

logger = logging.getLogger("phantom_x.http_runner")


class ControlledHttpResponse(BaseModel):
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    request_dump: str
    response_dump: str


class ControlledHttpRunner:
    """Safe, rate-limited HTTP client integrated with Central Safety Policy."""

    def __init__(self, safety_policy: Optional[SecuritySafetyPolicy] = None):
        self.safety = safety_policy or SecuritySafetyPolicy()

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        safety_classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY,
    ) -> ControlledHttpResponse:
        await self.safety.check_and_gate_request(
            url=url,
            method=method,
            payload=json_body,
            safety_classification=safety_classification
        )

        request_dump = f"{method.upper()} {url}\nHeaders: {headers}\nBody: {json_body}"

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers or {},
                params=params or {},
                json=json_body if json_body is not None else None,
            )

            response_dump = f"HTTP {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody: {resp.text[:2000]}"

            return ControlledHttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
                request_dump=request_dump,
                response_dump=response_dump
            )

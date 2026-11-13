import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.application import Application
from app.models.endpoint import DiscoveredEndpoint
from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
)
from app.features.application_intelligence.behavioral_digital_twin.normalizer import (
    normalize_endpoint_identity,
)
from app.features.application_intelligence.behavioral_digital_twin.sanitization import (
    sanitize_payload_recursively,
    sanitize_headers,
    hash_session_identifier,
)
from app.features.application_intelligence.behavioral_digital_twin.schema_inference import (
    infer_payload_schema,
)

# Reuse existing security-engine tools (Requirement 2 & 13)
from traffic.har_parser import HarTrafficParser, ParsedHarEntry
from execution.http_runner import ControlledHttpRunner, ControlledHttpResponse
from shared.enums.common import SafetyClassification


class TenantAccessDeniedError(Exception):
    """Raised when an application does not belong to the caller's organization."""
    pass


class ObservationIngestionService:
    """
    Core service for ingesting, normalizing, sanitizing, and persisting API observations.
    Supports passive HAR parsing, direct API telemetry, and controlled HTTP execution traces.
    Enforces strict tenant isolation and sensitive data redaction.
    """

    @staticmethod
    async def validate_application_tenant(
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Application:
        """
        Ensures the application exists and strictly belongs to the authenticated organization.
        Raises TenantAccessDeniedError or ValueError.
        """
        query = select(Application).where(Application.id == application_id)
        result = await db.execute(query)
        app_obj = result.scalars().first()

        if not app_obj:
            raise ValueError(f"Application {application_id} not found.")

        if app_obj.organization_id != organization_id:
            raise TenantAccessDeniedError(
                f"Unauthorized access: Application {application_id} does not belong to organization {organization_id}."
            )

        return app_obj

    @staticmethod
    async def lookup_endpoint(
        db: AsyncSession,
        application_id: uuid.UUID,
        method: str,
        normalized_path: str,
    ) -> Optional[uuid.UUID]:
        """
        Attempts to find a matching DiscoveredEndpoint for an observation.
        If not yet registered by Member 1's discovery crawler, returns None (nullable support).
        """
        query = select(DiscoveredEndpoint).where(
            DiscoveredEndpoint.application_id == application_id,
            DiscoveredEndpoint.path == normalized_path,
        )
        result = await db.execute(query)
        endpoints = result.scalars().all()

        for ep in endpoints:
            ep_method = ep.method.value if hasattr(ep.method, "value") else str(ep.method)
            if ep_method.upper() == method.upper():
                return ep.id

        return None

    @staticmethod
    def _parse_body_to_dict(body_val: Any) -> Dict[str, Any]:
        """Safely parses a string or dict body into a dictionary."""
        if not body_val:
            return {}
        if isinstance(body_val, dict):
            return body_val
        if isinstance(body_val, str) and body_val.strip():
            try:
                parsed = json.loads(body_val)
                if isinstance(parsed, dict):
                    return parsed
                elif isinstance(parsed, list):
                    return {"_items": parsed}
            except Exception:
                return {"_raw_text_length": len(body_val)}
        return {}

    @classmethod
    async def ingest_single_observation(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        method: str,
        url_or_path: str,
        status_code: int,
        request_headers: Optional[Dict[str, str]] = None,
        response_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[Any] = None,
        response_body: Optional[Any] = None,
        request_payload: Optional[Any] = None,
        response_payload: Optional[Any] = None,
        latency_ms: float = 0.0,
        session_identifier: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        endpoint_id: Optional[uuid.UUID] = None,
    ) -> BehavioralObservation:
        """
        Ingest, sanitize, and persist a single observation record.
        """
        # 1. Enforce tenant isolation
        await cls.validate_application_tenant(db, application_id, organization_id)

        # 2. Normalize endpoint identity
        clean_method, norm_path, _ = normalize_endpoint_identity(method, url_or_path)

        # 3. Resolve endpoint_id if not explicitly provided
        if not endpoint_id:
            endpoint_id = await cls.lookup_endpoint(db, application_id, clean_method, norm_path)

        # 4. Hash session token (never store raw credential)
        session_hash = None
        if session_identifier:
            session_hash = hash_session_identifier(session_identifier)
        elif request_headers:
            # Check for cookie or auth header to derive session correlation hash
            auth_val = request_headers.get("authorization") or request_headers.get("Authorization")
            cookie_val = request_headers.get("cookie") or request_headers.get("Cookie")
            if auth_val or cookie_val:
                session_hash = hash_session_identifier(str(auth_val or cookie_val))

        # 5. Sanitize payloads recursively
        req_val = request_payload if request_payload is not None else request_body
        resp_val = response_payload if response_payload is not None else response_body
        req_dict = cls._parse_body_to_dict(req_val)
        resp_dict = cls._parse_body_to_dict(resp_val)

        sanitized_req = sanitize_payload_recursively(req_dict)
        sanitized_resp = sanitize_payload_recursively(resp_dict)

        # 6. Infer structural schemas
        req_schema = infer_payload_schema(sanitized_req)
        resp_schema = infer_payload_schema(sanitized_resp)

        obs = BehavioralObservation(
            organization_id=organization_id,
            application_id=application_id,
            endpoint_id=endpoint_id,
            method=clean_method,
            normalized_path=norm_path,
            status_code=int(status_code),
            sanitized_request_schema=req_schema,
            sanitized_response_schema=resp_schema,
            latency_ms=max(0.0, float(latency_ms)),
            session_token_hash=session_hash,
            observed_at=observed_at or datetime.now(timezone.utc),
        )
        db.add(obs)
        await db.commit()
        await db.refresh(obs)
        return obs

    @classmethod
    async def ingest_batch(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        observations: List[Dict[str, Any]],
    ) -> List[BehavioralObservation]:
        """
        Batch-ingests a collection of observation dictionaries with tenant validation.
        """
        await cls.validate_application_tenant(db, application_id, organization_id)
        results: List[BehavioralObservation] = []
        for item in observations:
            obs = await cls.ingest_single_observation(
                db=db,
                application_id=application_id,
                organization_id=organization_id,
                method=item.get("method", "GET"),
                url_or_path=item.get("url_or_path") or item.get("path") or "/",
                status_code=item.get("status_code", 200),
                request_headers=item.get("request_headers"),
                response_headers=item.get("response_headers"),
                request_payload=item.get("request_payload") or item.get("request_body"),
                response_payload=item.get("response_payload") or item.get("response_body"),
                latency_ms=item.get("latency_ms", 0.0),
                session_identifier=item.get("session_identifier"),
                endpoint_id=item.get("endpoint_id"),
            )
            results.append(obs)
        return results

    @classmethod
    async def ingest_from_har(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        har_content: str,
        session_identifier: Optional[str] = None,
    ) -> List[BehavioralObservation]:
        """Alias for ingest_har_traffic."""
        return await cls.ingest_har_traffic(
            db=db,
            application_id=application_id,
            organization_id=organization_id,
            har_content=har_content,
            session_identifier=session_identifier,
        )

    @classmethod
    async def ingest_har_traffic(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        har_content: str,
        session_identifier: Optional[str] = None,
    ) -> List[BehavioralObservation]:
        """
        Parses HTTP Archive (.har) content using HarTrafficParser and batch-ingests observations.
        """
        await cls.validate_application_tenant(db, application_id, organization_id)

        entries = HarTrafficParser.parse_har_content(har_content)
        ingested: List[BehavioralObservation] = []

        for entry in entries:
            # Derive session identifier from entry cookie/auth if none provided
            entry_session = session_identifier
            if not entry_session:
                entry_session = (
                    entry.request_headers.get("authorization")
                    or entry.request_headers.get("cookie")
                )

            obs = await cls.ingest_single_observation(
                db=db,
                application_id=application_id,
                organization_id=organization_id,
                method=entry.method,
                url_or_path=entry.url,
                status_code=entry.status,
                request_headers=entry.request_headers,
                response_headers=entry.response_headers,
                request_body=entry.request_body,
                response_body=entry.response_body,
                latency_ms=entry.time_ms,
                session_identifier=entry_session,
            )
            ingested.append(obs)

        return ingested

    @classmethod
    async def ingest_controlled_execution(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        method: str,
        url: str,
        http_runner: ControlledHttpRunner,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        safety_classification: SafetyClassification = SafetyClassification.SAFE_READ_ONLY,
    ) -> BehavioralObservation:
        """
        Executes an active probe via ControlledHttpRunner with safety gating and persists the observation trace.
        """
        await cls.validate_application_tenant(db, application_id, organization_id)

        response = await http_runner.execute_request(
            method=method,
            url=url,
            headers=headers,
            json_body=json_body,
            safety_classification=safety_classification,
        )

        return await cls.ingest_single_observation(
            db=db,
            application_id=application_id,
            organization_id=organization_id,
            method=method,
            url_or_path=url,
            status_code=response.status_code,
            request_headers=headers,
            response_headers=response.headers,
            request_body=json_body,
            response_body=response.body,
            latency_ms=response.elapsed_ms,
        )

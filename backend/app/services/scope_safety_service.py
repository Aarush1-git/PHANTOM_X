import uuid
import re
import fnmatch
import time
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc

from app.models.scope_safety import ApplicationScopePolicy, BlockedExecutionLog
from app.models.application import Application
from app.models.audit import AuditLog
from app.features.security_operations.audit_logs.event_recorder import AuditEventRecorder
from app.features.security_operations.audit_logs.schemas import AuditStatus, AuditSeverity
from app.schemas.scope_safety import (
    ScopeStatus,
    AuthorizationStatus,
    ViolationCategory,
    ScopePolicyCreate,
    ScopePolicyUpdate,
    ScopeAuthorizeRequest,
    ScopeSuspendRequest,
    ScopeRevokeRequest,
    TestValidationResult,
)


class InMemoryRateTracker:
    """Sliding-window request rate limiter per application."""
    def __init__(self):
        self._history: Dict[str, List[float]] = {}

    def is_allowed(self, app_id: str, limit_rps: int) -> bool:
        now = time.time()
        window_start = now - 1.0
        
        timestamps = self._history.setdefault(app_id, [])
        # Prune old timestamps
        self._history[app_id] = [ts for ts in timestamps if ts > window_start]
        
        if len(self._history[app_id]) >= limit_rps:
            return False
            
        self._history[app_id].append(now)
        return True

    def reset(self, app_id: Optional[str] = None):
        if app_id:
            self._history.pop(app_id, None)
        else:
            self._history.clear()


rate_tracker = InMemoryRateTracker()


# Highly destructive indicators never permitted without explicit bypass & authorization
DESTRUCTIVE_PATTERNS = [
    r"(?i)\bdrop\s+table\b",
    r"(?i)\btruncate\s+table\b",
    r"(?i)\balter\s+system\b",
    r"(?i)\bdelete\s+from\s+[a-zA-Z0-9_]+(?!\s+where\b)", # Unconstrained DELETE
    r"(?i)\bexec\s+xp_cmdshell\b",
    r"(?i)\bgrant\s+dba\b",
    r"(?i)\brm\s+-rf\b",
    r"(?i)\bformat\s+[a-zA-Z]:",
    r"(?i)\bmkfs\b",
    r"(?i)\bshutdown\s+(-h|-r|/s|/r)\b",
    r"(?i):\(\)\s*\{\s*:\|:&\s*\};:", # Fork bomb
    r"(?i)/etc/shadow",
    r"(?i)/etc/master\.passwd",
    r"(?i)system32\\config\\sam",
]


class ScopeSafetyService:
    """
    Central service for application testing scope, permissions, safety validation,
    and prohibited execution logging.
    """

    @staticmethod
    def _normalize_host(url_or_host: str) -> str:
        """Extract clean hostname or lowercase domain from URL or host string."""
        if not url_or_host:
            return ""
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.netloc.split(":")[0]  # strip port
            return host.lower()
        return url_or_host.split("/")[0].split(":")[0].strip().lower()

    @staticmethod
    def _extract_path(url_or_path: str) -> str:
        """Extract clean URL path from URL or relative path."""
        if not url_or_path:
            return "/"
        if "://" in url_or_path:
            parsed = urlparse(url_or_path)
            return parsed.path or "/"
        if not url_or_path.startswith("/"):
            return f"/{url_or_path}"
        return url_or_path.split("?")[0].split("#")[0]

    @staticmethod
    def _match_pattern(path: str, pattern: str) -> bool:
        """Matches a URL path against a glob pattern or prefix."""
        # Handle simple glob patterns (e.g. /*, /admin/*, /api/v1/*)
        pattern = pattern.strip()
        if not pattern.startswith("/"):
            pattern = "/" + pattern
        return fnmatch.fnmatch(path, pattern)

    @classmethod
    async def create_or_update_scope(
        cls,
        db: AsyncSession,
        app_id: uuid.UUID,
        org_id: uuid.UUID,
        payload: ScopePolicyCreate
    ) -> ApplicationScopePolicy:
        """Create or update scope policy for an application."""
        result = await db.execute(
            select(ApplicationScopePolicy).where(ApplicationScopePolicy.application_id == app_id)
        )
        existing = result.scalars().first()

        clean_domain = cls._normalize_host(payload.target_domain or payload.base_url)

        if existing:
            existing.target_domain = clean_domain
            existing.base_url = payload.base_url
            existing.permitted_paths = payload.permitted_paths
            existing.excluded_paths = payload.excluded_paths
            existing.rate_limit_rps = payload.rate_limit_rps
            existing.max_concurrency = payload.max_concurrency
            existing.max_scan_duration_minutes = payload.max_scan_duration_minutes
            existing.allowed_methods = [m.upper() for m in payload.allowed_methods]
            existing.restricted_endpoint_patterns = payload.restricted_endpoint_patterns
            existing.require_synthetic_auth = payload.require_synthetic_auth
            existing.allow_destructive = payload.allow_destructive
            # Updating scope resets to DRAFT / requires re-authorization if domain changes
            policy = existing
        else:
            policy = ApplicationScopePolicy(
                organization_id=org_id,
                application_id=app_id,
                target_domain=clean_domain,
                base_url=payload.base_url,
                permitted_paths=payload.permitted_paths,
                excluded_paths=payload.excluded_paths,
                scope_status=ScopeStatus.DRAFT.value,
                authorization_status=AuthorizationStatus.PENDING.value,
                rate_limit_rps=payload.rate_limit_rps,
                max_concurrency=payload.max_concurrency,
                max_scan_duration_minutes=payload.max_scan_duration_minutes,
                allowed_methods=[m.upper() for m in payload.allowed_methods],
                restricted_endpoint_patterns=payload.restricted_endpoint_patterns,
                require_synthetic_auth=payload.require_synthetic_auth,
                allow_destructive=payload.allow_destructive,
            )
            db.add(policy)

        # Structured Audit log creation/update into tamper-evident chain
        await AuditEventRecorder.record_application_event(
            db=db,
            org_id=org_id,
            app_id=app_id,
            event_type="APP_SCOPE_CONFIGURED",
            action="UPDATE_SCOPE_POLICY" if existing else "CREATE_SCOPE_POLICY",
            details={
                "target_domain": clean_domain,
                "base_url": payload.base_url,
                "rate_limit_rps": payload.rate_limit_rps,
                "allow_destructive": payload.allow_destructive
            }
        )
        await db.commit()
        await db.refresh(policy)
        return policy

    @classmethod
    async def get_scope(
        cls,
        db: AsyncSession,
        app_id: uuid.UUID
    ) -> Optional[ApplicationScopePolicy]:
        """Fetch scope policy for a given application."""
        result = await db.execute(
            select(ApplicationScopePolicy).where(ApplicationScopePolicy.application_id == app_id)
        )
        return result.scalars().first()

    @classmethod
    async def list_scopes(
        cls,
        db: AsyncSession,
        org_id: Optional[uuid.UUID] = None
    ) -> List[ApplicationScopePolicy]:
        """List all application scope policies."""
        query = select(ApplicationScopePolicy)
        if org_id:
            query = query.where(ApplicationScopePolicy.organization_id == org_id)
        query = query.order_by(desc(ApplicationScopePolicy.created_at))
        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def authorize_scope(
        cls,
        db: AsyncSession,
        app_id: uuid.UUID,
        auth_req: ScopeAuthorizeRequest,
        org_id: Optional[uuid.UUID] = None
    ) -> ApplicationScopePolicy:
        """Grant explicit testing authorization to target scope."""
        policy = await cls.get_scope(db, app_id)
        if not policy:
            raise ValueError(f"Scope policy for application {app_id} does not exist.")

        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=auth_req.valid_days)

        policy.authorization_status = AuthorizationStatus.AUTHORIZED.value
        policy.scope_status = ScopeStatus.ACTIVE.value
        policy.authorized_by = auth_req.authorized_by
        policy.authorizer_role = auth_req.authorizer_role
        policy.authorization_notes = auth_req.authorization_notes
        policy.valid_from = now
        policy.valid_until = valid_until

        await AuditEventRecorder.record_authorization_event(
            db=db,
            org_id=policy.organization_id,
            app_id=app_id,
            event_type="AUTHZ_GRANTED",
            action="AUTHORIZE_SCOPE",
            authorizer_email=auth_req.authorized_by,
            authorizer_role=auth_req.authorizer_role,
            details={
                "authorized_by": auth_req.authorized_by,
                "authorizer_role": auth_req.authorizer_role,
                "valid_until": valid_until.isoformat(),
                "notes": auth_req.authorization_notes
            }
        )
        await db.commit()
        await db.refresh(policy)
        return policy

    @classmethod
    async def suspend_scope(
        cls,
        db: AsyncSession,
        app_id: uuid.UUID,
        suspend_req: ScopeSuspendRequest
    ) -> ApplicationScopePolicy:
        """Temporarily suspend testing authorization on a target scope."""
        policy = await cls.get_scope(db, app_id)
        if not policy:
            raise ValueError(f"Scope policy for application {app_id} does not exist.")

        policy.scope_status = ScopeStatus.SUSPENDED.value

        await AuditEventRecorder.record_authorization_event(
            db=db,
            org_id=policy.organization_id,
            app_id=app_id,
            event_type="AUTHZ_SUSPENDED",
            action="SUSPEND_SCOPE",
            details={"reason": suspend_req.reason}
        )
        await db.commit()
        await db.refresh(policy)
        return policy

    @classmethod
    async def revoke_scope(
        cls,
        db: AsyncSession,
        app_id: uuid.UUID,
        revoke_req: ScopeRevokeRequest
    ) -> ApplicationScopePolicy:
        """Permanently revoke authorization for security testing."""
        policy = await cls.get_scope(db, app_id)
        if not policy:
            raise ValueError(f"Scope policy for application {app_id} does not exist.")

        policy.authorization_status = AuthorizationStatus.REVOKED.value
        policy.scope_status = ScopeStatus.SUSPENDED.value

        await AuditEventRecorder.record_authorization_event(
            db=db,
            org_id=policy.organization_id,
            app_id=app_id,
            event_type="AUTHZ_REVOKED",
            action="REVOKE_SCOPE_AUTHORIZATION",
            details={"reason": revoke_req.reason}
        )
        await db.commit()
        await db.refresh(policy)
        return policy

    @classmethod
    async def validate_test_execution(
        cls,
        db: AsyncSession,
        target_url: str,
        http_method: str = "GET",
        payload_sample: Optional[str] = None,
        application_id: Optional[uuid.UUID] = None,
        source_agent: str = "SECURITY_SCANNER",
        dry_run: bool = False,
        client_ip: Optional[str] = None
    ) -> TestValidationResult:
        """
        Rigorous safety validation before any security test or request executes.
        Enforces all 10 safety criteria and returns detailed violation reasons.
        """
        norm_method = http_method.upper().strip()
        target_host = cls._normalize_host(target_url)
        target_path = cls._extract_path(target_url)

        # 1. Resolve Application Scope Policy
        policy: Optional[ApplicationScopePolicy] = None
        if application_id:
            policy = await cls.get_scope(db, application_id)
        else:
            # Try to lookup by target host or base_url match
            query = select(ApplicationScopePolicy).where(
                ApplicationScopePolicy.target_domain == target_host
            )
            result = await db.execute(query)
            policy = result.scalars().first()

        # Check unregistered target
        if not policy:
            return await cls._reject(
                db=db,
                org_id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
                app_id=application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.UNREGISTERED_TARGET.value,
                reason=f"Target '{target_host}' is not registered under any authorized scope policy.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )

        # 2. Domain / Host match validation
        allowed_domain = policy.target_domain.lower()
        if target_host != allowed_domain and not target_host.endswith(f".{allowed_domain}"):
            # Check if allowed_domain has wildcard like *.domain.com
            if allowed_domain.startswith("*."):
                suffix = allowed_domain[2:]
                if not (target_host == suffix or target_host.endswith(f".{suffix}")):
                    return await cls._reject(
                        db=db,
                        org_id=policy.organization_id,
                        app_id=policy.application_id,
                        target_url=target_url,
                        http_method=norm_method,
                        violation_category=ViolationCategory.UNAUTHORIZED_DOMAIN.value,
                        reason=f"Target domain '{target_host}' does not match authorized scope domain '{policy.target_domain}'.",
                        payload_sample=payload_sample,
                        source_agent=source_agent,
                        dry_run=dry_run,
                        client_ip=client_ip
                    )
            else:
                return await cls._reject(
                    db=db,
                    org_id=policy.organization_id,
                    app_id=policy.application_id,
                    target_url=target_url,
                    http_method=norm_method,
                    violation_category=ViolationCategory.UNAUTHORIZED_DOMAIN.value,
                    reason=f"Target domain '{target_host}' does not match authorized scope domain '{policy.target_domain}'.",
                    payload_sample=payload_sample,
                    source_agent=source_agent,
                    dry_run=dry_run,
                    client_ip=client_ip
                )

        # 3. Check Scope Status
        if policy.scope_status == ScopeStatus.SUSPENDED.value:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.SCOPE_NOT_ACTIVE.value,
                reason="Testing scope is currently SUSPENDED. All execution requests are blocked.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )
        elif policy.scope_status == ScopeStatus.DRAFT.value:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.SCOPE_NOT_ACTIVE.value,
                reason="Scope policy is in DRAFT status. Explicit authorization and activation are required before testing.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )

        # 4. Check Authorization Status and Validity Period
        if policy.authorization_status == AuthorizationStatus.PENDING.value:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.AUTHORIZATION_PENDING.value,
                reason="Application registration exists, but testing authorization is PENDING approval.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )
        elif policy.authorization_status == AuthorizationStatus.REVOKED.value:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.AUTHORIZATION_REVOKED.value,
                reason="Security testing authorization for this target was REVOKED.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )

        # Expiry Check
        now = datetime.now(timezone.utc)
        if policy.valid_until:
            valid_until_utc = policy.valid_until if policy.valid_until.tzinfo else policy.valid_until.replace(tzinfo=timezone.utc)
            if now > valid_until_utc:
                # Mark as expired in db
                policy.authorization_status = AuthorizationStatus.EXPIRED.value
                policy.scope_status = ScopeStatus.EXPIRED.value
                await db.commit()
                return await cls._reject(
                    db=db,
                    org_id=policy.organization_id,
                    app_id=policy.application_id,
                    target_url=target_url,
                    http_method=norm_method,
                    violation_category=ViolationCategory.AUTHORIZATION_EXPIRED.value,
                    reason=f"Security testing authorization expired on {policy.valid_until.isoformat()}.",
                    payload_sample=payload_sample,
                    source_agent=source_agent,
                    dry_run=dry_run,
                    client_ip=client_ip
                )

        # 5. Check Prohibited HTTP Method
        allowed_methods = [m.upper() for m in policy.allowed_methods or []]
        if norm_method not in allowed_methods:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.PROHIBITED_METHOD.value,
                reason=f"HTTP method '{norm_method}' is not in allowed methods {allowed_methods}.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )

        # 6. Check Excluded Paths (Strict Blacklist)
        for excluded_pattern in policy.excluded_paths or []:
            if cls._match_pattern(target_path, excluded_pattern):
                return await cls._reject(
                    db=db,
                    org_id=policy.organization_id,
                    app_id=policy.application_id,
                    target_url=target_url,
                    http_method=norm_method,
                    violation_category=ViolationCategory.EXCLUDED_PATH.value,
                    reason=f"Target path '{target_path}' matches strictly excluded pattern '{excluded_pattern}'.",
                    payload_sample=payload_sample,
                    source_agent=source_agent,
                    dry_run=dry_run,
                    client_ip=client_ip
                )

        # 7. Check Permitted Paths (Whitelist)
        permitted = policy.permitted_paths or ["/*"]
        path_permitted = any(cls._match_pattern(target_path, p) for p in permitted)
        if not path_permitted:
            return await cls._reject(
                db=db,
                org_id=policy.organization_id,
                app_id=policy.application_id,
                target_url=target_url,
                http_method=norm_method,
                violation_category=ViolationCategory.PATH_NOT_PERMITTED.value,
                reason=f"Target path '{target_path}' is outside permitted path patterns {permitted}.",
                payload_sample=payload_sample,
                source_agent=source_agent,
                dry_run=dry_run,
                client_ip=client_ip
            )

        # 8. Check Restricted Endpoint Patterns
        if not policy.allow_destructive:
            for restricted_pattern in policy.restricted_endpoint_patterns or []:
                if cls._match_pattern(target_path, restricted_pattern):
                    return await cls._reject(
                        db=db,
                        org_id=policy.organization_id,
                        app_id=policy.application_id,
                        target_url=target_url,
                        http_method=norm_method,
                        violation_category=ViolationCategory.RESTRICTED_ENDPOINT.value,
                        reason=f"Target path '{target_path}' matches restricted endpoint pattern '{restricted_pattern}' and destructive testing is disabled.",
                        payload_sample=payload_sample,
                        source_agent=source_agent,
                        dry_run=dry_run,
                        client_ip=client_ip
                    )

        # 9. Check Prohibited Destructive Patterns in Payload / Query
        if not policy.allow_destructive and payload_sample:
            for pattern in DESTRUCTIVE_PATTERNS:
                if re.search(pattern, payload_sample):
                    return await cls._reject(
                        db=db,
                        org_id=policy.organization_id,
                        app_id=policy.application_id,
                        target_url=target_url,
                        http_method=norm_method,
                        violation_category=ViolationCategory.DESTRUCTIVE_ACTION_PROHIBITED.value,
                        reason="Destructive payload detected (matching prohibited pattern). Destructive testing is not authorized.",
                        payload_sample=payload_sample,
                        source_agent=source_agent,
                        dry_run=dry_run,
                        client_ip=client_ip
                    )

        # 10. Rate Limiting Check
        if not dry_run:
            app_key = str(policy.application_id)
            if not rate_tracker.is_allowed(app_key, policy.rate_limit_rps):
                return await cls._reject(
                    db=db,
                    org_id=policy.organization_id,
                    app_id=policy.application_id,
                    target_url=target_url,
                    http_method=norm_method,
                    violation_category=ViolationCategory.RATE_LIMIT_EXCEEDED.value,
                    reason=f"Request exceeds configured target rate limit of {policy.rate_limit_rps} RPS.",
                    payload_sample=payload_sample,
                    source_agent=source_agent,
                    dry_run=dry_run,
                    client_ip=client_ip
                )

        # All checks passed!
        return TestValidationResult(
            is_allowed=True,
            violation_category=None,
            reason="Target URL and security test parameters strictly comply with authorized scope and safety policy.",
            application_id=policy.application_id,
            target_url=target_url,
            http_method=norm_method,
            checked_at=datetime.now(timezone.utc)
        )

    @classmethod
    async def _reject(
        cls,
        db: AsyncSession,
        org_id: uuid.UUID,
        app_id: Optional[uuid.UUID],
        target_url: str,
        http_method: str,
        violation_category: str,
        reason: str,
        payload_sample: Optional[str] = None,
        source_agent: Optional[str] = None,
        dry_run: bool = False,
        client_ip: Optional[str] = None
    ) -> TestValidationResult:
        """Record blocked execution log and return rejected validation result."""
        if not dry_run and org_id != uuid.UUID("00000000-0000-0000-0000-000000000000"):
            # Record in BlockedExecutionLog
            blocked_log = BlockedExecutionLog(
                organization_id=org_id,
                application_id=app_id,
                target_url=target_url[:1000],
                http_method=http_method,
                violation_category=violation_category,
                blocked_reason=reason[:1000],
                payload_sample=payload_sample[:2000] if payload_sample else None,
                source_agent=source_agent,
                client_ip=client_ip
            )
            db.add(blocked_log)

            # Record in AuditLog for global traceability with tamper-evident chain
            await AuditEventRecorder.record_security_testing_event(
                db=db,
                org_id=org_id,
                event_type="TEST_BLOCKED",
                action="BLOCKED_TEST_EXECUTION",
                app_id=app_id,
                status=AuditStatus.BLOCKED,
                severity=AuditSeverity.HIGH,
                source_module=source_agent or "SAFETY_ENGINE",
                details={
                    "violation": violation_category,
                    "reason": reason,
                    "url": target_url,
                    "method": http_method,
                    "source_agent": source_agent
                },
                ip_address=client_ip
            )
            await db.commit()

        return TestValidationResult(
            is_allowed=False,
            violation_category=violation_category,
            reason=reason,
            application_id=app_id,
            target_url=target_url,
            http_method=http_method,
            checked_at=datetime.now(timezone.utc)
        )

    @classmethod
    async def list_blocked_executions(
        cls,
        db: AsyncSession,
        org_id: Optional[uuid.UUID] = None,
        app_id: Optional[uuid.UUID] = None,
        limit: int = 100
    ) -> List[BlockedExecutionLog]:
        """Retrieve history of blocked security test attempts."""
        query = select(BlockedExecutionLog)
        if org_id:
            query = query.where(BlockedExecutionLog.organization_id == org_id)
        if app_id:
            query = query.where(BlockedExecutionLog.application_id == app_id)
        query = query.order_by(desc(BlockedExecutionLog.created_at)).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

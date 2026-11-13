"""
PHANTOM-X - Feature 6: Role & Resource Relationship Mapping
Role & Resource Mapping Service

Business logic, orchestration, and persistence coordinator:
- Ingests declared roles from ApplicationRole and relationships from ResourceRelationship.
- Ingests observed traffic interactions from BehavioralObservation.
- Runs structural containment inference and role access overlap analysis.
- Idempotently upserts mappings into `role_resource_mappings`.
- Strict multi-tenant isolation at organization_id level.
- Sanitizes all stored evidence and prevents raw credential exposure.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc, delete

from app.models.application import Application, ApplicationRole, ResourceRelationship
from app.models.endpoint import DiscoveredEndpoint
from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
)
from app.features.application_intelligence.role_resource_mapping.models import (
    RoleResourceMapping,
    SubjectType,
    ObjectType,
    RelationshipType,
    EvidenceSource,
    MappingStatus,
)
from app.features.application_intelligence.role_resource_mapping.schemas import (
    MappingDiscoveryRequest,
    MappingDiscoveryResultResponse,
    RoleResourceMappingResponse,
    RoleResourceMappingListResponse,
    MappingEvidenceItemResponse,
    MappingEvidenceListResponse,
    RoleResourceOverviewResponse,
    DiscrepancyListResponse,
    ApplicationRoleMappingResponse,
    ApplicationRoleMappingListResponse,
    ApplicationResourceMappingResponse,
    ApplicationResourceMappingListResponse,
)
from app.features.application_intelligence.role_resource_mapping.mapping_engine import (
    RoleResourceMappingEngine,
)
from app.features.application_intelligence.role_resource_mapping.sanitization import (
    sanitize_mapping_evidence,
    validate_evidence_reference,
)


class RoleResourceMappingService:
    """
    Orchestrates relationship discovery, idempotent persistence, and
    multi-tenant query evaluation.
    """

    @staticmethod
    async def _verify_application_ownership(
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Application:
        """Enforces multi-tenant ownership for application resources."""
        stmt = select(Application).where(
            and_(
                Application.id == application_id,
                Application.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        app = res.scalar_one_or_none()
        if not app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Application {application_id} not found or access denied.",
            )
        return app

    @classmethod
    async def discover_and_persist(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        request: MappingDiscoveryRequest,
    ) -> MappingDiscoveryResultResponse:
        """
        Executes end-to-end relationship discovery across declared, observed, and inferred
        sources, performing neutral discrepancy alignment and idempotent persistence.
        Supports explicit modes: ALL, DECLARED_ONLY, OBSERVED_ONLY, STRUCTURAL_ONLY, OVERLAP_ONLY.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        mode = (request.mode or "ALL").upper()
        include_decl = request.include_declared and mode in ("ALL", "DECLARED_ONLY")
        include_obs = request.include_observed and mode in ("ALL", "OBSERVED_ONLY")
        include_struct = request.include_inferred and mode in ("ALL", "STRUCTURAL_ONLY")
        include_overlap = request.include_inferred and mode in ("ALL", "OVERLAP_ONLY")

        declared_mappings: List[Dict[str, Any]] = []
        observed_mappings: List[Dict[str, Any]] = []
        inferred_mappings: List[Dict[str, Any]] = []

        # 1. Ingest Declared Roles and Relationships
        if include_decl:
            roles_stmt = select(ApplicationRole).where(
                ApplicationRole.application_id == application_id
            )
            roles_res = await db.execute(roles_stmt)
            roles = roles_res.scalars().all()
            declared_mappings.extend(
                RoleResourceMappingEngine.ingest_declared_roles(
                    roles=roles,
                    organization_id=organization_id,
                    application_id=application_id,
                )
            )

            rels_stmt = select(ResourceRelationship).where(
                ResourceRelationship.application_id == application_id
            )
            rels_res = await db.execute(rels_stmt)
            relationships = rels_res.scalars().all()
            declared_mappings.extend(
                RoleResourceMappingEngine.ingest_declared_relationships(
                    relationships=relationships,
                    organization_id=organization_id,
                    application_id=application_id,
                )
            )

        # 2. Ingest Behavioral Observations
        if include_obs or include_overlap or include_struct:
            obs_stmt = select(BehavioralObservation).where(
                and_(
                    BehavioralObservation.application_id == application_id,
                    BehavioralObservation.organization_id == organization_id,
                )
            ).order_by(BehavioralObservation.observed_at.asc())
            obs_res = await db.execute(obs_stmt)
            observations = obs_res.scalars().all()

            if include_obs or include_overlap:
                observed_mappings.extend(
                    RoleResourceMappingEngine.discover_observed_mappings(
                        observations=observations,
                        organization_id=organization_id,
                        application_id=application_id,
                    )
                )

        # 3. Ingest Inferred Structural Relationships & Role Overlaps
        if include_struct:
            ep_stmt = select(DiscoveredEndpoint).where(
                DiscoveredEndpoint.application_id == application_id
            )
            ep_res = await db.execute(ep_stmt)
            endpoints = ep_res.scalars().all()

            all_paths = [getattr(e, "normalized_path", "") for e in endpoints if getattr(e, "normalized_path", "")]
            if 'observations' in locals():
                all_paths.extend([getattr(o, "normalized_path", "") for o in observations if getattr(o, "normalized_path", "")])

            inferred_mappings.extend(
                RoleResourceMappingEngine.infer_structural_containment(
                    normalized_paths=all_paths,
                    organization_id=organization_id,
                    application_id=application_id,
                )
            )

        if include_overlap:
            role_endpoints: Dict[str, Set[str]] = {}
            for obs_m in observed_mappings:
                if obs_m.get("relationship_type") == RelationshipType.ROLE_ACCESSES_ENDPOINT.value:
                    r_name = obs_m.get("subject_name")
                    ep_name = obs_m.get("object_name")
                    if r_name and ep_name:
                        role_endpoints.setdefault(r_name, set()).add(ep_name)

            if len(role_endpoints) >= 2:
                inferred_mappings.extend(
                    RoleResourceMappingEngine.analyze_role_access_overlaps(
                        observed_role_endpoints=role_endpoints,
                        organization_id=organization_id,
                        application_id=application_id,
                    )
                )

        # 4. Synthesize, Align, and Apply Threshold Constraints
        unified_mappings, summary_metrics = RoleResourceMappingEngine.synthesize_and_align_mappings(
            declared_mappings=declared_mappings,
            observed_mappings=observed_mappings,
            inferred_mappings=inferred_mappings,
            min_confidence=request.min_confidence,
            min_sample_count=request.min_sample_count,
        )

        # 5. Idempotent Persistence into role_resource_mappings
        existing_stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.application_id == application_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        existing_res = await db.execute(existing_stmt)
        existing_rows = existing_res.scalars().all()

        existing_by_tuple: Dict[Tuple, RoleResourceMapping] = {}
        for row in existing_rows:
            key = (
                row.subject_type.upper(),
                row.subject_name.strip().lower(),
                row.relationship_type.upper(),
                row.object_type.upper(),
                row.object_name.strip().lower(),
            )
            existing_by_tuple[key] = row

        persisted_records: List[RoleResourceMapping] = []

        for m_data in unified_mappings:
            tuple_key = (
                m_data["subject_type"].upper(),
                m_data["subject_name"].strip().lower(),
                m_data["relationship_type"].upper(),
                m_data["object_type"].upper(),
                m_data["object_name"].strip().lower(),
            )

            sanitized_telemetry = sanitize_mapping_evidence(m_data.get("access_telemetry", {}))
            sanitized_dvo = sanitize_mapping_evidence(m_data.get("declared_vs_observed", {}))
            valid_refs = [
                r for r in m_data.get("evidence_references", [])
                if validate_evidence_reference(str(r))
            ]

            if tuple_key in existing_by_tuple:
                # Update existing record
                record = existing_by_tuple[tuple_key]
                record.confidence_score = float(m_data.get("confidence_score", 0.0))
                record.sample_count = int(m_data.get("sample_count", 1))
                record.evidence_source = m_data.get("evidence_source", record.evidence_source)
                record.access_telemetry = sanitized_telemetry
                record.declared_vs_observed = sanitized_dvo
                record.evidence_references = valid_refs
                record.status = m_data.get("status", MappingStatus.ACTIVE.value)
                record.last_observed_at = datetime.now(timezone.utc)
                persisted_records.append(record)
            else:
                # Insert new record
                new_record = RoleResourceMapping(
                    organization_id=organization_id,
                    application_id=application_id,
                    subject_type=m_data["subject_type"],
                    subject_id=m_data.get("subject_id"),
                    subject_name=m_data["subject_name"],
                    relationship_type=m_data["relationship_type"],
                    object_type=m_data["object_type"],
                    object_id=m_data.get("object_id"),
                    object_name=m_data["object_name"],
                    evidence_source=m_data.get("evidence_source", EvidenceSource.OBSERVED.value),
                    confidence_score=float(m_data.get("confidence_score", 0.0)),
                    sample_count=int(m_data.get("sample_count", 1)),
                    access_telemetry=sanitized_telemetry,
                    declared_vs_observed=sanitized_dvo,
                    evidence_references=valid_refs,
                    status=m_data.get("status", MappingStatus.ACTIVE.value),
                )
                db.add(new_record)
                persisted_records.append(new_record)

        await db.commit()

        # Refresh all records
        for rec in persisted_records:
            await db.refresh(rec)

        response_items = [
            RoleResourceMappingResponse.model_validate(rec)
            for rec in persisted_records
        ]

        return MappingDiscoveryResultResponse(
            application_id=application_id,
            discovered_mappings_count=len(persisted_records),
            declared_mappings_count=summary_metrics["declared_count"],
            observed_mappings_count=summary_metrics["observed_count"],
            inferred_mappings_count=summary_metrics["inferred_count"],
            discrepancies_count=summary_metrics["discrepancies_count"],
            insufficient_evidence=summary_metrics["insufficient_evidence"],
            insufficient_evidence_reason=summary_metrics["insufficient_evidence_reason"],
            mappings=response_items,
        )

    @classmethod
    async def get_mappings(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        subject_type: Optional[str] = None,
        object_type: Optional[str] = None,
        relationship_type: Optional[str] = None,
        evidence_source: Optional[str] = None,
        min_confidence: Optional[float] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> RoleResourceMappingListResponse:
        """Retrieves paginated mappings with multi-tenant filtering."""
        await cls._verify_application_ownership(db, application_id, organization_id)

        filters = [
            RoleResourceMapping.application_id == application_id,
            RoleResourceMapping.organization_id == organization_id,
        ]

        if subject_type:
            filters.append(RoleResourceMapping.subject_type == subject_type.upper())
        if object_type:
            filters.append(RoleResourceMapping.object_type == object_type.upper())
        if relationship_type:
            filters.append(RoleResourceMapping.relationship_type == relationship_type.upper())
        if evidence_source:
            filters.append(RoleResourceMapping.evidence_source == evidence_source.upper())
        if min_confidence is not None:
            filters.append(RoleResourceMapping.confidence_score >= min_confidence)

        count_stmt = select(func.count(RoleResourceMapping.id)).where(and_(*filters))
        count_res = await db.execute(count_stmt)
        total = count_res.scalar() or 0

        bounded_page = max(1, page)
        bounded_size = max(1, min(100, page_size))

        query_stmt = (
            select(RoleResourceMapping)
            .where(and_(*filters))
            .order_by(desc(RoleResourceMapping.confidence_score), desc(RoleResourceMapping.sample_count))
            .offset((bounded_page - 1) * bounded_size)
            .limit(bounded_size)
        )
        res = await db.execute(query_stmt)
        records = res.scalars().all()

        return RoleResourceMappingListResponse(
            items=[RoleResourceMappingResponse.model_validate(r) for r in records],
            total=total,
            page=bounded_page,
            page_size=bounded_size,
        )

    @classmethod
    async def get_mapping_by_id(
        cls,
        db: AsyncSession,
        mapping_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> RoleResourceMappingResponse:
        """Retrieves single mapping verifying multi-tenant ownership."""
        stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.id == mapping_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        mapping = res.scalar_one_or_none()
        if not mapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Mapping {mapping_id} not found or access denied.",
            )
        return RoleResourceMappingResponse.model_validate(mapping)

    @classmethod
    async def get_overview(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> RoleResourceOverviewResponse:
        """Computes summary overview of discovered roles, resources, and discrepancies."""
        await cls._verify_application_ownership(db, application_id, organization_id)

        stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.application_id == application_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        mappings = res.scalars().all()

        distinct_roles = set()
        distinct_resources = set()
        declared_count = 0
        observed_count = 0
        inferred_count = 0
        discrepancies_count = 0
        high_conf_count = 0

        for m in mappings:
            if m.subject_type == SubjectType.ROLE.value:
                distinct_roles.add(m.subject_name)
            if m.object_type == ObjectType.ROLE.value:
                distinct_roles.add(m.object_name)
            if m.subject_type == SubjectType.RESOURCE.value:
                distinct_resources.add(m.subject_name)
            if m.object_type == ObjectType.RESOURCE.value:
                distinct_resources.add(m.object_name)

            if m.evidence_source == EvidenceSource.DECLARED.value:
                declared_count += 1
            elif m.evidence_source == EvidenceSource.OBSERVED.value:
                observed_count += 1
            elif m.evidence_source == EvidenceSource.INFERRED.value:
                inferred_count += 1

            if m.confidence_score >= 0.80:
                high_conf_count += 1

            dvo = m.declared_vs_observed or {}
            cat = dvo.get("discrepancy_category", "NONE")
            if cat in {"DECLARED_NOT_OBSERVED", "OBSERVED_NOT_DECLARED"}:
                discrepancies_count += 1

        is_insufficient = len(mappings) == 0 or observed_count < 2
        return RoleResourceOverviewResponse(
            application_id=application_id,
            total_roles=len(distinct_roles),
            total_resources=len(distinct_resources),
            total_mappings=len(mappings),
            declared_count=declared_count,
            observed_count=observed_count,
            inferred_count=inferred_count,
            discrepancies_count=discrepancies_count,
            high_confidence_count=high_conf_count,
            insufficient_evidence=is_insufficient,
            insufficient_evidence_reason=(
                "Insufficient observations (< 2 samples) to establish statistically reliable alignment."
                if is_insufficient
                else None
            ),
        )

    @classmethod
    async def get_discrepancies(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
        category: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> DiscrepancyListResponse:
        """
        Retrieves declared-versus-observed discrepancy listings with breakdown.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.application_id == application_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        mappings = res.scalars().all()

        breakdown = {
            "ALIGNED": 0,
            "DECLARED_NOT_OBSERVED": 0,
            "OBSERVED_NOT_DECLARED": 0,
            "EVIDENCE_INSUFFICIENT": 0,
        }

        matching_items = []
        filter_cat = category.upper() if category else None

        for m in mappings:
            dvo = m.declared_vs_observed or {}
            m_cat = dvo.get("discrepancy_category", "NONE").upper()
            if m_cat in breakdown:
                breakdown[m_cat] += 1

            if filter_cat:
                if m_cat == filter_cat:
                    matching_items.append(m)
            else:
                # If no category filter, include all discrepancies (non-ALIGNED)
                if m_cat in {"DECLARED_NOT_OBSERVED", "OBSERVED_NOT_DECLARED", "EVIDENCE_INSUFFICIENT"}:
                    matching_items.append(m)

        bounded_page = max(1, page)
        bounded_size = max(1, min(100, page_size))
        start_idx = (bounded_page - 1) * bounded_size
        paginated_items = matching_items[start_idx : start_idx + bounded_size]

        return DiscrepancyListResponse(
            application_id=application_id,
            total_discrepancies=len(matching_items),
            category_filter=category,
            breakdown=breakdown,
            items=[RoleResourceMappingResponse.model_validate(r) for r in paginated_items],
        )

    @classmethod
    async def get_roles_summary(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> ApplicationRoleMappingListResponse:
        """
        Retrieves ApplicationRoles with their discovered endpoint/resource mappings.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        # Get declared roles
        roles_stmt = select(ApplicationRole).where(
            ApplicationRole.application_id == application_id
        )
        roles_res = await db.execute(roles_stmt)
        roles = roles_res.scalars().all()

        # Get mappings for application
        stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.application_id == application_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        mappings = res.scalars().all()

        role_items: List[ApplicationRoleMappingResponse] = []

        # Map by role name
        mappings_by_role: Dict[str, List[RoleResourceMapping]] = {}
        for m in mappings:
            if m.subject_type == SubjectType.ROLE.value:
                mappings_by_role.setdefault(m.subject_name.lower(), []).append(m)
            elif m.object_type == ObjectType.ROLE.value:
                mappings_by_role.setdefault(m.object_name.lower(), []).append(m)

        for role in roles:
            r_name = role.name.lower()
            r_mappings = mappings_by_role.pop(r_name, [])

            endpoints = [
                m.object_name for m in r_mappings
                if m.relationship_type == RelationshipType.ROLE_ACCESSES_ENDPOINT.value
            ]
            resources = [
                m.object_name for m in r_mappings
                if m.relationship_type == RelationshipType.ROLE_ACCESSES_RESOURCE.value
            ]

            role_items.append(
                ApplicationRoleMappingResponse(
                    role_id=str(role.id),
                    role_name=role.name,
                    description=role.description,
                    declared_permissions=role.permissions or {},
                    discovered_endpoints=sorted(list(set(endpoints))),
                    discovered_resources=sorted(list(set(resources))),
                    mappings=[RoleResourceMappingResponse.model_validate(m) for m in r_mappings],
                )
            )

        # Also include observed roles that were not formally declared in ApplicationRole
        for undeclared_role, r_mappings in mappings_by_role.items():
            endpoints = [
                m.object_name for m in r_mappings
                if m.relationship_type == RelationshipType.ROLE_ACCESSES_ENDPOINT.value
            ]
            resources = [
                m.object_name for m in r_mappings
                if m.relationship_type == RelationshipType.ROLE_ACCESSES_RESOURCE.value
            ]
            role_items.append(
                ApplicationRoleMappingResponse(
                    role_id=None,
                    role_name=undeclared_role,
                    description="Discovered through observed traffic telemetry",
                    declared_permissions={},
                    discovered_endpoints=sorted(list(set(endpoints))),
                    discovered_resources=sorted(list(set(resources))),
                    mappings=[RoleResourceMappingResponse.model_validate(m) for m in r_mappings],
                )
            )

        return ApplicationRoleMappingListResponse(
            application_id=application_id,
            total_roles=len(role_items),
            items=role_items,
        )

    @classmethod
    async def get_resources_summary(
        cls,
        db: AsyncSession,
        application_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> ApplicationResourceMappingListResponse:
        """
        Retrieves discovered resources with structural containment and accessing roles.
        """
        await cls._verify_application_ownership(db, application_id, organization_id)

        stmt = select(RoleResourceMapping).where(
            and_(
                RoleResourceMapping.application_id == application_id,
                RoleResourceMapping.organization_id == organization_id,
            )
        )
        res = await db.execute(stmt)
        mappings = res.scalars().all()

        resource_data: Dict[str, Dict[str, Any]] = {}

        for m in mappings:
            # Check if subject is resource
            if m.subject_type == SubjectType.RESOURCE.value:
                res_name = m.subject_name.lower()
                entry = resource_data.setdefault(res_name, {
                    "parents": set(),
                    "children": set(),
                    "roles": set(),
                    "mappings": [],
                })
                entry["mappings"].append(m)
                if m.relationship_type == RelationshipType.STRUCTURAL_CONTAINMENT.value:
                    entry["children"].add(m.object_name.lower())

            # Check if object is resource
            if m.object_type == ObjectType.RESOURCE.value:
                res_name = m.object_name.lower()
                entry = resource_data.setdefault(res_name, {
                    "parents": set(),
                    "children": set(),
                    "roles": set(),
                    "mappings": [],
                })
                entry["mappings"].append(m)
                if m.relationship_type == RelationshipType.STRUCTURAL_CONTAINMENT.value:
                    entry["parents"].add(m.subject_name.lower())
                elif m.relationship_type == RelationshipType.ROLE_ACCESSES_RESOURCE.value:
                    entry["roles"].add(m.subject_name.lower())

        items = []
        for res_name, data in sorted(resource_data.items()):
            items.append(
                ApplicationResourceMappingResponse(
                    resource_name=res_name,
                    structural_parents=sorted(list(data["parents"])),
                    structural_children=sorted(list(data["children"])),
                    accessing_roles=sorted(list(data["roles"])),
                    mappings=[RoleResourceMappingResponse.model_validate(m) for m in data["mappings"]],
                )
            )

        return ApplicationResourceMappingListResponse(
            application_id=application_id,
            total_resources=len(items),
            items=items,
        )

    @classmethod
    async def get_evidence(
        cls,
        db: AsyncSession,
        mapping_id: uuid.UUID,
        organization_id: uuid.UUID,
        limit: int = 50,
        application_id: Optional[uuid.UUID] = None,
    ) -> MappingEvidenceListResponse:
        """
        Retrieves sanitized evidence items for a specific relationship mapping.
        Guarantees that sensitive credentials and tokens are redacted.
        Validates ownership of mapping via organization_id.
        """
        filters = [
            RoleResourceMapping.id == mapping_id,
            RoleResourceMapping.organization_id == organization_id,
        ]
        if application_id:
            filters.append(RoleResourceMapping.application_id == application_id)

        stmt = select(RoleResourceMapping).where(and_(*filters))
        res = await db.execute(stmt)
        mapping = res.scalar_one_or_none()
        if not mapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Mapping {mapping_id} not found or access denied.",
            )

        evidence_ids = [
            uuid.UUID(ref)
            for ref in mapping.evidence_references
            if validate_evidence_reference(str(ref))
        ]

        if not evidence_ids:
            return MappingEvidenceListResponse(
                mapping_id=mapping_id,
                total_evidence=0,
                items=[],
            )

        bounded_limit = max(1, min(100, limit))
        obs_stmt = (
            select(BehavioralObservation)
            .where(
                and_(
                    BehavioralObservation.id.in_(evidence_ids),
                    BehavioralObservation.application_id == mapping.application_id,
                    BehavioralObservation.organization_id == organization_id,
                )
            )
            .limit(bounded_limit)
        )
        obs_res = await db.execute(obs_stmt)
        observations = obs_res.scalars().all()

        evidence_items = []
        for o in observations:
            sanitized_req = sanitize_mapping_evidence(o.sanitized_request_schema)
            sanitized_resp = sanitize_mapping_evidence(o.sanitized_response_schema)
            evidence_items.append(
                MappingEvidenceItemResponse(
                    observation_id=o.id,
                    session_token_hash=o.session_token_hash,
                    method=o.method,
                    normalized_path=o.normalized_path,
                    status_code=o.status_code,
                    latency_ms=o.latency_ms,
                    observed_at=o.observed_at,
                    sanitized_request_schema=sanitized_req,
                    sanitized_response_schema=sanitized_resp,
                )
            )

        return MappingEvidenceListResponse(
            mapping_id=mapping_id,
            total_evidence=len(evidence_items),
            items=evidence_items,
        )

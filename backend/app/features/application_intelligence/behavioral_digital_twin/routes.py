"""
PHANTOM-X - Feature 4: Behavioral Digital Twin
REST API Endpoints

Provides router endpoints for:
- Behavioral Digital Twin overview and telemetry metrics
- Observation ingestion (single, batch, HAR archive)
- Baseline lifecycle operations (compile, activate, supersede, archive)
- Drift and anomaly detection, filtering, and acknowledgment/resolution
- Enforces authenticated user context, RBAC permissions, and strict multi-tenant isolation.
"""

import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func

from app.database.session import get_db
from app.api.deps import get_current_user, require_role
from app.models.user import User
from shared.enums.common import UserRole

from app.features.application_intelligence.behavioral_digital_twin.models import (
    BehavioralObservation,
    BehavioralBaseline,
    BehavioralAnomaly,
    BaselineStatus,
    AnomalyStatus,
)
from app.features.application_intelligence.behavioral_digital_twin.schemas import (
    ObservationIngestRequest,
    ObservationBatchIngestRequest,
    ObservationResponse,
    ObservationListResponse,
    HarIngestRequest,
    BatchIngestResponse,
    BaselineCompileRequest,
    BaselineActivateRequest,
    BaselineResponse,
    BaselineListResponse,
    AnomalyStatusUpdateRequest,
    AnomalyResponse,
    AnomalyListResponse,
    DriftEvaluateRequest,
    DriftEvaluationResponse,
    DigitalTwinOverviewResponse,
)
from app.features.application_intelligence.behavioral_digital_twin.ingestion_service import (
    ObservationIngestionService,
    TenantAccessDeniedError,
)
from app.features.application_intelligence.behavioral_digital_twin.baseline_service import (
    BaselineService,
)
from app.features.application_intelligence.behavioral_digital_twin.drift_engine import (
    DriftEngine,
)

router = APIRouter(prefix="/behavioral-twin", tags=["Feature 4 — Behavioral Digital Twin"])


# ==============================================================================
# A. BEHAVIORAL DIGITAL TWIN OVERVIEW
# ==============================================================================

@router.get(
    "/applications/{application_id}/overview",
    response_model=DigitalTwinOverviewResponse,
    summary="Get application Behavioral Digital Twin overview",
)
@router.get(
    "/overview",
    response_model=DigitalTwinOverviewResponse,
    summary="Get application Behavioral Digital Twin overview (query param alias)",
)
async def get_digital_twin_overview(
    application_id: Optional[uuid.UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the high-level behavioral digital twin summary for an application:
    - Active baseline status, version, and statistical confidence
    - Total observation count and last observed timestamp
    - Aggregated endpoint behavior profiles
    - Open anomaly metrics and latest deviations
    """
    if not application_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="application_id is required.",
        )

    try:
        overview_data = await BaselineService.get_digital_twin_overview(
            db=db,
            organization_id=current_user.organization_id,
            application_id=application_id,
        )
        return overview_data
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# ==============================================================================
# B. OBSERVATION INGESTION
# ==============================================================================

@router.post(
    "/observations",
    response_model=ObservationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a single sanitized API observation",
)
async def ingest_observation(
    request: ObservationIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Ingests an observed HTTP interaction. Sanitizes headers and bodies,
    hashes session tokens, infers structural schemas, and normalizes endpoint paths.
    """
    try:
        obs = await ObservationIngestionService.ingest_single_observation(
            db=db,
            application_id=request.application_id,
            organization_id=current_user.organization_id,  # Never trust client-supplied org ID
            method=request.method,
            url_or_path=request.path,
            status_code=request.status_code,
            request_headers=request.request_headers,
            response_headers=request.response_headers,
            request_payload=request.request_payload,
            response_payload=request.response_payload,
            latency_ms=request.latency_ms,
            session_identifier=request.session_identifier,
            endpoint_id=request.endpoint_id,
        )
        return obs
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/observations/batch",
    response_model=BatchIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Batch ingest up to 200 sanitized API observations",
)
async def ingest_observations_batch(
    request: ObservationBatchIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Batch ingestion of observation records with application ownership validation.
    """
    try:
        # Transform ObservationIngestRequest models to dicts
        obs_dicts = [obs.model_dump() for obs in request.observations]
        ingested = await ObservationIngestionService.ingest_batch(
            db=db,
            application_id=request.application_id,
            organization_id=current_user.organization_id,
            observations=obs_dicts,
        )
        return {
            "application_id": request.application_id,
            "ingested_count": len(ingested),
            "failed_count": len(request.observations) - len(ingested),
            "observations": ingested,
        }
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/observations/har",
    response_model=BatchIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest observation traces from a raw HAR archive",
)
async def ingest_observations_har(
    request: HarIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Parses and ingests HTTP interaction traces from a HAR archive string
    using the HarTrafficParser.
    """
    try:
        ingested = await ObservationIngestionService.ingest_from_har(
            db=db,
            application_id=request.application_id,
            organization_id=current_user.organization_id,
            har_content=request.har_content,
        )
        return {
            "application_id": request.application_id,
            "ingested_count": len(ingested),
            "failed_count": 0,
            "observations": ingested,
        }
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/observations",
    response_model=ObservationListResponse,
    summary="List sanitized observations with bounded pagination",
)
async def list_observations(
    application_id: uuid.UUID = Query(..., description="Target application ID"),
    endpoint_id: Optional[uuid.UUID] = Query(None, description="Optional endpoint filter"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists persisted observations for an application, enforcing multi-tenant isolation.
    """
    filters = [
        BehavioralObservation.application_id == application_id,
        BehavioralObservation.organization_id == current_user.organization_id,
    ]
    if endpoint_id:
        filters.append(BehavioralObservation.endpoint_id == endpoint_id)

    # Count total
    count_query = select(func.count(BehavioralObservation.id)).where(and_(*filters))
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    offset = (page - 1) * limit
    data_query = (
        select(BehavioralObservation)
        .where(and_(*filters))
        .order_by(desc(BehavioralObservation.observed_at))
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(data_query)
    items = list(res.scalars().all())

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
    }


# ==============================================================================
# C. BASELINE MANAGEMENT
# ==============================================================================

@router.get(
    "/baselines",
    response_model=BaselineListResponse,
    summary="List historical and active baselines for an application",
)
async def list_baselines(
    application_id: uuid.UUID = Query(..., description="Target application ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns all baseline snapshots for an application.
    """
    baselines = await BaselineService.list_baselines(
        db=db,
        organization_id=current_user.organization_id,
        application_id=application_id,
    )
    return {
        "items": baselines,
        "total": len(baselines),
    }


@router.get(
    "/baselines/{baseline_id}",
    response_model=BaselineResponse,
    summary="Retrieve details of a specific baseline",
)
async def get_baseline(
    baseline_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves full details of a single baseline snapshot.
    """
    query = select(BehavioralBaseline).where(
        and_(
            BehavioralBaseline.id == baseline_id,
            BehavioralBaseline.organization_id == current_user.organization_id,
        )
    )
    res = await db.execute(query)
    baseline = res.scalar_one_or_none()
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline not found or access denied.",
        )
    return baseline


@router.post(
    "/baselines/compile",
    response_model=BaselineResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Compile observations into a new DRAFT baseline snapshot",
)
async def compile_baseline(
    request: BaselineCompileRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Compiles observations for a specified application window into a new DRAFT baseline.
    Requires SECURITY_ENGINEER, DEVELOPER, or ADMIN role.
    """
    try:
        baseline = await BaselineService.compile_baseline(
            db=db,
            organization_id=current_user.organization_id,
            application_id=request.application_id,
            version=request.version,
            start_time=request.start_time,
            end_time=request.end_time,
            min_samples=request.min_samples,
        )
        return baseline
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.post(
    "/baselines/{baseline_id}/activate",
    response_model=BaselineResponse,
    summary="Promote baseline to ACTIVE, superseding prior active baseline",
)
async def activate_baseline(
    baseline_id: uuid.UUID,
    request: Optional[BaselineActivateRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Promotes a baseline from DRAFT to ACTIVE.
    Enforces the single-active baseline invariant: supersedes any existing active baseline.
    Requires sufficient observation evidence.
    """
    try:
        baseline = await BaselineService.activate_baseline(
            db=db,
            organization_id=current_user.organization_id,
            baseline_id=baseline_id,
        )
        return baseline
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.post(
    "/baselines/{baseline_id}/archive",
    response_model=BaselineResponse,
    summary="Archive an inactive or superseded baseline",
)
async def archive_baseline(
    baseline_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Transitions a baseline into ARCHIVED state.
    Active baselines cannot be archived directly.
    """
    try:
        baseline = await BaselineService.archive_baseline(
            db=db,
            organization_id=current_user.organization_id,
            baseline_id=baseline_id,
        )
        return baseline
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


# ==============================================================================
# D. BEHAVIORAL DRIFT & ANOMALY MANAGEMENT
# ==============================================================================

@router.get(
    "/anomalies",
    response_model=AnomalyListResponse,
    summary="List detected anomalies with pagination and multi-criteria filters",
)
async def list_anomalies(
    application_id: uuid.UUID = Query(..., description="Target application ID"),
    status_filter: Optional[AnomalyStatus] = Query(None, alias="status", description="Filter by status"),
    anomaly_type: Optional[str] = Query(None, description="Filter by anomaly type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves detected behavioral deviations with pagination and filtering.
    """
    filters = [
        BehavioralAnomaly.application_id == application_id,
        BehavioralAnomaly.organization_id == current_user.organization_id,
    ]
    if status_filter:
        filters.append(BehavioralAnomaly.status == status_filter.value)
    if anomaly_type:
        filters.append(BehavioralAnomaly.anomaly_type == anomaly_type)
    if severity:
        filters.append(BehavioralAnomaly.severity == severity)

    count_query = select(func.count(BehavioralAnomaly.id)).where(and_(*filters))
    total = (await db.execute(count_query)).scalar() or 0

    offset = (page - 1) * limit
    data_query = (
        select(BehavioralAnomaly)
        .where(and_(*filters))
        .order_by(desc(BehavioralAnomaly.detected_at))
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(data_query)
    items = list(res.scalars().all())

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get(
    "/anomalies/{anomaly_id}",
    response_model=AnomalyResponse,
    summary="Retrieve individual anomaly details and forensic evidence",
)
async def get_anomaly(
    anomaly_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves full details and sanitized forensic evidence for a specific anomaly.
    """
    query = select(BehavioralAnomaly).where(
        and_(
            BehavioralAnomaly.id == anomaly_id,
            BehavioralAnomaly.organization_id == current_user.organization_id,
        )
    )
    res = await db.execute(query)
    anomaly = res.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found or access denied.",
        )
    return anomaly


@router.post(
    "/drift/evaluate",
    response_model=DriftEvaluationResponse,
    summary="Trigger drift evaluation across recent observations against active baseline",
)
async def evaluate_drift(
    request: DriftEvaluateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Evaluates recent observations for an application against the established baseline.
    Detects status code drift, schema mutations, sequence drift, and latency anomalies.
    """
    # Verify application ownership
    try:
        await ObservationIngestionService.validate_application_tenant(
            db=db,
            application_id=request.application_id,
            organization_id=current_user.organization_id,
        )
    except TenantAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Application does not belong to your organization.",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # Resolve baseline
    if request.baseline_id:
        b_query = select(BehavioralBaseline).where(
            and_(
                BehavioralBaseline.id == request.baseline_id,
                BehavioralBaseline.organization_id == current_user.organization_id,
            )
        )
        b_res = await db.execute(b_query)
        baseline = b_res.scalar_one_or_none()
    else:
        baseline = await BaselineService.get_active_baseline(
            db=db,
            organization_id=current_user.organization_id,
            application_id=request.application_id,
        )

    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active baseline found for this application. Compile and activate a baseline first.",
        )

    # Fetch recent observations
    obs_query = (
        select(BehavioralObservation)
        .where(
            and_(
                BehavioralObservation.application_id == request.application_id,
                BehavioralObservation.organization_id == current_user.organization_id,
            )
        )
        .order_by(desc(BehavioralObservation.observed_at))
        .limit(request.max_observations)
    )
    obs_res = await db.execute(obs_query)
    observations = list(obs_res.scalars().all())

    drift_engine = DriftEngine()
    detected_anomalies: List[BehavioralAnomaly] = []

    # Evaluate sequentially (with session context where available)
    for i, obs in enumerate(observations):
        prior = observations[i + 1] if i + 1 < len(observations) else None
        anoms = await drift_engine.evaluate_observation(
            db=db,
            observation=obs,
            baseline=baseline,
            prior_observation=prior,
        )
        detected_anomalies.extend(anoms)

    return {
        "application_id": request.application_id,
        "baseline_id": baseline.id,
        "evaluated_observations_count": len(observations),
        "new_anomalies_detected": len(detected_anomalies),
        "anomalies": detected_anomalies,
    }


@router.patch(
    "/anomalies/{anomaly_id}/status",
    response_model=AnomalyResponse,
    summary="Update anomaly status (OPEN, ACKNOWLEDGED, RESOLVED)",
)
async def update_anomaly_status(
    anomaly_id: uuid.UUID,
    request: AnomalyStatusUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """
    Updates the review lifecycle state of a behavioral anomaly.
    """
    try:
        updated = await DriftEngine.update_anomaly_status(
            db=db,
            organization_id=current_user.organization_id,
            anomaly_id=anomaly_id,
            new_status=request.status,
            notes=request.resolution_notes,
        )
        return updated
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/anomalies/{anomaly_id}/acknowledge",
    response_model=AnomalyResponse,
    summary="Acknowledge an anomaly",
)
async def acknowledge_anomaly(
    anomaly_id: uuid.UUID,
    notes: Optional[str] = Query(None, description="Optional acknowledgment notes"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """Shortcut to transition anomaly status to ACKNOWLEDGED."""
    try:
        return await DriftEngine.update_anomaly_status(
            db=db,
            organization_id=current_user.organization_id,
            anomaly_id=anomaly_id,
            new_status=AnomalyStatus.ACKNOWLEDGED,
            notes=notes,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post(
    "/anomalies/{anomaly_id}/resolve",
    response_model=AnomalyResponse,
    summary="Resolve an anomaly",
)
async def resolve_anomaly(
    anomaly_id: uuid.UUID,
    notes: Optional[str] = Query(None, description="Optional resolution notes"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)),
):
    """Shortcut to transition anomaly status to RESOLVED."""
    try:
        return await DriftEngine.update_anomaly_status(
            db=db,
            organization_id=current_user.organization_id,
            anomaly_id=anomaly_id,
            new_status=AnomalyStatus.RESOLVED,
            notes=notes,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

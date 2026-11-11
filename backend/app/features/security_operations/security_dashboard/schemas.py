import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class TimeRangePreset(str, Enum):
    DAYS_7 = "7d"
    DAYS_30 = "30d"
    DAYS_90 = "90d"
    CUSTOM = "custom"


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class DashboardFilterParams(BaseModel):
    time_range: Optional[str] = Field("30d", description="Preset time window (7d, 30d, 90d, custom)")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    application_id: Optional[uuid.UUID] = None
    severity: Optional[str] = None
    report_status: Optional[str] = None


class SecurityOverviewMetrics(BaseModel):
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    open_count: int
    fixed_count: int
    accepted_risk_count: int
    false_positive_count: int
    critical_and_high_open: int
    remediation_rate: float
    total_applications: int
    total_scans: int
    vulnerabilities_delta_pct: Optional[float] = None
    period_start: datetime
    period_end: datetime


class SeverityDistributionItem(BaseModel):
    severity: str
    count: int
    percentage: float
    open_count: int
    fixed_count: int


class SeverityDistributionResponse(BaseModel):
    total: int
    distribution: List[SeverityDistributionItem]


class VulnerabilityTrendPoint(BaseModel):
    date: str
    discovered: int
    resolved: int
    critical: int
    high: int
    medium: int
    low: int


class VulnerabilityTrendsResponse(BaseModel):
    trends: List[VulnerabilityTrendPoint]
    total_discovered: int
    total_resolved: int
    net_risk_change: int
    time_range: str


class ApplicationRiskItem(BaseModel):
    application_id: uuid.UUID
    name: str
    target_url: str
    risk_score: float
    risk_tier: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_count: int
    fixed_count: int
    last_scanned_at: Optional[datetime] = None


class ApplicationRiskResponse(BaseModel):
    total_applications: int
    vulnerable_applications_count: int
    risk_tier_distribution: Dict[str, int]
    top_exposed_applications: List[ApplicationRiskItem]


class ScanHistorySummary(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    status: str
    progress: float
    findings_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class ScanAnalyticsResponse(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    cancelled_scans: int
    success_rate: float
    average_duration_seconds: Optional[float] = None
    average_duration_formatted: str
    has_duration_data: bool
    recent_scans: List[ScanHistorySummary]


class AgeingBucket(BaseModel):
    under_7_days: int
    days_7_to_30: int
    days_30_to_90: int
    over_90_days: int


class RemediationAnalyticsResponse(BaseModel):
    mean_time_to_remediation_hours: Optional[float] = None
    mean_time_to_remediation_days: Optional[float] = None
    has_remediation_data: bool
    remediation_notes: Optional[str] = None
    open_vulnerabilities_ageing: AgeingBucket
    vulnerabilities_awaiting_remediation: int
    remediation_progress_percentage: float
    sla_breach_count: int


class RecentActivityItem(BaseModel):
    id: str
    timestamp: datetime
    activity_type: str
    severity: str
    title: str
    description: str
    actor_email: Optional[str] = None
    application_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RecentActivityResponse(BaseModel):
    activities: List[RecentActivityItem]
    total: int


import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ScanHistoryItem(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    target_url: str
    status: str
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    findings_count: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    notes: Optional[str] = None
    created_at: Optional[datetime] = None


class ScanHistoryListResponse(BaseModel):
    items: List[ScanHistoryItem]
    total: int
    page: int
    limit: int
    total_pages: int


class ScanFindingSummary(BaseModel):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: str
    severity: str
    status: str
    endpoint: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = 0.0
    recommendation: str = ""
    evidence_count: int = 0
    has_evidence: bool = False
    fingerprint: str
    created_at: Optional[datetime] = None


class ScanEvidenceSummary(BaseModel):
    id: uuid.UUID
    vulnerability_id: Optional[uuid.UUID] = None
    has_request_dump: bool = False
    has_response_dump: bool = False
    has_screenshot: bool = False
    screenshot_url: Optional[str] = None
    summary: Optional[str] = None


class ScanDetailResponse(BaseModel):
    scan: ScanHistoryItem
    vulnerabilities: List[ScanFindingSummary]
    evidence_items: List[ScanEvidenceSummary]


class VulnerabilityComparisonItem(BaseModel):
    fingerprint: str
    title: str
    endpoint: str
    cwe_id: Optional[str] = None
    comparison_status: str  # NEW, FIXED, PERSISTENT, REGRESSED, SEVERITY_CHANGED
    baseline_severity: Optional[str] = None
    comparison_severity: Optional[str] = None
    baseline_status: Optional[str] = None
    comparison_status_val: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    recommendation: Optional[str] = None
    has_evidence: bool = False


class ScanComparisonRequest(BaseModel):
    baseline_scan_id: uuid.UUID
    comparison_scan_id: uuid.UUID
    save_record: bool = False


class ScanComparisonSummary(BaseModel):
    baseline_scan_id: uuid.UUID
    comparison_scan_id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    target_url: str
    baseline_completed_at: Optional[datetime] = None
    comparison_completed_at: Optional[datetime] = None
    baseline_total: int = 0
    comparison_total: int = 0
    new_count: int = 0
    fixed_count: int = 0
    persistent_count: int = 0
    regressed_count: int = 0
    severity_increased_count: int = 0
    severity_decreased_count: int = 0
    net_finding_change: int = 0
    posture_change: str  # IMPROVED, DEGRADED, UNCHANGED
    posture_explanation: str
    baseline_severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    comparison_severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    comparison_items: List[VulnerabilityComparisonItem] = Field(default_factory=list)


class ApplicationFilterOption(BaseModel):
    id: uuid.UUID
    name: str
    target_url: str
    total_scans: int

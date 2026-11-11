export type ScanStatusType = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PAUSED' | 'CANCELLED';

export type VulnerabilitySeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ComparisonStatusType = 'NEW' | 'FIXED' | 'PERSISTENT' | 'REGRESSED' | 'SEVERITY_CHANGED';

export type PostureVerdict = 'IMPROVED' | 'DEGRADED' | 'UNCHANGED';

export interface ScanHistoryItem {
  id: string;
  organization_id: string;
  application_id: string;
  application_name: string;
  target_url: string;
  status: ScanStatusType;
  progress: number;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  findings_count: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  notes?: string | null;
  created_at?: string | null;
}

export interface ScanHistoryListResponse {
  items: ScanHistoryItem[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface ScanFindingSummary {
  id: string;
  scan_id?: string | null;
  title: string;
  severity: VulnerabilitySeverityType;
  status: string;
  endpoint: string;
  cwe_id?: string | null;
  cvss_score?: number | null;
  confidence: number;
  recommendation: string;
  evidence_count: number;
  has_evidence: boolean;
  fingerprint: string;
  created_at?: string | null;
}

export interface ScanEvidenceSummary {
  id: string;
  vulnerability_id?: string | null;
  has_request_dump: boolean;
  has_response_dump: boolean;
  has_screenshot: boolean;
  screenshot_url?: string | null;
  summary?: string | null;
}

export interface ScanDetailResponse {
  scan: ScanHistoryItem;
  vulnerabilities: ScanFindingSummary[];
  evidence_items: ScanEvidenceSummary[];
}

export interface VulnerabilityComparisonItem {
  fingerprint: string;
  title: string;
  endpoint: string;
  cwe_id?: string | null;
  comparison_status: ComparisonStatusType;
  baseline_severity?: VulnerabilitySeverityType | null;
  comparison_severity?: VulnerabilitySeverityType | null;
  baseline_status?: string | null;
  comparison_status_val?: string | null;
  cvss_score?: number | null;
  confidence?: number | null;
  recommendation?: string | null;
  has_evidence: boolean;
}

export interface ScanComparisonSummary {
  baseline_scan_id: string;
  comparison_scan_id: string;
  application_id: string;
  application_name: string;
  target_url: string;
  baseline_completed_at?: string | null;
  comparison_completed_at?: string | null;
  baseline_total: number;
  comparison_total: number;
  new_count: number;
  fixed_count: number;
  persistent_count: number;
  regressed_count: number;
  severity_increased_count: number;
  severity_decreased_count: number;
  net_finding_change: number;
  posture_change: PostureVerdict;
  posture_explanation: string;
  baseline_severity_breakdown: Record<string, number>;
  comparison_severity_breakdown: Record<string, number>;
  comparison_items: VulnerabilityComparisonItem[];
}

export interface ApplicationFilterOption {
  id: string;
  name: string;
  target_url: string;
  total_scans: number;
}

export interface ScanHistoryFilterParams {
  application_id?: string;
  status?: string;
  search?: string;
  start_date?: string;
  end_date?: string;
  sort_by?: 'created_at' | 'started_at' | 'completed_at' | 'findings_count';
  order?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

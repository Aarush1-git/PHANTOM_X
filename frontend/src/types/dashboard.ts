export interface DashboardFilterParams {
  time_range?: "7d" | "30d" | "90d" | "custom";
  start_date?: string;
  end_date?: string;
  application_id?: string;
  severity?: string;
  report_status?: string;
}

export interface SecurityOverviewMetrics {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  open_count: number;
  fixed_count: number;
  accepted_risk_count: number;
  false_positive_count: number;
  critical_and_high_open: number;
  remediation_rate: number;
  total_applications: number;
  total_scans: number;
  vulnerabilities_delta_pct?: number | null;
  period_start: string;
  period_end: string;
}

export interface SeverityDistributionItem {
  severity: string;
  count: number;
  percentage: number;
  open_count: number;
  fixed_count: number;
}

export interface SeverityDistributionResponse {
  total: number;
  distribution: SeverityDistributionItem[];
}

export interface VulnerabilityTrendPoint {
  date: string;
  discovered: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface VulnerabilityTrendsResponse {
  trends: VulnerabilityTrendPoint[];
  total_discovered: number;
  total_resolved: number;
  net_risk_change: number;
  time_range: string;
}

export interface ApplicationRiskItem {
  application_id: string;
  name: string;
  target_url: string;
  risk_score: number;
  risk_tier: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN";
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  open_count: number;
  fixed_count: number;
  last_scanned_at?: string | null;
}

export interface ApplicationRiskResponse {
  total_applications: number;
  vulnerable_applications_count: number;
  risk_tier_distribution: Record<string, number>;
  top_exposed_applications: ApplicationRiskItem[];
}

export interface ScanHistorySummary {
  id: string;
  application_id: string;
  application_name: string;
  status: string;
  progress: number;
  findings_count: number;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
}

export interface ScanAnalyticsResponse {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  running_scans: number;
  cancelled_scans: number;
  success_rate: number;
  average_duration_seconds?: number | null;
  average_duration_formatted: string;
  has_duration_data: boolean;
  recent_scans: ScanHistorySummary[];
}

export interface AgeingBucket {
  under_7_days: number;
  days_7_to_30: number;
  days_30_to_90: number;
  over_90_days: number;
}

export interface RemediationAnalyticsResponse {
  mean_time_to_remediation_hours?: number | null;
  mean_time_to_remediation_days?: number | null;
  has_remediation_data: boolean;
  remediation_notes?: string | null;
  open_vulnerabilities_ageing: AgeingBucket;
  vulnerabilities_awaiting_remediation: number;
  remediation_progress_percentage: number;
  sla_breach_count: number;
}

export interface RecentActivityItem {
  id: string;
  timestamp: string;
  activity_type: string;
  severity: string;
  title: string;
  description: string;
  actor_email?: string | null;
  application_name?: string | null;
  metadata: Record<string, any>;
}

export interface RecentActivityResponse {
  activities: RecentActivityItem[];
  total: number;
}

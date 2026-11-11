export type BaselineStatusType =
  | 'PENDING_VERIFICATION'
  | 'VERIFIED'
  | 'REGRESSION_DETECTED'
  | 'SUPERSEDED'
  | 'RETIRED';

export type RegressionStatusType = 'REGRESSION_DETECTED' | 'STILL_PROTECTED' | 'INCONCLUSIVE';

export type MatchQualityType =
  | 'EXACT_FINGERPRINT'
  | 'HIGH_CONFIDENCE'
  | 'AMBIGUOUS_ENDPOINT'
  | 'AMBIGUOUS_TITLE'
  | 'NO_MATCH';

export type SeverityChangeType = 'INCREASED' | 'DECREASED' | 'UNCHANGED' | 'NONE';

export interface SecurityBaseline {
  id: string;
  organization_id: string;
  application_id: string;
  application_name?: string | null;
  source_scan_id?: string | null;
  verification_scan_id?: string | null;
  original_vulnerability_id?: string | null;
  vulnerability_fingerprint: string;
  title: string;
  category?: string | null;
  cwe_id?: string | null;
  endpoint: string;
  http_method: string;
  severity: string;
  status: BaselineStatusType | string;
  verification_timestamp?: string | null;
  verification_status: string;
  verification_reason?: string | null;
  evidence_references: Record<string, any>;
  notes?: string | null;
  is_retired: boolean;
  retired_at?: string | null;
  retired_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface BaselineVerifyRequest {
  vulnerability_id: string;
  verification_scan_id: string;
  notes?: string;
}

export interface BaselineVerifyResponse {
  baseline?: SecurityBaseline | null;
  verification_status: 'VERIFIED' | 'FAILED' | string;
  reason: string;
}

export interface BaselineListResponse {
  items: SecurityBaseline[];
  total: number;
  page: number;
  limit: number;
}

export interface RegressionRecord {
  id: string;
  organization_id: string;
  application_id: string;
  application_name?: string | null;
  baseline_id: string;
  baseline_title?: string | null;
  baseline_endpoint?: string | null;
  scan_id: string;
  scan_notes?: string | null;
  reappeared_vulnerability_id?: string | null;
  status: RegressionStatusType | string;
  match_quality: MatchQualityType | string;
  confidence_score: number;
  original_severity: string;
  new_severity?: string | null;
  severity_change?: SeverityChangeType | string | null;
  first_observed_at: string;
  evidence_references: Record<string, any>;
  explanation: string;
  remediation_notes?: string | null;
  is_resolved: boolean;
  resolved_at?: string | null;
  created_at: string;
}

export interface RegressionListResponse {
  items: RegressionRecord[];
  total: number;
  page: number;
  limit: number;
}

export interface ScanEvaluationResponse {
  scan_id: string;
  application_id: string;
  application_name: string;
  baselines_evaluated: number;
  regressions_detected: number;
  still_protected: number;
  inconclusive: number;
  results: RegressionRecord[];
}

export type TimelineEventType =
  | 'DISCOVERY'
  | 'REPORT_STATUS_CHANGE'
  | 'FIX_DECLARED'
  | 'VERIFICATION_SCAN'
  | 'BASELINE_CREATED'
  | 'BASELINE_VERIFIED'
  | 'REGRESSION_DETECTED'
  | 'BASELINE_RETIRED'
  | 'RE_VERIFIED';

export interface SecurityTimelineEvent {
  id: string;
  event_type: TimelineEventType | string;
  timestamp: string;
  title: string;
  description: string;
  severity?: string | null;
  status?: string | null;
  metadata: Record<string, any>;
}

export interface SecurityTimelineResponse {
  application_id: string;
  application_name: string;
  events: SecurityTimelineEvent[];
  total_events: number;
}

export interface TimeTravelOverviewResponse {
  total_baselines: number;
  verified_baselines: number;
  active_baselines: number;
  retired_baselines: number;
  regressions_detected: number;
  inconclusive_evaluations: number;
  affected_applications_count: number;
  recent_regressions: RegressionRecord[];
}

export interface TimeTravelFilterParams {
  application_id?: string;
  status?: string;
  severity?: string;
  is_retired?: boolean;
  search?: string;
  page?: number;
  limit?: number;
}

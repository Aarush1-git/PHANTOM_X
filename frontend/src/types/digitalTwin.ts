export type BaselineStatus = "DRAFT" | "ACTIVE" | "SUPERSEDED" | "ARCHIVED";
export type AnomalyStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
export type AnomalySeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AnomalyType =
  | "UNEXPECTED_STATUS_CODE"
  | "SCHEMA_DRIFT"
  | "UNSEEN_SEQUENCE"
  | "UNAUTHORIZED_ROLE_HOP"
  | "LATENCY_SPIKE"
  | string;

export interface LatencyStats {
  min_ms: number;
  max_ms: number;
  avg_ms: number;
  p95_ms: number;
}

export interface EndpointProfile {
  method?: string;
  normalized_path?: string;
  endpoint_id?: string | null;
  total_requests: number;
  status_code_distribution: Record<string, number>;
  latency_stats: LatencyStats;
  inferred_request_schema: Record<string, any>;
  inferred_response_schema: Record<string, any>;
  confidence_score: number;
}

export interface BehavioralObservation {
  id: string;
  organization_id: string;
  application_id: string;
  endpoint_id?: string | null;
  method: string;
  normalized_path: string;
  status_code: number;
  sanitized_request_schema: Record<string, any>;
  sanitized_response_schema: Record<string, any>;
  latency_ms: number;
  session_token_hash?: string | null;
  observed_at: string;
  created_at: string;
}

export interface BehavioralBaseline {
  id: string;
  organization_id: string;
  application_id: string;
  version: string;
  status: BaselineStatus;
  sample_count: number;
  confidence_score: number;
  endpoint_profiles: Record<string, EndpointProfile>;
  transition_matrix: Record<string, Record<string, number>>;
  created_at: string;
  activated_at?: string | null;
}

export interface BehavioralAnomalyResponse {
  id: string;
  organization_id: string;
  application_id: string;
  baseline_id?: string | null;
  endpoint_id?: string | null;
  anomaly_type: AnomalyType;
  severity: AnomalySeverity;
  confidence: number;
  evidence_data: Record<string, any>;
  status: AnomalyStatus;
  detected_at: string;
  resolved_at?: string | null;
}

export interface DigitalTwinOverviewResponse {
  application_id: string;
  organization_id: string;
  total_observations: number;
  active_baseline_id?: string | null;
  active_baseline_version?: string | null;
  active_baseline_confidence: number;
  total_transitions_tracked: number;
  open_anomalies_count: number;
  last_observed_at?: string | null;
  endpoint_profiles: Record<string, EndpointProfile>;
  latest_anomalies: BehavioralAnomalyResponse[];
}

export interface BaselineListResponse {
  items: BehavioralBaseline[];
  total: number;
}

export interface AnomalyListResponse {
  items: BehavioralAnomalyResponse[];
  total: number;
  page: number;
  limit: number;
}

export interface ObservationListResponse {
  items: BehavioralObservation[];
  total: number;
  page: number;
  limit: number;
}

export interface BaselineCompileRequest {
  application_id: string;
  version?: string;
  start_time?: string;
  end_time?: string;
  min_samples?: number;
}

export interface DriftEvaluationResponse {
  application_id: string;
  baseline_id?: string | null;
  evaluated_observations_count: number;
  new_anomalies_detected: number;
  anomalies: BehavioralAnomalyResponse[];
}

export interface AnomalyFilterParams {
  application_id: string;
  status?: AnomalyStatus;
  anomaly_type?: string;
  severity?: string;
  page?: number;
  limit?: number;
}

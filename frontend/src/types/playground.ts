export interface ScenarioInfo {
  id: string;
  name: string;
  category: string;
  description: string;
  security_objective: string;
  preconditions: string[];
  required_authorization: string;
  expected_secure_behavior: string;
  potential_vulnerability_indicators: string[];
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  execution_constraints: {
    rate_limit_rps?: number;
    allow_destructive?: boolean;
    safe_read_only?: boolean;
    [key: string]: any;
  };
  target_endpoints: string[];
  sample_payload?: Record<string, any> | null;
  is_synthetic_compatible: boolean;
}

export interface ScenarioListResponse {
  scenarios: ScenarioInfo[];
  categories: string[];
  total: number;
}

export interface PlaygroundTargetInfo {
  id: string;
  name: string;
  target_url: string;
  target_type: 'SYNTHETIC_TARGET' | 'AUTHORIZED_APPLICATION';
  is_synthetic: boolean;
  scope_status?: string | null;
  authorization_status?: string | null;
  description?: string | null;
}

export interface PlaygroundSessionCreate {
  application_id: string;
  scenario_id: string;
  notes?: string;
}

export interface PlaygroundAuthorizeRequest {
  notes?: string;
}

export interface PlaygroundExecutionPlan {
  target_url: string;
  endpoint: string;
  http_method: string;
  payload_preview: Record<string, any>;
  safety_classification: string;
  rate_limit_rps: number;
  max_concurrency: number;
  is_synthetic: boolean;
  safety_restrictions: string[];
}

export interface PlaygroundSession {
  id: string;
  organization_id: string;
  application_id: string;
  application_name?: string | null;
  parent_session_id?: string | null;
  scenario_id: string;
  scenario_name: string;
  scenario_category: string;
  target_type: 'SYNTHETIC_TARGET' | 'AUTHORIZED_APPLICATION';
  status: 'READY' | 'AWAITING_AUTHORIZATION' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'BLOCKED';
  security_result?: 'VULNERABILITY_CONFIRMED' | 'SECURE_BEHAVIOR_CONFIRMED' | 'INCONCLUSIVE' | 'BLOCKED_BY_POLICY' | 'EXECUTION_FAILED' | null;
  is_authorized: boolean;
  authorized_by?: string | null;
  authorizer_role?: string | null;
  authorized_at?: string | null;
  execution_plan: PlaygroundExecutionPlan;
  execution_results: Record<string, any>;
  evidence_references: Record<string, any>;
  safety_decisions: Record<string, any>;
  duration_seconds?: number | null;
  notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PlaygroundSessionListResponse {
  items: PlaygroundSession[];
  total: number;
  page: number;
  limit: number;
}

export interface PlaygroundResult {
  session_id: string;
  scenario_id: string;
  scenario_name: string;
  target_application: string;
  target_url: string;
  execution_status: string;
  security_result: 'VULNERABILITY_CONFIRMED' | 'SECURE_BEHAVIOR_CONFIRMED' | 'INCONCLUSIVE' | 'BLOCKED_BY_POLICY' | 'EXECUTION_FAILED';
  vulnerability_category: string;
  severity?: string | null;
  expected_behavior: string;
  observed_behavior: string;
  evidence_references: {
    request_dump?: string;
    response_dump?: string;
    target_endpoint?: string;
    is_synthetic?: boolean;
    violation_category?: string;
    policy_reason?: string;
    [key: string]: any;
  };
  duration_seconds: number;
  safety_decisions: {
    allowed?: boolean;
    violation_category?: string | null;
    reason?: string;
    [key: string]: any;
  };
  recommended_next_step: string;
  is_synthetic: boolean;
  previous_result_comparison?: {
    previous_session_id: string;
    previous_security_result: string;
    previous_duration_seconds?: number;
    result_changed: boolean;
    regression_detected: boolean;
  } | null;
}

// PHANTOM-X Shared TypeScript Contracts
// Matching Pydantic Schemas in shared/contracts/models.py

export type UserRole = "ADMIN" | "SECURITY_ENGINEER" | "DEVELOPER" | "AUDITOR";

export type ExecutionMode = "OBSERVE" | "ACTIVE_VERIFY" | "ATTACK_SIMULATION";

export type SafetyClassification =
  | "SAFE_READ_ONLY"
  | "LOW_RISK_PROBE"
  | "STATE_MODIFYING"
  | "HIGH_RISK_DESTRUCTIVE";

export type ScanStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "PAUSED"
  | "CANCELLED";

export type SecurityTestStatus =
  | "PENDING"
  | "APPROVED"
  | "RUNNING"
  | "PASSED"
  | "FAILED"
  | "BLOCKED"
  | "SKIPPED";

export type VulnerabilitySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type VulnerabilityStatus =
  | "DISCOVERED"
  | "VERIFYING"
  | "VERIFIED"
  | "FALSE_POSITIVE"
  | "MITIGATED"
  | "RESOLVED";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD";

export type EndpointRiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNASSESSED";

export type AttackChainSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type RegressionTestStatus = "PASSED" | "REGRESSED" | "ERROR" | "SKIPPED";

// ==============================================================================
// 1. APPLICATION
// ==============================================================================

export interface ApplicationCreate {
  name: string;
  description?: string;
  target_url: string;
  environment_name?: string;
  organization_id?: string;
}

export interface ApplicationUpdate {
  name?: string;
  description?: string;
  target_url?: string;
  risk_score?: number;
  status?: string;
}

export interface ApplicationResponse {
  id: string;
  organization_id: string;
  name: string;
  description?: string;
  target_url: string;
  risk_score: number;
  status: string;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 2. SCAN
// ==============================================================================

export interface ScanCreate {
  application_id: string;
  configuration_id?: string;
  mode?: ExecutionMode;
  notes?: string;
}

export interface ScanProgress {
  scan_id: string;
  status: ScanStatus;
  percent_complete: number;
  current_phase: string;
  discovered_endpoints_count: number;
  executed_tests_count: number;
  findings_count: number;
  timestamp: string;
}

export interface ScanResponse {
  id: string;
  organization_id: string;
  application_id: string;
  configuration_id?: string;
  status: ScanStatus;
  progress: number;
  findings_count: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 3. DISCOVERED ENDPOINT
// ==============================================================================

export interface EndpointParameter {
  name: string;
  location: "query" | "path" | "header" | "body" | string;
  param_type: string;
  required: boolean;
  example?: unknown;
}

export interface EndpointAuthentication {
  auth_type: "NONE" | "BEARER" | "BASIC" | "COOKIE" | "API_KEY" | string;
  header_name?: string;
  roles_permitted: string[];
}

export interface EndpointCreate {
  application_id: string;
  path: string;
  method: HttpMethod;
  auth_required?: boolean;
  parameters?: EndpointParameter[];
  authentication?: EndpointAuthentication;
  response_codes?: number[];
  risk_level?: EndpointRiskLevel;
}

export interface EndpointResponse {
  id: string;
  application_id: string;
  path: string;
  method: HttpMethod;
  auth_required: boolean;
  parameters: Record<string, unknown>[];
  response_codes: number[];
  risk_level: EndpointRiskLevel;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 4. ATTACK PLAN
// ==============================================================================

export interface AttackScenario {
  scenario_id: string;
  name: string;
  category: string;
  target_endpoint: string;
  method: HttpMethod;
  hypothesis: string;
  safety_classification: SafetyClassification;
  preconditions: string[];
}

export interface AttackPlanRequest {
  scan_id: string;
  application_id: string;
  risk_appetite?: "LOW" | "MEDIUM" | "HIGH";
}

export interface AttackPlanResponse {
  id: string;
  scan_id: string;
  application_id: string;
  status: "DRAFT" | "APPROVED" | "REJECTED" | "EXECUTED";
  scenarios: AttackScenario[];
  approved_by?: string;
  approved_at?: string;
  created_at: string;
}

// ==============================================================================
// 5. SECURITY TEST
// ==============================================================================

export interface SecurityTestRequest {
  plan_id: string;
  endpoint_id: string;
  test_category: string;
  test_parameters?: Record<string, unknown>;
  safety_classification?: SafetyClassification;
}

export interface SecurityTestResponse {
  id: string;
  plan_id: string;
  endpoint_id: string;
  test_category: string;
  test_parameters: Record<string, unknown>;
  safety_classification: SafetyClassification;
  status: SecurityTestStatus;
  result_summary?: string;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 6. EVIDENCE
// ==============================================================================

export interface EvidenceCreate {
  vulnerability_id?: string;
  test_id?: string;
  request_dump: string;
  response_dump: string;
  proof_data?: Record<string, unknown>;
  screenshot_url?: string;
  har_entry?: Record<string, unknown>;
}

export interface EvidenceResponse {
  id: string;
  vulnerability_id?: string;
  test_id?: string;
  request_dump: string;
  response_dump: string;
  proof_data: Record<string, unknown>;
  screenshot_url?: string;
  created_at: string;
}

// ==============================================================================
// 7. VULNERABILITY
// ==============================================================================

export interface VulnerabilityCreate {
  application_id: string;
  scan_id?: string;
  test_id?: string;
  title: string;
  severity: VulnerabilitySeverity;
  status?: VulnerabilityStatus;
  endpoint: string;
  confidence?: number;
  recommendation: string;
  cwe_id?: string;
  cvss_score?: number;
}

export interface VulnerabilityResponse {
  id: string;
  organization_id: string;
  application_id: string;
  scan_id?: string;
  test_id?: string;
  title: string;
  severity: VulnerabilitySeverity;
  status: VulnerabilityStatus;
  endpoint: string;
  confidence: number;
  recommendation: string;
  cwe_id?: string;
  cvss_score?: number;
  evidence?: EvidenceResponse[];
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 8. ATTACK CHAIN
// ==============================================================================

export interface AttackChainNode {
  id: string;
  label: string;
  step_type: string;
  endpoint?: string;
  vulnerability_id?: string;
  severity: VulnerabilitySeverity;
}

export interface AttackChainEdge {
  id: string;
  source: string;
  target: string;
  description: string;
}

export interface AttackChainResponse {
  id: string;
  application_id: string;
  scan_id?: string;
  title: string;
  description: string;
  severity: AttackChainSeverity;
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
  is_verified: boolean;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 9. REGRESSION
// ==============================================================================

export interface RegressionTestRequest {
  vulnerability_id: string;
  application_id: string;
  trigger_reason?: string;
}

export interface RegressionResult {
  id: string;
  vulnerability_id: string;
  application_id: string;
  status: RegressionTestStatus;
  last_run_at: string;
  result_summary: string;
  is_reintroduced: boolean;
  created_at: string;
}

// ==============================================================================
// 10. AUDIT & SAFETY
// ==============================================================================

export interface AuditLogResponse {
  id: string;
  organization_id: string;
  user_id?: string;
  action: string;
  target_type: string;
  target_id?: string;
  details: Record<string, unknown>;
  ip_address?: string;
  created_at: string;
}

export interface ScopePermissionResponse {
  id: string;
  organization_id: string;
  application_id: string;
  host_pattern: string;
  allowed_methods: string[];
  rate_limit_rps: number;
  is_destructive_allowed: boolean;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 11. AUTHENTICATION & USER
// ==============================================================================

export interface UserLogin {
  email: string;
  password: string;
}

export interface UserResponse {
  id: string;
  organization_id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user_id: string;
  email: string;
  role: UserRole;
}

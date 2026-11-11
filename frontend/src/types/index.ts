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
  sequence_number?: number;
  user_id?: string;
  actor_email?: string;
  actor_role?: string;
  application_id?: string;
  scan_id?: string;
  category?: string;
  event_type?: string;
  action: string;
  status?: string;
  severity?: string;
  source_module?: string;
  target_type: string;
  target_id?: string;
  details: Record<string, unknown>;
  ip_address?: string;
  correlation_id?: string;
  event_hash?: string;
  prev_event_hash?: string;
  created_at: string;
  updated_at?: string;
}

// Feature 25: Audit Logs & Execution History Types
export type AuditCategory =
  | "AUTHENTICATION"
  | "APPLICATION_MANAGEMENT"
  | "AUTHORIZATION"
  | "SECURITY_TESTING"
  | "VULNERABILITY"
  | "PLATFORM";

export interface AuditOverviewResponse {
  total_events: number;
  successful_events: number;
  failed_events: number;
  blocked_events: number;
  critical_events: number;
  categories_breakdown: Record<string, number>;
  generated_at: string;
}

export interface AuditIntegrityVerificationResponse {
  is_intact: boolean;
  records_checked: number;
  anomalies: string[];
  broken_event_ids: string[];
  verified_at: string;
  genesis_event_id?: string;
  latest_event_id?: string;
  chain_head_hash?: string;
}

export interface ScanLifecycleEvent {
  status: string;
  timestamp: string;
  note?: string;
  details?: Record<string, unknown>;
}

export interface ScanExecutionRecordResponse {
  id: string;
  organization_id: string;
  scan_id: string;
  application_id: string;
  initiating_user_id?: string;
  initiating_user?: string;
  start_time?: string;
  end_time?: string;
  duration_seconds?: number;
  final_status: string;
  tests_executed: number;
  tests_blocked: number;
  verified_findings: number;
  failure_reason?: string;
  lifecycle_events: ScanLifecycleEvent[];
  created_at: string;
  updated_at: string;
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

// Feature 26: Scope, Permission & Safety Management Types
export type ScopeStatus = "DRAFT" | "ACTIVE" | "SUSPENDED" | "EXPIRED";
export type AuthorizationStatus = "PENDING" | "AUTHORIZED" | "REVOKED" | "EXPIRED";

export interface ScopePolicyBase {
  target_domain: string;
  base_url: string;
  permitted_paths: string[];
  excluded_paths: string[];
  rate_limit_rps: number;
  max_concurrency: number;
  max_scan_duration_minutes: number;
  allowed_methods: string[];
  restricted_endpoint_patterns: string[];
  require_synthetic_auth: boolean;
  allow_destructive: boolean;
}

export interface ScopePolicyCreate extends ScopePolicyBase {
  application_id?: string;
}

export interface ScopePolicyUpdate {
  target_domain?: string;
  base_url?: string;
  permitted_paths?: string[];
  excluded_paths?: string[];
  rate_limit_rps?: number;
  max_concurrency?: number;
  max_scan_duration_minutes?: number;
  allowed_methods?: string[];
  restricted_endpoint_patterns?: string[];
  require_synthetic_auth?: boolean;
  allow_destructive?: boolean;
  scope_status?: ScopeStatus;
}

export interface ScopePolicyResponse extends ScopePolicyBase {
  id: string;
  organization_id: string;
  application_id: string;
  application_name?: string;
  scope_status: ScopeStatus;
  authorization_status: AuthorizationStatus;
  authorized_by?: string;
  authorizer_role?: string;
  authorization_notes?: string;
  valid_from?: string;
  valid_until?: string;
  created_at: string;
  updated_at: string;
}

export interface ScopeAuthorizeRequest {
  authorized_by: string;
  authorizer_role: string;
  valid_days: number;
  authorization_notes?: string;
}

export interface ScopeSuspendRequest {
  reason: string;
}

export interface ScopeRevokeRequest {
  reason: string;
}

export interface TestValidationRequest {
  application_id?: string;
  target_url: string;
  http_method?: string;
  payload_sample?: string;
  source_agent?: string;
  dry_run?: boolean;
}

export interface TestValidationResult {
  is_allowed: boolean;
  violation_category?: string;
  reason: string;
  application_id?: string;
  target_url: string;
  http_method: string;
  checked_at: string;
}

export interface BlockedExecutionResponse {
  id: string;
  organization_id: string;
  application_id?: string;
  application_name?: string;
  target_url: string;
  http_method: string;
  violation_category: string;
  blocked_reason: string;
  payload_sample?: string;
  source_agent?: string;
  client_ip?: string;
  created_at: string;
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

// ==============================================================================
// 12. FEATURE 21: VULNERABILITY REPORTS
// ==============================================================================

export type ReportLifecycleStatus =
  | "OPEN"
  | "IN_PROGRESS"
  | "FIXED"
  | "ACCEPTED_RISK"
  | "FALSE_POSITIVE"
  | "REOPENED";

export interface StatusHistoryItem {
  id: string;
  report_id: string;
  organization_id: string;
  from_status: string;
  to_status: string;
  changed_by_user_id?: string;
  changed_by_email?: string;
  reason?: string;
  created_at: string;
}

export interface SanitizedEvidenceItem {
  id: string;
  request_dump: string;
  response_dump: string;
  proof_data: Record<string, any>;
  screenshot_url?: string;
  har_entry?: Record<string, any>;
  created_at?: string;
}

export interface VulnerabilityReportListItem {
  id: string;
  report_id: string;
  vulnerability_id: string;
  application_id: string;
  application_name?: string;
  scan_id?: string;
  title: string;
  severity: VulnerabilitySeverity;
  status: ReportLifecycleStatus;
  cvss_score?: number;
  cwe_id?: string;
  endpoint: string;
  http_method: string;
  business_impact: string;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityReportDetail {
  id: string;
  report_id: string;
  organization_id: string;
  vulnerability_id: string;
  application_id: string;
  application_name?: string;
  scan_id?: string;
  title: string;
  severity: VulnerabilitySeverity;
  status: ReportLifecycleStatus;
  cvss_score?: number;
  cwe_id?: string;
  endpoint: string;
  http_method: string;
  technical_details: Record<string, any>;
  expected_behavior: string;
  actual_behavior: string;
  business_impact: string;
  reproduction_steps: string[];
  remediation_advice: string;
  evidence_summary: Record<string, any>;
  evidences: SanitizedEvidenceItem[];
  status_history: StatusHistoryItem[];
  created_at: string;
  updated_at: string;
}

export interface ReportStatusUpdateRequest {
  new_status: ReportLifecycleStatus;
  reason?: string;
}

export interface ReportDashboardMetrics {
  total_reports: number;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  critical_and_high_open: number;
  remediation_rate: number;
  total_applications: number;
  total_scans: number;
}

export interface ReportListPagination {
  items: VulnerabilityReportListItem[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}


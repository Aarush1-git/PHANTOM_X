export type WorkflowType = "STANDARD" | "BRANCHED" | "ABANDONED" | "CYCLIC";
export type WorkflowStatus = "DISCOVERED" | "ACTIVE" | "ARCHIVED";
export type StepType = "ENTRY" | "INTERMEDIATE" | "TERMINAL" | "DROPOUT";

export interface WorkflowStep {
  step_index: number;
  method: string;
  normalized_path: string;
  endpoint_id?: string | null;
  step_type: StepType;
  avg_latency_ms: number;
  error_rate: number;
  sample_count: number;
  observation_ids: string[];
}

export interface WorkflowNode {
  id: string;
  label: string;
  method: string;
  normalized_path: string;
  step_type: StepType;
  endpoint_id?: string | null;
  observation_count: number;
  avg_latency_ms: number;
  error_rate: number;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  transition_count: number;
  probability: number;
  confidence: number;
}

export interface WorkflowGraph {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
}

export interface DiscoveredWorkflow {
  id: string;
  organization_id: string;
  application_id: string;
  name: string;
  description?: string | null;
  workflow_type: WorkflowType;
  status: WorkflowStatus;
  confidence_score: number;
  sample_count: number;
  step_count: number;
  is_incomplete: boolean;
  dropout_step_index?: number | null;
  steps_sequence: WorkflowStep[];
  discovered_at: string;
  last_observed_at: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveredWorkflowDetail extends DiscoveredWorkflow {
  graph_data: WorkflowGraph;
  variations: Record<string, unknown>;
}

export interface DiscoveredWorkflowListResponse {
  items: DiscoveredWorkflow[];
  total: number;
  page: number;
  page_size: number;
}

export interface WorkflowDiscoveryRequest {
  since?: string | null;
  until?: string | null;
  min_confidence?: number;
  min_sample_count?: number;
}

export interface WorkflowDiscoveryResult {
  application_id: string;
  discovered_count: number;
  analyzed_sessions_count: number;
  analyzed_observations_count: number;
  insufficient_data: boolean;
  insufficient_data_reason?: string | null;
  workflows: DiscoveredWorkflow[];
}

export interface WorkflowEvidenceItem {
  observation_id: string;
  session_token_hash?: string | null;
  method: string;
  normalized_path: string;
  status_code: number;
  latency_ms: number;
  observed_at: string;
  sanitized_request_schema: Record<string, unknown>;
  sanitized_response_schema: Record<string, unknown>;
}

export interface WorkflowEvidenceListResponse {
  workflow_id: string;
  step_index?: number | null;
  total_evidence: number;
  items: WorkflowEvidenceItem[];
}

export interface WorkflowOverview {
  application_id: string;
  total_workflows: number;
  active_workflows: number;
  incomplete_workflows: number;
  branched_workflows: number;
  average_steps: number;
  high_confidence_count: number;
  total_observed_sessions: number;
  insufficient_data: boolean;
}

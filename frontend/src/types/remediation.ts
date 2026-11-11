export type RemediationPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type RecommendationStatus =
  | 'GENERATED'
  | 'REVIEWED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'IN_PROGRESS'
  | 'VERIFIED'
  | 'DEFERRED';

export type VerificationStatus = 'UNVERIFIED' | 'VERIFIED' | 'PERSISTENT' | 'INCONCLUSIVE';

export interface PriorityFactor {
  factor: string;
  points: number;
  reason: string;
}

export interface RemediationRecommendationBase {
  id: string;
  organization_id: string;
  application_id: string;
  vulnerability_id: string;
  scan_id?: string | null;
  title: string;
  category: string;
  cwe_id?: string | null;
  severity: string;
  calculated_priority: RemediationPriority;
  risk_score: number;
  status: RecommendationStatus;
  endpoint?: string | null;
  http_method?: string | null;
  estimated_effort?: string | null;
  suggested_playground_scenario_id?: string | null;
  assigned_to?: string | null;
  verification_status: VerificationStatus;
  created_at: string;
  updated_at: string;
}

export interface RemediationRecommendationListItem extends RemediationRecommendationBase {
  why_it_matters_summary?: string | null;
}

export interface RemediationRecommendationDetail extends RemediationRecommendationBase {
  priority_rationale: PriorityFactor[];
  why_it_matters: string;
  potential_business_impact: string;
  remediation_steps: string[];
  suggested_fix_snippet?: string | null;
  validation_steps: string[];
  missing_information_notes?: string | null;
  decision_notes?: string | null;
  deferred_reason?: string | null;
  verification_evidence: Record<string, any>;
  verified_at?: string | null;
  verified_by?: string | null;
}

export interface RecommendationHistoryItem {
  id: string;
  recommendation_id: string;
  from_status: string;
  to_status: string;
  actor_email?: string | null;
  actor_role?: string | null;
  notes?: string | null;
  created_at: string;
}

export interface RecommendationListResponse {
  items: RemediationRecommendationListItem[];
  total: number;
  page: number;
  size: number;
}

export interface RecommendationGenerateRequest {
  application_id: string;
  vulnerability_id?: string | null;
  scan_id?: string | null;
}

export interface RecommendationGenerateResponse {
  generated_count: number;
  updated_count: number;
  recommendations: RemediationRecommendationListItem[];
}

export interface RecommendationStatusUpdateRequest {
  status: RecommendationStatus;
  notes?: string | null;
  deferred_reason?: string | null;
  assigned_to?: string | null;
}

export interface RecommendationNotesUpdateRequest {
  notes?: string | null;
  assigned_to?: string | null;
}

export interface RecommendationVerifyRequest {
  verification_scan_id?: string | null;
  playground_session_id?: string | null;
  notes?: string | null;
}

export interface RecommendationVerifyResponse {
  recommendation_id: string;
  previous_status: string;
  new_status: string;
  verification_status: VerificationStatus;
  is_verified: boolean;
  message: string;
  evidence_details: Record<string, any>;
  verified_at?: string | null;
}

export interface PriorityCountBreakdown {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFORMATIONAL: number;
}

export interface StatusCountBreakdown {
  GENERATED: number;
  REVIEWED: number;
  ACCEPTED: number;
  REJECTED: number;
  IN_PROGRESS: number;
  VERIFIED: number;
  DEFERRED: number;
}

export interface RemediationOverviewResponse {
  total_recommendations: number;
  by_priority: PriorityCountBreakdown;
  by_status: StatusCountBreakdown;
  average_risk_score: number;
  verified_count: number;
  pending_verification_count: number;
  in_progress_count: number;
}


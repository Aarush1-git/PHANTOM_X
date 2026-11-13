// Type definitions for Feature 6: Role & Resource Relationship Mapping

export type SubjectType = "ROLE" | "IDENTITY" | "RESOURCE";
export type ObjectType = "RESOURCE" | "ENDPOINT" | "ROLE";

export type RelationshipType =
  | "ROLE_ACCESSES_RESOURCE"
  | "ROLE_ACCESSES_ENDPOINT"
  | "STRUCTURAL_CONTAINMENT"
  | "RESOURCE_REFERENCES_RESOURCE"
  | "IDENTITY_ASSIGNED_ROLE"
  | "ROLE_DECLARED_INHERITANCE"
  | "OBSERVED_ACCESS_OVERLAP";

export type EvidenceSource = "DECLARED" | "OBSERVED" | "INFERRED";
export type MappingStatus = "ACTIVE" | "CANDIDATE" | "DISPUTED" | "ARCHIVED";

export type DiscrepancyCategory =
  | "NONE"
  | "ALIGNED"
  | "DECLARED_NOT_OBSERVED"
  | "OBSERVED_NOT_DECLARED"
  | "EVIDENCE_INSUFFICIENT";

export interface AccessTelemetry {
  request_outcomes?: {
    "2xx"?: number;
    "4xx"?: number;
    "5xx"?: number;
    [key: string]: number | undefined;
  };
  authentication_status?: "AUTHENTICATED" | "UNAUTHENTICATED" | "UNKNOWN" | string;
  authorization_status?: "EXPLICIT_ALLOW" | "EXPLICIT_DENY" | "UNSPECIFIED" | string;
  authorization_scope?: string;
  authorization_note?: string;
  first_observed_at?: string;
  last_observed_at?: string;
}

export interface DeclaredVsObserved {
  declared_in_spec?: boolean;
  observed_in_traffic?: boolean;
  discrepancy_category?: DiscrepancyCategory | string;
  notes?: string;
}

export interface RoleResourceMapping {
  id: string;
  organization_id: string;
  application_id: string;
  subject_type: SubjectType | string;
  subject_id?: string | null;
  subject_name: string;
  object_type: ObjectType | string;
  object_id?: string | null;
  object_name: string;
  relationship_type: RelationshipType | string;
  evidence_source: EvidenceSource | string;
  confidence_score: number;
  sample_count: number;
  access_telemetry: AccessTelemetry;
  declared_vs_observed: DeclaredVsObserved;
  status: MappingStatus | string;
  discovered_at: string;
  last_observed_at: string;
  created_at: string;
  updated_at: string;
}

export interface RoleResourceMappingListResponse {
  items: RoleResourceMapping[];
  total: number;
  page: number;
  page_size: number;
}

export interface RoleResourceOverview {
  application_id: string;
  total_roles: number;
  total_resources: number;
  total_mappings: number;
  declared_count: number;
  observed_count: number;
  inferred_count: number;
  discrepancies_count: number;
  high_confidence_count: number;
  insufficient_evidence: boolean;
  insufficient_evidence_reason?: string | null;
}

export interface DiscrepancyListResponse {
  application_id: string;
  total_discrepancies: number;
  category_filter?: string | null;
  breakdown: Record<string, number>;
  items: RoleResourceMapping[];
  evidence_limitations_note: string;
}

export interface ApplicationRoleMapping {
  role_id?: string | null;
  role_name: string;
  description?: string | null;
  declared_permissions: Record<string, any>;
  discovered_endpoints: string[];
  discovered_resources: string[];
  mappings: RoleResourceMapping[];
}

export interface ApplicationRoleMappingListResponse {
  application_id: string;
  total_roles: number;
  items: ApplicationRoleMapping[];
}

export interface ApplicationResourceMapping {
  resource_name: string;
  structural_parents: string[];
  structural_children: string[];
  accessing_roles: string[];
  mappings: RoleResourceMapping[];
}

export interface ApplicationResourceMappingListResponse {
  application_id: string;
  total_resources: number;
  items: ApplicationResourceMapping[];
}

export interface MappingEvidenceItem {
  observation_id: string;
  session_token_hash?: string | null;
  method: string;
  normalized_path: string;
  status_code: number;
  latency_ms: number;
  observed_at: string;
  sanitized_request_schema: Record<string, any>;
  sanitized_response_schema: Record<string, any>;
}

export interface MappingEvidenceListResponse {
  mapping_id: string;
  total_evidence: number;
  items: MappingEvidenceItem[];
}

export interface MappingDiscoveryRequest {
  mode?: "ALL" | "DECLARED_ONLY" | "OBSERVED_ONLY" | "STRUCTURAL_ONLY" | "OVERLAP_ONLY" | string;
  min_confidence?: number;
  min_sample_count?: number;
  include_declared?: boolean;
  include_observed?: boolean;
  include_inferred?: boolean;
}

export interface MappingDiscoveryResult {
  application_id: string;
  discovered_mappings_count: number;
  declared_mappings_count: number;
  observed_mappings_count: number;
  inferred_mappings_count: number;
  discrepancies_count: number;
  insufficient_evidence: boolean;
  insufficient_evidence_reason?: string | null;
  mappings: RoleResourceMapping[];
}

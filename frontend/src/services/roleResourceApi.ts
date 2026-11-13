import { apiClient } from "./api";
import {
  RoleResourceOverview,
  RoleResourceMapping,
  RoleResourceMappingListResponse,
  DiscrepancyListResponse,
  ApplicationRoleMappingListResponse,
  ApplicationResourceMappingListResponse,
  MappingEvidenceListResponse,
  MappingDiscoveryRequest,
  MappingDiscoveryResult,
} from "../types/roleResource";

export const roleResourceApi = {
  getOverview: async (applicationId: string): Promise<RoleResourceOverview> => {
    const { data } = await apiClient.get<RoleResourceOverview>(
      `/role-resource-mapping/applications/${applicationId}/overview`
    );
    return data;
  },

  listMappings: async (
    applicationId: string,
    params?: {
      subject_type?: string;
      object_type?: string;
      relationship_type?: string;
      evidence_source?: string;
      status?: string;
      min_confidence?: number;
      page?: number;
      page_size?: number;
    }
  ): Promise<RoleResourceMappingListResponse> => {
    const { data } = await apiClient.get<RoleResourceMappingListResponse>(
      `/role-resource-mapping/applications/${applicationId}/mappings`,
      { params }
    );
    return data;
  },

  getMappingById: async (mappingId: string): Promise<RoleResourceMapping> => {
    const { data } = await apiClient.get<RoleResourceMapping>(
      `/role-resource-mapping/mappings/${mappingId}`
    );
    return data;
  },

  triggerDiscovery: async (
    applicationId: string,
    request?: MappingDiscoveryRequest
  ): Promise<MappingDiscoveryResult> => {
    const { data } = await apiClient.post<MappingDiscoveryResult>(
      `/role-resource-mapping/applications/${applicationId}/discover`,
      request || {}
    );
    return data;
  },

  triggerDiscoveryMode: async (
    applicationId: string,
    mode: "declared" | "observed" | "structural" | "overlap"
  ): Promise<MappingDiscoveryResult> => {
    const { data } = await apiClient.post<MappingDiscoveryResult>(
      `/role-resource-mapping/applications/${applicationId}/discover/${mode}`
    );
    return data;
  },

  getDiscrepancies: async (
    applicationId: string,
    category?: string
  ): Promise<DiscrepancyListResponse> => {
    const { data } = await apiClient.get<DiscrepancyListResponse>(
      `/role-resource-mapping/applications/${applicationId}/discrepancies`,
      { params: category ? { category } : undefined }
    );
    return data;
  },

  getRoles: async (applicationId: string): Promise<ApplicationRoleMappingListResponse> => {
    const { data } = await apiClient.get<ApplicationRoleMappingListResponse>(
      `/role-resource-mapping/applications/${applicationId}/roles`
    );
    return data;
  },

  getResources: async (applicationId: string): Promise<ApplicationResourceMappingListResponse> => {
    const { data } = await apiClient.get<ApplicationResourceMappingListResponse>(
      `/role-resource-mapping/applications/${applicationId}/resources`
    );
    return data;
  },

  getEvidence: async (
    mappingId: string,
    limit: number = 50
  ): Promise<MappingEvidenceListResponse> => {
    const { data } = await apiClient.get<MappingEvidenceListResponse>(
      `/role-resource-mapping/mappings/${mappingId}/evidence`,
      { params: { limit } }
    );
    return data;
  },
};

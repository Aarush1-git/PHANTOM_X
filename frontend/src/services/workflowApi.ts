import { apiClient } from "./api";
import {
  WorkflowOverview,
  DiscoveredWorkflowListResponse,
  DiscoveredWorkflowDetail,
  WorkflowDiscoveryRequest,
  WorkflowDiscoveryResult,
  WorkflowEvidenceListResponse,
} from "../types/workflow";

export const workflowApi = {
  getOverview: async (applicationId: string): Promise<WorkflowOverview> => {
    const { data } = await apiClient.get<WorkflowOverview>(
      `/workflows/applications/${applicationId}/overview`
    );
    return data;
  },

  listWorkflows: async (
    applicationId: string,
    params?: {
      status?: string;
      workflow_type?: string;
      is_incomplete?: boolean;
      min_confidence?: number;
      page?: number;
      page_size?: number;
    }
  ): Promise<DiscoveredWorkflowListResponse> => {
    const { data } = await apiClient.get<DiscoveredWorkflowListResponse>(
      `/workflows/applications/${applicationId}`,
      { params }
    );
    return data;
  },

  getWorkflowDetail: async (workflowId: string): Promise<DiscoveredWorkflowDetail> => {
    const { data } = await apiClient.get<DiscoveredWorkflowDetail>(
      `/workflows/${workflowId}`
    );
    return data;
  },

  triggerDiscovery: async (
    applicationId: string,
    request?: WorkflowDiscoveryRequest
  ): Promise<WorkflowDiscoveryResult> => {
    const { data } = await apiClient.post<WorkflowDiscoveryResult>(
      `/workflows/applications/${applicationId}/discover`,
      request || {}
    );
    return data;
  },

  getWorkflowEvidence: async (
    workflowId: string,
    stepIndex?: number,
    limit: number = 50
  ): Promise<WorkflowEvidenceListResponse> => {
    const { data } = await apiClient.get<WorkflowEvidenceListResponse>(
      `/workflows/${workflowId}/evidence`,
      {
        params: {
          step_index: stepIndex,
          limit,
        },
      }
    );
    return data;
  },
};

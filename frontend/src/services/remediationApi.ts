import { apiClient } from './api';
import {
  RemediationOverviewResponse,
  RecommendationListResponse,
  RemediationRecommendationDetail,
  RecommendationGenerateRequest,
  RecommendationGenerateResponse,
  RecommendationStatusUpdateRequest,
  RecommendationNotesUpdateRequest,
  RecommendationVerifyRequest,
  RecommendationVerifyResponse,
  RecommendationHistoryItem,
  RemediationPriority,
  RecommendationStatus,
} from '../types/remediation';

export const remediationApi = {
  getOverview: async (applicationId?: string): Promise<RemediationOverviewResponse> => {
    const { data } = await apiClient.get<RemediationOverviewResponse>('/remediation/overview', {
      params: applicationId ? { application_id: applicationId } : undefined,
    });
    return data;
  },

  listRecommendations: async (params?: {
    application_id?: string;
    priority?: RemediationPriority;
    status?: RecommendationStatus;
    cwe_id?: string;
    search?: string;
    sort_by?: string;
    sort_order?: string;
    page?: number;
    size?: number;
  }): Promise<RecommendationListResponse> => {
    const { data } = await apiClient.get<RecommendationListResponse>('/remediation/recommendations', {
      params,
    });
    return data;
  },

  getRecommendation: async (id: string): Promise<RemediationRecommendationDetail> => {
    const { data } = await apiClient.get<RemediationRecommendationDetail>(`/remediation/recommendations/${id}`);
    return data;
  },

  generateRecommendations: async (
    payload: RecommendationGenerateRequest
  ): Promise<RecommendationGenerateResponse> => {
    const { data } = await apiClient.post<RecommendationGenerateResponse>(
      '/remediation/recommendations/generate',
      payload
    );
    return data;
  },

  updateStatus: async (
    id: string,
    payload: RecommendationStatusUpdateRequest
  ): Promise<RemediationRecommendationDetail> => {
    const { data } = await apiClient.patch<RemediationRecommendationDetail>(
      `/remediation/recommendations/${id}/status`,
      payload
    );
    return data;
  },

  updateNotes: async (
    id: string,
    payload: RecommendationNotesUpdateRequest
  ): Promise<RemediationRecommendationDetail> => {
    const { data } = await apiClient.post<RemediationRecommendationDetail>(
      `/remediation/recommendations/${id}/notes`,
      payload
    );
    return data;
  },

  verifyRecommendation: async (
    id: string,
    payload: RecommendationVerifyRequest
  ): Promise<RecommendationVerifyResponse> => {
    const { data } = await apiClient.post<RecommendationVerifyResponse>(
      `/remediation/recommendations/${id}/verify`,
      payload
    );
    return data;
  },

  getHistory: async (id: string): Promise<RecommendationHistoryItem[]> => {
    const { data } = await apiClient.get<RecommendationHistoryItem[]>(
      `/remediation/recommendations/${id}/history`
    );
    return data;
  },
};


import { apiClient } from "./api";
import {
  TimeTravelOverviewResponse,
  BaselineListResponse,
  SecurityBaseline,
  BaselineVerifyRequest,
  BaselineVerifyResponse,
  RegressionListResponse,
  RegressionRecord,
  ScanEvaluationResponse,
  SecurityTimelineResponse,
  TimeTravelFilterParams,
} from "../types/timeTravel";

export const timeTravelApi = {
  getOverview: async (): Promise<TimeTravelOverviewResponse> => {
    const { data } = await apiClient.get<TimeTravelOverviewResponse>("/time-travel/overview");
    return data;
  },

  listBaselines: async (params?: TimeTravelFilterParams): Promise<BaselineListResponse> => {
    const { data } = await apiClient.get<BaselineListResponse>("/time-travel/baselines", {
      params,
    });
    return data;
  },

  getBaselineDetails: async (baselineId: string): Promise<SecurityBaseline> => {
    const { data } = await apiClient.get<SecurityBaseline>(`/time-travel/baselines/${baselineId}`);
    return data;
  },

  verifyBaseline: async (request: BaselineVerifyRequest): Promise<BaselineVerifyResponse> => {
    const { data } = await apiClient.post<BaselineVerifyResponse>("/time-travel/baselines/verify", request);
    return data;
  },

  retireBaseline: async (baselineId: string, reason?: string): Promise<SecurityBaseline> => {
    const { data } = await apiClient.post<SecurityBaseline>(`/time-travel/baselines/${baselineId}/retire`, {
      reason,
    });
    return data;
  },

  evaluateScan: async (scanId: string): Promise<ScanEvaluationResponse> => {
    const { data } = await apiClient.post<ScanEvaluationResponse>(`/time-travel/evaluate/${scanId}`);
    return data;
  },

  listRegressions: async (params?: {
    application_id?: string;
    status?: string;
    baseline_id?: string;
    page?: number;
    limit?: number;
  }): Promise<RegressionListResponse> => {
    const { data } = await apiClient.get<RegressionListResponse>("/time-travel/regressions", {
      params,
    });
    return data;
  },

  getRegressionDetails: async (regressionId: string): Promise<RegressionRecord> => {
    const { data } = await apiClient.get<RegressionRecord>(`/time-travel/regressions/${regressionId}`);
    return data;
  },

  getApplicationTimeline: async (applicationId: string): Promise<SecurityTimelineResponse> => {
    const { data } = await apiClient.get<SecurityTimelineResponse>(
      `/time-travel/applications/${applicationId}/timeline`
    );
    return data;
  },
};


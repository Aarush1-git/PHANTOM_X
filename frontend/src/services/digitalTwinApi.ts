import { apiClient } from "./api";
import {
  DigitalTwinOverviewResponse,
  BehavioralObservation,
  ObservationListResponse,
  BaselineListResponse,
  BehavioralBaseline,
  BaselineCompileRequest,
  AnomalyListResponse,
  BehavioralAnomalyResponse,
  AnomalyFilterParams,
  AnomalyStatus,
  DriftEvaluationResponse,
} from "../types/digitalTwin";

export const digitalTwinApi = {
  getOverview: async (applicationId: string): Promise<DigitalTwinOverviewResponse> => {
    const { data } = await apiClient.get<DigitalTwinOverviewResponse>(
      `/behavioral-twin/applications/${applicationId}/overview`
    );
    return data;
  },

  listObservations: async (
    applicationId: string,
    page: number = 1,
    limit: number = 20,
    endpointId?: string
  ): Promise<ObservationListResponse> => {
    const { data } = await apiClient.get<ObservationListResponse>("/behavioral-twin/observations", {
      params: {
        application_id: applicationId,
        page,
        limit,
        endpoint_id: endpointId,
      },
    });
    return data;
  },

  listBaselines: async (applicationId: string): Promise<BaselineListResponse> => {
    const { data } = await apiClient.get<BaselineListResponse>("/behavioral-twin/baselines", {
      params: { application_id: applicationId },
    });
    return data;
  },

  getBaseline: async (baselineId: string): Promise<BehavioralBaseline> => {
    const { data } = await apiClient.get<BehavioralBaseline>(`/behavioral-twin/baselines/${baselineId}`);
    return data;
  },

  compileBaseline: async (request: BaselineCompileRequest): Promise<BehavioralBaseline> => {
    const { data } = await apiClient.post<BehavioralBaseline>("/behavioral-twin/baselines/compile", request);
    return data;
  },

  activateBaseline: async (baselineId: string, notes?: string): Promise<BehavioralBaseline> => {
    const { data } = await apiClient.post<BehavioralBaseline>(
      `/behavioral-twin/baselines/${baselineId}/activate`,
      notes ? { activation_notes: notes } : {}
    );
    return data;
  },

  archiveBaseline: async (baselineId: string): Promise<BehavioralBaseline> => {
    const { data } = await apiClient.post<BehavioralBaseline>(`/behavioral-twin/baselines/${baselineId}/archive`);
    return data;
  },

  listAnomalies: async (params: AnomalyFilterParams): Promise<AnomalyListResponse> => {
    const { data } = await apiClient.get<AnomalyListResponse>("/behavioral-twin/anomalies", {
      params,
    });
    return data;
  },

  getAnomaly: async (anomalyId: string): Promise<BehavioralAnomalyResponse> => {
    const { data } = await apiClient.get<BehavioralAnomalyResponse>(`/behavioral-twin/anomalies/${anomalyId}`);
    return data;
  },

  evaluateDrift: async (
    applicationId: string,
    baselineId?: string,
    maxObservations: number = 50
  ): Promise<DriftEvaluationResponse> => {
    const { data } = await apiClient.post<DriftEvaluationResponse>("/behavioral-twin/drift/evaluate", {
      application_id: applicationId,
      baseline_id: baselineId,
      max_observations: maxObservations,
    });
    return data;
  },

  updateAnomalyStatus: async (
    anomalyId: string,
    status: AnomalyStatus,
    notes?: string
  ): Promise<BehavioralAnomalyResponse> => {
    const { data } = await apiClient.patch<BehavioralAnomalyResponse>(
      `/behavioral-twin/anomalies/${anomalyId}/status`,
      {
        status,
        resolution_notes: notes,
      }
    );
    return data;
  },

  acknowledgeAnomaly: async (anomalyId: string, notes?: string): Promise<BehavioralAnomalyResponse> => {
    const { data } = await apiClient.post<BehavioralAnomalyResponse>(
      `/behavioral-twin/anomalies/${anomalyId}/acknowledge`,
      null,
      { params: notes ? { notes } : {} }
    );
    return data;
  },

  resolveAnomaly: async (anomalyId: string, notes?: string): Promise<BehavioralAnomalyResponse> => {
    const { data } = await apiClient.post<BehavioralAnomalyResponse>(
      `/behavioral-twin/anomalies/${anomalyId}/resolve`,
      null,
      { params: notes ? { notes } : {} }
    );
    return data;
  },
};

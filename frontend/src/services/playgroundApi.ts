import { apiClient } from './api';
import {
  ScenarioInfo,
  ScenarioListResponse,
  PlaygroundTargetInfo,
  PlaygroundSessionCreate,
  PlaygroundAuthorizeRequest,
  PlaygroundSession,
  PlaygroundSessionListResponse,
  PlaygroundResult,
} from '../types/playground';

export const playgroundApi = {
  listScenarios: async (category?: string): Promise<ScenarioListResponse> => {
    const { data } = await apiClient.get<ScenarioListResponse>('/playground/scenarios', {
      params: category ? { category } : undefined,
    });
    return data;
  },

  getScenario: async (scenarioId: string): Promise<ScenarioInfo> => {
    const { data } = await apiClient.get<ScenarioInfo>(`/playground/scenarios/${scenarioId}`);
    return data;
  },

  listTargets: async (): Promise<PlaygroundTargetInfo[]> => {
    const { data } = await apiClient.get<PlaygroundTargetInfo[]>('/playground/targets');
    return data;
  },

  createSession: async (payload: PlaygroundSessionCreate): Promise<PlaygroundSession> => {
    const { data } = await apiClient.post<PlaygroundSession>('/playground/sessions', payload);
    return data;
  },

  listSessions: async (params?: {
    application_id?: string;
    status?: string;
    scenario_id?: string;
    page?: number;
    limit?: number;
  }): Promise<PlaygroundSessionListResponse> => {
    const { data } = await apiClient.get<PlaygroundSessionListResponse>('/playground/sessions', {
      params,
    });
    return data;
  },

  getSession: async (sessionId: string): Promise<PlaygroundSession> => {
    const { data } = await apiClient.get<PlaygroundSession>(`/playground/sessions/${sessionId}`);
    return data;
  },

  authorizeSession: async (
    sessionId: string,
    payload: PlaygroundAuthorizeRequest = {}
  ): Promise<PlaygroundSession> => {
    const { data } = await apiClient.post<PlaygroundSession>(
      `/playground/sessions/${sessionId}/authorize`,
      payload
    );
    return data;
  },

  executeSession: async (sessionId: string): Promise<PlaygroundResult> => {
    const { data } = await apiClient.post<PlaygroundResult>(
      `/playground/sessions/${sessionId}/execute`
    );
    return data;
  },

  getSessionResults: async (sessionId: string): Promise<PlaygroundResult> => {
    const { data } = await apiClient.get<PlaygroundResult>(
      `/playground/sessions/${sessionId}/results`
    );
    return data;
  },

  replaySession: async (sessionId: string): Promise<PlaygroundSession> => {
    const { data } = await apiClient.post<PlaygroundSession>(
      `/playground/sessions/${sessionId}/replay`
    );
    return data;
  },
};

import axios, { AxiosError, AxiosInstance } from "axios";
import {
  ApplicationResponse,
  ApplicationCreate,
  ScanResponse,
  ScanCreate,
  ScanProgress,
  EndpointResponse,
  VulnerabilityResponse,
  AttackChainResponse,
  EvidenceResponse,
  RegressionResult,
  AuditLogResponse,
  ScopePermissionResponse,
  TokenResponse,
  UserLogin,
} from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 10000,
});

// Request interceptor to attach JWT token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("phantom_token");
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Clear token on 401
      localStorage.removeItem("phantom_token");
    }
    return Promise.reject(error);
  }
);

// ============================================================================
// API Service Methods
// ============================================================================

export const api = {
  // Authentication
  auth: {
    login: async (credentials: UserLogin): Promise<TokenResponse> => {
      const { data } = await apiClient.post<TokenResponse>("/auth/login", credentials);
      return data;
    },
    getMe: async () => {
      const { data } = await apiClient.get("/auth/me");
      return data;
    },
  },

  // Applications
  applications: {
    list: async (): Promise<ApplicationResponse[]> => {
      const { data } = await apiClient.get<ApplicationResponse[]>("/applications/");
      return data;
    },
    getById: async (id: string): Promise<ApplicationResponse> => {
      const { data } = await apiClient.get<ApplicationResponse>(`/applications/${id}`);
      return data;
    },
    create: async (app: ApplicationCreate): Promise<ApplicationResponse> => {
      const { data } = await apiClient.post<ApplicationResponse>("/applications/", app);
      return data;
    },
    delete: async (id: string): Promise<void> => {
      await apiClient.delete(`/applications/${id}`);
    },
  },

  // Scans
  scans: {
    list: async (appId?: string): Promise<ScanResponse[]> => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get<ScanResponse[]>("/scans/", { params });
      return data;
    },
    getById: async (id: string): Promise<ScanResponse> => {
      const { data } = await apiClient.get<ScanResponse>(`/scans/${id}`);
      return data;
    },
    getProgress: async (id: string): Promise<ScanProgress> => {
      const { data } = await apiClient.get<ScanProgress>(`/scans/${id}/progress`);
      return data;
    },
    launch: async (scan: ScanCreate): Promise<ScanResponse> => {
      const { data } = await apiClient.post<ScanResponse>("/scans/", scan);
      return data;
    },
    abort: async (id: string): Promise<ScanResponse> => {
      const { data } = await apiClient.post<ScanResponse>(`/scans/${id}/abort`);
      return data;
    },
  },

  // Discovery
  discovery: {
    listEndpoints: async (appId?: string): Promise<EndpointResponse[]> => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get<EndpointResponse[]>("/discovery/endpoints", { params });
      return data;
    },
    trigger: async (appId: string) => {
      const { data } = await apiClient.post("/discovery/trigger", null, { params: { app_id: appId } });
      return data;
    },
  },

  // Vulnerabilities
  vulnerabilities: {
    list: async (filters?: { app_id?: string; severity?: string }): Promise<VulnerabilityResponse[]> => {
      const { data } = await apiClient.get<VulnerabilityResponse[]>("/vulnerabilities/", { params: filters });
      return data;
    },
    getById: async (id: string): Promise<VulnerabilityResponse> => {
      const { data } = await apiClient.get<VulnerabilityResponse>(`/vulnerabilities/${id}`);
      return data;
    },
    updateStatus: async (id: string, status: string): Promise<VulnerabilityResponse> => {
      const { data } = await apiClient.patch<VulnerabilityResponse>(`/vulnerabilities/${id}/status`, null, {
        params: { new_status: status },
      });
      return data;
    },
  },

  // Attack Chains
  attackChains: {
    list: async (appId?: string): Promise<AttackChainResponse[]> => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get<AttackChainResponse[]>("/attack-chains/", { params });
      return data;
    },
    getById: async (id: string): Promise<AttackChainResponse> => {
      const { data } = await apiClient.get<AttackChainResponse>(`/attack-chains/${id}`);
      return data;
    },
  },

  // Evidence
  evidence: {
    list: async (vulnId?: string): Promise<EvidenceResponse[]> => {
      const params = vulnId ? { vuln_id: vulnId } : {};
      const { data } = await apiClient.get<EvidenceResponse[]>("/evidence/", { params });
      return data;
    },
    getById: async (id: string): Promise<EvidenceResponse> => {
      const { data } = await apiClient.get<EvidenceResponse>(`/evidence/${id}`);
      return data;
    },
  },

  // Regression
  regression: {
    list: async (appId?: string): Promise<RegressionResult[]> => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get<RegressionResult[]>("/regression/", { params });
      return data;
    },
    trigger: async (vulnId: string, appId: string): Promise<RegressionResult> => {
      const { data } = await apiClient.post<RegressionResult>("/regression/run", {
        vulnerability_id: vulnId,
        application_id: appId,
      });
      return data;
    },
  },

  // Reports
  reports: {
    getSummary: async (appId?: string) => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get("/reports/summary", { params });
      return data;
    },
  },

  // Settings & Safety
  settings: {
    getSafetyPolicy: async () => {
      const { data } = await apiClient.get("/settings/safety-policy");
      return data;
    },
    listScopePermissions: async (appId?: string): Promise<ScopePermissionResponse[]> => {
      const params = appId ? { app_id: appId } : {};
      const { data } = await apiClient.get<ScopePermissionResponse[]>("/settings/scope", { params });
      return data;
    },
    listAuditLogs: async (): Promise<AuditLogResponse[]> => {
      const { data } = await apiClient.get<AuditLogResponse[]>("/settings/audit-logs");
      return data;
    },
  },

  // Health
  health: async () => {
    const { data } = await apiClient.get("/health");
    return data;
  },
};


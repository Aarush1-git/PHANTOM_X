import { apiClient } from "./api";
import {
  DashboardFilterParams,
  SecurityOverviewMetrics,
  SeverityDistributionResponse,
  VulnerabilityTrendsResponse,
  ApplicationRiskResponse,
  ScanAnalyticsResponse,
  RemediationAnalyticsResponse,
  RecentActivityResponse,
} from "../types/dashboard";

export const dashboardApi = {
  getOverview: async (params?: DashboardFilterParams): Promise<SecurityOverviewMetrics> => {
    const { data } = await apiClient.get<SecurityOverviewMetrics>("/security-dashboard/overview", {
      params,
    });
    return data;
  },

  getSeverityDistribution: async (params?: DashboardFilterParams): Promise<SeverityDistributionResponse> => {
    const { data } = await apiClient.get<SeverityDistributionResponse>("/security-dashboard/severity-distribution", {
      params,
    });
    return data;
  },

  getVulnerabilityTrends: async (params?: DashboardFilterParams): Promise<VulnerabilityTrendsResponse> => {
    const { data } = await apiClient.get<VulnerabilityTrendsResponse>("/security-dashboard/vulnerability-trends", {
      params,
    });
    return data;
  },

  getApplicationRisk: async (params?: DashboardFilterParams): Promise<ApplicationRiskResponse> => {
    const { data } = await apiClient.get<ApplicationRiskResponse>("/security-dashboard/application-risk", {
      params,
    });
    return data;
  },

  getScanAnalytics: async (params?: DashboardFilterParams): Promise<ScanAnalyticsResponse> => {
    const { data } = await apiClient.get<ScanAnalyticsResponse>("/security-dashboard/scan-analytics", {
      params,
    });
    return data;
  },

  getRemediationAnalytics: async (params?: DashboardFilterParams): Promise<RemediationAnalyticsResponse> => {
    const { data } = await apiClient.get<RemediationAnalyticsResponse>("/security-dashboard/remediation-analytics", {
      params,
    });
    return data;
  },

  getRecentActivity: async (limit = 25, applicationId?: string): Promise<RecentActivityResponse> => {
    const { data } = await apiClient.get<RecentActivityResponse>("/security-dashboard/recent-activity", {
      params: { limit, application_id: applicationId },
    });
    return data;
  },
};

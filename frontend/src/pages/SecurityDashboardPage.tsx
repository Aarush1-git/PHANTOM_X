import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, AlertTriangle, RefreshCw } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { dashboardApi } from "../services/dashboardApi";
import { api } from "../services/api";
import { ApplicationResponse } from "../types";
import { DashboardFilterParams } from "../types/dashboard";

import { DashboardFilters } from "../components/security-dashboard/DashboardFilters";
import { SecurityOverviewCards } from "../components/security-dashboard/SecurityOverviewCards";
import { SeverityDistributionChart } from "../components/security-dashboard/SeverityDistributionChart";
import { VulnerabilityTrendChart } from "../components/security-dashboard/VulnerabilityTrendChart";
import { ApplicationRiskChart } from "../components/security-dashboard/ApplicationRiskChart";
import { ScanAnalyticsChart } from "../components/security-dashboard/ScanAnalyticsChart";
import { RemediationAnalytics } from "../components/security-dashboard/RemediationAnalytics";
import { SecurityActivityTimeline } from "../components/security-dashboard/SecurityActivityTimeline";

export const SecurityDashboardPage: React.FC = () => {
  const [filters, setFilters] = useState<DashboardFilterParams>({
    time_range: "30d",
  });

  const handleFilterChange = (updated: Partial<DashboardFilterParams>) => {
    setFilters((prev) => ({ ...prev, ...updated }));
  };

  // 1. Fetch Registered Applications for filter dropdown
  const { data: applications = [] } = useQuery({
    queryKey: ["dashboard-applications-filter"],
    queryFn: async () => {
      try {
        const apps = await api.applications.list();
        return apps.map((a: ApplicationResponse) => ({ id: a.id, name: a.name }));
      } catch (err) {
        return [];
      }
    },
    staleTime: 60000,
  });

  // 2. Fetch Overview KPIs
  const {
    data: overview,
    isLoading: isOverviewLoading,
    isError: isOverviewError,
    refetch: refetchOverview,
    isFetching: isOverviewFetching,
  } = useQuery({
    queryKey: ["security-dashboard-overview", filters],
    queryFn: () => dashboardApi.getOverview(filters),
    staleTime: 30000,
  });

  // 3. Fetch Severity Distribution
  const {
    data: severityDist,
    isLoading: isSeverityLoading,
    refetch: refetchSeverity,
  } = useQuery({
    queryKey: ["security-dashboard-severity", filters],
    queryFn: () => dashboardApi.getSeverityDistribution(filters),
    staleTime: 30000,
  });

  // 4. Fetch Vulnerability Trends
  const {
    data: trends,
    isLoading: isTrendsLoading,
    refetch: refetchTrends,
  } = useQuery({
    queryKey: ["security-dashboard-trends", filters],
    queryFn: () => dashboardApi.getVulnerabilityTrends(filters),
    staleTime: 30000,
  });

  // 5. Fetch Application Risk Ranking
  const {
    data: appRisk,
    isLoading: isAppRiskLoading,
    refetch: refetchAppRisk,
  } = useQuery({
    queryKey: ["security-dashboard-app-risk", filters],
    queryFn: () => dashboardApi.getApplicationRisk(filters),
    staleTime: 30000,
  });

  // 6. Fetch Scan Analytics
  const {
    data: scanAnalytics,
    isLoading: isScanLoading,
    refetch: refetchScans,
  } = useQuery({
    queryKey: ["security-dashboard-scan-analytics", filters],
    queryFn: () => dashboardApi.getScanAnalytics(filters),
    staleTime: 30000,
  });

  // 7. Fetch Remediation Velocity Analytics
  const {
    data: remediation,
    isLoading: isRemediationLoading,
    refetch: refetchRemediation,
  } = useQuery({
    queryKey: ["security-dashboard-remediation", filters],
    queryFn: () => dashboardApi.getRemediationAnalytics(filters),
    staleTime: 30000,
  });

  // 8. Fetch Recent Activity Stream
  const {
    data: activityData,
    isLoading: isActivityLoading,
    refetch: refetchActivity,
  } = useQuery({
    queryKey: ["security-dashboard-activity", filters.application_id],
    queryFn: () => dashboardApi.getRecentActivity(25, filters.application_id),
    staleTime: 15000,
  });

  const handleRefreshAll = () => {
    refetchOverview();
    refetchSeverity();
    refetchTrends();
    refetchAppRisk();
    refetchScans();
    refetchRemediation();
    refetchActivity();
  };

  const isAnyLoading =
    isOverviewLoading ||
    isSeverityLoading ||
    isTrendsLoading ||
    isAppRiskLoading ||
    isScanLoading ||
    isRemediationLoading ||
    isActivityLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Intelligence Command"
        description="Real-time multi-tenant cybersecurity posture, vulnerability trends, remediation velocity, and exposure analytics."
      />

      {/* Global Dashboard Filters */}
      <DashboardFilters
        filters={filters}
        onFilterChange={handleFilterChange}
        onRefresh={handleRefreshAll}
        applications={applications}
        isRefreshing={isOverviewFetching}
      />

      {/* Error Notice with Retry */}
      {isOverviewError && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 flex items-center justify-between text-xs text-rose-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>Failed to load security dashboard telemetry. Please verify tenant authorization.</span>
          </div>
          <button
            type="button"
            onClick={handleRefreshAll}
            className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 rounded font-mono transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Row 1: Executive KPI Metrics Cards */}
      <SecurityOverviewCards metrics={overview} isLoading={isOverviewLoading} />

      {/* Row 2: Severity Donut & Trends Area Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4">
          <SeverityDistributionChart data={severityDist} isLoading={isSeverityLoading} />
        </div>
        <div className="lg:col-span-8">
          <VulnerabilityTrendChart data={trends} isLoading={isTrendsLoading} />
        </div>
      </div>

      {/* Row 3: Application Risk Ranking & Exposure */}
      <ApplicationRiskChart data={appRisk} isLoading={isAppRiskLoading} />

      {/* Row 4: Remediation Velocity & Scan Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RemediationAnalytics data={remediation} isLoading={isRemediationLoading} />
        <ScanAnalyticsChart data={scanAnalytics} isLoading={isScanLoading} />
      </div>

      {/* Row 5: Chronological Security Activity Stream */}
      <SecurityActivityTimeline
        activities={activityData?.activities || []}
        isLoading={isActivityLoading}
      />
    </div>
  );
};


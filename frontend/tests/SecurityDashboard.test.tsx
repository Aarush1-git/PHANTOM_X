import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { SecurityOverviewCards } from "../src/components/security-dashboard/SecurityOverviewCards";
import { DashboardFilters } from "../src/components/security-dashboard/DashboardFilters";
import { SeverityDistributionChart } from "../src/components/security-dashboard/SeverityDistributionChart";
import { ApplicationRiskChart } from "../src/components/security-dashboard/ApplicationRiskChart";
import { ScanAnalyticsChart } from "../src/components/security-dashboard/ScanAnalyticsChart";
import { RemediationAnalytics } from "../src/components/security-dashboard/RemediationAnalytics";
import { SecurityActivityTimeline } from "../src/components/security-dashboard/SecurityActivityTimeline";

import {
  SecurityOverviewMetrics,
  SeverityDistributionResponse,
  ApplicationRiskResponse,
  ScanAnalyticsResponse,
  RemediationAnalyticsResponse,
  RecentActivityItem,
} from "../src/types/dashboard";

describe("Feature 22: Security Dashboard & Analytics UI Components", () => {
  const mockOverviewMetrics: SecurityOverviewMetrics = {
    total_vulnerabilities: 42,
    critical_count: 5,
    high_count: 12,
    medium_count: 18,
    low_count: 7,
    info_count: 0,
    open_count: 17,
    fixed_count: 22,
    accepted_risk_count: 1,
    false_positive_count: 2,
    critical_and_high_open: 6,
    remediation_rate: 55.0,
    total_applications: 8,
    total_scans: 34,
    vulnerabilities_delta_pct: 12.5,
    period_start: "2026-10-11T00:00:00Z",
    period_end: "2026-11-10T00:00:00Z",
  };

  it("renders SecurityOverviewCards with executive KPIs, counts, and deltas", () => {
    render(<SecurityOverviewCards metrics={mockOverviewMetrics} />);

    expect(screen.getByText("Total Vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("12.5%")).toBeInTheDocument();

    expect(screen.getByText("Critical / High Open")).toBeInTheDocument();
    expect(screen.getByText("6")).toBeInTheDocument();
    expect(screen.getByText(/5 Critical/i)).toBeInTheDocument();
    expect(screen.getByText(/12 High/i)).toBeInTheDocument();

    expect(screen.getByText("Remediation Rate")).toBeInTheDocument();
    expect(screen.getByText("55%")).toBeInTheDocument();

    expect(screen.getByText("Target Applications")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();

    expect(screen.getByText("Security Scans")).toBeInTheDocument();
    expect(screen.getByText("34")).toBeInTheDocument();
  });

  it("renders DashboardFilters and handles preset and dropdown selections", () => {
    const handleFilterChange = vi.fn();
    const handleRefresh = vi.fn();

    const mockApps = [
      { id: "app-1", name: "Core Banking Service" },
      { id: "app-2", name: "Customer Portal" },
    ];

    render(
      <DashboardFilters
        filters={{ time_range: "30d" }}
        onFilterChange={handleFilterChange}
        onRefresh={handleRefresh}
        applications={mockApps}
      />
    );

    // Test time range buttons
    const btn7d = screen.getByRole("button", { name: "7 Days" });
    fireEvent.click(btn7d);
    expect(handleFilterChange).toHaveBeenCalledWith({ time_range: "7d" });

    // Test application dropdown
    const selectApp = screen.getByRole("combobox", { name: /Filter by Application/i });
    fireEvent.change(selectApp, { target: { value: "app-1" } });
    expect(handleFilterChange).toHaveBeenCalledWith({ application_id: "app-1" });

    // Test severity dropdown
    const selectSev = screen.getByRole("combobox", { name: /Filter by Severity/i });
    fireEvent.change(selectSev, { target: { value: "CRITICAL" } });
    expect(handleFilterChange).toHaveBeenCalledWith({ severity: "CRITICAL" });

    // Test refresh button
    const refreshBtn = screen.getByRole("button", { name: /Refresh/i });
    fireEvent.click(refreshBtn);
    expect(handleRefresh).toHaveBeenCalled();
  });

  it("renders SeverityDistributionChart with donut percentages and breakdown", () => {
    const mockSeverityData: SeverityDistributionResponse = {
      total: 40,
      distribution: [
        { severity: "CRITICAL", count: 4, percentage: 10.0, open_count: 2, fixed_count: 2 },
        { severity: "HIGH", count: 12, percentage: 30.0, open_count: 6, fixed_count: 6 },
        { severity: "MEDIUM", count: 16, percentage: 40.0, open_count: 4, fixed_count: 12 },
        { severity: "LOW", count: 8, percentage: 20.0, open_count: 1, fixed_count: 7 },
        { severity: "INFO", count: 0, percentage: 0.0, open_count: 0, fixed_count: 0 },
      ],
    };

    render(<SeverityDistributionChart data={mockSeverityData} />);

    expect(screen.getByText("Severity Distribution")).toBeInTheDocument();
    expect(screen.getByText("Total: 40")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("10%")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("30%")).toBeInTheDocument();
  });

  it("renders ApplicationRiskChart with risk tiers and top exposed assets", () => {
    const mockAppRisk: ApplicationRiskResponse = {
      total_applications: 3,
      vulnerable_applications_count: 2,
      risk_tier_distribution: {
        CRITICAL: 1,
        HIGH: 1,
        MEDIUM: 0,
        LOW: 0,
        CLEAN: 1,
      },
      top_exposed_applications: [
        {
          application_id: "app-1",
          name: "Payment Gateway",
          target_url: "https://pay.example.local",
          risk_score: 9.2,
          risk_tier: "CRITICAL",
          total_vulnerabilities: 8,
          critical_count: 3,
          high_count: 2,
          medium_count: 2,
          low_count: 1,
          open_count: 5,
          fixed_count: 3,
        },
        {
          application_id: "app-2",
          name: "Documentation Wiki",
          target_url: "https://docs.example.local",
          risk_score: 0.0,
          risk_tier: "CLEAN",
          total_vulnerabilities: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          open_count: 0,
          fixed_count: 0,
        },
      ],
    };

    render(<ApplicationRiskChart data={mockAppRisk} />);

    expect(screen.getByText("Application Risk & Exposure Ranking")).toBeInTheDocument();
    expect(screen.getByText(/CRITICAL: 1/i)).toBeInTheDocument();
    expect(screen.getByText(/CLEAN: 1/i)).toBeInTheDocument();
    expect(screen.getByText("Payment Gateway")).toBeInTheDocument();
    expect(screen.getByText(/5 open/i)).toBeInTheDocument();
  });

  it("renders ScanAnalyticsChart with success rate, duration, and execution history", () => {
    const mockScanData: ScanAnalyticsResponse = {
      total_scans: 15,
      completed_scans: 12,
      failed_scans: 2,
      running_scans: 1,
      cancelled_scans: 0,
      success_rate: 85.7,
      average_duration_seconds: 420.0,
      average_duration_formatted: "7m 0s",
      has_duration_data: true,
      recent_scans: [
        {
          id: "scan-1",
          application_id: "app-1",
          application_name: "Core Banking Gateway",
          status: "COMPLETED",
          progress: 1.0,
          findings_count: 4,
          started_at: "2026-11-10T12:00:00Z",
          completed_at: "2026-11-10T12:07:00Z",
          duration_seconds: 420,
        },
      ],
    };

    render(<ScanAnalyticsChart data={mockScanData} />);

    expect(screen.getByText("Scan Execution & Telemetry")).toBeInTheDocument();
    expect(screen.getByText("85.7%")).toBeInTheDocument();
    expect(screen.getByText("7m 0s")).toBeInTheDocument();
    expect(screen.getByText("Core Banking Gateway")).toBeInTheDocument();
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
  });

  it("renders RemediationAnalytics with MTTR, ageing buckets, and SLA breaches", () => {
    const mockRemediation: RemediationAnalyticsResponse = {
      mean_time_to_remediation_hours: 72.0,
      mean_time_to_remediation_days: 3.0,
      has_remediation_data: true,
      open_vulnerabilities_ageing: {
        under_7_days: 4,
        days_7_to_30: 8,
        days_30_to_90: 2,
        over_90_days: 1,
      },
      vulnerabilities_awaiting_remediation: 15,
      remediation_progress_percentage: 68.0,
      sla_breach_count: 2,
    };

    render(<RemediationAnalytics data={mockRemediation} />);

    expect(screen.getByText("Remediation Velocity & Ageing")).toBeInTheDocument();
    expect(screen.getByText(/2 SLA Breaches/i)).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText(/days \(72h\)/i)).toBeInTheDocument();
    expect(screen.getByText("15")).toBeInTheDocument();
    expect(screen.getByText("68%")).toBeInTheDocument();
    expect(screen.getByText(/< 7 Days/i)).toBeInTheDocument();
    expect(screen.getByText(/> 90 Days/i)).toBeInTheDocument();
  });

  it("renders SecurityActivityTimeline with chronological security events and badges", () => {
    const mockActivities: RecentActivityItem[] = [
      {
        id: "act-1",
        timestamp: "2026-11-10T14:30:00Z",
        activity_type: "BLOCKED_EXECUTION",
        severity: "HIGH",
        title: "Blocked POST probe: PROHIBITED_ENDPOINT",
        description: "Attempt to invoke administrative purge routine",
        actor_email: null,
        application_name: "Payment Gateway",
        metadata: {},
      },
      {
        id: "act-2",
        timestamp: "2026-11-10T14:00:00Z",
        activity_type: "REPORT_GENERATED",
        severity: "CRITICAL",
        title: "Generated Report: RCE Deserialization",
        description: "Enriched intelligence report created for finding",
        actor_email: "secops@example.local",
        application_name: "Core Banking",
        metadata: {},
      },
    ];

    render(<SecurityActivityTimeline activities={mockActivities} />);

    expect(screen.getByText("Recent Security Activity Stream")).toBeInTheDocument();
    expect(screen.getByText("Blocked POST probe: PROHIBITED_ENDPOINT")).toBeInTheDocument();
    expect(screen.getByText("Generated Report: RCE Deserialization")).toBeInTheDocument();
    expect(screen.getByText("secops@example.local")).toBeInTheDocument();
    expect(screen.getByText("Payment Gateway")).toBeInTheDocument();
  });
});


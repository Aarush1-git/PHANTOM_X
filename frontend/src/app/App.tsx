import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AppLayout } from "../components/layout/AppLayout";
import { LoginPage } from "../pages/LoginPage";
import { DashboardPage } from "../pages/DashboardPage";
import { SecurityDashboardPage } from "../pages/SecurityDashboardPage";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { ApplicationDetailsPage } from "../pages/ApplicationDetailsPage";
import { ApiDiscoveryPage } from "../pages/ApiDiscoveryPage";
import { SecurityScansPage } from "../pages/SecurityScansPage";
import { ScanDetailsPage } from "../pages/ScanDetailsPage";
import { VulnerabilitiesPage } from "../pages/VulnerabilitiesPage";
import { VulnerabilityDetailsPage } from "../pages/VulnerabilityDetailsPage";
import { AttackChainsPage } from "../pages/AttackChainsPage";
import { EvidenceExplorerPage } from "../pages/EvidenceExplorerPage";
import { RegressionMonitoringPage } from "../pages/RegressionMonitoringPage";
import { ReportsPage } from "../pages/ReportsPage";
import { PlaygroundPage } from "../pages/PlaygroundPage";
import { SettingsPage } from "../pages/SettingsPage";
import { AuditLogsPage } from "../pages/AuditLogsPage";
import { ScanHistoryPage } from "../pages/ScanHistoryPage";
import { TimeTravelPage } from "../pages/TimeTravelPage";
import { RemediationPage } from "../pages/RemediationPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          <Route path="/" element={<AppLayout />}>
            <Route index element={<DashboardPage />} />
            <Route path="dashboard" element={<SecurityDashboardPage />} />
            <Route path="applications" element={<ApplicationsPage />} />
            <Route path="applications/:id" element={<ApplicationDetailsPage />} />
            <Route path="discovery" element={<ApiDiscoveryPage />} />
            <Route path="scans" element={<SecurityScansPage />} />
            <Route path="scans/history" element={<ScanHistoryPage />} />
            <Route path="scan-history" element={<ScanHistoryPage />} />
            <Route path="scans/:id" element={<ScanDetailsPage />} />
            <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="vulnerabilities/:id" element={<VulnerabilityDetailsPage />} />
            <Route path="attack-chains" element={<AttackChainsPage />} />
            <Route path="evidence" element={<EvidenceExplorerPage />} />
            <Route path="regression" element={<RegressionMonitoringPage />} />
            <Route path="time-travel" element={<TimeTravelPage />} />
            <Route path="regression/time-travel" element={<TimeTravelPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="remediation" element={<RemediationPage />} />
            <Route path="playground" element={<PlaygroundPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="audit-logs" element={<AuditLogsPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
};

export default App;


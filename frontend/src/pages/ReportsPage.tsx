import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  FileText,
  Download,
  ShieldCheck,
  RefreshCw,
  Plus,
  AlertCircle,
} from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { ReportMetricsCards } from "../components/reports/ReportMetricsCards";
import { ReportTable } from "../components/reports/ReportTable";
import { ReportDetailModal } from "../components/reports/ReportDetailModal";
import { ReportStatusModal } from "../components/reports/ReportStatusModal";
import { api } from "../services/api";
import {
  VulnerabilityReportListItem,
  VulnerabilityReportDetail,
  ReportLifecycleStatus,
} from "../types";

export const ReportsPage: React.FC = () => {
  const queryClient = useQueryClient();

  // State
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<string>("");
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  const [selectedReportSummary, setSelectedReportSummary] =
    useState<VulnerabilityReportListItem | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [isStatusModalOpen, setIsStatusModalOpen] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // 1. Fetch Metrics Query
  const { data: metrics, isLoading: isMetricsLoading, refetch: refetchMetrics } = useQuery({
    queryKey: ["vulnerability-reports-metrics"],
    queryFn: () => api.reports.getMetrics(),
  });

  // 2. Fetch Reports Table Query
  const {
    data: reportsData,
    isLoading: isReportsLoading,
    refetch: refetchReports,
  } = useQuery({
    queryKey: [
      "vulnerability-reports-list",
      currentPage,
      pageSize,
      searchTerm,
      selectedSeverity,
      selectedStatus,
    ],
    queryFn: () =>
      api.reports.listReports({
        page: currentPage,
        limit: pageSize,
        search: searchTerm || undefined,
        severity: selectedSeverity || undefined,
        status: selectedStatus || undefined,
      }),
  });

  // 3. Fetch Full Report Detail Query (when modal is opened)
  const {
    data: reportDetail,
    isLoading: isDetailLoading,
    refetch: refetchDetail,
  } = useQuery({
    queryKey: ["vulnerability-report-detail", selectedReportSummary?.id],
    queryFn: () =>
      selectedReportSummary
        ? api.reports.getReport(selectedReportSummary.id)
        : Promise.resolve(null),
    enabled: !!selectedReportSummary && isDetailOpen,
  });

  // 4. Update Status Mutation
  const statusMutation = useMutation({
    mutationFn: ({
      reportId,
      newStatus,
      reason,
    }: {
      reportId: string;
      newStatus: ReportLifecycleStatus;
      reason: string;
    }) => api.reports.updateStatus(reportId, { new_status: newStatus, reason }),
    onSuccess: (updatedReport) => {
      queryClient.invalidateQueries({ queryKey: ["vulnerability-reports-list"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability-reports-metrics"] });
      queryClient.invalidateQueries({
        queryKey: ["vulnerability-report-detail", selectedReportSummary?.id],
      });
      setNotification({
        type: "success",
        message: `Report ${updatedReport.report_id} status updated to ${updatedReport.status}.`,
      });
      setTimeout(() => setNotification(null), 4000);
    },
    onError: (err: any) => {
      setNotification({
        type: "error",
        message: err.response?.data?.detail || "Failed to update report status.",
      });
      setTimeout(() => setNotification(null), 5000);
    },
  });

  // Action Handlers
  const handleViewReport = (report: VulnerabilityReportListItem) => {
    setSelectedReportSummary(report);
    setIsDetailOpen(true);
  };

  const handleQuickStatusChange = (report: VulnerabilityReportListItem) => {
    setSelectedReportSummary(report);
    setIsStatusModalOpen(true);
  };

  const handleStatusSubmit = async (newStatus: ReportLifecycleStatus, reason: string) => {
    if (!selectedReportSummary) return;
    await statusMutation.mutateAsync({
      reportId: selectedReportSummary.id,
      newStatus,
      reason,
    });
  };

  const handleExportPdf = async (reportId: string) => {
    try {
      const blob = await api.reports.exportReport(reportId, "pdf");
      const url = window.URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `PHANTOM-X_${reportId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert("Failed to export PDF report: " + (err.message || "Unknown error"));
    }
  };

  const handleExportJson = async (reportId: string) => {
    try {
      const data = await api.reports.exportReport(reportId, "json");
      const jsonStr = JSON.stringify(data, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `PHANTOM-X_${reportId}.json`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert("Failed to export JSON report: " + (err.message || "Unknown error"));
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Vulnerability Intelligence Reports"
        description="Transform automated dynamic assessment findings into evidence-backed intelligence reports with reproduction guides and tamper-evident lifecycle tracking."
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                refetchMetrics();
                refetchReports();
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-300 font-mono text-xs transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh</span>
            </button>
          </div>
        }
      />

      {/* Global Notification Banner */}
      {notification && (
        <div
          className={`p-3.5 rounded-lg border text-xs flex items-center justify-between animate-in fade-in ${
            notification.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 flex-shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-slate-400 hover:text-slate-200"
          >
            &times;
          </button>
        </div>
      )}

      {/* KPI Metrics Dashboard */}
      <ReportMetricsCards
        metrics={metrics}
        isLoading={isMetricsLoading}
        selectedSeverity={selectedSeverity}
        onSeverityClick={(sev) => {
          setSelectedSeverity(sev);
          setCurrentPage(1);
        }}
      />

      {/* Reports Listing Table */}
      <ReportTable
        reports={reportsData?.items || []}
        isLoading={isReportsLoading}
        total={reportsData?.total || 0}
        page={currentPage}
        limit={pageSize}
        onPageChange={setCurrentPage}
        searchTerm={searchTerm}
        onSearchChange={(term) => {
          setSearchTerm(term);
          setCurrentPage(1);
        }}
        statusFilter={selectedStatus}
        onStatusFilterChange={(st) => {
          setSelectedStatus(st);
          setCurrentPage(1);
        }}
        onViewReport={handleViewReport}
        onQuickStatusChange={handleQuickStatusChange}
        onExportPdf={handleExportPdf}
        onExportJson={handleExportJson}
      />

      {/* Detailed Report View Modal */}
      <ReportDetailModal
        isOpen={isDetailOpen}
        onClose={() => setIsDetailOpen(false)}
        report={reportDetail || null}
        isLoading={isDetailLoading}
        onOpenStatusModal={() => setIsStatusModalOpen(true)}
        onExportPdf={handleExportPdf}
        onExportJson={handleExportJson}
      />

      {/* Quick Status Transition Modal */}
      <ReportStatusModal
        isOpen={isStatusModalOpen}
        onClose={() => setIsStatusModalOpen(false)}
        report={reportDetail || selectedReportSummary}
        onUpdateStatus={handleStatusSubmit}
      />
    </div>
  );
};

export default ReportsPage;

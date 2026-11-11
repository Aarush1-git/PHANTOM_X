import React from "react";
import {
  Search,
  Filter,
  Eye,
  Download,
  FileCode,
  ArrowUpDown,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import { VulnerabilityReportListItem, ReportLifecycleStatus } from "../../types";
import { ReportSeverityBadge, ReportStatusBadge, ReportCvssBadge } from "./ReportBadge";

interface ReportTableProps {
  reports: VulnerabilityReportListItem[];
  isLoading: boolean;
  total: number;
  page: number;
  limit: number;
  onPageChange: (newPage: number) => void;
  searchTerm: string;
  onSearchChange: (value: string) => void;
  statusFilter: string;
  onStatusFilterChange: (status: string) => void;
  onViewReport: (report: VulnerabilityReportListItem) => void;
  onQuickStatusChange: (report: VulnerabilityReportListItem) => void;
  onExportPdf: (reportId: string) => void;
  onExportJson: (reportId: string) => void;
}

export const ReportTable: React.FC<ReportTableProps> = ({
  reports,
  isLoading,
  total,
  page,
  limit,
  onPageChange,
  searchTerm,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  onViewReport,
  onQuickStatusChange,
  onExportPdf,
  onExportJson,
}) => {
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col">
      {/* Table Toolbar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
        <div className="flex items-center gap-2 flex-1 min-w-[240px] max-w-md">
          <div className="relative w-full">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search by title, report ID, endpoint, CWE..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Status:</span>
          </div>
          <select
            value={statusFilter}
            onChange={(e) => onStatusFilterChange(e.target.value)}
            className="rounded-lg bg-slate-900 border border-slate-800 px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="FIXED">Fixed</option>
            <option value="ACCEPTED_RISK">Accepted Risk</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="REOPENED">Reopened</option>
          </select>
        </div>
      </div>

      {/* Table Element */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-semibold text-slate-400 font-mono uppercase tracking-wider">
              <th className="py-3 px-4">Report ID</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">CVSS</th>
              <th className="py-3 px-4">Vulnerability Finding</th>
              <th className="py-3 px-4">Target Endpoint</th>
              <th className="py-3 px-4">Application</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Discovered</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
            {isLoading ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-500">
                  <div className="flex items-center justify-center gap-2">
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>Loading security intelligence reports...</span>
                  </div>
                </td>
              </tr>
            ) : reports.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-500">
                  <p className="text-sm font-sans font-medium text-slate-400">No vulnerability reports found.</p>
                  <p className="text-xs text-slate-500 mt-1 font-sans">
                    Run an automated security scan or generate reports from upstream findings.
                  </p>
                </td>
              </tr>
            ) : (
              reports.map((rep) => (
                <tr
                  key={rep.id}
                  className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                  onClick={() => onViewReport(rep)}
                >
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="text-cyan-400 font-bold hover:underline flex items-center gap-1">
                      {rep.report_id}
                    </span>
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <ReportSeverityBadge severity={rep.severity} />
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <ReportCvssBadge score={rep.cvss_score} />
                  </td>

                  <td className="py-3 px-4 max-w-xs">
                    <div className="font-sans font-semibold text-slate-200 line-clamp-1 group-hover:text-cyan-300 transition-colors">
                      {rep.title}
                    </div>
                    {rep.cwe_id && (
                      <span className="text-[10px] text-slate-500 font-mono">
                        {rep.cwe_id}
                      </span>
                    )}
                  </td>

                  <td className="py-3 px-4 max-w-[200px] truncate" title={rep.endpoint}>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold mr-1.5">
                      {rep.http_method || "GET"}
                    </span>
                    <span className="text-slate-300">{rep.endpoint}</span>
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                    {rep.application_name || "Primary Gateway"}
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <ReportStatusBadge status={rep.status} />
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap text-slate-500 text-[11px]">
                    {new Date(rep.created_at).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </td>

                  <td
                    className="py-3 px-4 whitespace-nowrap text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-center justify-end gap-1">
                      <button
                        title="View Full Report"
                        onClick={() => onViewReport(rep)}
                        className="p-1.5 rounded text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      <button
                        title="Update Lifecycle Status"
                        onClick={() => onQuickStatusChange(rep)}
                        className="p-1.5 rounded text-slate-400 hover:text-amber-300 hover:bg-slate-800 transition-colors"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                      </button>

                      <button
                        title="Export PDF"
                        onClick={() => onExportPdf(rep.report_id)}
                        className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>

                      <button
                        title="Export JSON"
                        onClick={() => onExportJson(rep.report_id)}
                        className="p-1.5 rounded text-slate-400 hover:text-sky-400 hover:bg-slate-800 transition-colors"
                      >
                        <FileCode className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div className="p-3.5 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 bg-slate-950/40">
        <div>
          Showing{" "}
          <span className="font-mono font-bold text-slate-200">
            {reports.length > 0 ? (page - 1) * limit + 1 : 0}
          </span>{" "}
          to{" "}
          <span className="font-mono font-bold text-slate-200">
            {Math.min(page * limit, total)}
          </span>{" "}
          of <span className="font-mono font-bold text-slate-200">{total}</span> reports
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1 || isLoading}
            className="px-2.5 py-1 rounded border border-slate-800 text-xs font-medium hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Previous
          </button>
          <span className="font-mono text-slate-300">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages || isLoading}
            className="px-2.5 py-1 rounded border border-slate-800 text-xs font-medium hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
};


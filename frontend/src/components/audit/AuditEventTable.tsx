import React, { useState } from "react";
import { AuditLogResponse } from "../../types";
import { AuditCategoryBadge, AuditStatusBadge, AuditSeverityBadge } from "./AuditBadge";
import { Search, Filter, Download, ChevronLeft, ChevronRight, Eye } from "lucide-react";

interface AuditEventTableProps {
  events: AuditLogResponse[];
  isLoading: boolean;
  onSelectEvent: (event: AuditLogResponse) => void;
  onExport: () => void;
  onRefresh: () => void;
}

export const AuditEventTable: React.FC<AuditEventTableProps> = ({
  events,
  isLoading,
  onSelectEvent,
  onExport,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [page, setPage] = useState<number>(1);
  const pageSize = 15;

  const filteredEvents = events.filter((ev) => {
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      ev.action?.toLowerCase().includes(term) ||
      ev.event_type?.toLowerCase().includes(term) ||
      ev.actor_email?.toLowerCase().includes(term) ||
      ev.target_type?.toLowerCase().includes(term) ||
      ev.target_id?.toLowerCase().includes(term);

    const matchesCategory = categoryFilter ? ev.category === categoryFilter : true;
    const matchesStatus = statusFilter ? ev.status === statusFilter : true;
    const matchesSeverity = severityFilter ? ev.severity === severityFilter : true;

    return matchesSearch && matchesCategory && matchesStatus && matchesSeverity;
  });

  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = filteredEvents.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-3">
      {/* Search & Filter Controls */}
      <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-3">
        <div className="flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Search by action, actor, target..."
              className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">All Categories</option>
              <option value="AUTHENTICATION">Authentication</option>
              <option value="APPLICATION_MANAGEMENT">Application Mgmt</option>
              <option value="AUTHORIZATION">Authorization</option>
              <option value="SECURITY_TESTING">Security Testing</option>
              <option value="VULNERABILITY">Vulnerability</option>
              <option value="PLATFORM">Platform</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">All Statuses</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
              <option value="BLOCKED">Blocked</option>
            </select>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">All Severities</option>
              <option value="INFO">Info</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>

            {/* Export */}
            <button
              onClick={onExport}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-300 bg-slate-950 border border-slate-800 hover:bg-slate-800 rounded transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
        {paginatedEvents.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <Filter className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">No Matching Audit Events</p>
            <p className="text-xs text-slate-500">Try adjusting your filters or search query.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3.5">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3.5">Category</th>
                  <th className="py-2.5 px-3.5">Action & Event Type</th>
                  <th className="py-2.5 px-3.5">Actor</th>
                  <th className="py-2.5 px-3.5">Target</th>
                  <th className="py-2.5 px-3.5">Status</th>
                  <th className="py-2.5 px-3.5">Severity</th>
                  <th className="py-2.5 px-3.5 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {paginatedEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => onSelectEvent(ev)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-3.5 font-mono text-slate-400 whitespace-nowrap text-[11px]">
                      {new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <AuditCategoryBadge category={ev.category} />
                    </td>
                    <td className="py-2.5 px-3.5 max-w-xs truncate">
                      <div className="font-mono text-xs font-semibold text-slate-200 truncate">{ev.event_type}</div>
                      <div className="text-[11px] text-slate-400 truncate">{ev.action}</div>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11px] whitespace-nowrap">
                      {ev.actor_email || "System"}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-slate-400 text-[11px] max-w-[120px] truncate">
                      {ev.target_type}
                    </td>
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <AuditStatusBadge status={ev.status} />
                    </td>
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <AuditSeverityBadge severity={ev.severity} />
                    </td>
                    <td className="py-2.5 px-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev);
                        }}
                        className="text-slate-400 hover:text-cyan-400 p-1 rounded hover:bg-slate-800 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400">
          <span>
            Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, filteredEvents.length)} of{" "}
            {filteredEvents.length} events
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page <= 1}
              className="p-1 rounded bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-slate-300 font-bold">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= totalPages}
              className="p-1 rounded bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-800 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};


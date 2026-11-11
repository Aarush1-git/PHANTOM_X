import React from "react";
import { Calendar, Filter, RotateCcw, Server } from "lucide-react";
import { DashboardFilterParams } from "../../types/dashboard";

interface ApplicationOption {
  id: string;
  name: string;
}

interface DashboardFiltersProps {
  filters: DashboardFilterParams;
  onFilterChange: (updated: Partial<DashboardFilterParams>) => void;
  onRefresh: () => void;
  applications: ApplicationOption[];
  isRefreshing?: boolean;
}

export const DashboardFilters: React.FC<DashboardFiltersProps> = ({
  filters,
  onFilterChange,
  onRefresh,
  applications,
  isRefreshing = false,
}) => {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 sm:p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm backdrop-blur">
      <div className="flex flex-wrap items-center gap-3">
        {/* Time Range Selector */}
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="text-xs font-medium text-slate-400">Window:</span>
          <div className="inline-flex rounded-md shadow-sm bg-slate-950 p-0.5 border border-slate-800">
            {(["7d", "30d", "90d"] as const).map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => onFilterChange({ time_range: range })}
                className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                  filters.time_range === range
                    ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {range === "7d" ? "7 Days" : range === "30d" ? "30 Days" : "90 Days"}
              </button>
            ))}
          </div>
        </div>

        {/* Application Selector */}
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-slate-400 shrink-0" />
          <select
            aria-label="Filter by Application"
            value={filters.application_id || ""}
            onChange={(e) =>
              onFilterChange({ application_id: e.target.value ? e.target.value : undefined })
            }
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="">All Applications (Scope)</option>
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Selector */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400 shrink-0" />
          <select
            aria-label="Filter by Severity"
            value={filters.severity || ""}
            onChange={(e) =>
              onFilterChange({ severity: e.target.value ? e.target.value : undefined })
            }
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors border border-slate-700 disabled:opacity-50"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>
    </div>
  );
};

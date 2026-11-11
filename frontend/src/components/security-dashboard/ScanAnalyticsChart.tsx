import React from "react";
import { Radar, CheckCircle2, XCircle, Clock, Activity, Info } from "lucide-react";
import { ScanAnalyticsResponse } from "../../types/dashboard";

interface ScanAnalyticsChartProps {
  data?: ScanAnalyticsResponse;
  isLoading?: boolean;
}

export const ScanAnalyticsChart: React.FC<ScanAnalyticsChartProps> = ({
  data,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 animate-pulse h-80 flex flex-col justify-between" />
    );
  }

  const total = data?.total_scans || 0;
  const completed = data?.completed_scans || 0;
  const failed = data?.failed_scans || 0;
  const running = data?.running_scans || 0;
  const successRate = data?.success_rate || 0;
  const avgDuration = data?.average_duration_formatted || "Unavailable";
  const recentScans = data?.recent_scans || [];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col h-full shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Radar className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Scan Execution & Telemetry</h3>
        </div>
        <span className="text-xs font-mono text-slate-400">Total Runs: {total}</span>
      </div>

      {total === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-10 text-slate-500">
          <Info className="w-8 h-8 text-slate-600 mb-2" />
          <p className="text-xs">No scan executions recorded in this time range.</p>
        </div>
      ) : (
        <div className="pt-4 space-y-4">
          {/* Key Scan KPI Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="bg-slate-950/80 border border-slate-800 rounded p-2.5">
              <span className="text-[11px] text-slate-400 font-medium block">Success Rate</span>
              <span className="text-lg font-bold font-mono text-emerald-400 mt-1 block">
                {successRate}%
              </span>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded p-2.5">
              <span className="text-[11px] text-slate-400 font-medium block">Avg Duration</span>
              <span className="text-sm font-bold font-mono text-cyan-400 mt-1.5 block truncate">
                {avgDuration}
              </span>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded p-2.5">
              <span className="text-[11px] text-slate-400 font-medium block">Completed</span>
              <span className="text-lg font-bold font-mono text-slate-200 mt-1 block">
                {completed}
              </span>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded p-2.5">
              <span className="text-[11px] text-slate-400 font-medium block">Failed / Errors</span>
              <span className="text-lg font-bold font-mono text-rose-400 mt-1 block">
                {failed}
              </span>
            </div>
          </div>

          {/* Recent Scans Micro-Feed */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider font-mono">
              Recent Execution Runs
            </h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {recentScans.slice(0, 5).map((scan) => (
                <div
                  key={scan.id}
                  className="bg-slate-950/60 border border-slate-800/80 rounded px-3 py-2 flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2 truncate mr-2">
                    {scan.status === "COMPLETED" ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : scan.status === "FAILED" ? (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : (
                      <Activity className="w-3.5 h-3.5 text-cyan-400 animate-spin shrink-0" />
                    )}
                    <span className="font-medium text-slate-200 truncate">{scan.application_name}</span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 font-mono text-[11px]">
                    {scan.duration_seconds !== null && scan.duration_seconds !== undefined && (
                      <span className="text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {Math.round(scan.duration_seconds)}s
                      </span>
                    )}
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        scan.status === "COMPLETED"
                          ? "bg-emerald-500/10 text-emerald-400"
                          : scan.status === "FAILED"
                          ? "bg-rose-500/10 text-rose-400"
                          : "bg-cyan-500/10 text-cyan-400"
                      }`}
                    >
                      {scan.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};


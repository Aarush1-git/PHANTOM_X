import React from "react";
import { Activity, ShieldAlert, CheckCircle2, XCircle, ShieldX, User, Server, Info } from "lucide-react";
import { RecentActivityItem } from "../../types/dashboard";

interface SecurityActivityTimelineProps {
  activities?: RecentActivityItem[];
  isLoading?: boolean;
}

export const SecurityActivityTimeline: React.FC<SecurityActivityTimelineProps> = ({
  activities = [],
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 animate-pulse h-96 flex flex-col justify-between" />
    );
  }

  const getActivityIcon = (type: string, severity: string) => {
    if (type === "BLOCKED_EXECUTION") {
      return <ShieldX className="w-4 h-4 text-rose-400" />;
    }
    if (type.includes("SCAN_COMPLETED")) {
      return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    }
    if (type.includes("FAILED")) {
      return <XCircle className="w-4 h-4 text-rose-400" />;
    }
    if (type.includes("VULNERABILITY") || type.includes("REPORT")) {
      return <ShieldAlert className="w-4 h-4 text-cyan-400" />;
    }
    return <Activity className="w-4 h-4 text-slate-400" />;
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      case "HIGH":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "MEDIUM":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      case "LOW":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col h-full shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Recent Security Activity Stream</h3>
        </div>
        <span className="text-xs font-mono text-slate-400">{activities.length} Recorded Events</span>
      </div>

      {activities.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-10 text-slate-500">
          <Info className="w-8 h-8 text-slate-600 mb-2" />
          <p className="text-xs">No recent security events recorded.</p>
        </div>
      ) : (
        <div className="pt-4 space-y-3 max-h-96 overflow-y-auto pr-2">
          {activities.map((act) => {
            const timeFormatted = new Date(act.timestamp).toLocaleString(undefined, {
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            });

            return (
              <div
                key={act.id}
                className="bg-slate-950/70 border border-slate-800/80 rounded p-3 flex items-start gap-3 hover:border-slate-700 transition-colors text-xs"
              >
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 shrink-0 mt-0.5">
                  {getActivityIcon(act.activity_type, act.severity)}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-slate-200 truncate">{act.title}</span>
                    <span className="text-[11px] font-mono text-slate-500">{timeFormatted}</span>
                  </div>

                  <p className="text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                    {act.description}
                  </p>

                  <div className="flex flex-wrap items-center gap-3 mt-2 font-mono text-[11px]">
                    <span
                      className={`px-1.5 py-0.2 rounded border text-[10px] font-semibold ${getSeverityBadgeClass(
                        act.severity
                      )}`}
                    >
                      {act.severity}
                    </span>

                    {act.application_name && (
                      <span className="text-slate-400 flex items-center gap-1">
                        <Server className="w-3 h-3 text-slate-500" />
                        <span>{act.application_name}</span>
                      </span>
                    )}

                    {act.actor_email && (
                      <span className="text-slate-500 flex items-center gap-1 truncate max-w-[200px]">
                        <User className="w-3 h-3 text-slate-600" />
                        <span className="truncate">{act.actor_email}</span>
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};


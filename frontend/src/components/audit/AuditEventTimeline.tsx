import React from "react";
import { AuditLogResponse } from "../../types";
import { AuditCategoryBadge, AuditStatusBadge, AuditSeverityBadge } from "./AuditBadge";
import {
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  FileCode,
  AlertTriangle,
  Settings,
  Circle,
  Clock,
} from "lucide-react";

interface AuditEventTimelineProps {
  events: AuditLogResponse[];
  onSelectEvent: (event: AuditLogResponse) => void;
}

export const AuditEventTimeline: React.FC<AuditEventTimelineProps> = ({ events, onSelectEvent }) => {
  const getCategoryIcon = (category?: string) => {
    switch (category) {
      case "AUTHENTICATION":
        return <KeyRound className="w-3.5 h-3.5 text-blue-400" />;
      case "APPLICATION_MANAGEMENT":
        return <FileCode className="w-3.5 h-3.5 text-indigo-400" />;
      case "AUTHORIZATION":
        return <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />;
      case "SECURITY_TESTING":
        return <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />;
      case "VULNERABILITY":
        return <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />;
      default:
        return <Settings className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  if (events.length === 0) {
    return (
      <div className="p-8 text-center bg-phantom-900 border border-slate-800 rounded-lg text-slate-500 font-mono text-xs">
        No recent timeline events found.
      </div>
    );
  }

  return (
    <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
      <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <Clock className="w-4 h-4 text-cyan-400" />
        Chronological Decision & Execution Timeline
      </h3>

      <div className="relative border-l border-slate-800 ml-3 space-y-6 pt-2">
        {events.slice(0, 30).map((ev) => (
          <div
            key={ev.id}
            onClick={() => onSelectEvent(ev)}
            className="relative pl-6 group cursor-pointer"
          >
            {/* Timeline node icon */}
            <div className="absolute -left-3 top-0.5 w-6 h-6 rounded-full bg-slate-950 border border-slate-800 flex items-center justify-center group-hover:border-cyan-400 transition-colors">
              {getCategoryIcon(ev.category)}
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 group-hover:border-slate-700 p-3 rounded-lg space-y-1.5 transition-colors">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs font-bold text-slate-200 group-hover:text-cyan-400 transition-colors">
                  {ev.event_type}
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {new Date(ev.created_at).toLocaleTimeString()} ({new Date(ev.created_at).toLocaleDateString()})
                </span>
              </div>

              <p className="text-xs text-slate-300">{ev.action}</p>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                <AuditCategoryBadge category={ev.category} />
                <AuditStatusBadge status={ev.status} />
                <AuditSeverityBadge severity={ev.severity} />
                <span className="text-[11px] text-slate-500 font-mono">
                  Actor: <strong className="text-slate-400">{ev.actor_email || "System"}</strong>
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};


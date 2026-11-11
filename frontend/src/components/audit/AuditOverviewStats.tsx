import React from "react";
import { AuditOverviewResponse } from "../../types";
import { ScrollText, CheckCircle2, XCircle, ShieldAlert, AlertTriangle } from "lucide-react";

interface AuditOverviewStatsProps {
  overview: AuditOverviewResponse | null;
  isLoading: boolean;
}

export const AuditOverviewStats: React.FC<AuditOverviewStatsProps> = ({ overview, isLoading }) => {
  if (isLoading || !overview) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="bg-phantom-900 border border-slate-800 rounded p-4 animate-pulse h-20" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
        {/* Total Events */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono">TOTAL EVENTS</span>
            <ScrollText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-100">{overview.total_events}</div>
          <p className="text-[10px] text-slate-500">Immutable ledger events</p>
        </div>

        {/* Successful Operations */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono">SUCCESSFUL</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">{overview.successful_events}</div>
          <p className="text-[10px] text-slate-500">Normal operations</p>
        </div>

        {/* Failed Operations */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono">FAILED</span>
            <XCircle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400">{overview.failed_events}</div>
          <p className="text-[10px] text-slate-500">Errors & auth rejections</p>
        </div>

        {/* Blocked Actions */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono">BLOCKED ACTIONS</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">{overview.blocked_events}</div>
          <p className="text-[10px] text-slate-500">Safety policy intercepts</p>
        </div>

        {/* Critical Security Events */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono">CRITICAL SEVERITY</span>
            <AlertTriangle className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-300">{overview.critical_events}</div>
          <p className="text-[10px] text-slate-500">High-priority alerts</p>
        </div>
      </div>

      {/* Category breakdown pills */}
      {overview.categories_breakdown && Object.keys(overview.categories_breakdown).length > 0 && (
        <div className="bg-slate-950 border border-slate-800/80 rounded px-3 py-2 flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="text-[11px] text-slate-500 mr-1">Activity by Category:</span>
          {Object.entries(overview.categories_breakdown).map(([cat, count]) => (
            <span key={cat} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
              {cat}: <strong className="text-cyan-400 font-bold">{count}</strong>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};


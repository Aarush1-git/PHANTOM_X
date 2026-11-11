import React from "react";
import { ShieldAlert, AlertTriangle, CheckCircle2, Server, Radar, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { SecurityOverviewMetrics } from "../../types/dashboard";

interface SecurityOverviewCardsProps {
  metrics?: SecurityOverviewMetrics;
  isLoading?: boolean;
}

export const SecurityOverviewCards: React.FC<SecurityOverviewCardsProps> = ({
  metrics,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="bg-slate-900 border border-slate-800 rounded-lg p-4 animate-pulse h-28" />
        ))}
      </div>
    );
  }

  if (!metrics) {
    return null;
  }

  const delta = metrics.vulnerabilities_delta_pct;
  const isDeltaPositive = delta !== null && delta !== undefined && delta > 0;
  const isDeltaNegative = delta !== null && delta !== undefined && delta < 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {/* 1. Total Discovered Vulnerabilities */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-slate-700 transition-colors shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Total Vulnerabilities</span>
          <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <span className="text-2xl font-bold font-mono text-slate-100">{metrics.total_vulnerabilities}</span>
          {delta !== null && delta !== undefined && (
            <span
              className={`inline-flex items-center gap-0.5 text-[11px] font-mono px-1.5 py-0.5 rounded ${
                isDeltaPositive
                  ? "bg-rose-500/10 text-rose-400"
                  : isDeltaNegative
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "bg-slate-800 text-slate-400"
              }`}
            >
              {isDeltaPositive ? (
                <TrendingUp className="w-3 h-3" />
              ) : isDeltaNegative ? (
                <TrendingDown className="w-3 h-3" />
              ) : (
                <Minus className="w-3 h-3" />
              )}
              <span>{Math.abs(delta)}%</span>
            </span>
          )}
        </div>
        <div className="mt-2 text-[11px] text-slate-500 flex items-center justify-between">
          <span>Open: {metrics.open_count}</span>
          <span>Fixed: {metrics.fixed_count}</span>
        </div>
      </div>

      {/* 2. Critical & High Exposure */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-rose-500/30 transition-colors shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Critical / High Open</span>
          <div className="p-1.5 rounded bg-rose-500/10 text-rose-400">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-rose-400">{metrics.critical_and_high_open}</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 flex items-center justify-between">
          <span className="text-rose-400/90 font-medium">{metrics.critical_count} Critical</span>
          <span className="text-amber-400/90 font-medium">{metrics.high_count} High</span>
        </div>
      </div>

      {/* 3. Remediation Rate */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-emerald-500/30 transition-colors shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Remediation Rate</span>
          <div className="p-1.5 rounded bg-emerald-500/10 text-emerald-400">
            <CheckCircle2 className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-emerald-400">{metrics.remediation_rate}%</span>
        </div>
        {/* Progress Bar */}
        <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
          <div
            className="bg-emerald-500 h-1.5 rounded-full transition-all duration-500"
            style={{ width: `${Math.min(100, Math.max(0, metrics.remediation_rate))}%` }}
          />
        </div>
      </div>

      {/* 4. Target Applications */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-slate-700 transition-colors shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Target Applications</span>
          <div className="p-1.5 rounded bg-blue-500/10 text-blue-400">
            <Server className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-slate-100">{metrics.total_applications}</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500">
          <span>Active in enterprise scope</span>
        </div>
      </div>

      {/* 5. Security Scans */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-slate-700 transition-colors shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Security Scans</span>
          <div className="p-1.5 rounded bg-purple-500/10 text-purple-400">
            <Radar className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-slate-100">{metrics.total_scans}</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500">
          <span>Autonomous test runs</span>
        </div>
      </div>
    </div>
  );
};

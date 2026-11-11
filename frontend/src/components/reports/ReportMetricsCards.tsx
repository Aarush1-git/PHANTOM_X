import React from "react";
import {
  FileText,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import { ReportDashboardMetrics } from "../../types";

interface ReportMetricsCardsProps {
  metrics?: ReportDashboardMetrics;
  isLoading: boolean;
  onSeverityClick?: (severity: string) => void;
  selectedSeverity?: string;
}

export const ReportMetricsCards: React.FC<ReportMetricsCardsProps> = ({
  metrics,
  isLoading,
  onSeverityClick,
  selectedSeverity,
}) => {
  const total = metrics?.total_reports ?? 0;
  const critical = metrics?.severity_distribution?.CRITICAL ?? 0;
  const high = metrics?.severity_distribution?.HIGH ?? 0;
  const medium = metrics?.severity_distribution?.MEDIUM ?? 0;
  const low = metrics?.severity_distribution?.LOW ?? 0;
  const info = metrics?.severity_distribution?.INFO ?? 0;

  const openCount = metrics?.status_distribution?.OPEN ?? 0;
  const inProgress = metrics?.status_distribution?.IN_PROGRESS ?? 0;
  const fixedCount = metrics?.status_distribution?.FIXED ?? 0;
  const accepted = metrics?.status_distribution?.ACCEPTED_RISK ?? 0;
  const remediationRate = metrics?.remediation_rate ?? 0.0;
  const criticalHighOpen = metrics?.critical_and_high_open ?? (critical + high);

  return (
    <div className="space-y-4">
      {/* Primary KPI Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3.5">
        {/* 1. Total Intelligence Reports */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Reports</span>
            <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-400">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {isLoading ? "..." : total}
            </span>
            <span className="text-[11px] text-slate-500">verified findings</span>
          </div>
        </div>

        {/* 2. Critical & High Active Exposure */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical / High Open</span>
            <div className="p-1.5 rounded bg-red-500/10 text-red-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-red-400">
              {isLoading ? "..." : criticalHighOpen}
            </span>
            <span className="text-[11px] text-red-400/80 font-mono">active threats</span>
          </div>
        </div>

        {/* 3. In Progress / Under Triage */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">In Remediation</span>
            <div className="p-1.5 rounded bg-amber-500/10 text-amber-400">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300">
              {isLoading ? "..." : inProgress + openCount}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">
              {openCount} open / {inProgress} triage
            </span>
          </div>
        </div>

        {/* 4. Resolved / Mitigated */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Remediated Findings</span>
            <div className="p-1.5 rounded bg-emerald-500/10 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {isLoading ? "..." : fixedCount}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">
              +{accepted} accepted
            </span>
          </div>
        </div>

        {/* 5. Remediation Rate % */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-sm col-span-2 md:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Remediation Rate</span>
            <div className="p-1.5 rounded bg-sky-500/10 text-sky-400">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-sky-400">
              {isLoading ? "..." : `${remediationRate}%`}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">closed posture</span>
          </div>
        </div>
      </div>

      {/* Severity Filter Quick-Bar */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-2.5 flex items-center justify-between flex-wrap gap-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-medium text-xs flex items-center gap-1.5 pl-1">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            Severity Posture:
          </span>
          <button
            onClick={() => onSeverityClick?.("")}
            className={`px-2 py-1 rounded font-mono text-xs transition-colors ${
              !selectedSeverity
                ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            }`}
          >
            All ({total})
          </button>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={() => onSeverityClick?.("CRITICAL")}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-all flex items-center gap-1.5 border ${
              selectedSeverity === "CRITICAL"
                ? "bg-red-500/20 text-red-300 border-red-500/50 font-bold"
                : "bg-red-950/20 text-red-400/80 border-red-900/30 hover:border-red-700/50"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
            Critical <span className="font-bold">({critical})</span>
          </button>

          <button
            onClick={() => onSeverityClick?.("HIGH")}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-all flex items-center gap-1.5 border ${
              selectedSeverity === "HIGH"
                ? "bg-orange-500/20 text-orange-300 border-orange-500/50 font-bold"
                : "bg-orange-950/20 text-orange-400/80 border-orange-900/30 hover:border-orange-700/50"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />
            High <span className="font-bold">({high})</span>
          </button>

          <button
            onClick={() => onSeverityClick?.("MEDIUM")}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-all flex items-center gap-1.5 border ${
              selectedSeverity === "MEDIUM"
                ? "bg-amber-500/20 text-amber-300 border-amber-500/50 font-bold"
                : "bg-amber-950/20 text-amber-400/80 border-amber-900/30 hover:border-amber-700/50"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            Medium <span className="font-bold">({medium})</span>
          </button>

          <button
            onClick={() => onSeverityClick?.("LOW")}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-all flex items-center gap-1.5 border ${
              selectedSeverity === "LOW"
                ? "bg-blue-500/20 text-blue-300 border-blue-500/50 font-bold"
                : "bg-blue-950/20 text-blue-400/80 border-blue-900/30 hover:border-blue-700/50"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
            Low <span className="font-bold">({low})</span>
          </button>

          <button
            onClick={() => onSeverityClick?.("INFO")}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-all flex items-center gap-1.5 border ${
              selectedSeverity === "INFO"
                ? "bg-slate-500/20 text-slate-300 border-slate-500/50 font-bold"
                : "bg-slate-800/40 text-slate-400 border-slate-700/40 hover:border-slate-600"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
            Info <span className="font-bold">({info})</span>
          </button>
        </div>
      </div>
    </div>
  );
};


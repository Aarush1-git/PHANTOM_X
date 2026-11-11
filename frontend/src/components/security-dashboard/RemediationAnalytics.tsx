import React from "react";
import { CheckCircle2, Clock, AlertOctagon, Hourglass, Info } from "lucide-react";
import { RemediationAnalyticsResponse } from "../../types/dashboard";

interface RemediationAnalyticsProps {
  data?: RemediationAnalyticsResponse;
  isLoading?: boolean;
}

export const RemediationAnalytics: React.FC<RemediationAnalyticsProps> = ({
  data,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 animate-pulse h-80 flex flex-col justify-between" />
    );
  }

  const hasData = data?.has_remediation_data ?? false;
  const mttrDays = data?.mean_time_to_remediation_days;
  const mttrHours = data?.mean_time_to_remediation_hours;
  const ageing = data?.open_vulnerabilities_ageing || {
    under_7_days: 0,
    days_7_to_30: 0,
    days_30_to_90: 0,
    over_90_days: 0,
  };
  const awaitingRemediation = data?.vulnerabilities_awaiting_remediation ?? 0;
  const slaBreaches = data?.sla_breach_count ?? 0;
  const progressPct = data?.remediation_progress_percentage ?? 100.0;

  const totalAgeing =
    ageing.under_7_days + ageing.days_7_to_30 + ageing.days_30_to_90 + ageing.over_90_days;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col h-full shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Remediation Velocity & Ageing</h3>
        </div>
        {slaBreaches > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[11px] font-mono">
            <AlertOctagon className="w-3 h-3" />
            <span>{slaBreaches} SLA Breaches</span>
          </span>
        )}
      </div>

      <div className="pt-4 space-y-5">
        {/* MTTR & Awaiting Stat Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* MTTR */}
          <div className="bg-slate-950/80 border border-slate-800 rounded p-3 text-center sm:text-left">
            <span className="text-[11px] text-slate-400 font-medium block">Mean Time to Remediate</span>
            {hasData && mttrDays !== null && mttrDays !== undefined ? (
              <div className="mt-1 flex items-baseline gap-1">
                <span className="text-xl font-bold font-mono text-emerald-400">{mttrDays}</span>
                <span className="text-xs text-slate-500 font-mono">days ({mttrHours}h)</span>
              </div>
            ) : (
              <span className="text-xs font-mono text-slate-500 mt-1 block">
                {data?.remediation_notes || "No resolved findings"}
              </span>
            )}
          </div>

          {/* Vulnerabilities Awaiting Fix */}
          <div className="bg-slate-950/80 border border-slate-800 rounded p-3 text-center sm:text-left">
            <span className="text-[11px] text-slate-400 font-medium block">Awaiting Remediation</span>
            <div className="mt-1">
              <span className="text-xl font-bold font-mono text-amber-400">{awaitingRemediation}</span>
              <span className="text-xs text-slate-500 font-mono ml-1">open findings</span>
            </div>
          </div>

          {/* Remediation Progress */}
          <div className="bg-slate-950/80 border border-slate-800 rounded p-3 text-center sm:text-left">
            <span className="text-[11px] text-slate-400 font-medium block">Progress to Baseline</span>
            <div className="mt-1">
              <span className="text-xl font-bold font-mono text-cyan-400">{progressPct}%</span>
            </div>
          </div>
        </div>

        {/* Ageing Breakdown */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
              <Hourglass className="w-3.5 h-3.5 text-slate-400" />
              <span>Open Finding Ageing Breakdown</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">Total Open: {totalAgeing}</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            {/* < 7 Days */}
            <div>
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span>&lt; 7 Days (Fresh)</span>
                <span className="text-emerald-400">{ageing.under_7_days}</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-emerald-500 h-1.5 rounded-full"
                  style={{ width: `${totalAgeing > 0 ? (ageing.under_7_days / totalAgeing) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* 7 - 30 Days */}
            <div>
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span>7 - 30 Days</span>
                <span className="text-cyan-400">{ageing.days_7_to_30}</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-cyan-500 h-1.5 rounded-full"
                  style={{ width: `${totalAgeing > 0 ? (ageing.days_7_to_30 / totalAgeing) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* 30 - 90 Days */}
            <div>
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span>30 - 90 Days (Stale)</span>
                <span className="text-amber-400">{ageing.days_30_to_90}</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-amber-500 h-1.5 rounded-full"
                  style={{ width: `${totalAgeing > 0 ? (ageing.days_30_to_90 / totalAgeing) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* > 90 Days */}
            <div>
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span>&gt; 90 Days (Critical Backlog)</span>
                <span className="text-rose-400">{ageing.over_90_days}</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-rose-500 h-1.5 rounded-full"
                  style={{ width: `${totalAgeing > 0 ? (ageing.over_90_days / totalAgeing) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};


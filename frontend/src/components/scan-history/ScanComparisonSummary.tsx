import React from 'react';
import { ShieldCheck, AlertTriangle, Minus, TrendingUp, TrendingDown, CheckCircle2, RefreshCw } from 'lucide-react';
import { ScanComparisonSummary as SummaryType } from '../../types/scanHistory';

interface Props {
  summary: SummaryType;
}

export const ScanComparisonSummary: React.FC<Props> = ({ summary }) => {
  const isImproved = summary.posture_change === 'IMPROVED';
  const isDegraded = summary.posture_change === 'DEGRADED';

  const verdictStyles = isImproved
    ? {
        border: 'border-emerald-500/40',
        bg: 'bg-emerald-950/40',
        text: 'text-emerald-400',
        icon: ShieldCheck,
        badgeBg: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80',
      }
    : isDegraded
    ? {
        border: 'border-rose-500/40',
        bg: 'bg-rose-950/40',
        text: 'text-rose-400',
        icon: AlertTriangle,
        badgeBg: 'bg-rose-950/80 text-rose-300 border-rose-700/80',
      }
    : {
        border: 'border-slate-700/80',
        bg: 'bg-slate-900/60',
        text: 'text-slate-300',
        icon: Minus,
        badgeBg: 'bg-slate-800 text-slate-300 border-slate-700',
      };

  const VerdictIcon = verdictStyles.icon;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm backdrop-blur-sm space-y-5">
      {/* Posture Verdict Banner */}
      <div className={`p-4 rounded-xl border ${verdictStyles.border} ${verdictStyles.bg} flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4`}>
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-lg bg-slate-950/60 border ${verdictStyles.border} flex-shrink-0 mt-0.5 sm:mt-0`}>
            <VerdictIcon className={`w-6 h-6 ${verdictStyles.text}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wider font-bold text-slate-400">Security Posture Trajectory</span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${verdictStyles.badgeBg}`}>
                {summary.posture_change}
              </span>
            </div>
            <p className="text-sm text-slate-200 mt-1 leading-relaxed">
              {summary.posture_explanation}
            </p>
          </div>
        </div>

        {/* Net Change Pill */}
        <div className="text-right sm:text-right flex-shrink-0 self-end sm:self-center">
          <span className="text-[11px] text-slate-400 block font-mono">Net Finding Delta</span>
          <span
            className={`text-xl font-bold font-mono ${
              summary.net_finding_change > 0
                ? 'text-rose-400'
                : summary.net_finding_change < 0
                ? 'text-emerald-400'
                : 'text-slate-300'
            }`}
          >
            {summary.net_finding_change > 0 ? `+${summary.net_finding_change}` : summary.net_finding_change}
          </span>
        </div>
      </div>

      {/* Metrics Counter Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* New */}
        <div className="bg-slate-950/70 border border-rose-900/30 rounded-xl p-3.5">
          <div className="text-xs text-rose-400 font-medium flex items-center justify-between">
            <span>New Findings</span>
            <TrendingUp className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1.5">
            {summary.new_count}
          </div>
          <span className="text-[10px] text-slate-400">Absent in baseline</span>
        </div>

        {/* Regressed */}
        <div className="bg-slate-950/70 border border-amber-900/30 rounded-xl p-3.5">
          <div className="text-xs text-amber-400 font-medium flex items-center justify-between">
            <span>Regressed</span>
            <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1.5">
            {summary.regressed_count}
          </div>
          <span className="text-[10px] text-slate-400">Reappeared issues</span>
        </div>

        {/* Fixed */}
        <div className="bg-slate-950/70 border border-emerald-900/30 rounded-xl p-3.5">
          <div className="text-xs text-emerald-400 font-medium flex items-center justify-between">
            <span>Fixed / Resolved</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1.5">
            {summary.fixed_count}
          </div>
          <span className="text-[10px] text-slate-400">Resolved in target</span>
        </div>

        {/* Persistent */}
        <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5">
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            <span>Persistent</span>
            <Minus className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-200 mt-1.5">
            {summary.persistent_count}
          </div>
          <span className="text-[10px] text-slate-400">Unchanged severity</span>
        </div>

        {/* Escalated */}
        <div className="bg-slate-950/70 border border-purple-900/30 rounded-xl p-3.5">
          <div className="text-xs text-purple-400 font-medium flex items-center justify-between">
            <span>Escalated</span>
            <TrendingUp className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-1.5">
            {summary.severity_increased_count}
          </div>
          <span className="text-[10px] text-slate-400">Higher severity</span>
        </div>

        {/* De-escalated */}
        <div className="bg-slate-950/70 border border-blue-900/30 rounded-xl p-3.5">
          <div className="text-xs text-blue-400 font-medium flex items-center justify-between">
            <span>De-escalated</span>
            <TrendingDown className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-blue-300 mt-1.5">
            {summary.severity_decreased_count}
          </div>
          <span className="text-[10px] text-slate-400">Lower severity</span>
        </div>
      </div>

      {/* Side-by-side Severity Comparison Bars */}
      <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
          Severity Breakdown Comparison
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* Baseline scan counts */}
          <div className="space-y-1.5">
            <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
              <span>Baseline ({summary.baseline_total} total)</span>
              <span className="text-[11px] text-slate-400">
                {summary.baseline_completed_at ? new Date(summary.baseline_completed_at).toLocaleDateString() : ''}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-red-400">Critical:</span>
              <span className="font-bold text-slate-200">{summary.baseline_severity_breakdown.CRITICAL || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-orange-400">High:</span>
              <span className="font-bold text-slate-200">{summary.baseline_severity_breakdown.HIGH || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-amber-400">Medium:</span>
              <span className="font-bold text-slate-200">{summary.baseline_severity_breakdown.MEDIUM || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-blue-400">Low:</span>
              <span className="font-bold text-slate-200">{summary.baseline_severity_breakdown.LOW || 0}</span>
            </div>
          </div>

          {/* Comparison scan counts */}
          <div className="space-y-1.5">
            <div className="text-indigo-400 font-semibold mb-1 flex items-center justify-between">
              <span>Comparison ({summary.comparison_total} total)</span>
              <span className="text-[11px] text-slate-400">
                {summary.comparison_completed_at ? new Date(summary.comparison_completed_at).toLocaleDateString() : ''}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-red-400">Critical:</span>
              <span className="font-bold text-slate-200">{summary.comparison_severity_breakdown.CRITICAL || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-orange-400">High:</span>
              <span className="font-bold text-slate-200">{summary.comparison_severity_breakdown.HIGH || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-amber-400">Medium:</span>
              <span className="font-bold text-slate-200">{summary.comparison_severity_breakdown.MEDIUM || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 text-blue-400">Low:</span>
              <span className="font-bold text-slate-200">{summary.comparison_severity_breakdown.LOW || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

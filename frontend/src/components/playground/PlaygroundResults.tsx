import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  RotateCcw,
  CheckCircle,
  HelpCircle,
  ArrowRight,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { PlaygroundResult } from '../../types/playground';
import { EvidenceViewer } from './EvidenceViewer';

interface PlaygroundResultsProps {
  result: PlaygroundResult;
  onReplay: () => void;
  isReplaying?: boolean;
}

export const PlaygroundResults: React.FC<PlaygroundResultsProps> = ({
  result,
  onReplay,
  isReplaying = false,
}) => {
  const getResultBadge = () => {
    switch (result.security_result) {
      case 'VULNERABILITY_CONFIRMED':
        return {
          label: 'Vulnerability Confirmed',
          icon: <ShieldAlert className="w-5 h-5 text-red-400" />,
          classes: 'bg-red-500/10 text-red-400 border-red-500/40',
        };
      case 'SECURE_BEHAVIOR_CONFIRMED':
        return {
          label: 'Secure Behavior Confirmed',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
          classes: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/40',
        };
      case 'BLOCKED_BY_POLICY':
        return {
          label: 'Blocked by Safety Policy',
          icon: <AlertOctagon className="w-5 h-5 text-amber-400" />,
          classes: 'bg-amber-500/10 text-amber-400 border-amber-500/40',
        };
      default:
        return {
          label: result.security_result,
          icon: <HelpCircle className="w-5 h-5 text-slate-400" />,
          classes: 'bg-slate-500/10 text-slate-400 border-slate-500/40',
        };
    }
  };

  const badge = getResultBadge();
  const comparison = result.previous_result_comparison;

  return (
    <div className="space-y-4">
      {/* Replay Historical Comparison Banner */}
      {comparison && (
        <div
          className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            comparison.regression_detected
              ? 'bg-red-950/30 border-red-500/50 text-red-200'
              : comparison.result_changed
              ? 'bg-cyan-950/30 border-cyan-500/50 text-cyan-200'
              : 'bg-slate-900 border-slate-800 text-slate-300'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {comparison.regression_detected ? (
              <TrendingDown className="w-5 h-5 text-red-400 shrink-0" />
            ) : (
              <TrendingUp className="w-5 h-5 text-cyan-400 shrink-0" />
            )}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider">
                Replay Run Comparison
              </div>
              <div className="text-sm font-medium mt-0.5">
                Previous Result: <span className="font-mono">{comparison.previous_security_result}</span>{' '}
                <ArrowRight className="inline w-3.5 h-3.5 mx-1" /> Current:{' '}
                <span className="font-mono">{result.security_result}</span>
              </div>
            </div>
          </div>

          {comparison.regression_detected && (
            <span className="px-2.5 py-1 rounded-lg text-xs font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/40">
              Security Regression Detected
            </span>
          )}
        </div>
      )}

      {/* Main Result Card */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {result.scenario_id}
              </span>
              <span className="text-xs font-medium text-slate-400">
                {result.vulnerability_category}
              </span>
              {result.is_synthetic && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Synthetic Target
                </span>
              )}
            </div>
            <h3 className="text-base font-semibold text-slate-100">
              {result.scenario_name}
            </h3>
            <div className="text-xs font-mono text-cyan-400/90 mt-0.5">
              Target: {result.target_application} ({result.target_url})
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3.5 py-2 rounded-xl border ${badge.classes}`}>
              {badge.icon}
              <span className="text-xs font-bold uppercase tracking-wider">
                {badge.label}
              </span>
            </div>

            <button
              type="button"
              disabled={isReplaying}
              onClick={onReplay}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 transition-colors shadow-sm"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isReplaying ? 'animate-spin' : ''}`} />
              Replay Scenario
            </button>
          </div>
        </div>

        {/* Expected vs Observed Behavior Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> Expected Secure Behavior
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {result.expected_behavior}
            </p>
          </div>

          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Observed Application Behavior
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {result.observed_behavior}
            </p>
          </div>
        </div>

        {/* Recommended Next Step Box */}
        <div className="p-4 bg-cyan-950/20 border border-cyan-500/30 rounded-xl">
          <div className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-1">
            Recommended Security Remediation & Next Steps
          </div>
          <p className="text-xs text-cyan-200/90 leading-relaxed">
            {result.recommended_next_step}
          </p>
        </div>

        {/* Safety Engine Decision Details */}
        {result.safety_decisions && (
          <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-400 gap-2">
            <div>
              <span className="font-semibold text-slate-300">Feature 26 Safety Verdict: </span>
              {result.safety_decisions.allowed ? (
                <span className="text-emerald-400 font-mono">ALLOWED (Scope Verified)</span>
              ) : (
                <span className="text-red-400 font-mono">
                  BLOCKED ({result.safety_decisions.violation_category || 'POLICY_VIOLATION'})
                </span>
              )}
            </div>
            {result.safety_decisions.reason && (
              <div className="text-slate-400 text-xs italic">
                {result.safety_decisions.reason}
              </div>
            )}
            <div className="text-slate-500 font-mono text-[11px]">
              Duration: {result.duration_seconds?.toFixed(2)}s
            </div>
          </div>
        )}

        {/* Evidence Viewer */}
        <EvidenceViewer
          evidence={result.evidence_references}
          isSynthetic={result.is_synthetic}
        />
      </div>
    </div>
  );
};

import React from 'react';
import { X, AlertTriangle, ShieldCheck, ArrowRight, ShieldAlert, FileText, CheckCircle2 } from 'lucide-react';
import { RegressionRecord } from '../../types/timeTravel';

interface RegressionDetailsPanelProps {
  regression: RegressionRecord | null;
  onClose: () => void;
}

export const RegressionDetailsPanel: React.FC<RegressionDetailsPanelProps> = ({
  regression,
  onClose,
}) => {
  if (!regression) return null;

  const isConfirmed = regression.status === 'REGRESSION_DETECTED';

  const getSeverityBadge = (sev?: string | null) => {
    if (!sev) return null;
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'HIGH':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'LOW':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div className="bg-surface border border-border rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-border/80 flex items-center justify-between bg-surface-raised/30">
          <div className="flex items-center gap-2.5">
            <div
              className={`p-2 rounded-xl border ${
                isConfirmed
                  ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                  : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
              }`}
            >
              {isConfirmed ? <ShieldAlert className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-base font-bold text-text-primary">
                {isConfirmed ? 'Regression Analysis & Evidence' : 'Inconclusive Finding Review'}
              </h3>
              <p className="text-xs text-text-muted">
                {regression.application_name || 'Application'} &bull; Detected on{' '}
                {new Date(regression.first_observed_at).toLocaleString()}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-raised transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs text-text-primary">
          {/* Overview Banner */}
          <div
            className={`p-4 rounded-xl border ${
              isConfirmed
                ? 'bg-rose-500/5 border-rose-500/30 text-rose-300'
                : 'bg-amber-500/5 border-amber-500/30 text-amber-300'
            }`}
          >
            <div className="font-semibold text-sm mb-1">{regression.baseline_title}</div>
            <p className="text-xs text-text-muted">{regression.explanation}</p>
          </div>

          {/* Side by Side: Baseline State vs Reappeared State */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Baseline Condition */}
            <div className="p-3 bg-surface-raised/40 border border-border/70 rounded-xl space-y-2">
              <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-xs">
                <ShieldCheck className="w-4 h-4" />
                Baseline Invariant (Resolved)
              </div>
              <div>
                <span className="text-text-muted text-[11px]">Endpoint:</span>
                <div className="font-mono text-xs text-text-primary truncate">
                  {regression.baseline_endpoint || 'Target Endpoint'}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-text-muted text-[11px]">Original Severity:</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(regression.original_severity)}`}>
                  {regression.original_severity}
                </span>
              </div>
              <div className="text-[11px] text-text-muted truncate">
                Baseline ID: <span className="font-mono">{regression.baseline_id}</span>
              </div>
            </div>

            {/* Regression Occurrence */}
            <div className="p-3 bg-surface-raised/40 border border-border/70 rounded-xl space-y-2">
              <div className="flex items-center gap-1.5 text-rose-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                Reappeared Finding
              </div>
              <div>
                <span className="text-text-muted text-[11px]">Severity Change:</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(regression.original_severity)}`}>
                    {regression.original_severity}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-text-muted" />
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(regression.new_severity || regression.original_severity)}`}>
                    {regression.new_severity || regression.original_severity}
                  </span>
                  <span className="text-[10px] font-semibold text-text-muted ml-1">
                    ({regression.severity_change || 'UNCHANGED'})
                  </span>
                </div>
              </div>
              <div className="text-[11px] text-text-muted truncate">
                Scan ID: <span className="font-mono">{regression.scan_id}</span>
              </div>
              {regression.scan_notes && (
                <div className="text-[11px] text-text-muted truncate">
                  Scan Notes: {regression.scan_notes}
                </div>
              )}
            </div>
          </div>

          {/* Match Quality & Confidence */}
          <div className="p-3 bg-surface border border-border/70 rounded-xl space-y-1.5">
            <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wider">
              Matching Telemetry
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-text-muted">Match Category: </span>
                <span className="font-semibold text-text-primary">{regression.match_quality}</span>
              </div>
              <div>
                <span className="text-text-muted">Algorithm Confidence: </span>
                <span className="font-semibold text-text-primary">
                  {Math.round(regression.confidence_score * 100)}%
                </span>
              </div>
            </div>
          </div>

          {/* Technical Evidence Payload */}
          {regression.evidence_references && Object.keys(regression.evidence_references).length > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center gap-1 text-[11px] font-semibold text-text-muted uppercase tracking-wider">
                <FileText className="w-3.5 h-3.5" />
                Sanitized Evidence References
              </div>
              <pre className="p-3 bg-background border border-border rounded-xl text-[11px] font-mono text-text-muted overflow-x-auto max-h-36">
                {JSON.stringify(regression.evidence_references, null, 2)}
              </pre>
            </div>
          )}

          {/* Recommended Next Actions */}
          <div className="p-3.5 bg-primary/5 border border-primary/20 rounded-xl space-y-1.5">
            <div className="flex items-center gap-1.5 font-semibold text-primary text-xs">
              <CheckCircle2 className="w-4 h-4" />
              Recommended Security Remediation
            </div>
            <p className="text-text-muted text-[11px] leading-relaxed">
              {isConfirmed
                ? 'Inspect code commit and deployment diffs between the verification scan and the current scan. Deploy targeted fix and execute a re-verification scan to restore this baseline invariant.'
                : 'Review the endpoint routing changes or title similarity to confirm if this finding is a true regression or an independent novel finding.'}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-border/80 bg-surface-raised/20 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-surface-raised hover:bg-surface border border-border text-xs font-semibold text-text-primary rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};


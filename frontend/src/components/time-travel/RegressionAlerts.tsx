import React from 'react';
import { AlertTriangle, HelpCircle, ArrowRight, ShieldAlert, Eye, CheckCircle2 } from 'lucide-react';
import { RegressionRecord } from '../../types/timeTravel';

interface RegressionAlertsProps {
  regressions: RegressionRecord[];
  loading: boolean;
  onSelectRegression: (regression: RegressionRecord) => void;
}

export const RegressionAlerts: React.FC<RegressionAlertsProps> = ({
  regressions,
  loading,
  onSelectRegression,
}) => {
  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-28 bg-surface/50 border border-border/60 rounded-xl animate-pulse" />
        ))}
      </div>
    );
  }

  if (regressions.length === 0) {
    return (
      <div className="bg-surface border border-border/80 rounded-xl p-12 text-center">
        <CheckCircle2 className="w-12 h-12 text-emerald-400/60 mx-auto mb-3" />
        <h3 className="text-base font-medium text-text-primary mb-1">Zero Active Regressions</h3>
        <p className="text-xs text-text-muted max-w-md mx-auto">
          All monitored security invariants are holding. No previously resolved security conditions have regressed in evaluated scans.
        </p>
      </div>
    );
  }

  const getSeverityBadge = (sev: string) => {
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
    <div className="space-y-3">
      {regressions.map((reg) => {
        const isConfirmed = reg.status === 'REGRESSION_DETECTED';
        const isEscalated = reg.severity_change === 'INCREASED';

        return (
          <div
            key={reg.id}
            className={`p-4 rounded-xl border transition-all ${
              isConfirmed
                ? 'bg-rose-500/[0.03] border-rose-500/30 hover:border-rose-500/50'
                : 'bg-amber-500/[0.03] border-amber-500/30 hover:border-amber-500/50'
            }`}
          >
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
              {/* Left Column: Icon & Titles */}
              <div className="flex items-start gap-3 flex-1 min-w-0">
                <div
                  className={`p-2 rounded-lg border mt-0.5 ${
                    isConfirmed
                      ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                      : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                  }`}
                >
                  {isConfirmed ? <ShieldAlert className="w-5 h-5" /> : <HelpCircle className="w-5 h-5" />}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                      {reg.application_name || 'Application'}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${
                        isConfirmed
                          ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                          : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                      }`}
                    >
                      {isConfirmed ? 'Regression Confirmed' : 'Inconclusive Review Required'}
                    </span>
                    {isEscalated && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider text-rose-300 bg-rose-950/60 border border-rose-500/40 animate-pulse">
                        Severity Escalated
                      </span>
                    )}
                  </div>

                  <h4 className="text-sm font-semibold text-text-primary mt-1 truncate">
                    {reg.baseline_title || 'Security Invariant'}
                  </h4>

                  <p className="text-xs text-text-muted mt-1 line-clamp-2">{reg.explanation}</p>
                </div>
              </div>

              {/* Right Column: Severity Transition & Actions */}
              <div className="flex flex-wrap items-center gap-4 w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 pt-2 md:pt-0 border-border/40">
                {/* Severity Transition */}
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-text-muted text-[11px]">Severity:</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(
                      reg.original_severity
                    )}`}
                  >
                    {reg.original_severity}
                  </span>
                  {reg.new_severity && reg.new_severity !== reg.original_severity && (
                    <>
                      <ArrowRight className="w-3.5 h-3.5 text-text-muted" />
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(
                          reg.new_severity
                        )}`}
                      >
                        {reg.new_severity}
                      </span>
                    </>
                  )}
                </div>

                {/* Match Confidence */}
                <div className="text-[11px] text-text-muted">
                  Confidence: <span className="font-semibold text-text-primary">{Math.round(reg.confidence_score * 100)}%</span>
                </div>

                {/* Details Button */}
                <button
                  onClick={() => onSelectRegression(reg)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-text-primary bg-surface border border-border hover:border-primary/50 rounded-lg transition-colors"
                >
                  <Eye className="w-3.5 h-3.5" />
                  View Evidence
                </button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};


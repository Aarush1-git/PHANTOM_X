import React from 'react';
import { ShieldCheck, AlertTriangle, Archive, ChevronLeft, ChevronRight, Eye } from 'lucide-react';
import { SecurityBaseline } from '../../types/timeTravel';

interface BaselineTableProps {
  baselines: SecurityBaseline[];
  total: number;
  page: number;
  limit: number;
  loading: boolean;
  onPageChange: (newPage: number) => void;
  onSelectBaseline: (baseline: SecurityBaseline) => void;
  onRetireBaseline: (baseline: SecurityBaseline) => void;
}

export const BaselineTable: React.FC<BaselineTableProps> = ({
  baselines,
  total,
  page,
  limit,
  loading,
  onPageChange,
  onSelectBaseline,
  onRetireBaseline,
}) => {
  const totalPages = Math.ceil(total / limit) || 1;

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

  const getStatusBadge = (status: string, isRetired: boolean) => {
    if (isRetired || status === 'RETIRED') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium border text-zinc-400 bg-zinc-500/10 border-zinc-500/30">
          <Archive className="w-3 h-3" />
          Retired
        </span>
      );
    }
    switch (status.toUpperCase()) {
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium border text-emerald-400 bg-emerald-500/10 border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            Verified
          </span>
        );
      case 'REGRESSION_DETECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium border text-rose-400 bg-rose-500/10 border-rose-500/30">
            <AlertTriangle className="w-3 h-3" />
            Regression
          </span>
        );
      case 'PENDING_VERIFICATION':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium border text-amber-400 bg-amber-500/10 border-amber-500/30">
            Pending
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium border text-slate-400 bg-slate-500/10 border-slate-500/30">
            {status}
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="bg-surface border border-border/80 rounded-xl overflow-hidden">
        <div className="p-8 text-center text-text-muted">Loading security baselines...</div>
      </div>
    );
  }

  if (baselines.length === 0) {
    return (
      <div className="bg-surface border border-border/80 rounded-xl p-12 text-center">
        <ShieldCheck className="w-12 h-12 text-text-muted/40 mx-auto mb-3" />
        <h3 className="text-base font-medium text-text-primary mb-1">No Security Baselines Found</h3>
        <p className="text-xs text-text-muted max-w-md mx-auto">
          No security invariants match your current filter criteria. Verify a fixed finding from a scan to establish a new security baseline.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-surface border border-border/80 rounded-xl overflow-hidden shadow-sm flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-surface-raised/40 text-[11px] font-semibold text-text-muted uppercase tracking-wider">
              <th className="py-3 px-4">Application</th>
              <th className="py-3 px-4">Security Invariant / Issue</th>
              <th className="py-3 px-4">Endpoint</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Verified Date</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60 text-xs text-text-primary">
            {baselines.map((b) => (
              <tr
                key={b.id}
                className="hover:bg-surface-raised/60 transition-colors group"
              >
                <td className="py-3 px-4 font-medium max-w-[160px] truncate">
                  {b.application_name || 'Application'}
                </td>
                <td className="py-3 px-4 max-w-[240px]">
                  <div className="font-semibold text-text-primary truncate">{b.title}</div>
                  {b.cwe_id && (
                    <span className="text-[10px] text-text-muted font-mono">{b.cwe_id}</span>
                  )}
                </td>
                <td className="py-3 px-4 max-w-[220px]">
                  <div className="font-mono text-[11px] text-text-muted truncate">
                    <span className="text-primary/70 mr-1">{b.http_method}</span>
                    {b.endpoint}
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span
                    className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${getSeverityBadge(
                      b.severity
                    )}`}
                  >
                    {b.severity}
                  </span>
                </td>
                <td className="py-3 px-4">{getStatusBadge(b.status, b.is_retired)}</td>
                <td className="py-3 px-4 text-text-muted text-[11px]">
                  {b.verification_timestamp
                    ? new Date(b.verification_timestamp).toLocaleDateString()
                    : new Date(b.created_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4 text-right space-x-2">
                  <button
                    onClick={() => onSelectBaseline(b)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-text-primary bg-surface-raised border border-border hover:border-primary/50 rounded-lg transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Details
                  </button>
                  {!b.is_retired && (
                    <button
                      onClick={() => onRetireBaseline(b)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-text-muted hover:text-rose-400 border border-transparent hover:border-rose-500/20 rounded-lg transition-colors"
                      title="Retire this baseline invariant"
                    >
                      <Archive className="w-3.5 h-3.5" />
                      Retire
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-border/80 bg-surface-raised/20 flex items-center justify-between text-xs text-text-muted">
        <div>
          Showing {Math.min((page - 1) * limit + 1, total)} to{' '}
          {Math.min(page * limit, total)} of {total} baselines
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="p-1.5 rounded-lg border border-border hover:bg-surface disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            aria-label="Previous Page"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="p-1.5 rounded-lg border border-border hover:bg-surface disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            aria-label="Next Page"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};


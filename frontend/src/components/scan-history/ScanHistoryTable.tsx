import React from 'react';
import { Clock, Eye, Layers, GitCompare, Check, AlertCircle, PlayCircle, XCircle } from 'lucide-react';
import { ScanHistoryItem } from '../../types/scanHistory';

interface Props {
  scans: ScanHistoryItem[];
  isLoading: boolean;
  baselineScanId?: string | null;
  comparisonScanId?: string | null;
  onSelectBaseline: (scan: ScanHistoryItem) => void;
  onSelectComparison: (scan: ScanHistoryItem) => void;
  onViewDetails: (scanId: string) => void;
  page: number;
  totalPages: number;
  totalItems: number;
  onPageChange: (page: number) => void;
}

const STATUS_CONFIG: Record<string, { label: string; bg: string; text: string; border: string; icon: any }> = {
  COMPLETED: { label: 'Completed', bg: 'bg-emerald-950/60', text: 'text-emerald-400', border: 'border-emerald-800/80', icon: Check },
  RUNNING: { label: 'Running', bg: 'bg-cyan-950/60', text: 'text-cyan-400', border: 'border-cyan-800/80', icon: PlayCircle },
  FAILED: { label: 'Failed', bg: 'bg-rose-950/60', text: 'text-rose-400', border: 'border-rose-800/80', icon: AlertCircle },
  CANCELLED: { label: 'Cancelled', bg: 'bg-slate-800/60', text: 'text-slate-400', border: 'border-slate-700/80', icon: XCircle },
  QUEUED: { label: 'Queued', bg: 'bg-amber-950/60', text: 'text-amber-400', border: 'border-amber-800/80', icon: Clock },
  PAUSED: { label: 'Paused', bg: 'bg-purple-950/60', text: 'text-purple-400', border: 'border-purple-800/80', icon: Clock },
};

export const ScanHistoryTable: React.FC<Props> = ({
  scans,
  isLoading,
  baselineScanId,
  comparisonScanId,
  onSelectBaseline,
  onSelectComparison,
  onViewDetails,
  page,
  totalPages,
  totalItems,
  onPageChange,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500 mb-3" />
        <p className="text-slate-400 text-sm">Loading security scan history records...</p>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center">
        <Layers className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h4 className="text-slate-300 font-medium text-base mb-1">No Security Scans Found</h4>
        <p className="text-slate-500 text-sm max-w-md mx-auto">
          No scans match your current filter parameters. Try adjusting filters or launch a new security scan.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm backdrop-blur-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 text-xs uppercase tracking-wider font-semibold">
              <th className="py-3 px-4">Scan & Application</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Execution Time</th>
              <th className="py-3 px-4">Findings Breakdown</th>
              <th className="py-3 px-4 text-center">Compare Selection</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm text-slate-300">
            {scans.map((scan) => {
              const statusCfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.QUEUED;
              const StatusIcon = statusCfg.icon;
              const isBaseline = baselineScanId === scan.id;
              const isComparison = comparisonScanId === scan.id;

              return (
                <tr
                  key={scan.id}
                  className={`hover:bg-slate-800/40 transition-colors ${
                    isBaseline ? 'bg-cyan-950/20' : isComparison ? 'bg-indigo-950/20' : ''
                  }`}
                >
                  {/* Scan & App info */}
                  <td className="py-3.5 px-4">
                    <div className="font-medium text-slate-100 flex items-center gap-2">
                      <span>{scan.application_name}</span>
                      {isBaseline && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                          BASELINE
                        </span>
                      )}
                      {isComparison && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                          COMPARE
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-xs" title={scan.target_url}>
                      {scan.target_url}
                    </div>
                    {scan.notes && (
                      <div className="text-xs text-slate-400 italic mt-1 line-clamp-1">{scan.notes}</div>
                    )}
                    <div className="text-[11px] text-slate-400 font-mono mt-1">ID: {scan.id}</div>
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${statusCfg.bg} ${statusCfg.text} ${statusCfg.border}`}
                    >
                      <StatusIcon className="w-3.5 h-3.5" />
                      {statusCfg.label}
                    </span>
                    {scan.status === 'RUNNING' && (
                      <div className="w-24 bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                        <div
                          className="bg-cyan-500 h-full rounded-full transition-all"
                          style={{ width: `${Math.round(scan.progress * 100)}%` }}
                        />
                      </div>
                    )}
                  </td>

                  {/* Execution Time */}
                  <td className="py-3.5 px-4 text-xs whitespace-nowrap">
                    <div className="text-slate-300 font-medium">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'Not started'}
                    </div>
                    {scan.duration_seconds !== null && scan.duration_seconds !== undefined && (
                      <div className="text-slate-400 flex items-center gap-1 mt-0.5">
                        <Clock className="w-3 h-3 text-slate-400" />
                        <span>
                          {scan.duration_seconds < 60
                            ? `${scan.duration_seconds}s`
                            : `${Math.round(scan.duration_seconds / 60)} min (${scan.duration_seconds}s)`}
                        </span>
                      </div>
                    )}
                  </td>

                  {/* Findings Breakdown */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className="font-semibold text-slate-200">{scan.total_vulnerabilities}</span>
                      <span className="text-xs text-slate-400">findings</span>
                    </div>
                    <div className="flex items-center gap-1">
                      {scan.critical_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-800/60" title="Critical">
                          {scan.critical_count} C
                        </span>
                      )}
                      {scan.high_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-950/80 text-orange-400 border border-orange-800/60" title="High">
                          {scan.high_count} H
                        </span>
                      )}
                      {scan.medium_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800/60" title="Medium">
                          {scan.medium_count} M
                        </span>
                      )}
                      {scan.low_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950/80 text-blue-400 border border-blue-800/60" title="Low">
                          {scan.low_count} L
                        </span>
                      )}
                      {scan.total_vulnerabilities === 0 && (
                        <span className="text-xs text-slate-400 font-mono">0 vulnerabilities</span>
                      )}
                    </div>
                  </td>

                  {/* Compare Selection */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-center">
                    <div className="inline-flex items-center rounded-lg border border-slate-700/80 bg-slate-950 p-0.5">
                      <button
                        onClick={() => onSelectBaseline(scan)}
                        className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                          isBaseline
                            ? 'bg-cyan-600 text-white shadow-sm'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                        }`}
                        title="Set as Baseline scan for diff"
                      >
                        Baseline
                      </button>
                      <button
                        onClick={() => onSelectComparison(scan)}
                        className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                          isComparison
                            ? 'bg-indigo-600 text-white shadow-sm'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                        }`}
                        title="Set as Target comparison scan"
                      >
                        Compare
                      </button>
                    </div>
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-right">
                    <button
                      onClick={() => onViewDetails(scan.id)}
                      className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 inline-flex items-center gap-1.5 transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5 text-cyan-400" />
                      Details
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/50 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
        <div>
          Showing page <span className="font-semibold text-slate-200">{page}</span> of{' '}
          <span className="font-semibold text-slate-200">{totalPages}</span> ({totalItems} total scans)
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300 transition-colors"
          >
            Previous
          </button>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300 transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
};

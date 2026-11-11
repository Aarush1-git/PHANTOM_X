import React from 'react';
import { GitCompare, ArrowLeftRight, X, AlertTriangle, ShieldCheck } from 'lucide-react';
import { ScanHistoryItem } from '../../types/scanHistory';

interface Props {
  baselineScan: ScanHistoryItem | null;
  comparisonScan: ScanHistoryItem | null;
  onSwap: () => void;
  onClear: () => void;
  onCompare: () => void;
  isLoading?: boolean;
}

export const ScanComparisonSelector: React.FC<Props> = ({
  baselineScan,
  comparisonScan,
  onSwap,
  onClear,
  onCompare,
  isLoading = false,
}) => {
  const isSameScan = baselineScan && comparisonScan && baselineScan.id === comparisonScan.id;
  const isDifferentApp =
    baselineScan &&
    comparisonScan &&
    baselineScan.application_id !== comparisonScan.application_id;

  const canCompare =
    baselineScan &&
    comparisonScan &&
    !isSameScan &&
    !isDifferentApp &&
    !isLoading;

  if (!baselineScan && !comparisonScan) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
        <div className="flex items-center justify-center gap-2 text-slate-400 text-xs">
          <GitCompare className="w-4 h-4 text-cyan-400" />
          <span>
            Select a <strong>Baseline Scan</strong> and a <strong>Comparison Scan</strong> from the table below to analyze differential security findings.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-700/80 rounded-xl p-4 shadow-lg">
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
        {/* Selector Cards Container */}
        <div className="flex flex-col sm:flex-row items-center gap-3 flex-1">
          {/* Baseline Card */}
          <div className="w-full sm:w-1/2 bg-slate-950/80 border border-cyan-500/40 rounded-lg p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/80">
                Baseline (Earlier)
              </span>
              {baselineScan && (
                <span className="text-xs text-slate-400 font-mono">
                  {baselineScan.total_vulnerabilities} findings
                </span>
              )}
            </div>
            {baselineScan ? (
              <div>
                <div className="font-semibold text-slate-100 text-sm truncate">
                  {baselineScan.application_name}
                </div>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  {baselineScan.started_at
                    ? new Date(baselineScan.started_at).toLocaleDateString()
                    : 'Unscheduled'}{' '}
                  • {baselineScan.status}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 italic py-2">
                Click &ldquo;Baseline&rdquo; on any scan in the table below...
              </div>
            )}
          </div>

          {/* Swap Button */}
          <button
            onClick={onSwap}
            disabled={!baselineScan || !comparisonScan}
            title="Swap Baseline and Comparison"
            className="p-2 rounded-full bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-30 disabled:hover:bg-slate-800 transition-colors border border-slate-700 self-center"
          >
            <ArrowLeftRight className="w-4 h-4" />
          </button>

          {/* Comparison Card */}
          <div className="w-full sm:w-1/2 bg-slate-950/80 border border-indigo-500/40 rounded-lg p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-indigo-400 bg-indigo-950/80 px-2 py-0.5 rounded border border-indigo-800/80">
                Comparison (Target)
              </span>
              {comparisonScan && (
                <span className="text-xs text-slate-400 font-mono">
                  {comparisonScan.total_vulnerabilities} findings
                </span>
              )}
            </div>
            {comparisonScan ? (
              <div>
                <div className="font-semibold text-slate-100 text-sm truncate">
                  {comparisonScan.application_name}
                </div>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  {comparisonScan.started_at
                    ? new Date(comparisonScan.started_at).toLocaleDateString()
                    : 'Unscheduled'}{' '}
                  • {comparisonScan.status}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 italic py-2">
                Click &ldquo;Compare&rdquo; on any scan in the table below...
              </div>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 justify-end">
          <button
            onClick={onClear}
            className="px-3 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors border border-slate-800 flex items-center gap-1"
          >
            <X className="w-3.5 h-3.5" />
            Clear
          </button>
          <button
            onClick={onCompare}
            disabled={!canCompare}
            className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-medium text-xs rounded-lg shadow-md transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <GitCompare className="w-4 h-4" />
            {isLoading ? 'Comparing...' : 'Compare Scans'}
          </button>
        </div>
      </div>

      {/* Warnings / Errors */}
      {isSameScan && (
        <div className="mt-3 p-2.5 bg-amber-950/40 border border-amber-800/80 rounded-lg flex items-center gap-2 text-xs text-amber-300">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>Cannot compare a scan to itself. Please select two distinct security scans.</span>
        </div>
      )}
      {isDifferentApp && (
        <div className="mt-3 p-2.5 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-center gap-2 text-xs text-rose-300">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>
            Selected scans belong to different applications ({baselineScan?.application_name} vs{' '}
            {comparisonScan?.application_name}). Scans must evaluate the same target for valid comparison.
          </span>
        </div>
      )}
    </div>
  );
};

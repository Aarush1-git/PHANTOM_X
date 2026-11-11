import React from 'react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { VulnerabilitySeverityType } from '../../types/scanHistory';

interface Props {
  baselineSeverity?: VulnerabilitySeverityType | null;
  comparisonSeverity?: VulnerabilitySeverityType | null;
}

const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-950/60 border-red-800/80',
  HIGH: 'text-orange-400 bg-orange-950/60 border-orange-800/80',
  MEDIUM: 'text-amber-400 bg-amber-950/60 border-amber-800/80',
  LOW: 'text-blue-400 bg-blue-950/60 border-blue-800/80',
  INFO: 'text-slate-400 bg-slate-800/60 border-slate-700/80',
};

export const SeverityChangeIndicator: React.FC<Props> = ({
  baselineSeverity,
  comparisonSeverity,
}) => {
  if (!baselineSeverity && comparisonSeverity) {
    const col = SEVERITY_COLORS[comparisonSeverity] || SEVERITY_COLORS.INFO;
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border ${col}`}>
        {comparisonSeverity}
      </span>
    );
  }

  if (baselineSeverity && !comparisonSeverity) {
    const col = SEVERITY_COLORS[baselineSeverity] || SEVERITY_COLORS.INFO;
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium line-through opacity-70 border ${col}`}>
        {baselineSeverity}
      </span>
    );
  }

  if (baselineSeverity && comparisonSeverity) {
    const bWeight = SEVERITY_WEIGHT[baselineSeverity] || 0;
    const cWeight = SEVERITY_WEIGHT[comparisonSeverity] || 0;
    const increased = cWeight > bWeight;
    const decreased = cWeight < bWeight;

    const bCol = SEVERITY_COLORS[baselineSeverity] || SEVERITY_COLORS.INFO;
    const cCol = SEVERITY_COLORS[comparisonSeverity] || SEVERITY_COLORS.INFO;

    if (baselineSeverity === comparisonSeverity) {
      return (
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border ${cCol}`}>
          <Minus className="w-3 h-3 text-slate-400" />
          {comparisonSeverity}
        </span>
      );
    }

    return (
      <div className="inline-flex items-center gap-1.5 font-mono text-xs">
        <span className={`px-1.5 py-0.5 rounded border opacity-75 ${bCol}`}>
          {baselineSeverity}
        </span>
        {increased ? (
          <ArrowUpRight className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
        ) : decreased ? (
          <ArrowDownRight className="w-3.5 h-3.5 text-emerald-400" />
        ) : null}
        <span className={`px-1.5 py-0.5 rounded border font-semibold ${cCol}`}>
          {comparisonSeverity}
        </span>
      </div>
    );
  }

  return <span className="text-slate-500 font-mono text-xs">—</span>;
};

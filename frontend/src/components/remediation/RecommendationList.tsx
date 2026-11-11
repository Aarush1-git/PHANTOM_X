import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  Clock,
  Search,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Filter,
  Sparkles,
} from 'lucide-react';
import {
  RemediationRecommendationListItem,
  RemediationPriority,
  RecommendationStatus,
} from '../../types/remediation';

interface RecommendationListProps {
  items: RemediationRecommendationListItem[];
  total: number;
  page: number;
  size: number;
  loading: boolean;
  search: string;
  onSearchChange: (val: string) => void;
  statusFilter: RecommendationStatus | null;
  onStatusFilterChange: (st: RecommendationStatus | null) => void;
  onPageChange: (newPage: number) => void;
  onSelectRecommendation: (id: string) => void;
  onGenerateClick: () => void;
  isGenerating?: boolean;
}

export const RecommendationList: React.FC<RecommendationListProps> = ({
  items,
  total,
  page,
  size,
  loading,
  search,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  onPageChange,
  onSelectRecommendation,
  onGenerateClick,
  isGenerating = false,
}) => {
  const totalPages = Math.ceil(total / size) || 1;

  const getPriorityBadge = (priority: RemediationPriority) => {
    switch (priority) {
      case 'CRITICAL':
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-orange-500/10 text-orange-400 border border-orange-500/30 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1">
            <AlertCircle className="w-3 h-3" />
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 flex items-center gap-1">
            <Info className="w-3 h-3" />
            LOW
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30 flex items-center gap-1">
            <CheckCircle className="w-3 h-3" />
            INFO
          </span>
        );
    }
  };

  const getStatusBadge = (status: RecommendationStatus) => {
    const map: Record<RecommendationStatus, { text: string; cls: string }> = {
      GENERATED: { text: 'Generated', cls: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30' },
      REVIEWED: { text: 'Reviewed', cls: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' },
      ACCEPTED: { text: 'Accepted', cls: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
      IN_PROGRESS: { text: 'In Progress', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
      VERIFIED: { text: 'Verified', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
      DEFERRED: { text: 'Deferred', cls: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
      REJECTED: { text: 'Rejected', cls: 'bg-rose-500/10 text-rose-400 border-rose-500/30' },
    };
    const c = map[status] || { text: status, cls: 'bg-slate-800 text-slate-400' };
    return (
      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${c.cls}`}>
        {c.text}
      </span>
    );
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (score >= 55) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (score >= 35) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Controls Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
        <div className="flex items-center gap-3 flex-1 min-w-[240px]">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search recommendations by title, endpoint, CWE..."
              className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700/80 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <Filter className="w-4 h-4 text-slate-500" />
            <select
              value={statusFilter || ''}
              onChange={(e) =>
                onStatusFilterChange(
                  e.target.value ? (e.target.value as RecommendationStatus) : null
                )
              }
              className="bg-slate-900 border border-slate-700/80 rounded-lg text-xs text-slate-300 px-2.5 py-1.5 focus:outline-none focus:border-indigo-500"
            >
              <option value="">All Statuses</option>
              <option value="GENERATED">Generated</option>
              <option value="REVIEWED">Reviewed</option>
              <option value="ACCEPTED">Accepted</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="VERIFIED">Verified</option>
              <option value="DEFERRED">Deferred</option>
              <option value="REJECTED">Rejected</option>
            </select>
          </div>
        </div>

        <button
          onClick={onGenerateClick}
          disabled={isGenerating}
          className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 shadow-md shadow-indigo-600/20"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>{isGenerating ? 'Evaluating Scans...' : 'Generate / Sync Recommendations'}</span>
        </button>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Priority & Score</th>
              <th className="py-3 px-4">Recommendation Title & Impact</th>
              <th className="py-3 px-4">Target Endpoint</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Effort</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {loading ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  Loading prioritized recommendations...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400">
                  No recommendations found matching your criteria.
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => onSelectRecommendation(item.id)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-9 h-9 rounded-lg border font-mono font-bold flex items-center justify-center text-xs ${getScoreColor(
                          item.risk_score
                        )}`}
                      >
                        {item.risk_score.toFixed(0)}
                      </span>
                      {getPriorityBadge(item.calculated_priority)}
                    </div>
                  </td>
                  <td className="py-3 px-4 max-w-md">
                    <div className="font-semibold text-white group-hover:text-indigo-300 transition-colors">
                      {item.title}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">
                      {item.why_it_matters_summary || item.category}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-cyan-300/80 max-w-xs truncate">
                    {item.endpoint || 'General'}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">{getStatusBadge(item.status)}</td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {item.estimated_effort || 'MEDIUM'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectRecommendation(item.id);
                      }}
                      className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors inline-flex items-center gap-1"
                    >
                      <span>Inspect</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
        <div>
          Showing {items.length} of {total} recommendations
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition-colors text-slate-300"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition-colors text-slate-300"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};


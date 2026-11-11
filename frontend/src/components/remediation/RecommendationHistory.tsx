import React from 'react';
import { History, User, Clock, ArrowRight } from 'lucide-react';
import { RecommendationHistoryItem } from '../../types/remediation';

interface RecommendationHistoryProps {
  history: RecommendationHistoryItem[];
  loading?: boolean;
}

export const RecommendationHistory: React.FC<RecommendationHistoryProps> = ({ history, loading }) => {
  if (loading) {
    return (
      <div className="space-y-3 animate-pulse">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-16 bg-slate-800/40 rounded-xl border border-slate-700/50" />
        ))}
      </div>
    );
  }

  if (!history || history.length === 0) {
    return (
      <div className="p-6 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
        <History className="w-8 h-8 text-slate-500 mx-auto mb-2" />
        <p className="text-xs text-slate-400">No lifecycle transitions recorded yet.</p>
      </div>
    );
  }

  return (
    <div className="relative pl-4 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
      {history.map((item) => (
        <div key={item.id} className="relative pl-4 group">
          <div className="absolute -left-2.5 top-1.5 w-3 h-3 rounded-full bg-slate-900 border-2 border-indigo-500" />
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl transition-all group-hover:border-slate-700">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-1.5 font-medium text-slate-200">
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[11px]">
                  {item.from_status}
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono text-[11px]">
                  {item.to_status}
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-500 text-[11px]">
                <Clock className="w-3.5 h-3.5" />
                <span>{new Date(item.created_at).toLocaleString()}</span>
              </div>
            </div>

            <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
              <div className="flex items-center gap-1">
                <User className="w-3.5 h-3.5 text-slate-500" />
                <span>
                  {item.actor_email || 'System'}{' '}
                  {item.actor_role && (
                    <span className="text-[10px] text-slate-500">({item.actor_role})</span>
                  )}
                </span>
              </div>
            </div>

            {item.notes && (
              <p className="mt-2 text-xs text-slate-300 bg-slate-950/60 p-2 rounded border border-slate-800/80">
                {item.notes}
              </p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};


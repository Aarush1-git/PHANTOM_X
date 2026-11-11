import React from 'react';
import {
  Clock,
  RotateCcw,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  Zap,
} from 'lucide-react';
import { PlaygroundSession } from '../../types/playground';

interface SessionHistoryProps {
  sessions: PlaygroundSession[];
  isLoading: boolean;
  onSelectSession: (session: PlaygroundSession) => void;
  onReplaySession: (sessionId: string) => void;
}

export const SessionHistory: React.FC<SessionHistoryProps> = ({
  sessions,
  isLoading,
  onSelectSession,
  onReplaySession,
}) => {
  const getResultBadge = (result?: string | null) => {
    switch (result) {
      case 'VULNERABILITY_CONFIRMED':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'SECURE_BEHAVIOR_CONFIRMED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'BLOCKED_BY_POLICY':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'BLOCKED':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'AWAITING_AUTHORIZATION':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default:
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
    }
  };

  if (isLoading) {
    return (
      <div className="text-center py-12 text-slate-500 text-sm">
        <Clock className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
        Loading playground history...
      </div>
    );
  }

  if (sessions.length === 0) {
    return (
      <div className="text-center py-12 bg-slate-900/40 border border-slate-800 rounded-xl">
        <Clock className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <h4 className="text-sm font-semibold text-slate-300">No Playground Sessions Found</h4>
        <p className="text-xs text-slate-500 mt-1">
          Select an attack scenario and target above to execute a controlled simulation.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[11px]">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Scenario</th>
              <th className="px-4 py-3">Target Application</th>
              <th className="px-4 py-3">Authorizer</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Security Result</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sessions.map((s) => (
              <tr
                key={s.id}
                className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                onClick={() => onSelectSession(s)}
              >
                <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                  {new Date(s.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <div className="font-semibold text-slate-200">{s.scenario_name}</div>
                  <div className="text-[11px] font-mono text-slate-500">{s.scenario_id}</div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <span className="font-medium text-slate-300">
                      {s.application_name || 'Application'}
                    </span>
                    {s.target_type === 'SYNTHETIC_TARGET' && (
                      <span className="inline-flex items-center gap-0.5 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/20">
                        <Zap className="w-2.5 h-2.5" /> Synthetic
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-slate-400">
                  {s.authorized_by ? (
                    <span className="text-slate-300 font-medium">{s.authorized_by}</span>
                  ) : (
                    <span className="italic text-slate-600">Pending</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${getStatusBadge(
                      s.status
                    )}`}
                  >
                    {s.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {s.security_result ? (
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getResultBadge(
                        s.security_result
                      )}`}
                    >
                      {s.security_result.replace(/_/g, ' ')}
                    </span>
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td
                  className="px-4 py-3 text-right whitespace-nowrap space-x-2"
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    type="button"
                    onClick={() => onSelectSession(s)}
                    className="p-1 rounded text-slate-400 hover:text-cyan-400 transition-colors"
                    title="View Session Details"
                  >
                    <ExternalLink className="w-4 h-4 inline" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onReplaySession(s.id)}
                    className="p-1 rounded text-slate-400 hover:text-amber-400 transition-colors"
                    title="Replay Scenario"
                  >
                    <RotateCcw className="w-4 h-4 inline" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

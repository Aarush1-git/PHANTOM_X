import React from 'react';
import {
  CheckCircle2,
  Clock,
  AlertOctagon,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { PlaygroundSession } from '../../types/playground';

interface ExecutionProgressProps {
  session: PlaygroundSession;
  isExecuting?: boolean;
}

export const ExecutionProgress: React.FC<ExecutionProgressProps> = ({
  session,
  isExecuting = false,
}) => {
  const getStatusBadge = () => {
    switch (session.status) {
      case 'COMPLETED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'RUNNING':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse';
      case 'BLOCKED':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'FAILED':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'READY':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
  };

  const steps = [
    {
      id: 1,
      name: 'Scenario & Target',
      status: 'complete',
    },
    {
      id: 2,
      name: 'Plan Preview',
      status: 'complete',
    },
    {
      id: 3,
      name: 'Explicit Authorization',
      status: session.is_authorized ? 'complete' : 'current',
    },
    {
      id: 4,
      name: 'Feature 26 Safety Check',
      status:
        session.status === 'BLOCKED'
          ? 'blocked'
          : session.status === 'COMPLETED' || session.status === 'RUNNING'
          ? 'complete'
          : session.is_authorized
          ? 'ready'
          : 'upcoming',
    },
    {
      id: 5,
      name: 'Execution & Evidence',
      status:
        session.status === 'COMPLETED'
          ? 'complete'
          : session.status === 'RUNNING' || isExecuting
          ? 'running'
          : session.status === 'BLOCKED'
          ? 'blocked'
          : 'upcoming',
    },
  ];

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-400 uppercase tracking-wider font-semibold">
          Execution Lifecycle Pipeline
        </span>
        <span className={`px-2 py-0.5 rounded font-mono font-semibold border ${getStatusBadge()}`}>
          {isExecuting ? 'DISPATCHING...' : session.status}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 pt-1">
        {steps.map((st) => {
          let bgClass = 'bg-slate-950/40 border-slate-800 text-slate-500';
          let icon = <Clock className="w-3.5 h-3.5 text-slate-600" />;

          if (st.status === 'complete') {
            bgClass = 'bg-cyan-950/20 border-cyan-500/30 text-cyan-300';
            icon = <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />;
          } else if (st.status === 'current') {
            bgClass = 'bg-amber-950/20 border-amber-500/30 text-amber-300';
            icon = <Clock className="w-3.5 h-3.5 text-amber-400 animate-pulse" />;
          } else if (st.status === 'running') {
            bgClass = 'bg-cyan-950/30 border-cyan-400 text-cyan-200';
            icon = <Zap className="w-3.5 h-3.5 text-cyan-400 animate-spin" />;
          } else if (st.status === 'blocked') {
            bgClass = 'bg-red-950/30 border-red-500/40 text-red-300';
            icon = <AlertOctagon className="w-3.5 h-3.5 text-red-400" />;
          }

          return (
            <div
              key={st.id}
              className={`p-2.5 rounded-lg border flex flex-col justify-between text-xs transition-colors ${bgClass}`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] opacity-75">Step 0{st.id}</span>
                {icon}
              </div>
              <span className="font-medium text-[11px] truncate">{st.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

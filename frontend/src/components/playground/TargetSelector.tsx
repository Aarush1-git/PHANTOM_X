import React from 'react';
import {
  Server,
  Zap,
  ShieldCheck,
  AlertOctagon,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { PlaygroundTargetInfo } from '../../types/playground';

interface TargetSelectorProps {
  targets: PlaygroundTargetInfo[];
  selectedTarget: PlaygroundTargetInfo | null;
  onSelectTarget: (target: PlaygroundTargetInfo) => void;
}

export const TargetSelector: React.FC<TargetSelectorProps> = ({
  targets,
  selectedTarget,
  onSelectTarget,
}) => {
  const getScopeBadge = (status?: string | null) => {
    switch (status?.toUpperCase()) {
      case 'ACTIVE':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'EXPIRED':
      case 'SUSPENDED':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      default:
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-cyan-400" /> Select Target Environment
        </label>
        <span className="text-xs text-slate-500">
          {targets.length} target{targets.length === 1 ? '' : 's'} available
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {targets.map((target) => {
          const isSelected = selectedTarget?.id === target.id;
          const isSynthetic = target.is_synthetic || target.target_type === 'SYNTHETIC_TARGET';

          return (
            <div
              key={target.id}
              onClick={() => onSelectTarget(target)}
              className={`cursor-pointer border rounded-xl p-4 transition-all flex flex-col justify-between ${
                isSelected
                  ? 'bg-cyan-950/25 border-cyan-500 shadow-md shadow-cyan-950/40'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-slate-100">
                      {target.name}
                    </span>
                    {isSelected && (
                      <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                    )}
                  </div>
                  {isSynthetic ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      <Zap className="w-3 h-3" /> Synthetic Lab
                    </span>
                  ) : (
                    <span className="text-[11px] font-mono font-medium text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                      Production Target
                    </span>
                  )}
                </div>

                <div className="text-xs font-mono text-cyan-400/90 truncate mb-2">
                  {target.target_url}
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                  {target.description || (isSynthetic ? 'Isolated sandbox for safe simulated vulnerability testing.' : 'Registered application target.')}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-500">Scope:</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[11px] font-mono border ${getScopeBadge(
                      target.scope_status
                    )}`}
                  >
                    {target.scope_status || 'UNCONFIGURED'}
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-slate-500">Authz:</span>
                  <span className="text-slate-300 font-mono text-[11px]">
                    {target.authorization_status || 'AUTHORIZED'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {selectedTarget && (selectedTarget.scope_status === 'EXPIRED' || selectedTarget.scope_status === 'SUSPENDED') && (
        <div className="p-3 bg-red-950/20 border border-red-500/30 rounded-lg flex items-center gap-2 text-xs text-red-300">
          <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
          <span>
            <strong>Warning:</strong> The selected target has scope status '{selectedTarget.scope_status}'. Feature 26 safety engine will block execution attempts against this target.
          </span>
        </div>
      )}

      {selectedTarget && selectedTarget.is_synthetic && (
        <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-xs text-emerald-300">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>
            <strong>Isolated Sandbox:</strong> Synthetic target simulations run in strict in-memory isolation without external network access or risk to production systems.
          </span>
        </div>
      )}
    </div>
  );
};

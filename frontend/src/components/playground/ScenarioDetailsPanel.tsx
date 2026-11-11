import React from 'react';
import {
  X,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileCode,
  Lock,
  Zap,
  Play,
} from 'lucide-react';
import { ScenarioInfo } from '../../types/playground';

interface ScenarioDetailsPanelProps {
  scenario: ScenarioInfo | null;
  onClose: () => void;
  onSelectAndConfigure: (scenario: ScenarioInfo) => void;
}

export const ScenarioDetailsPanel: React.FC<ScenarioDetailsPanelProps> = ({
  scenario,
  onClose,
  onSelectAndConfigure,
}) => {
  if (!scenario) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  {scenario.id}
                </span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                  {scenario.risk_level}
                </span>
                <span className="text-xs text-slate-400 font-medium">
                  {scenario.category}
                </span>
              </div>
              <h3 className="text-base font-semibold text-slate-100 mt-1">
                {scenario.name}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 text-sm">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Description
            </h4>
            <p className="text-slate-300">{scenario.description}</p>
          </div>

          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Security Objective
            </h4>
            <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg text-slate-300">
              {scenario.security_objective}
            </div>
          </div>

          {scenario.preconditions && scenario.preconditions.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Preconditions & Prerequisites
              </h4>
              <ul className="list-disc list-inside space-y-1 text-slate-300 text-xs pl-1">
                {scenario.preconditions.map((pre, idx) => (
                  <li key={idx}>{pre}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg">
              <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-xs mb-1">
                <CheckCircle className="w-4 h-4" /> Expected Secure Behavior
              </div>
              <p className="text-xs text-emerald-200/90 leading-relaxed">
                {scenario.expected_secure_behavior}
              </p>
            </div>

            <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg">
              <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-xs mb-1">
                <AlertTriangle className="w-4 h-4" /> Potential Vulnerability Indicators
              </div>
              <ul className="list-disc list-inside text-xs text-amber-200/90 space-y-1 pl-1">
                {scenario.potential_vulnerability_indicators.map((ind, idx) => (
                  <li key={idx}>{ind}</li>
                ))}
              </ul>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Sample Attack Payload / Headers Preview
              </h4>
              <span className="text-[11px] font-mono text-cyan-400">
                Non-Destructive Proof
              </span>
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto">
              {JSON.stringify(scenario.sample_payload || {}, null, 2)}
            </pre>
          </div>

          <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-400">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Required Authorization:</span>
              <span className="font-mono font-semibold text-slate-200">
                {scenario.required_authorization}
              </span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <Zap className="w-4 h-4 text-amber-400" />
              <span>Rate Limit:</span>
              <span className="font-mono font-semibold text-slate-200">
                {scenario.execution_constraints?.rate_limit_rps || 5} req/s
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950/40">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            Close
          </button>
          <button
            type="button"
            onClick={() => onSelectAndConfigure(scenario)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-white shadow-md transition-colors"
          >
            <Play className="w-4 h-4" /> Select Scenario & Configure Target
          </button>
        </div>
      </div>
    </div>
  );
};

import React from "react";
import { GitBranch, Compass, RefreshCw, AlertCircle, CheckCircle2, Split, Activity } from "lucide-react";
import { WorkflowOverview } from "../../types/workflow";

interface WorkflowDiscoveryOverviewProps {
  overview: WorkflowOverview;
  isDiscovering: boolean;
  onTriggerDiscovery: () => void;
}

export const WorkflowDiscoveryOverview: React.FC<WorkflowDiscoveryOverviewProps> = ({
  overview,
  isDiscovering,
  onTriggerDiscovery,
}) => {
  return (
    <div className="space-y-4">
      {/* Notice Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3.5 flex items-start gap-3">
        <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
        <div className="text-xs text-slate-400 leading-relaxed">
          <span className="font-semibold text-slate-200">Behavioral Journey Discovery: </span>
          Workflows represent empirical multi-step user navigation journeys reconstructed from observed API session
          traffic. Alternative branches and dropout points highlight navigation behavior, not confirmed security vulnerabilities.
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <Compass className="w-3.5 h-3.5 text-cyan-400" />
            <span>Total Journeys</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-100">{overview.total_workflows}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Active</span>
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">{overview.active_workflows}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>Incomplete / Drop</span>
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">{overview.incomplete_workflows}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <Split className="w-3.5 h-3.5 text-indigo-400" />
            <span>Branched</span>
          </div>
          <div className="text-xl font-bold font-mono text-indigo-400">{overview.branched_workflows}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <Activity className="w-3.5 h-3.5 text-teal-400" />
            <span>Avg Steps</span>
          </div>
          <div className="text-xl font-bold font-mono text-teal-300">{overview.average_steps}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
            <span>High Confidence</span>
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400">{overview.high_confidence_count}</div>
        </div>
      </div>

      {/* Action Header */}
      <div className="flex items-center justify-between pt-1">
        <div className="text-xs text-slate-400">
          Observed Sessions Analyzed: <span className="font-mono text-slate-200">{overview.total_observed_sessions}</span>
        </div>
        <button
          onClick={onTriggerDiscovery}
          disabled={isDiscovering}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-semibold text-xs transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isDiscovering ? "animate-spin" : ""}`} />
          <span>{isDiscovering ? "Discovering Workflows..." : "Re-Discover Workflows"}</span>
        </button>
      </div>
    </div>
  );
};

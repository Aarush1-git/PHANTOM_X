import React from "react";
import {
  Shield,
  Layers,
  Database,
  Key,
  Compass,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Play,
  FileCode,
  Network,
  Activity,
} from "lucide-react";
import { RoleResourceOverview } from "../../types/roleResource";

interface RoleResourceOverviewProps {
  overview: RoleResourceOverview;
  isDiscovering: boolean;
  onTriggerDiscovery: (mode: string) => void;
  lastDiscoveryStatus?: { success: boolean; message: string } | null;
}

export const RoleResourceOverviewComponent: React.FC<RoleResourceOverviewProps> = ({
  overview,
  isDiscovering,
  onTriggerDiscovery,
  lastDiscoveryStatus,
}) => {
  return (
    <div className="space-y-6">
      {/* Insufficient Evidence Warning Banner */}
      {overview.insufficient_evidence && (
        <div className="p-3.5 bg-amber-950/40 border border-amber-800/60 rounded-lg flex items-center gap-3 text-xs font-mono">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <div className="text-amber-200">
            <span className="font-semibold">Insufficient Observation Evidence: </span>
            {overview.insufficient_evidence_reason ||
              "Traffic observations are below statistical threshold. Discovered empirical mappings may have low confidence."}
          </div>
        </div>
      )}

      {/* Discovery Feedback Banner */}
      {lastDiscoveryStatus && (
        <div
          className={`p-3 rounded-lg flex items-center gap-2.5 text-xs font-mono border ${
            lastDiscoveryStatus.success
              ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-200"
              : "bg-red-950/40 border-red-800/60 text-red-200"
          }`}
        >
          {lastDiscoveryStatus.success ? (
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          )}
          <span>{lastDiscoveryStatus.message}</span>
        </div>
      )}

      {/* High-Level Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Roles</span>
            <Key className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-100">
            {overview.total_roles}
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            Application-scoped subjects
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Resources</span>
            <Database className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-100">
            {overview.total_resources}
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            Identified domain entities
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Total Mappings</span>
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400">
            {overview.total_mappings}
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            {overview.high_confidence_count} high confidence (&ge; 70%)
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Discrepancies</span>
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400">
            {overview.discrepancies_count}
          </div>
          <div className="text-[10px] font-mono text-slate-500">
            Declared vs. observed deltas
          </div>
        </div>
      </div>

      {/* Provenance Breakdown */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
          Relationship Provenance Breakdown
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-emerald-900/40 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" />
              <span className="text-slate-300">Declared (Specs)</span>
            </div>
            <span className="font-bold text-emerald-400">{overview.declared_count}</span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-cyan-900/40 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
              <span className="text-slate-300">Observed (Traffic)</span>
            </div>
            <span className="font-bold text-cyan-400">{overview.observed_count}</span>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-purple-900/40 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
              <span className="text-slate-300">Inferred (Structure/Overlap)</span>
            </div>
            <span className="font-bold text-purple-400">{overview.inferred_count}</span>
          </div>
        </div>
      </div>

      {/* Discovery Action Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <h4 className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
              <Compass className="w-3.5 h-3.5 text-cyan-400" />
              <span>Discovery Engine Controls</span>
            </h4>
            <p className="text-[11px] text-slate-500">
              Trigger automated relationship mining across specifications, runtime observations, and path structures.
            </p>
          </div>
          {isDiscovering && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Running Discovery...</span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={() => onTriggerDiscovery("ALL")}
            disabled={isDiscovering}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-semibold text-xs font-mono transition-colors"
          >
            <Play className="w-3 h-3" />
            <span>Discover All</span>
          </button>

          <button
            onClick={() => onTriggerDiscovery("DECLARED")}
            disabled={isDiscovering}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-800 disabled:text-slate-600 text-emerald-300 border border-emerald-900/60 text-xs font-mono transition-colors"
          >
            <FileCode className="w-3 h-3" />
            <span>Declared Specs Only</span>
          </button>

          <button
            onClick={() => onTriggerDiscovery("OBSERVED")}
            disabled={isDiscovering}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-800 disabled:text-slate-600 text-cyan-300 border border-cyan-900/60 text-xs font-mono transition-colors"
          >
            <Activity className="w-3 h-3" />
            <span>Observed Traffic Only</span>
          </button>

          <button
            onClick={() => onTriggerDiscovery("STRUCTURAL")}
            disabled={isDiscovering}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-800 disabled:text-slate-600 text-purple-300 border border-purple-900/60 text-xs font-mono transition-colors"
          >
            <Layers className="w-3 h-3" />
            <span>Structural Containment</span>
          </button>

          <button
            onClick={() => onTriggerDiscovery("OVERLAP")}
            disabled={isDiscovering}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-800 disabled:text-slate-600 text-indigo-300 border border-indigo-900/60 text-xs font-mono transition-colors"
          >
            <Network className="w-3 h-3" />
            <span>Role Access Overlap</span>
          </button>
        </div>
      </div>
    </div>
  );
};

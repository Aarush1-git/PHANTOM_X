import React, { useState } from "react";
import { Database, Plus, CheckCircle2, Archive, AlertCircle, Sparkles } from "lucide-react";
import { BehavioralBaseline } from "../../types/digitalTwin";

interface BaselineManagerProps {
  baselines: BehavioralBaseline[];
  onCompileBaseline: (version?: string, minSamples?: number) => Promise<void>;
  onActivateBaseline: (baselineId: string) => Promise<void>;
  onArchiveBaseline: (baselineId: string) => Promise<void>;
  isCompiling?: boolean;
}

export const BaselineManager: React.FC<BaselineManagerProps> = ({
  baselines,
  onCompileBaseline,
  onActivateBaseline,
  onArchiveBaseline,
  isCompiling = false,
}) => {
  const [showCompileModal, setShowCompileModal] = useState(false);
  const [customVersion, setCustomVersion] = useState("");
  const [minSamples, setMinSamples] = useState(5);
  const [actionInProgressId, setActionInProgressId] = useState<string | null>(null);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "ACTIVE":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            ACTIVE
          </span>
        );
      case "DRAFT":
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            DRAFT
          </span>
        );
      case "SUPERSEDED":
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-500/10 text-slate-400 border border-slate-500/30">
            SUPERSEDED
          </span>
        );
      case "ARCHIVED":
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-zinc-500/10 text-zinc-500 border border-zinc-500/30">
            ARCHIVED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-400">
            {status}
          </span>
        );
    }
  };

  const handleCompile = async (e: React.FormEvent) => {
    e.preventDefault();
    await onCompileBaseline(customVersion.trim() || undefined, minSamples);
    setCustomVersion("");
    setShowCompileModal(false);
  };

  const handleActivate = async (id: string) => {
    if (confirm("Are you sure you want to promote this baseline to ACTIVE? This will automatically supersede the current active baseline.")) {
      try {
        setActionInProgressId(id);
        await onActivateBaseline(id);
      } finally {
        setActionInProgressId(null);
      }
    }
  };

  const handleArchive = async (id: string) => {
    if (confirm("Archive this baseline? It will no longer be considered for active drift comparisons.")) {
      try {
        setActionInProgressId(id);
        await onArchiveBaseline(id);
      } finally {
        setActionInProgressId(null);
      }
    }
  };

  return (
    <div className="space-y-4">
      {/* Top action header */}
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-semibold font-mono text-slate-200">Behavioral Baseline Repository</h4>
          <p className="text-xs text-slate-400">
            Versioned snapshots of profile distributions and sequence flow graphs.
          </p>
        </div>

        <button
          onClick={() => setShowCompileModal(true)}
          disabled={isCompiling}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{isCompiling ? "Compiling..." : "Compile Baseline"}</span>
        </button>
      </div>

      {/* Compile Modal */}
      {showCompileModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-phantom-900 border border-slate-800 rounded-lg max-w-md w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                Compile New Baseline Snapshot
              </h3>
              <button
                onClick={() => setShowCompileModal(false)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCompile} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">VERSION LABEL (OPTIONAL)</label>
                <input
                  type="text"
                  placeholder="Auto-increment (e.g. v1.1)"
                  value={customVersion}
                  onChange={(e) => setCustomVersion(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">MINIMUM REQUIRED SAMPLES</label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={minSamples}
                  onChange={(e) => setMinSamples(parseInt(e.target.value) || 1)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Ensures baseline is not compiled over insufficient empirical observations.
                </span>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCompileModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCompiling}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs"
                >
                  {isCompiling ? "Compiling..." : "Compile Baseline"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Baselines Table */}
      {baselines.length === 0 ? (
        <div className="bg-phantom-900 border border-slate-800/80 rounded-lg p-8 text-center space-y-2">
          <Database className="w-8 h-8 text-slate-600 mx-auto" />
          <h4 className="text-sm font-semibold text-slate-300 font-mono">No Baseline Snapshots Found</h4>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Click "Compile Baseline" to generate the first behavioral profile from ingested observations.
          </p>
        </div>
      ) : (
        <div className="bg-phantom-900 border border-slate-800/80 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Version</th>
                <th className="p-3">Status</th>
                <th className="p-3">Samples</th>
                <th className="p-3">Confidence</th>
                <th className="p-3">Created</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {baselines.map((b) => {
                const confPercent = Math.round((b.confidence_score || 0) * 100);
                const isEligibleForActivation = b.sample_count >= 5 && b.confidence_score >= 0.2;
                const isBusy = actionInProgressId === b.id;

                return (
                  <tr key={b.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3 font-semibold text-slate-100 flex items-center gap-2">
                      <Database className="w-3.5 h-3.5 text-slate-500" />
                      <span>{b.version}</span>
                    </td>
                    <td className="p-3">{getStatusBadge(b.status)}</td>
                    <td className="p-3">{b.sample_count.toLocaleString()}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`font-bold ${
                            confPercent >= 70
                              ? "text-emerald-400"
                              : confPercent >= 30
                              ? "text-amber-400"
                              : "text-slate-500"
                          }`}
                        >
                          {confPercent}%
                        </span>
                      </div>
                    </td>
                    <td className="p-3 text-slate-400">
                      {new Date(b.created_at).toLocaleDateString()}
                    </td>
                    <td className="p-3 text-right">
                      <div className="inline-flex items-center gap-2 justify-end">
                        {/* Activate Button */}
                        {b.status !== "ACTIVE" && b.status !== "ARCHIVED" && (
                          <button
                            onClick={() => handleActivate(b.id)}
                            disabled={!isEligibleForActivation || isBusy}
                            title={
                              !isEligibleForActivation
                                ? `Requires >= 5 samples and >= 20% confidence (Current: ${b.sample_count} samples, ${confPercent}% confidence)`
                                : "Promote to ACTIVE baseline"
                            }
                            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                              isEligibleForActivation
                                ? "bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 cursor-pointer"
                                : "bg-slate-900 text-slate-600 border border-slate-800 cursor-not-allowed"
                            }`}
                          >
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Activate</span>
                          </button>
                        )}

                        {/* Archive Button */}
                        {b.status !== "ACTIVE" && b.status !== "ARCHIVED" && (
                          <button
                            onClick={() => handleArchive(b.id)}
                            disabled={isBusy}
                            title="Archive this baseline"
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700 cursor-pointer transition-colors"
                          >
                            <Archive className="w-3 h-3" />
                            <span>Archive</span>
                          </button>
                        )}

                        {b.status === "ACTIVE" && (
                          <span className="text-[11px] text-emerald-400 font-semibold px-2 py-1">
                            Primary Baseline
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

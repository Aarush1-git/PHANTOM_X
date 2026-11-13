import React from "react";
import { Activity, ShieldAlert, Database, Clock, Layers, Sparkles } from "lucide-react";
import { DigitalTwinOverviewResponse } from "../../types/digitalTwin";
import { StatCard } from "../common/StatCard";

interface DigitalTwinOverviewProps {
  overview: DigitalTwinOverviewResponse;
  onTriggerDriftEvaluation?: () => void;
  isEvaluating?: boolean;
}

export const DigitalTwinOverview: React.FC<DigitalTwinOverviewProps> = ({
  overview,
  onTriggerDriftEvaluation,
  isEvaluating,
}) => {
  const confidencePercent = Math.round(overview.active_baseline_confidence * 100);
  const endpointCount = Object.keys(overview.endpoint_profiles || {}).length;

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Observations"
          value={overview.total_observations.toLocaleString()}
          subtitle="Sanitized API telemetry traces"
          icon={Activity}
          trend={overview.total_observations > 0 ? "Active Ingestion" : "No Telemetry"}
          trendColor={overview.total_observations > 0 ? "emerald" : "slate"}
        />

        <StatCard
          title="Behavioral Coverage"
          value={`${endpointCount} Endpoints`}
          subtitle={`${overview.total_transitions_tracked} Markov transitions learned`}
          icon={Layers}
          trend={endpointCount > 0 ? "Profiled" : "Pending"}
          trendColor={endpointCount > 0 ? "cyan" : "slate"}
        />

        <StatCard
          title="Active Baseline"
          value={overview.active_baseline_version || "None"}
          subtitle={
            overview.active_baseline_version
              ? `Confidence: ${confidencePercent}%`
              : "Draft baseline required"
          }
          icon={Database}
          trend={overview.active_baseline_version ? "Active" : "Unestablished"}
          trendColor={overview.active_baseline_version ? "emerald" : "rose"}
        />

        <StatCard
          title="Open Anomalies"
          value={overview.open_anomalies_count}
          subtitle="Unresolved behavioral deviations"
          icon={ShieldAlert}
          trend={overview.open_anomalies_count > 0 ? "Action Required" : "Clean"}
          trendColor={overview.open_anomalies_count > 0 ? "rose" : "emerald"}
        />
      </div>

      {/* Overview Status & Drift Trigger Banner */}
      <div className="bg-phantom-900 border border-slate-800/90 rounded-lg p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
              Telemetry Status
            </span>
            {overview.active_baseline_version ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                ACTIVE MONITORING
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                NO ACTIVE BASELINE
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Last observation:{" "}
            {overview.last_observed_at
              ? new Date(overview.last_observed_at).toLocaleString()
              : "Never"}
            {overview.active_baseline_id && (
              <span className="ml-3 text-slate-500">
                Baseline ID: <span className="text-slate-400">{overview.active_baseline_id.slice(0, 8)}...</span>
              </span>
            )}
          </p>
        </div>

        {onTriggerDriftEvaluation && (
          <button
            onClick={onTriggerDriftEvaluation}
            disabled={isEvaluating || !overview.active_baseline_id}
            className={`inline-flex items-center gap-2 px-3.5 py-2 rounded text-xs font-semibold font-mono transition-colors border ${
              overview.active_baseline_id
                ? "bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border-cyan-800/80 cursor-pointer"
                : "bg-slate-900 text-slate-600 border-slate-800 cursor-not-allowed"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isEvaluating ? "Evaluating Drift..." : "Trigger Drift Evaluation"}</span>
          </button>
        )}
      </div>
    </div>
  );
};

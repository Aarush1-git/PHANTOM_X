import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Layers,
  GitFork,
  Database,
  ShieldAlert,
  AlertCircle,
  RefreshCw,
} from "lucide-react";
import { digitalTwinApi } from "../../services/digitalTwinApi";
import { DigitalTwinOverview } from "./DigitalTwinOverview";
import { EndpointBehaviorExplorer } from "./EndpointBehaviorExplorer";
import { WorkflowTransitionGraph } from "./WorkflowTransitionGraph";
import { BaselineManager } from "./BaselineManager";
import { AnomalyExplorer } from "./AnomalyExplorer";
import { LoadingSpinner } from "../common/LoadingSpinner";

interface BehavioralDigitalTwinPanelProps {
  applicationId: string;
}

type TabType = "overview" | "endpoints" | "workflow" | "baselines" | "anomalies";

export const BehavioralDigitalTwinPanel: React.FC<BehavioralDigitalTwinPanelProps> = ({
  applicationId,
}) => {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const queryClient = useQueryClient();

  // 1. Fetch High-level Overview
  const {
    data: overview,
    isLoading: isOverviewLoading,
    error: overviewError,
    refetch: refetchOverview,
  } = useQuery({
    queryKey: ["digitalTwinOverview", applicationId],
    queryFn: () => digitalTwinApi.getOverview(applicationId),
    enabled: !!applicationId,
  });

  // 2. Fetch Baselines List
  const {
    data: baselinesData,
    isLoading: isBaselinesLoading,
    refetch: refetchBaselines,
  } = useQuery({
    queryKey: ["digitalTwinBaselines", applicationId],
    queryFn: () => digitalTwinApi.listBaselines(applicationId),
    enabled: !!applicationId,
  });

  // 3. Fetch Anomalies List
  const {
    data: anomaliesData,
    isLoading: isAnomaliesLoading,
    refetch: refetchAnomalies,
  } = useQuery({
    queryKey: ["digitalTwinAnomalies", applicationId],
    queryFn: () => digitalTwinApi.listAnomalies({ application_id: applicationId, limit: 100 }),
    enabled: !!applicationId,
  });

  // Mutations
  const compileMutation = useMutation({
    mutationFn: ({ version, minSamples }: { version?: string; minSamples?: number }) =>
      digitalTwinApi.compileBaseline({
        application_id: applicationId,
        version,
        min_samples: minSamples,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinBaselines", applicationId] });
    },
  });

  const activateMutation = useMutation({
    mutationFn: (baselineId: string) => digitalTwinApi.activateBaseline(baselineId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinBaselines", applicationId] });
    },
  });

  const archiveMutation = useMutation({
    mutationFn: (baselineId: string) => digitalTwinApi.archiveBaseline(baselineId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinBaselines", applicationId] });
    },
  });

  const evaluateDriftMutation = useMutation({
    mutationFn: () => digitalTwinApi.evaluateDrift(applicationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinAnomalies", applicationId] });
    },
  });

  const acknowledgeMutation = useMutation({
    mutationFn: ({ anomalyId, notes }: { anomalyId: string; notes?: string }) =>
      digitalTwinApi.acknowledgeAnomaly(anomalyId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinAnomalies", applicationId] });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ anomalyId, notes }: { anomalyId: string; notes?: string }) =>
      digitalTwinApi.resolveAnomaly(anomalyId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["digitalTwinOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["digitalTwinAnomalies", applicationId] });
    },
  });

  const handleRefresh = () => {
    refetchOverview();
    refetchBaselines();
    refetchAnomalies();
  };

  // Find active baseline transition matrix for the graph
  const activeBaseline = baselinesData?.items.find((b) => b.status === "ACTIVE");
  const transitionMatrix = activeBaseline?.transition_matrix || {};

  // Loading state
  if (isOverviewLoading && !overview) {
    return (
      <div className="bg-phantom-900 border border-slate-800 rounded-lg p-10 flex flex-col items-center justify-center space-y-3">
        <LoadingSpinner />
        <span className="text-xs font-mono text-slate-400">Loading Behavioral Digital Twin telemetry...</span>
      </div>
    );
  }

  // Error state
  if (overviewError && !overview) {
    const errorMsg =
      (overviewError as any)?.response?.data?.detail || "Failed to load Behavioral Digital Twin telemetry.";
    return (
      <div className="bg-phantom-900 border border-rose-900/60 rounded-lg p-6 space-y-3">
        <div className="flex items-center gap-2 text-rose-400 font-mono text-xs font-bold">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>Behavioral Twin Service Unavailable</span>
        </div>
        <p className="text-xs text-slate-400 font-mono">{errorMsg}</p>
        <button
          onClick={handleRefresh}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry Connection</span>
        </button>
      </div>
    );
  }

  const openAnomaliesCount = overview?.open_anomalies_count || 0;

  return (
    <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col space-y-4 p-5">
      {/* Header with Title & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider">
              Behavioral Digital Twin
            </h3>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Empirical behavioral profiling, Markov workflow state machines, and statistical drift telemetry.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          className="self-start sm:self-center inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono border border-slate-700 transition-colors"
          title="Refresh Telemetry"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Sync</span>
        </button>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-1 border-b border-slate-800 pb-2 text-xs font-mono">
        <button
          onClick={() => setActiveTab("overview")}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded transition-colors ${
            activeTab === "overview"
              ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Overview</span>
        </button>

        <button
          onClick={() => setActiveTab("endpoints")}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded transition-colors ${
            activeTab === "endpoints"
              ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Endpoint Profiles</span>
          <span className="text-[10px] px-1 rounded bg-slate-900 text-slate-400">
            {Object.keys(overview?.endpoint_profiles || {}).length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("workflow")}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded transition-colors ${
            activeTab === "workflow"
              ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <GitFork className="w-3.5 h-3.5" />
          <span>State Machine</span>
        </button>

        <button
          onClick={() => setActiveTab("baselines")}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded transition-colors ${
            activeTab === "baselines"
              ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Baselines</span>
          <span className="text-[10px] px-1 rounded bg-slate-900 text-slate-400">
            {baselinesData?.total || 0}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("anomalies")}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded transition-colors ${
            activeTab === "anomalies"
              ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Anomalies</span>
          {openAnomaliesCount > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
              {openAnomaliesCount}
            </span>
          )}
        </button>
      </div>

      {/* Tab Contents */}
      <div className="pt-2">
        {activeTab === "overview" && overview && (
          <DigitalTwinOverview
            overview={overview}
            onTriggerDriftEvaluation={() => evaluateDriftMutation.mutate()}
            isEvaluating={evaluateDriftMutation.isPending}
          />
        )}

        {activeTab === "endpoints" && (
          <EndpointBehaviorExplorer
            endpointProfiles={overview?.endpoint_profiles || {}}
          />
        )}

        {activeTab === "workflow" && (
          <WorkflowTransitionGraph transitionMatrix={transitionMatrix} />
        )}

        {activeTab === "baselines" && (
          <BaselineManager
            baselines={baselinesData?.items || []}
            onCompileBaseline={async (version, minSamples) => {
              await compileMutation.mutateAsync({ version, minSamples });
            }}
            onActivateBaseline={async (baselineId) => {
              await activateMutation.mutateAsync(baselineId);
            }}
            onArchiveBaseline={async (baselineId) => {
              await archiveMutation.mutateAsync(baselineId);
            }}
            isCompiling={compileMutation.isPending}
          />
        )}

        {activeTab === "anomalies" && (
          <AnomalyExplorer
            anomalies={anomaliesData?.items || []}
            onAcknowledge={async (anomalyId, notes) => {
              await acknowledgeMutation.mutateAsync({ anomalyId, notes });
            }}
            onResolve={async (anomalyId, notes) => {
              await resolveMutation.mutateAsync({ anomalyId, notes });
            }}
          />
        )}
      </div>
    </div>
  );
};

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { GitBranch, AlertCircle, RefreshCw } from "lucide-react";
import { workflowApi } from "../../services/workflowApi";
import { DiscoveredWorkflow, DiscoveredWorkflowDetail } from "../../types/workflow";
import { WorkflowDiscoveryOverview } from "./WorkflowDiscoveryOverview";
import { WorkflowGraphView } from "./WorkflowGraphView";
import { WorkflowList } from "./WorkflowList";
import { WorkflowDetailModal } from "./WorkflowDetailModal";

interface WorkflowDiscoveryPanelProps {
  applicationId: string;
}

export const WorkflowDiscoveryPanel: React.FC<WorkflowDiscoveryPanelProps> = ({
  applicationId,
}) => {
  const queryClient = useQueryClient();

  // Filters & Pagination State
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState("");
  const [confidenceFilter, setConfidenceFilter] = useState(0);
  const [incompleteFilter, setIncompleteFilter] = useState("");

  // Selected Workflow for Graph & Modal
  const [selectedWorkflow, setSelectedWorkflow] = useState<DiscoveredWorkflow | null>(null);
  const [modalWorkflow, setModalWorkflow] = useState<DiscoveredWorkflowDetail | null>(null);

  // 1. Fetch Overview
  const {
    data: overview,
    isLoading: loadingOverview,
    error: overviewError,
  } = useQuery({
    queryKey: ["workflowOverview", applicationId],
    queryFn: () => workflowApi.getOverview(applicationId),
    enabled: !!applicationId,
  });

  // 2. Fetch Workflow List
  const {
    data: workflowList,
    isLoading: loadingList,
    error: listError,
  } = useQuery({
    queryKey: [
      "workflowList",
      applicationId,
      page,
      typeFilter,
      confidenceFilter,
      incompleteFilter,
    ],
    queryFn: () =>
      workflowApi.listWorkflows(applicationId, {
        page,
        page_size: 10,
        workflow_type: typeFilter || undefined,
        min_confidence: confidenceFilter || undefined,
        is_incomplete:
          incompleteFilter === "true"
            ? true
            : incompleteFilter === "false"
            ? false
            : undefined,
      }),
    enabled: !!applicationId,
  });

  // 3. Fetch Selected Workflow Detail with Graph
  const activeWorkflowId = selectedWorkflow?.id || (workflowList?.items?.[0]?.id ?? null);
  const { data: workflowDetail } = useQuery({
    queryKey: ["workflowDetail", activeWorkflowId],
    queryFn: () => (activeWorkflowId ? workflowApi.getWorkflowDetail(activeWorkflowId) : null),
    enabled: !!activeWorkflowId,
  });

  // 4. Discovery Mutation
  const discoveryMutation = useMutation({
    mutationFn: () => workflowApi.triggerDiscovery(applicationId, { min_sample_count: 1 }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["workflowOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["workflowList", applicationId] });
    },
  });

  // Handle open details modal
  const handleViewDetails = async (wf: DiscoveredWorkflow) => {
    try {
      const detail = await workflowApi.getWorkflowDetail(wf.id);
      setModalWorkflow(detail);
    } catch {
      // Fallback to basic object if fetch fails
      setModalWorkflow({
        ...wf,
        graph_data: { nodes: [], edges: [] },
        variations: {},
      });
    }
  };

  if (loadingOverview && !overview) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 flex items-center justify-center gap-2 text-xs font-mono text-slate-400">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Workflow Discovery telemetry...</span>
      </div>
    );
  }

  if (overviewError || listError) {
    return (
      <div className="bg-slate-900 border border-red-900/40 rounded-lg p-6 flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-xs font-mono">
          <div className="font-semibold text-red-300">Failed to load workflow discovery data</div>
          <div className="text-slate-400">
            Please verify API connectivity or ensure the application exists.
          </div>
        </div>
      </div>
    );
  }

  // Insufficient Data State
  if (overview?.insufficient_data && (workflowList?.total ?? 0) === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-slate-800 text-cyan-400 flex items-center justify-center mx-auto">
          <GitBranch className="w-6 h-6" />
        </div>
        <div className="space-y-1.5 max-w-md mx-auto">
          <h3 className="text-sm font-mono font-semibold text-slate-200">
            Insufficient Workflow Telemetry
          </h3>
          <p className="text-xs text-slate-400">
            The application has not accumulated enough API traffic observations to reliably reconstruct
            multi-step user journeys (minimum 2 observations required).
          </p>
        </div>
        <button
          onClick={() => discoveryMutation.mutate()}
          disabled={discoveryMutation.isPending}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-slate-950 font-semibold text-xs font-mono transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${discoveryMutation.isPending ? "animate-spin" : ""}`} />
          <span>{discoveryMutation.isPending ? "Checking Traffic..." : "Trigger Discovery Check"}</span>
        </button>
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-6">
      {/* Overview Metrics Header */}
      {overview && (
        <WorkflowDiscoveryOverview
          overview={overview}
          isDiscovering={discoveryMutation.isPending}
          onTriggerDiscovery={() => discoveryMutation.mutate()}
        />
      )}

      {/* Interactive Workflow Graph */}
      {workflowDetail && (
        <div className="space-y-2 pt-2 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
              Selected Journey Graph Visualization
            </span>
            <span className="text-xs font-mono text-cyan-400">
              Confidence: {Math.round(workflowDetail.confidence_score * 100)}%
            </span>
          </div>
          <WorkflowGraphView
            graph={workflowDetail.graph_data}
            workflowName={workflowDetail.name}
          />
        </div>
      )}

      {/* Discovered Workflows Table / List */}
      <div className="space-y-3 pt-2 border-t border-slate-800">
        <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider block">
          Discovered Application Journeys
        </span>
        <WorkflowList
          workflows={workflowList?.items || []}
          total={workflowList?.total || 0}
          page={page}
          pageSize={10}
          selectedWorkflowId={activeWorkflowId}
          onSelectWorkflow={(wf) => setSelectedWorkflow(wf)}
          onViewDetails={handleViewDetails}
          onPageChange={(p) => setPage(p)}
          typeFilter={typeFilter}
          onTypeFilterChange={setTypeFilter}
          confidenceFilter={confidenceFilter}
          onConfidenceFilterChange={setConfidenceFilter}
          incompleteFilter={incompleteFilter}
          onIncompleteFilterChange={setIncompleteFilter}
        />
      </div>

      {/* Detail Modal */}
      {modalWorkflow && (
        <WorkflowDetailModal
          workflow={modalWorkflow}
          onClose={() => setModalWorkflow(null)}
        />
      )}
    </div>
  );
};

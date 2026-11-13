import React from "react";
import { GitBranch, Eye, ArrowRight, Activity, Filter, ChevronLeft, ChevronRight } from "lucide-react";
import { DiscoveredWorkflow, WorkflowType, WorkflowStatus } from "../../types/workflow";

interface WorkflowListProps {
  workflows: DiscoveredWorkflow[];
  total: number;
  page: number;
  pageSize: number;
  selectedWorkflowId?: string | null;
  onSelectWorkflow: (workflow: DiscoveredWorkflow) => void;
  onViewDetails: (workflow: DiscoveredWorkflow) => void;
  onPageChange: (newPage: number) => void;
  // Filters
  typeFilter: string;
  onTypeFilterChange: (val: string) => void;
  confidenceFilter: number;
  onConfidenceFilterChange: (val: number) => void;
  incompleteFilter: string;
  onIncompleteFilterChange: (val: string) => void;
}

export const WorkflowList: React.FC<WorkflowListProps> = ({
  workflows,
  total,
  page,
  pageSize,
  selectedWorkflowId,
  onSelectWorkflow,
  onViewDetails,
  onPageChange,
  typeFilter,
  onTypeFilterChange,
  confidenceFilter,
  onConfidenceFilterChange,
  incompleteFilter,
  onIncompleteFilterChange,
}) => {
  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 border border-slate-800 rounded-lg p-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Filters:</span>
          </div>

          {/* Workflow Type */}
          <select
            value={typeFilter}
            onChange={(e) => onTypeFilterChange(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Types</option>
            <option value="STANDARD">Standard</option>
            <option value="BRANCHED">Branched</option>
            <option value="ABANDONED">Abandoned</option>
            <option value="CYCLIC">Cyclic</option>
          </select>

          {/* Confidence */}
          <select
            value={confidenceFilter}
            onChange={(e) => onConfidenceFilterChange(parseFloat(e.target.value))}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="0">All Confidence</option>
            <option value="0.5">Confidence &ge; 50%</option>
            <option value="0.7">Confidence &ge; 70%</option>
            <option value="0.85">Confidence &ge; 85%</option>
          </select>

          {/* Incomplete */}
          <select
            value={incompleteFilter}
            onChange={(e) => onIncompleteFilterChange(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Journeys</option>
            <option value="false">Completed Only</option>
            <option value="true">Abandoned / Incomplete Only</option>
          </select>
        </div>

        <div className="text-slate-500">
          Showing <span className="text-slate-300 font-semibold">{workflows.length}</span> of{" "}
          <span className="text-slate-300 font-semibold">{total}</span>
        </div>
      </div>

      {/* Workflows Table */}
      {workflows.length === 0 ? (
        <div className="p-8 text-center border border-slate-800 rounded-lg bg-slate-900/40 text-slate-500 text-xs font-mono">
          No discovered workflows matched the specified filter criteria.
        </div>
      ) : (
        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3 font-semibold">Workflow Name</th>
                <th className="py-2.5 px-3 font-semibold">Type</th>
                <th className="py-2.5 px-3 font-semibold">Steps</th>
                <th className="py-2.5 px-3 font-semibold">Sessions</th>
                <th className="py-2.5 px-3 font-semibold">Confidence</th>
                <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {workflows.map((wf) => {
                const isSelected = selectedWorkflowId === wf.id;
                return (
                  <tr
                    key={wf.id}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      isSelected ? "bg-slate-800/60 border-l-2 border-l-cyan-400" : ""
                    }`}
                  >
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-slate-200 truncate max-w-xs" title={wf.name}>
                        {wf.name}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate max-w-xs">
                        {wf.description}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                          wf.workflow_type === "STANDARD"
                            ? "bg-slate-950 text-slate-400 border-slate-800"
                            : wf.workflow_type === "BRANCHED"
                            ? "bg-indigo-950/80 text-indigo-400 border-indigo-800"
                            : wf.workflow_type === "ABANDONED"
                            ? "bg-amber-950/80 text-amber-400 border-amber-800"
                            : "bg-teal-950/80 text-teal-400 border-teal-800"
                        }`}
                      >
                        {wf.workflow_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-bold">{wf.step_count}</td>
                    <td className="py-2.5 px-3 text-slate-300">{wf.sample_count}</td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full ${
                              wf.confidence_score >= 0.7
                                ? "bg-cyan-400"
                                : wf.confidence_score >= 0.4
                                ? "bg-teal-400"
                                : "bg-slate-500"
                            }`}
                            style={{ width: `${Math.round(wf.confidence_score * 100)}%` }}
                          />
                        </div>
                        <span className="text-cyan-400 font-bold">
                          {Math.round(wf.confidence_score * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => onSelectWorkflow(wf)}
                          className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                            isSelected
                              ? "bg-cyan-600 text-slate-950 font-bold"
                              : "bg-slate-800 hover:bg-slate-700 text-slate-300"
                          }`}
                        >
                          Graph
                        </button>
                        <button
                          onClick={() => onViewDetails(wf)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono transition-colors"
                        >
                          Details
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-2">
          <span>
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

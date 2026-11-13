import React, { useState } from "react";
import { X, Eye, FileText, CheckCircle2, AlertTriangle, ShieldCheck } from "lucide-react";
import { DiscoveredWorkflowDetail, WorkflowEvidenceItem } from "../../types/workflow";
import { workflowApi } from "../../services/workflowApi";

interface WorkflowDetailModalProps {
  workflow: DiscoveredWorkflowDetail;
  onClose: () => void;
}

export const WorkflowDetailModal: React.FC<WorkflowDetailModalProps> = ({
  workflow,
  onClose,
}) => {
  const [selectedStepIndex, setSelectedStepIndex] = useState<number | null>(null);
  const [evidenceItems, setEvidenceItems] = useState<WorkflowEvidenceItem[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);

  const fetchEvidence = async (stepIdx?: number) => {
    try {
      setLoadingEvidence(true);
      setSelectedStepIndex(stepIdx ?? null);
      const res = await workflowApi.getWorkflowEvidence(workflow.id, stepIdx, 10);
      setEvidenceItems(res.items);
    } catch {
      setEvidenceItems([]);
    } finally {
      setLoadingEvidence(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-mono font-bold text-slate-100">{workflow.name}</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                {workflow.workflow_type}
              </span>
              {workflow.is_incomplete && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
                  ABANDONED @ STEP {workflow.dropout_step_index ?? "?"}
                </span>
              )}
            </div>
            <div className="text-xs text-slate-400 font-mono">
              Confidence: <span className="text-cyan-400 font-bold">{Math.round(workflow.confidence_score * 100)}%</span> |
              Sessions Observed: <span className="text-slate-200 font-bold">{workflow.sample_count}</span> |
              Discovered: {new Date(workflow.discovered_at).toLocaleString()}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-6 flex-1">
          {/* Steps Sequence */}
          <div className="space-y-3">
            <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
              Ordered Journey Steps ({workflow.steps_sequence.length})
            </div>
            <div className="border border-slate-800 rounded-lg overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3 font-semibold">#</th>
                    <th className="py-2.5 px-3 font-semibold">Type</th>
                    <th className="py-2.5 px-3 font-semibold">Method</th>
                    <th className="py-2.5 px-3 font-semibold">Normalized Path</th>
                    <th className="py-2.5 px-3 font-semibold">Avg Latency</th>
                    <th className="py-2.5 px-3 font-semibold">Error Rate</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {workflow.steps_sequence.map((step) => (
                    <tr
                      key={step.step_index}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        selectedStepIndex === step.step_index ? "bg-slate-800/60" : ""
                      }`}
                    >
                      <td className="py-2.5 px-3 text-slate-400">{step.step_index + 1}</td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                            step.step_type === "ENTRY"
                              ? "bg-emerald-950/80 text-emerald-400 border-emerald-800"
                              : step.step_type === "TERMINAL"
                              ? "bg-blue-950/80 text-blue-400 border-blue-800"
                              : step.step_type === "DROPOUT"
                              ? "bg-amber-950/80 text-amber-400 border-amber-800"
                              : "bg-cyan-950/80 text-cyan-400 border-cyan-800"
                          }`}
                        >
                          {step.step_type}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{step.method}</td>
                      <td className="py-2.5 px-3 text-slate-200 break-all">{step.normalized_path}</td>
                      <td className="py-2.5 px-3 text-slate-300">{step.avg_latency_ms} ms</td>
                      <td className="py-2.5 px-3">
                        <span className={step.error_rate > 0 ? "text-amber-400" : "text-slate-400"}>
                          {Math.round(step.error_rate * 100)}%
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => fetchEvidence(step.step_index)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Evidence Inspector */}
          {selectedStepIndex !== null && (
            <div className="space-y-3 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <div className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>Sanitized Telemetry Evidence (Step {selectedStepIndex + 1})</span>
                </div>
                <button
                  onClick={() => setSelectedStepIndex(null)}
                  className="text-xs text-slate-500 hover:text-slate-300 font-mono"
                >
                  Dismiss
                </button>
              </div>

              {loadingEvidence ? (
                <div className="p-4 text-xs font-mono text-slate-500 text-center">Loading evidence records...</div>
              ) : evidenceItems.length === 0 ? (
                <div className="p-4 text-xs font-mono text-slate-500 text-center bg-slate-950 rounded border border-slate-800">
                  No direct observation evidence records found.
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {evidenceItems.map((ev) => (
                    <div
                      key={ev.observation_id}
                      className="bg-slate-950/80 border border-slate-800 rounded p-3 text-xs font-mono space-y-2"
                    >
                      <div className="flex items-center justify-between text-slate-400">
                        <div className="flex items-center gap-2">
                          <span className="text-cyan-400 font-bold">{ev.method}</span>
                          <span className="text-slate-200">{ev.normalized_path}</span>
                          <span
                            className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              ev.status_code >= 400
                                ? "bg-red-950 text-red-400 border border-red-800"
                                : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                            }`}
                          >
                            HTTP {ev.status_code}
                          </span>
                        </div>
                        <span className="text-slate-500">{new Date(ev.observed_at).toLocaleTimeString()}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-900">
                        <div>
                          <span className="text-slate-500 block">Sanitized Request Schema:</span>
                          <pre className="text-slate-300 bg-slate-900 p-1.5 rounded overflow-x-auto text-[10px]">
                            {JSON.stringify(ev.sanitized_request_schema, null, 2)}
                          </pre>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Sanitized Response Schema:</span>
                          <pre className="text-slate-300 bg-slate-900 p-1.5 rounded overflow-x-auto text-[10px]">
                            {JSON.stringify(ev.sanitized_response_schema, null, 2)}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Alternative Variations */}
          {workflow.variations && Object.keys(workflow.variations).length > 0 && (
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Observed Path Variations & Sibling Branches
              </div>
              <pre className="text-xs font-mono bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300 overflow-x-auto">
                {JSON.stringify(workflow.variations, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs font-mono text-slate-500">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Multi-tenant isolated & sanitized</span>
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors font-sans"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

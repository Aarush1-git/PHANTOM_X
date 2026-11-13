import React, { useState } from "react";
import { AlertTriangle, Check, Eye, HelpCircle, ShieldAlert } from "lucide-react";
import { BehavioralAnomalyResponse, AnomalyStatus } from "../../types/digitalTwin";
import { SeverityBadge } from "../common/Badge";

interface AnomalyExplorerProps {
  anomalies: BehavioralAnomalyResponse[];
  onAcknowledge: (anomalyId: string, notes?: string) => Promise<void>;
  onResolve: (anomalyId: string, notes?: string) => Promise<void>;
}

export const AnomalyExplorer: React.FC<AnomalyExplorerProps> = ({
  anomalies,
  onAcknowledge,
  onResolve,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [selectedAnomaly, setSelectedAnomaly] = useState<BehavioralAnomalyResponse | null>(null);
  const [actionNotes, setActionNotes] = useState("");
  const [actionType, setActionType] = useState<"ack" | "resolve" | null>(null);
  const [targetId, setTargetId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Filter anomalies
  const filtered = anomalies.filter((a) => {
    if (statusFilter !== "ALL" && a.status !== statusFilter) return false;
    if (severityFilter !== "ALL" && a.severity !== severityFilter) return false;
    return true;
  });

  const handleActionConfirm = async () => {
    if (!targetId || !actionType) return;
    try {
      setIsSubmitting(true);
      if (actionType === "ack") {
        await onAcknowledge(targetId, actionNotes.trim() || undefined);
      } else {
        await onResolve(targetId, actionNotes.trim() || undefined);
      }
      setActionType(null);
      setTargetId(null);
      setActionNotes("");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Disclaimer Banner: Non-Vulnerability Clarification */}
      <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3.5 flex items-start gap-3">
        <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-300/90 leading-relaxed font-mono">
          <span className="font-bold text-amber-300">NOTICE: BEHAVIORAL DEVIATION TELEMETRY</span>
          <p className="text-[11px] text-amber-400/80 mt-0.5">
            Behavioral anomalies represent statistical or structural divergences from the established baseline (such as unseen status codes, novel fields, or unexpected latency). They are NOT confirmed security vulnerabilities and do not inherently signify exploitation.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">STATUS:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">SEVERITY:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        <span className="text-slate-500">
          Showing {filtered.length} of {anomalies.length} Deviations
        </span>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="bg-phantom-900 border border-slate-800/80 rounded-lg p-8 text-center space-y-2">
          <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
          <h4 className="text-sm font-semibold text-slate-300 font-mono">No Behavioral Anomalies</h4>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            {anomalies.length === 0
              ? "No behavioral deviations have been flagged for this application against the active baseline."
              : "No deviations matched the selected filter criteria."}
          </p>
        </div>
      ) : (
        <div className="bg-phantom-900 border border-slate-800/80 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Severity</th>
                <th className="p-3">Anomaly Type</th>
                <th className="p-3">Target Endpoint</th>
                <th className="p-3">Occurrences</th>
                <th className="p-3">Status</th>
                <th className="p-3">Detected</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filtered.map((anom) => {
                const endpointKey =
                  anom.evidence_data?.endpoint_key ||
                  anom.evidence_data?.normalized_path ||
                  anom.evidence_data?.signature ||
                  "—";
                const occurrences = anom.evidence_data?.occurrence_count || 1;

                return (
                  <tr key={anom.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3">
                      <SeverityBadge severity={anom.severity} />
                    </td>
                    <td className="p-3 font-semibold text-slate-200">
                      {anom.anomaly_type.replace(/_/g, " ")}
                    </td>
                    <td className="p-3 text-slate-300 truncate max-w-[200px]" title={endpointKey}>
                      {endpointKey}
                    </td>
                    <td className="p-3 text-slate-400">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[11px] text-slate-200 font-bold">
                        {occurrences}x
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          anom.status === "OPEN"
                            ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                            : anom.status === "ACKNOWLEDGED"
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                            : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                        }`}
                      >
                        {anom.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-500 text-[11px]">
                      {new Date(anom.detected_at).toLocaleDateString()}
                    </td>
                    <td className="p-3 text-right">
                      <div className="inline-flex items-center gap-1.5 justify-end">
                        <button
                          onClick={() => setSelectedAnomaly(anom)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                          title="Inspect Evidence"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Evidence</span>
                        </button>

                        {anom.status === "OPEN" && (
                          <button
                            onClick={() => {
                              setTargetId(anom.id);
                              setActionType("ack");
                            }}
                            className="px-2 py-1 rounded bg-amber-950/80 hover:bg-amber-900 text-amber-300 border border-amber-800/80 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                          >
                            <span>Ack</span>
                          </button>
                        )}

                        {anom.status !== "RESOLVED" && (
                          <button
                            onClick={() => {
                              setTargetId(anom.id);
                              setActionType("resolve");
                            }}
                            className="px-2 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800/80 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                          >
                            <Check className="w-3 h-3" />
                            <span>Resolve</span>
                          </button>
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

      {/* Evidence Viewer Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-phantom-900 border border-slate-800 rounded-lg max-w-2xl w-full p-5 space-y-4 shadow-xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={selectedAnomaly.severity} />
                <h3 className="text-sm font-semibold font-mono text-slate-200">
                  {selectedAnomaly.anomaly_type.replace(/_/g, " ")} Evidence
                </h3>
              </div>
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 font-mono text-xs">
              <div className="bg-slate-950/60 p-3 rounded border border-slate-800/80 space-y-1 text-slate-400 text-[11px]">
                <div>
                  Anomaly ID: <span className="text-slate-200">{selectedAnomaly.id}</span>
                </div>
                <div>
                  Confidence:{" "}
                  <span className="text-cyan-400 font-bold">
                    {Math.round(selectedAnomaly.confidence * 100)}%
                  </span>
                </div>
                <div>
                  First Detected:{" "}
                  <span className="text-slate-200">
                    {new Date(selectedAnomaly.detected_at).toLocaleString()}
                  </span>
                </div>
                {selectedAnomaly.resolved_at && (
                  <div>
                    Resolved At:{" "}
                    <span className="text-emerald-400">
                      {new Date(selectedAnomaly.resolved_at).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>

              <div>
                <span className="text-slate-400 block mb-1">SANITIZED FORENSIC EVIDENCE PAYLOAD</span>
                <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-300 overflow-x-auto max-h-72">
                  {JSON.stringify(selectedAnomaly.evidence_data, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Review Action Modal (Ack / Resolve) */}
      {actionType && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-phantom-900 border border-slate-800 rounded-lg max-w-md w-full p-5 space-y-4 shadow-xl">
            <h3 className="text-sm font-semibold font-mono text-slate-200">
              {actionType === "ack" ? "Acknowledge Anomaly" : "Resolve Anomaly"}
            </h3>

            <div className="text-xs font-mono text-slate-400 space-y-2">
              <label className="block text-slate-400">AUDIT / RESOLUTION NOTES (OPTIONAL)</label>
              <textarea
                rows={3}
                placeholder="Document verification findings, patch details, or justification..."
                value={actionNotes}
                onChange={(e) => setActionNotes(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => {
                  setActionType(null);
                  setTargetId(null);
                }}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleActionConfirm}
                disabled={isSubmitting}
                className={`px-3 py-1.5 rounded font-semibold text-xs font-mono ${
                  actionType === "ack"
                    ? "bg-amber-600 hover:bg-amber-500 text-slate-950"
                    : "bg-emerald-600 hover:bg-emerald-500 text-slate-950"
                }`}
              >
                {isSubmitting ? "Submitting..." : actionType === "ack" ? "Acknowledge" : "Resolve"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  X,
  Shield,
  Activity,
  AlertTriangle,
  Lock,
  Code,
  Calendar,
  CheckCircle,
  FileText,
  Clock,
  Layers,
} from "lucide-react";
import { roleResourceApi } from "../../services/roleResourceApi";
import { RoleResourceMapping } from "../../types/roleResource";

interface EvidenceDetailModalProps {
  mapping: RoleResourceMapping | null;
  onClose: () => void;
}

export const EvidenceDetailModal: React.FC<EvidenceDetailModalProps> = ({
  mapping,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<"telemetry" | "observations">("telemetry");

  const { data: evidenceData, isLoading: loadingEvidence } = useQuery({
    queryKey: ["mappingEvidence", mapping?.id],
    queryFn: () => (mapping ? roleResourceApi.getEvidence(mapping.id, 50) : null),
    enabled: !!mapping?.id,
  });

  if (!mapping) return null;

  const telemetry = mapping.access_telemetry || {};
  const hasDenyOutcome =
    telemetry.authorization_status === "EXPLICIT_DENY" ||
    (telemetry.request_outcomes?.["4xx"] ?? 0) > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-mono">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <Shield className="w-4 h-4 text-cyan-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Evidence & Telemetry Inspector
              </h3>
              <p className="text-[11px] text-slate-400">
                {mapping.subject_name} &rarr; {mapping.object_name} ({mapping.relationship_type})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Toggle */}
        <div className="flex border-b border-slate-800 bg-slate-950/30 px-4 pt-2 gap-2 text-xs">
          <button
            onClick={() => setActiveTab("telemetry")}
            className={`pb-2 px-2.5 border-b-2 font-medium transition-colors ${
              activeTab === "telemetry"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Access Telemetry
          </button>
          <button
            onClick={() => setActiveTab("observations")}
            className={`pb-2 px-2.5 border-b-2 font-medium transition-colors ${
              activeTab === "observations"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Sanitized Observations ({evidenceData?.total_evidence ?? mapping.sample_count})
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 overflow-y-auto space-y-4 text-xs">
          {/* Provenance & Confidence Pill Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">SOURCE</span>
              <span
                className={`font-semibold ${
                  mapping.evidence_source === "DECLARED"
                    ? "text-emerald-400"
                    : mapping.evidence_source === "OBSERVED"
                    ? "text-cyan-400"
                    : "text-purple-400"
                }`}
              >
                {mapping.evidence_source}
              </span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">CONFIDENCE</span>
              <span className="text-emerald-400 font-bold">
                {Math.round(mapping.confidence_score * 100)}%
              </span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">STATUS</span>
              <span className="text-slate-200 font-semibold">{mapping.status}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">SAMPLES</span>
              <span className="text-slate-200 font-semibold">{mapping.sample_count}</span>
            </div>
          </div>

          {/* HTTP 403 Scoping Warning Banner */}
          {hasDenyOutcome && (
            <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg space-y-1">
              <div className="flex items-center gap-2 text-amber-300 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>Request-Scoped Access Denial Observed</span>
              </div>
              <p className="text-[11px] text-amber-200/90 leading-relaxed pl-6">
                {telemetry.authorization_note ||
                  "HTTP 403 observed for this specific request instance. This indicates an explicit access denial for the requested target or parameter set, but does NOT establish that the role universally lacks permission to this endpoint or resource."}
              </p>
            </div>
          )}

          {activeTab === "telemetry" ? (
            <div className="space-y-4">
              {/* Telemetry Breakdown */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-3">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5 text-xs">
                  <Activity className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Request Status-Code Outcomes</span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                    <span className="text-slate-500 block text-[10px]">2xx (SUCCESS)</span>
                    <span className="text-sm font-bold text-emerald-400">
                      {telemetry.request_outcomes?.["2xx"] ?? 0}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                    <span className="text-slate-500 block text-[10px]">4xx (CLIENT/DENIED)</span>
                    <span className="text-sm font-bold text-amber-400">
                      {telemetry.request_outcomes?.["4xx"] ?? 0}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                    <span className="text-slate-500 block text-[10px]">5xx (SERVER ERR)</span>
                    <span className="text-sm font-bold text-rose-400">
                      {telemetry.request_outcomes?.["5xx"] ?? 0}
                    </span>
                  </div>
                </div>
              </div>

              {/* Authentication & Authorization Status */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1">
                  <span className="text-slate-500 text-[10px] block">AUTHENTICATION STATUS</span>
                  <div className="flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-slate-400" />
                    <span className="font-semibold text-slate-200">
                      {telemetry.authentication_status || "UNKNOWN"}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500">
                    Derived from presence of validated session or token hash.
                  </p>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1">
                  <span className="text-slate-500 text-[10px] block">AUTHORIZATION EVIDENCE</span>
                  <div className="flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-slate-400" />
                    <span className="font-semibold text-slate-200">
                      {telemetry.authorization_status || "UNSPECIFIED"}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500">
                    2xx codes remain UNSPECIFIED; 403 records EXPLICIT_DENY.
                  </p>
                </div>
              </div>

              {/* Observation Timeline */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5 text-xs">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Observation Timestamp Window</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                  <div>
                    <span className="text-slate-500 block">First Observed:</span>
                    <span className="text-slate-300">
                      {telemetry.first_observed_at
                        ? new Date(telemetry.first_observed_at).toLocaleString()
                        : "N/A"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Last Observed:</span>
                    <span className="text-slate-300">
                      {telemetry.last_observed_at
                        ? new Date(telemetry.last_observed_at).toLocaleString()
                        : new Date(mapping.last_observed_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {loadingEvidence && (
                <div className="p-6 text-center text-slate-400 text-xs">
                  Loading sanitized observation logs...
                </div>
              )}

              {evidenceData && evidenceData.items.length === 0 && (
                <div className="p-6 text-center text-slate-500 text-xs">
                  No empirical observations directly attached to this mapping (e.g. purely declared specification).
                </div>
              )}

              {evidenceData?.items.map((obs) => (
                <div
                  key={obs.observation_id}
                  className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center justify-between text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 font-bold text-slate-200">
                        {obs.method}
                      </span>
                      <span className="font-bold text-slate-100">{obs.normalized_path}</span>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        obs.status_code >= 200 && obs.status_code < 300
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          : obs.status_code === 403
                          ? "bg-rose-950 text-rose-400 border border-rose-800"
                          : "bg-amber-950 text-amber-400 border border-amber-800"
                      }`}
                    >
                      HTTP {obs.status_code}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-400 pt-1 border-t border-slate-900">
                    <div>
                      <span className="text-slate-500">Session Hash: </span>
                      <span className="text-slate-300 truncate inline-block max-w-[200px]" title={obs.session_token_hash || "None"}>
                        {obs.session_token_hash ? `${obs.session_token_hash.slice(0, 16)}...` : "None"}
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="text-slate-500">Latency: </span>
                      <span className="text-slate-300">{obs.latency_ms} ms</span>
                    </div>
                  </div>

                  {/* Sanitized JSON Schemas Preview */}
                  {(Object.keys(obs.sanitized_request_schema || {}).length > 0 ||
                    Object.keys(obs.sanitized_response_schema || {}).length > 0) && (
                    <div className="bg-slate-900/60 rounded p-2 text-[10px] space-y-1 font-mono">
                      {Object.keys(obs.sanitized_request_schema || {}).length > 0 && (
                        <div>
                          <span className="text-slate-500 block">Sanitized Request Keys:</span>
                          <span className="text-cyan-300 break-all">
                            {JSON.stringify(obs.sanitized_request_schema)}
                          </span>
                        </div>
                      )}
                      {Object.keys(obs.sanitized_response_schema || {}).length > 0 && (
                        <div>
                          <span className="text-slate-500 block">Sanitized Response Keys:</span>
                          <span className="text-emerald-300 break-all">
                            {JSON.stringify(obs.sanitized_response_schema)}
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-[11px] text-slate-500">
          <span>Safe Sanitization Active: Credentials, tokens, and raw bodies excluded.</span>
          <button
            onClick={onClose}
            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

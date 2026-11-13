import React, { useState } from "react";
import { ChevronDown, ChevronRight, Code2, Gauge, Zap } from "lucide-react";
import { EndpointProfile } from "../../types/digitalTwin";

interface EndpointBehaviorExplorerProps {
  endpointProfiles: Record<string, EndpointProfile>;
}

export const EndpointBehaviorExplorer: React.FC<EndpointBehaviorExplorerProps> = ({
  endpointProfiles,
}) => {
  const [expandedKey, setExpandedKey] = useState<string | null>(null);

  const entries = Object.entries(endpointProfiles || {});

  const getMethodBadge = (method?: string) => {
    const m = (method || "GET").toUpperCase();
    const styles: Record<string, string> = {
      GET: "bg-blue-500/15 text-blue-400 border-blue-500/30",
      POST: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
      PUT: "bg-amber-500/15 text-amber-400 border-amber-500/30",
      PATCH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
      DELETE: "bg-rose-500/15 text-rose-400 border-rose-500/30",
    };
    return (
      <span
        className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${
          styles[m] || "bg-slate-500/15 text-slate-400 border-slate-500/30"
        }`}
      >
        {m}
      </span>
    );
  };

  if (entries.length === 0) {
    return (
      <div className="bg-phantom-900 border border-slate-800/80 rounded-lg p-8 text-center space-y-2">
        <Gauge className="w-8 h-8 text-slate-600 mx-auto" />
        <h4 className="text-sm font-semibold text-slate-300 font-mono">No Endpoint Profiles Available</h4>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          The Behavioral Digital Twin has not profiled any endpoints yet. Ingest interaction traces or compile an active baseline to view behavioral telemetry.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
        <span>Showing {entries.length} Profiled Endpoints</span>
        <span>Confidence Score & Latency (P95)</span>
      </div>

      <div className="space-y-3">
        {entries.map(([key, profile]) => {
          const isExpanded = expandedKey === key;
          const confScore = Math.round((profile.confidence_score || 0) * 100);

          return (
            <div
              key={key}
              className="bg-phantom-900 border border-slate-800/80 hover:border-slate-700/80 rounded-lg transition-colors overflow-hidden"
            >
              {/* Header row */}
              <div
                onClick={() => setExpandedKey(isExpanded ? null : key)}
                className="p-4 cursor-pointer flex flex-col md:flex-row items-start md:items-center justify-between gap-4 select-none"
              >
                <div className="flex items-center gap-3">
                  <button className="text-slate-500 hover:text-slate-300">
                    {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </button>
                  {getMethodBadge(profile.method || key.split(":")[0])}
                  <span className="font-mono text-sm text-slate-200 font-medium break-all">
                    {profile.normalized_path || key.split(":")[1] || key}
                  </span>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono">
                  {/* Status codes */}
                  <div className="flex items-center gap-1.5">
                    {Object.entries(profile.status_code_distribution || {}).map(([code, count]) => (
                      <span
                        key={code}
                        className={`px-1.5 py-0.5 rounded text-[10px] border ${
                          code.startsWith("2")
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : code.startsWith("4")
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                            : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                        }`}
                      >
                        {code}: {count}
                      </span>
                    ))}
                  </div>

                  {/* P95 latency */}
                  <div className="text-slate-400">
                    P95: <span className="text-slate-200 font-semibold">{profile.latency_stats?.p95_ms || 0}ms</span>
                  </div>

                  {/* Confidence */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-500">Conf:</span>
                    <span
                      className={`font-bold ${
                        confScore >= 70
                          ? "text-emerald-400"
                          : confScore >= 30
                          ? "text-amber-400"
                          : "text-slate-500"
                      }`}
                    >
                      {confScore}%
                    </span>
                  </div>

                  <span className="text-slate-500 text-[11px]">
                    ({profile.total_requests} reqs)
                  </span>
                </div>
              </div>

              {/* Expanded Schema Inspector */}
              {isExpanded && (
                <div className="border-t border-slate-800/80 bg-slate-950/70 p-4 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Latency Stats Detail */}
                    <div className="bg-slate-900/60 border border-slate-800/70 rounded p-3 text-xs font-mono space-y-2">
                      <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-1">
                        <Zap className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Latency Profile</span>
                      </div>
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <div className="bg-slate-950/50 p-2 rounded">
                          <span className="text-[10px] text-slate-500 block">MIN</span>
                          <span className="text-slate-300 font-bold">{profile.latency_stats?.min_ms || 0}ms</span>
                        </div>
                        <div className="bg-slate-950/50 p-2 rounded">
                          <span className="text-[10px] text-slate-500 block">AVG</span>
                          <span className="text-slate-300 font-bold">{profile.latency_stats?.avg_ms || 0}ms</span>
                        </div>
                        <div className="bg-slate-950/50 p-2 rounded">
                          <span className="text-[10px] text-slate-500 block">P95</span>
                          <span className="text-cyan-400 font-bold">{profile.latency_stats?.p95_ms || 0}ms</span>
                        </div>
                        <div className="bg-slate-950/50 p-2 rounded">
                          <span className="text-[10px] text-slate-500 block">MAX</span>
                          <span className="text-slate-300 font-bold">{profile.latency_stats?.max_ms || 0}ms</span>
                        </div>
                      </div>
                    </div>

                    {/* Endpoint Metadata */}
                    <div className="bg-slate-900/60 border border-slate-800/70 rounded p-3 text-xs font-mono space-y-2">
                      <div className="text-slate-300 font-semibold mb-1">Behavioral Attributes</div>
                      <div className="space-y-1 text-slate-400 text-[11px]">
                        <div>
                          Endpoint ID:{" "}
                          <span className="text-slate-300">{profile.endpoint_id || "Unregistered (Dynamic)"}</span>
                        </div>
                        <div>
                          Status Codes Observed:{" "}
                          <span className="text-slate-300">
                            {Object.keys(profile.status_code_distribution || {}).join(", ") || "None"}
                          </span>
                        </div>
                        <div>
                          Observation Sample Count:{" "}
                          <span className="text-slate-300">{profile.total_requests} samples</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Structural Schemas */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Inferred Request Schema */}
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                        <Code2 className="w-3.5 h-3.5 text-slate-500" />
                        <span>Inferred Request Schema</span>
                      </div>
                      <pre className="p-3 bg-slate-950 border border-slate-800/80 rounded text-[11px] font-mono text-slate-300 overflow-x-auto max-h-48">
                        {profile.inferred_request_schema && Object.keys(profile.inferred_request_schema).length > 0
                          ? JSON.stringify(profile.inferred_request_schema, null, 2)
                          : "// No request payload observed"}
                      </pre>
                    </div>

                    {/* Inferred Response Schema */}
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                        <Code2 className="w-3.5 h-3.5 text-slate-500" />
                        <span>Inferred Response Schema</span>
                      </div>
                      <pre className="p-3 bg-slate-950 border border-slate-800/80 rounded text-[11px] font-mono text-slate-300 overflow-x-auto max-h-48">
                        {profile.inferred_response_schema && Object.keys(profile.inferred_response_schema).length > 0
                          ? JSON.stringify(profile.inferred_response_schema, null, 2)
                          : "// No response payload observed"}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

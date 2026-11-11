import React, { useState } from "react";
import { BlockedExecutionResponse } from "../../types";
import { ShieldAlert, RefreshCw, Search, Clock, Terminal, AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";

interface BlockedExecutionHistoryProps {
  logs: BlockedExecutionResponse[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const BlockedExecutionHistory: React.FC<BlockedExecutionHistoryProps> = ({
  logs,
  isLoading,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredLogs = logs.filter((log) => {
    const term = searchTerm.toLowerCase();
    return (
      log.target_url.toLowerCase().includes(term) ||
      log.violation_category.toLowerCase().includes(term) ||
      log.blocked_reason.toLowerCase().includes(term) ||
      (log.source_agent && log.source_agent.toLowerCase().includes(term))
    );
  });

  const getViolationBadgeStyle = (category: string) => {
    switch (category) {
      case "DESTRUCTIVE_ACTION_PROHIBITED":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "UNREGISTERED_TARGET":
      case "UNAUTHORIZED_DOMAIN":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "EXCLUDED_PATH":
      case "RESTRICTED_ENDPOINT":
        return "bg-purple-500/20 text-purple-300 border-purple-500/40";
      case "RATE_LIMIT_EXCEEDED":
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
      default:
        return "bg-slate-500/20 text-slate-300 border-slate-500/40";
    }
  };

  return (
    <div className="space-y-4">
      {/* Header controls */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by URL, category, or agent..."
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="flex items-center gap-2 px-3 py-2 text-xs text-slate-300 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
          <span>Refresh History</span>
        </button>
      </div>

      {/* Table */}
      <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="p-8 text-center space-y-2">
            <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-medium text-slate-300">No Blocked Executions Found</p>
            <p className="text-xs text-slate-500">
              When an autonomous agent, scanner, or user request violates scope or safety limits, it will be catalogued here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono">
                <tr>
                  <th className="py-2.5 px-3 w-8"></th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Target URL</th>
                  <th className="py-2.5 px-3">Method</th>
                  <th className="py-2.5 px-3">Violation Category</th>
                  <th className="py-2.5 px-3">Agent</th>
                  <th className="py-2.5 px-3">Blocked Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredLogs.map((log) => {
                  const isExpanded = expandedId === log.id;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedId(isExpanded ? null : log.id)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 text-slate-500">
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                          {new Date(log.created_at).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-200 max-w-xs truncate" title={log.target_url}>
                          {log.target_url}
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold text-cyan-400">
                          {log.http_method}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${getViolationBadgeStyle(
                              log.violation_category
                            )}`}
                          >
                            {log.violation_category}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                          {log.source_agent || "SCANNER"}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 max-w-sm truncate" title={log.blocked_reason}>
                          {log.blocked_reason}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-950/60">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                              <div>
                                <span className="text-slate-500 font-mono text-[11px] block mb-1">
                                  FULL BLOCKED REASON:
                                </span>
                                <p className="text-slate-300 bg-slate-900 border border-slate-800 rounded p-2.5 font-mono">
                                  {log.blocked_reason}
                                </p>
                              </div>
                              {log.payload_sample && (
                                <div>
                                  <span className="text-slate-500 font-mono text-[11px] block mb-1">
                                    PAYLOAD SAMPLE DETECTED:
                                  </span>
                                  <pre className="text-rose-300 bg-slate-900 border border-rose-950/40 rounded p-2.5 font-mono text-[11px] overflow-x-auto">
                                    {log.payload_sample}
                                  </pre>
                                </div>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-500 font-mono flex items-center gap-4">
                              <span>Log ID: {log.id}</span>
                              {log.client_ip && <span>Origin IP: {log.client_ip}</span>}
                              {log.application_id && <span>Application ID: {log.application_id}</span>}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};


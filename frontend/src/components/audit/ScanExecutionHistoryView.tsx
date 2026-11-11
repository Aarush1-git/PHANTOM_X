import React, { useState } from "react";
import { ScanExecutionRecordResponse } from "../../types";
import { StatusBadge } from "../common/Badge";
import { History, Play, Clock, CheckCircle2, ShieldAlert, AlertTriangle, ChevronDown, ChevronRight, Search } from "lucide-react";

interface ScanExecutionHistoryViewProps {
  records: ScanExecutionRecordResponse[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const ScanExecutionHistoryView: React.FC<ScanExecutionHistoryViewProps> = ({
  records,
  isLoading,
  onRefresh,
}) => {
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>("");

  const filtered = records.filter(
    (r) =>
      r.scan_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.final_status.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.initiating_user && r.initiating_user.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by scan ID or status..."
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <button
          onClick={onRefresh}
          className="px-3 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded transition-colors"
        >
          Refresh History
        </button>
      </div>

      <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <History className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">No Scan Execution Records Available</p>
            <p className="text-xs text-slate-500">
              When security scans are initiated, their lifecycle transitions and test outcomes will be captured here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3 w-8"></th>
                  <th className="py-2.5 px-3">Scan ID</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Tests Executed</th>
                  <th className="py-2.5 px-3">Blocked</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Duration</th>
                  <th className="py-2.5 px-3">Initiated By</th>
                  <th className="py-2.5 px-3">Recorded At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filtered.map((record) => {
                  const isExpanded = expandedScanId === record.id;
                  return (
                    <React.Fragment key={record.id}>
                      <tr
                        onClick={() => setExpandedScanId(isExpanded ? null : record.id)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 text-slate-500">
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-cyan-400 font-bold max-w-[140px] truncate" title={record.scan_id}>
                          {record.scan_id}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <StatusBadge status={record.final_status} />
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-200">
                          {record.tests_executed}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-amber-400">
                          {record.tests_blocked}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-rose-400">
                          {record.verified_findings}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400">
                          {record.duration_seconds !== null && record.duration_seconds !== undefined
                            ? `${record.duration_seconds.toFixed(1)}s`
                            : "—"}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px] truncate max-w-[120px]">
                          {record.initiating_user || "System"}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-500 text-[11px] whitespace-nowrap">
                          {new Date(record.created_at).toLocaleString()}
                        </td>
                      </tr>

                      {/* Expanded lifecycle timeline */}
                      {isExpanded && (
                        <tr className="bg-slate-950/70">
                          <td colSpan={9} className="p-4 space-y-3 font-mono">
                            <div className="flex items-center justify-between text-xs text-slate-300 pb-2 border-b border-slate-800">
                              <span className="font-bold flex items-center gap-1.5">
                                <History className="w-3.5 h-3.5 text-cyan-400" /> Scan Lifecycle Transition Events
                              </span>
                              {record.failure_reason && (
                                <span className="text-rose-400 flex items-center gap-1">
                                  <AlertTriangle className="w-3 h-3" /> Failure: {record.failure_reason}
                                </span>
                              )}
                            </div>

                            <div className="space-y-2 pt-1 pl-2 border-l border-slate-800 ml-2">
                              {record.lifecycle_events?.map((ev, idx) => (
                                <div key={idx} className="relative pl-4 text-xs space-y-0.5">
                                  <div className="absolute -left-1.5 top-1.5 w-2 h-2 rounded-full bg-cyan-400" />
                                  <div className="flex items-center gap-2">
                                    <span className="font-bold text-slate-200">{ev.status}</span>
                                    <span className="text-[11px] text-slate-500">
                                      {new Date(ev.timestamp).toLocaleString()}
                                    </span>
                                  </div>
                                  {ev.note && <p className="text-[11px] text-slate-400 font-sans">{ev.note}</p>}
                                </div>
                              ))}
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


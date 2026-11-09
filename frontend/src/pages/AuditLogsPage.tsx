import React, { useState, useEffect } from "react";
import { ScrollText, Shield } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { AuditLogResponse } from "../types";

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        setIsLoading(true);
        const data = await api.settings.listAuditLogs();
        setLogs(data);
      } catch {
        setLogs([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchLogs();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Audit Logs & Decision Traceability"
        description="Immutable audit trail of operator approvals, policy authorizations, and autonomous agent test dispatches."
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Filter audit events by action or actor..." />

      {isLoading ? (
        <LoadingSpinner />
      ) : logs.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No Audit Records Available"
          description="All safety decisions, plan validations, and operator actions will be logged here for compliance auditing."
        />
      ) : (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
          <table className="w-full text-left">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-3">TIMESTAMP</th>
                <th className="p-3">ACTION</th>
                <th className="p-3">TARGET TYPE</th>
                <th className="p-3">TARGET ID</th>
                <th className="p-3">IP ADDRESS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30">
                  <td className="p-3 text-slate-400">{new Date(log.created_at).toLocaleString()}</td>
                  <td className="p-3 font-semibold text-cyan-400">{log.action}</td>
                  <td className="p-3 text-slate-300">{log.target_type}</td>
                  <td className="p-3 text-slate-500">{log.target_id || "-"}</td>
                  <td className="p-3 text-slate-400">{log.ip_address || "127.0.0.1"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Radar, Plus, Play, Pause, ExternalLink, ShieldCheck } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { StatusBadge } from "../components/common/Badge";
import { api } from "../services/api";
import { ScanResponse } from "../types";

export const SecurityScansPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");

  const fetchScans = async () => {
    try {
      setIsLoading(true);
      const data = await api.scans.list();
      setScans(data);
    } catch {
      setScans([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Autonomous Security Scans"
        description="Dynamic Application Security Testing runs with autonomous planning and verification."
        actions={
          <button
            onClick={() => alert("Configure scan target and policy profile.")}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Launch Security Scan</span>
          </button>
        }
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Search scans by ID or status..." />

      {isLoading ? (
        <LoadingSpinner />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={Radar}
          title="No Security Scans Run Yet"
          description="Initiate an authorized DAST scan to execute intelligent security tests and collect exploit proof."
          action={
            <button
              onClick={() => alert("Select target application to initiate test plan.")}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Configure Scan Session</span>
            </button>
          }
        />
      ) : (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-3">SCAN ID</th>
                <th className="p-3">STATUS</th>
                <th className="p-3">PROGRESS</th>
                <th className="p-3">FINDINGS</th>
                <th className="p-3">STARTED</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3 text-slate-200">{scan.id.slice(0, 8)}...</td>
                  <td className="p-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="p-3 text-cyan-400">{scan.progress}%</td>
                  <td className="p-3 font-bold text-amber-400">{scan.findings_count}</td>
                  <td className="p-3 text-slate-500">{new Date(scan.created_at).toLocaleString()}</td>
                  <td className="p-3 text-right">
                    <Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline">
                      Telemetry
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


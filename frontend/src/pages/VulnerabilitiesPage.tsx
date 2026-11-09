import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Bug, ShieldAlert, CheckCircle, ExternalLink, Filter } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { api } from "../services/api";
import { VulnerabilityResponse } from "../types";

export const VulnerabilitiesPage: React.FC = () => {
  const [vulns, setVulns] = useState<VulnerabilityResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");

  const fetchVulns = async () => {
    try {
      setIsLoading(true);
      const data = await api.vulnerabilities.list();
      setVulns(data);
    } catch {
      setVulns([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVulns();
  }, []);

  const filtered = vulns.filter((v) => {
    const matchesSearch =
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.endpoint.toLowerCase().includes(search.toLowerCase());
    const matchesSev = severityFilter ? v.severity === severityFilter : true;
    return matchesSearch && matchesSev;
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities & Findings"
        description="Verified vulnerabilities discovered by autonomous security checks and backed by forensic evidence."
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Search vulnerabilities by title or endpoint...">
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-phantom-900 border border-slate-800 rounded text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </SearchFilterBar>

      {isLoading ? (
        <LoadingSpinner />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="No Vulnerabilities Recorded"
          description="Verified security issues discovered during active testing will be detailed here with reproducibility steps."
        />
      ) : (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-3">SEVERITY</th>
                <th className="p-3">VULNERABILITY TITLE</th>
                <th className="p-3">ENDPOINT</th>
                <th className="p-3">STATUS</th>
                <th className="p-3">CONFIDENCE</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((v) => (
                <tr key={v.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3">
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td className="p-3 text-slate-100 font-semibold">{v.title}</td>
                  <td className="p-3 text-slate-300">{v.endpoint}</td>
                  <td className="p-3">
                    <StatusBadge status={v.status} />
                  </td>
                  <td className="p-3 text-cyan-400">{(v.confidence * 100).toFixed(0)}%</td>
                  <td className="p-3 text-right">
                    <Link to={`/vulnerabilities/${v.id}`} className="text-cyan-400 hover:underline">
                      Inspect Proof
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


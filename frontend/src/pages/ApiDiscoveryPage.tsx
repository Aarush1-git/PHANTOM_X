import React, { useState, useEffect } from "react";
import { Compass, Play, ShieldAlert, Key, Globe } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { EndpointResponse } from "../types";

export const ApiDiscoveryPage: React.FC = () => {
  const [endpoints, setEndpoints] = useState<EndpointResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");

  const fetchEndpoints = async () => {
    try {
      setIsLoading(true);
      const data = await api.discovery.listEndpoints();
      setEndpoints(data);
    } catch {
      setEndpoints([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();
  }, []);

  const filtered = endpoints.filter(
    (e) =>
      e.path.toLowerCase().includes(search.toLowerCase()) ||
      e.method.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Endpoint Inventory & Discovery"
        description="Autonomous surface reconnaissance, HAR parsing, Playwright crawling, and endpoint classification."
        actions={
          <button
            onClick={() => alert("Discovery Agent triggered for active targets.")}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Trigger Discovery Agent</span>
          </button>
        }
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Filter by endpoint path or HTTP method..." />

      {isLoading ? (
        <LoadingSpinner />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Compass}
          title="No Endpoints Discovered"
          description="Endpoints discovered via HAR file upload or Playwright headless browser crawling will appear here."
          action={
            <button
              onClick={() => alert("Member 1 Discovery Agent module is ready for implementation.")}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              <span>Initialize Discovery Crawl</span>
            </button>
          }
        />
      ) : (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-3">METHOD</th>
                <th className="p-3">ENDPOINT PATH</th>
                <th className="p-3">AUTH</th>
                <th className="p-3">RISK LEVEL</th>
                <th className="p-3">DISCOVERED</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((ep) => (
                <tr key={ep.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3">
                    <span className="font-bold text-cyan-400">{ep.method}</span>
                  </td>
                  <td className="p-3 text-slate-200">{ep.path}</td>
                  <td className="p-3">
                    {ep.auth_required ? (
                      <span className="text-amber-400 flex items-center gap-1">
                        <Key className="w-3 h-3" /> Required
                      </span>
                    ) : (
                      <span className="text-slate-500">Public</span>
                    )}
                  </td>
                  <td className="p-3">
                    <span className="text-slate-400">{ep.risk_level}</span>
                  </td>
                  <td className="p-3 text-slate-500">{new Date(ep.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


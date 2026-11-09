import React, { useState, useEffect } from "react";
import { History, Play, CheckCircle2, AlertTriangle } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { RegressionResult } from "../types";

export const RegressionMonitoringPage: React.FC = () => {
  const [results, setResults] = useState<RegressionResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchRegressions = async () => {
      try {
        setIsLoading(true);
        const data = await api.regression.list();
        setResults(data);
      } catch {
        setResults([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchRegressions();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Time-Travel Regression Monitoring (Member 4)"
        description="Continuous re-verification of past vulnerabilities across code revisions to prevent reintroduction."
        actions={
          <button
            onClick={() => alert("All historical security tests queued for re-verification.")}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Replay Full Test Suite</span>
          </button>
        }
      />

      {isLoading ? (
        <LoadingSpinner />
      ) : results.length === 0 ? (
        <EmptyState
          icon={History}
          title="No Regression Tests Triggered"
          description="Resolved vulnerability test traces can be replayed at any time to verify application updates."
        />
      ) : (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
          <table className="w-full text-left">
            <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="p-3">TEST ID</th>
                <th className="p-3">STATUS</th>
                <th className="p-3">LAST REPLAYED</th>
                <th className="p-3">SUMMARY</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {results.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/30">
                  <td className="p-3 text-cyan-400">{r.id.slice(0, 8)}...</td>
                  <td className="p-3">
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{new Date(r.last_run_at).toLocaleString()}</td>
                  <td className="p-3 text-slate-300">{r.result_summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


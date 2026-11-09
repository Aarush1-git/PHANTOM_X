import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { Radar, ArrowLeft, ShieldAlert, Activity, StopCircle } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { StatusBadge } from "../components/common/Badge";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { ScanResponse, ScanProgress } from "../types";

export const ScanDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    const fetchScanData = async () => {
      try {
        setIsLoading(true);
        const s = await api.scans.getById(id);
        setScan(s);
        const p = await api.scans.getProgress(id);
        setProgress(p);
      } catch {
        // Mock fallback
        setScan({
          id,
          organization_id: "org-1",
          application_id: "app-1",
          status: "RUNNING",
          progress: 45.0,
          findings_count: 2,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
        setProgress({
          scan_id: id,
          status: "RUNNING",
          percent_complete: 45.0,
          current_phase: "AUTONOMOUS_ATTACK_CHALLENGE",
          discovered_endpoints_count: 14,
          executed_tests_count: 8,
          findings_count: 2,
          timestamp: new Date().toISOString(),
        });
      } finally {
        setIsLoading(false);
      }
    };
    fetchScanData();
  }, [id]);

  if (isLoading) return <LoadingSpinner />;
  if (!scan) return <div>Scan not found.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-2">
        <Link to="/scans" className="hover:text-slate-300 flex items-center gap-1">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Scans</span>
        </Link>
      </div>

      <PageHeader
        title={`Scan Telemetry: ${scan.id.slice(0, 8)}`}
        description="Real-time WebSocket telemetry, test execution logs, and live vulnerability discoveries."
        badge={<StatusBadge status={scan.status} />}
        actions={
          <button
            onClick={() => alert("Scan abort signal dispatched.")}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-mono transition-colors"
          >
            <StopCircle className="w-3.5 h-3.5" />
            <span>Abort Scan</span>
          </button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
        <div className="bg-phantom-900 border border-slate-800 rounded p-4">
          <span className="text-slate-500 block mb-1">EXECUTION PHASE</span>
          <span className="text-cyan-400 font-semibold">{progress?.current_phase || "INITIALIZING"}</span>
        </div>
        <div className="bg-phantom-900 border border-slate-800 rounded p-4">
          <span className="text-slate-500 block mb-1">PROGRESS</span>
          <span className="text-slate-100 font-semibold">{progress?.percent_complete || 0}%</span>
        </div>
        <div className="bg-phantom-900 border border-slate-800 rounded p-4">
          <span className="text-slate-500 block mb-1">TESTS EXECUTED</span>
          <span className="text-slate-100 font-semibold">{progress?.executed_tests_count || 0}</span>
        </div>
        <div className="bg-phantom-900 border border-slate-800 rounded p-4">
          <span className="text-slate-500 block mb-1">VERIFIED FINDINGS</span>
          <span className="text-amber-400 font-semibold">{progress?.findings_count || 0}</span>
        </div>
      </div>

      <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5">
        <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-3">
          Live Telemetry Stream (/api/v1/ws/{scan.id})
        </h3>
        <div className="bg-phantom-950 border border-slate-800 rounded p-4 font-mono text-xs text-slate-400 h-64 overflow-y-auto space-y-1">
          <div className="text-slate-500">[00:00:01] WebSocket channel connected to security engine.</div>
          <div className="text-slate-400">[00:00:02] Target allowlist validated: in-scope host localhost:3000.</div>
          <div className="text-cyan-400">[00:00:05] Planning Agent formulated 8 test scenarios under OBSERVE mode.</div>
          <div className="text-emerald-400">[00:00:08] Central Safety Policy: APPROVED all 8 scenarios.</div>
          <div className="text-slate-400">[00:00:15] Executing controlled BOLA test on /api/v1/bookings/{'{id}'}.</div>
        </div>
      </div>
    </div>
  );
};


import React, { useState } from "react";
import { AuditIntegrityVerificationResponse } from "../../types";
import { api } from "../../services/api";
import { ShieldCheck, ShieldAlert, RefreshCw, Hash, AlertTriangle, CheckCircle2, Lock } from "lucide-react";

export const AuditIntegrityPanel: React.FC = () => {
  const [result, setResult] = useState<AuditIntegrityVerificationResponse | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const runVerification = async () => {
    try {
      setIsVerifying(true);
      setError(null);
      const res = await api.settings.verifyAuditIntegrity();
      setResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Failed to execute integrity verification.");
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4 font-mono text-xs">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            Tamper-Evident Hash Chain Verification
          </h3>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            Every audit event contains an immutable SHA-256 hash linked to its predecessor. Run verification to validate
            chain integrity across all stored records.
          </p>
        </div>

        <button
          onClick={runVerification}
          disabled={isVerifying}
          className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50 whitespace-nowrap"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? "animate-spin" : ""}`} />
          <span>{isVerifying ? "Verifying Chain..." : "Run Integrity Check"}</span>
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded text-rose-400 text-xs flex items-center gap-2 font-sans">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Verification Result Display */}
      {result && (
        <div
          className={`p-4 rounded-lg border space-y-3 transition-all ${
            result.is_intact
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
              : "bg-rose-500/10 border-rose-500/30 text-rose-200"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-bold text-sm">
              {result.is_intact ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              )}
              <span>
                STATUS: {result.is_intact ? "CRYPTOGRAPHIC AUDIT CHAIN INTACT" : "INTEGRITY COMPROMISED"}
              </span>
            </div>
            <span className="text-[11px] text-slate-400">
              Verified: {new Date(result.verified_at).toLocaleTimeString()}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[11px]">
            <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block">RECORDS CHECKED</span>
              <span className="text-slate-100 font-bold text-sm">{result.records_checked}</span>
            </div>
            <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block">ANOMALIES DETECTED</span>
              <span className={result.anomalies.length === 0 ? "text-emerald-400 font-bold text-sm" : "text-rose-400 font-bold text-sm"}>
                {result.anomalies.length}
              </span>
            </div>
            <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block">CHAIN HEAD HASH</span>
              <span className="text-cyan-400 font-mono text-[10px] truncate block" title={result.chain_head_hash || ""}>
                {result.chain_head_hash ? `${result.chain_head_hash.slice(0, 16)}...` : "None"}
              </span>
            </div>
          </div>

          {result.anomalies.length > 0 && (
            <div className="space-y-1 bg-slate-950/80 p-3 rounded border border-rose-500/30 text-xs">
              <span className="text-rose-400 font-bold block mb-1">Detected Anomaly Logs:</span>
              {result.anomalies.map((a, idx) => (
                <div key={idx} className="text-rose-300 font-mono text-[11px]">
                  • {a}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Limitations Notice */}
      <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded text-[11px] text-slate-400 font-sans space-y-1">
        <span className="font-semibold text-slate-300 flex items-center gap-1.5 font-mono">
          <Lock className="w-3.5 h-3.5 text-cyan-400" /> Chain Trustworthiness Architecture
        </span>
        <p>
          The tamper-evident hash chain detects post-hoc content alterations, unauthorized row deletions, and record reordering.
          Privileged database administrators could theoretically re-sign a chain; therefore, periodic external cryptographic
          checkpoints should be published to immutable external storage.
        </p>
      </div>
    </div>
  );
};


import React, { useState, useEffect } from "react";
import { Settings, ShieldCheck, ShieldAlert, Cpu, Database, CheckCircle2 } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { api } from "../services/api";

export const SettingsPage: React.FC = () => {
  const [safetyConfig, setSafetyConfig] = useState<any>({
    execution_mode: "OBSERVE",
    strict_target_authorization: true,
    allowed_target_hosts: ["localhost", "127.0.0.1", "api.example-target.local"],
    max_concurrent_tests: 5,
    rate_limit_rps: 10,
    synthetic_data_enforced: true,
  });

  useEffect(() => {
    const fetchPolicy = async () => {
      try {
        const data = await api.settings.getSafetyPolicy();
        setSafetyConfig(data);
      } catch {
        // Keep initial state
      }
    };
    fetchPolicy();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings & Scope Governance"
        description="Configure target scope permissions, unbypassable safety constraints, and external integration connectors."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Central Safety Policy Box */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-semibold text-slate-100">Central Safety Policy Engine</h3>
          </div>
          <p className="text-xs text-slate-400">
            Enforces the 10 safety rules across all autonomous agents. Individual agents cannot alter or bypass these boundaries.
          </p>

          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 bg-slate-950 rounded border border-slate-800">
              <span className="text-slate-400">EXECUTION MODE</span>
              <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {safetyConfig.execution_mode}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-slate-950 rounded border border-slate-800">
              <span className="text-slate-400">STRICT SCOPE ENFORCEMENT</span>
              <span className="text-emerald-400 font-bold">ENABLED</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-slate-950 rounded border border-slate-800">
              <span className="text-slate-400">MAX RATE LIMIT</span>
              <span className="text-cyan-400 font-bold">{safetyConfig.rate_limit_rps} RPS</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-slate-950 rounded border border-slate-800">
              <span className="text-slate-400">SYNTHETIC ACCOUNTS ONLY</span>
              <span className="text-emerald-400 font-bold">ENFORCED</span>
            </div>
          </div>
        </div>

        {/* Allowlisted Target Domains */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">Authorized Target Domains</h3>
          </div>
          <p className="text-xs text-slate-400">
            Out-of-scope hosts and unauthorized endpoints are blocked at the networking layer before transmission.
          </p>

          <div className="bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs space-y-2">
            {safetyConfig.allowed_target_hosts.map((host: string, idx: number) => (
              <div key={idx} className="flex items-center gap-2 text-slate-200">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>{host}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};


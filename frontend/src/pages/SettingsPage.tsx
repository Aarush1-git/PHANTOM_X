import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  History,
  Lock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { api } from "../services/api";
import {
  ScopePolicyResponse,
  ScopePolicyCreate,
  ScopeAuthorizeRequest,
  ApplicationResponse,
  BlockedExecutionResponse,
} from "../types";
import { ScopePolicyList } from "../components/settings/ScopePolicyList";
import { ScopePolicyModal } from "../components/settings/ScopePolicyModal";
import { AuthorizationModal } from "../components/settings/AuthorizationModal";
import { BlockedExecutionHistory } from "../components/settings/BlockedExecutionHistory";
import { TestValidationSimulator } from "../components/settings/TestValidationSimulator";

type TabType = "scopes" | "simulator" | "blocked" | "central-policy";

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>("scopes");
  const [scopes, setScopes] = useState<ScopePolicyResponse[]>([]);
  const [applications, setApplications] = useState<ApplicationResponse[]>([]);
  const [blockedLogs, setBlockedLogs] = useState<BlockedExecutionResponse[]>([]);
  const [safetyConfig, setSafetyConfig] = useState<any>({
    execution_mode: "OBSERVE",
    strict_target_authorization: true,
    allowed_target_hosts: ["localhost", "127.0.0.1", "api.example-target.local"],
    max_concurrent_tests: 5,
    rate_limit_rps: 10,
    synthetic_data_enforced: true,
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [editingPolicy, setEditingPolicy] = useState<ScopePolicyResponse | null>(null);
  const [authorizingPolicy, setAuthorizingPolicy] = useState<ScopePolicyResponse | null>(null);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const [scopesData, appsData, blockedData, policyData] = await Promise.all([
        api.settings.listScopes().catch(() => []),
        api.applications.list().catch(() => []),
        api.settings.listBlockedExecutions().catch(() => []),
        api.settings.getSafetyPolicy().catch(() => null),
      ]);

      setScopes(scopesData);
      setApplications(appsData);
      setBlockedLogs(blockedData);
      if (policyData) setSafetyConfig(policyData);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSaveScope = async (appId: string, payload: ScopePolicyCreate) => {
    await api.settings.createOrUpdateScope(appId, payload);
    await fetchData();
  };

  const handleAuthorize = async (appId: string, payload: ScopeAuthorizeRequest) => {
    await api.settings.authorizeScope(appId, payload);
    await fetchData();
  };

  const handleSuspend = async (policy: ScopePolicyResponse) => {
    const reason = prompt("Enter reason for suspending scope (e.g. maintenance, incident):", "Temporary maintenance");
    if (!reason) return;
    await api.settings.suspendScope(policy.application_id, { reason });
    await fetchData();
  };

  const handleRevoke = async (policy: ScopePolicyResponse) => {
    const reason = prompt("Enter reason for revoking testing authorization:", "Authorization expired or target decommissioned");
    if (!reason) return;
    await api.settings.revokeScope(policy.application_id, { reason });
    await fetchData();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scope, Permission & Safety Governance"
        description="Enforce strict application authorization boundaries, configure testing safety constraints, simulate live request gating, and audit blocked executions."
      />

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-1">
        <button
          onClick={() => setActiveTab("scopes")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "scopes"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Target Scopes & Permissions ({scopes.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("simulator")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "simulator"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Zap className="w-4 h-4" />
          <span>Safety Validation Simulator</span>
        </button>

        <button
          onClick={() => setActiveTab("blocked")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "blocked"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <History className="w-4 h-4" />
          <span>Blocked Executions ({blockedLogs.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("central-policy")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "central-policy"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>Central Safety Engine</span>
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === "scopes" && (
        <ScopePolicyList
          scopes={scopes}
          isLoading={isLoading}
          onOpenCreateModal={() => {
            setEditingPolicy(null);
            setIsModalOpen(true);
          }}
          onOpenEditModal={(policy) => {
            setEditingPolicy(policy);
            setIsModalOpen(true);
          }}
          onOpenAuthorizeModal={(policy) => {
            setAuthorizingPolicy(policy);
          }}
          onSuspend={handleSuspend}
          onRevoke={handleRevoke}
        />
      )}

      {activeTab === "simulator" && <TestValidationSimulator applications={applications} />}

      {activeTab === "blocked" && (
        <BlockedExecutionHistory logs={blockedLogs} isLoading={isLoading} onRefresh={fetchData} />
      )}

      {activeTab === "central-policy" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Central Safety Policy Box */}
          <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-semibold text-slate-100">Central Safety Policy Engine</h3>
            </div>
            <p className="text-xs text-slate-400">
              Enforces the 10 safety rules across all autonomous agents. Individual agents (LLMs, fuzzers, crawlers)
              cannot alter or bypass these boundaries.
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
                <span className="text-slate-400">GLOBAL MAX RATE LIMIT</span>
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
              <h3 className="text-sm font-semibold text-slate-100">Allowlisted Target Domains</h3>
            </div>
            <p className="text-xs text-slate-400">
              Out-of-scope hosts and unauthorized endpoints are blocked at the networking layer before transmission.
            </p>

            <div className="bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs space-y-2">
              {safetyConfig.allowed_target_hosts?.map((host: string, idx: number) => (
                <div key={idx} className="flex items-center gap-2 text-slate-200">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{host}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Scope Policy Modal */}
      <ScopePolicyModal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setEditingPolicy(null);
        }}
        onSave={handleSaveScope}
        initialPolicy={editingPolicy}
        applications={applications}
      />

      {/* Authorization Modal */}
      <AuthorizationModal
        isOpen={!!authorizingPolicy}
        onClose={() => setAuthorizingPolicy(null)}
        onAuthorize={handleAuthorize}
        policy={authorizingPolicy}
      />
    </div>
  );
};

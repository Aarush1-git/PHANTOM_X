import React, { useState } from "react";
import { ScopePolicyResponse } from "../../types";
import { ScopeStatusBadge, AuthorizationStatusBadge } from "./ScopeBadge";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Plus,
  Edit2,
  PauseCircle,
  XCircle,
  Search,
  ExternalLink,
  Lock,
  Globe,
  Sliders,
} from "lucide-react";

interface ScopePolicyListProps {
  scopes: ScopePolicyResponse[];
  isLoading: boolean;
  onOpenCreateModal: () => void;
  onOpenEditModal: (policy: ScopePolicyResponse) => void;
  onOpenAuthorizeModal: (policy: ScopePolicyResponse) => void;
  onSuspend: (policy: ScopePolicyResponse) => void;
  onRevoke: (policy: ScopePolicyResponse) => void;
}

export const ScopePolicyList: React.FC<ScopePolicyListProps> = ({
  scopes,
  isLoading,
  onOpenCreateModal,
  onOpenEditModal,
  onOpenAuthorizeModal,
  onSuspend,
  onRevoke,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>("");

  const filteredScopes = scopes.filter((s) => {
    const term = searchTerm.toLowerCase();
    return (
      s.target_domain?.toLowerCase().includes(term) ||
      s.base_url?.toLowerCase().includes(term) ||
      (s.application_name && s.application_name.toLowerCase().includes(term)) ||
      s.scope_status?.toLowerCase().includes(term) ||
      s.authorization_status?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-4">
      {/* Search and Action Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by domain, URL, or status..."
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          onClick={onOpenCreateModal}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors whitespace-nowrap"
        >
          <Plus className="w-4 h-4" />
          <span>Register Target Scope</span>
        </button>
      </div>

      {/* Scope Cards */}
      {filteredScopes.length === 0 ? (
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-10 text-center space-y-3">
          <Shield className="w-10 h-10 text-slate-600 mx-auto" />
          <p className="text-sm font-semibold text-slate-200">No Target Scopes Registered</p>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            PHANTOM-X enforces strict authorization boundaries. Autonomous testing agents cannot run against any application
            until its scope is registered and authorized.
          </p>
          <button
            onClick={onOpenCreateModal}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Configure First Target Scope</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredScopes.map((policy) => {
            const isAuthorized = policy.authorization_status === "AUTHORIZED";
            const isActive = policy.scope_status === "ACTIVE";

            return (
              <div
                key={policy.id}
                className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4 hover:border-slate-700 transition-colors"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
                      <h4 className="text-sm font-bold text-slate-100 font-mono">
                        {policy.application_name || policy.target_domain}
                      </h4>
                    </div>
                    <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
                      <span>Base URL:</span>
                      <span className="text-slate-300">{policy.base_url}</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <ScopeStatusBadge status={policy.scope_status} />
                    <AuthorizationStatusBadge status={policy.authorization_status} />
                  </div>
                </div>

                {/* Scope Details Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                    <span className="text-slate-500 block text-[11px] mb-1">RATE & CONCURRENCY</span>
                    <span className="text-cyan-400 font-semibold">{policy.rate_limit_rps} RPS</span>
                    <span className="text-slate-500 text-[11px] ml-1">/ {policy.max_concurrency} max workers</span>
                  </div>

                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                    <span className="text-slate-500 block text-[11px] mb-1">ALLOWED METHODS</span>
                    <div className="flex flex-wrap gap-1">
                      {policy.allowed_methods?.map((m) => (
                        <span key={m} className="px-1 text-[10px] rounded bg-slate-800 text-slate-300">
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                    <span className="text-slate-500 block text-[11px] mb-1">PATH FILTERS</span>
                    <div className="text-[11px]">
                      <span className="text-emerald-400">+{policy.permitted_paths?.length || 0} permitted</span>
                      <span className="text-slate-600 mx-1">|</span>
                      <span className="text-rose-400">-{policy.excluded_paths?.length || 0} excluded</span>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                    <span className="text-slate-500 block text-[11px] mb-1">DESTRUCTIVE TESTING</span>
                    {policy.allow_destructive ? (
                      <span className="text-rose-400 font-semibold">ALLOWED (High Risk)</span>
                    ) : (
                      <span className="text-emerald-400 font-semibold">BLOCKED (Safe)</span>
                    )}
                  </div>
                </div>

                {/* Authorization Meta & Path summary */}
                <div className="text-xs text-slate-400 flex flex-col md:flex-row md:items-center justify-between gap-2 bg-slate-950/50 p-2.5 rounded border border-slate-800/40">
                  <div className="space-y-0.5">
                    {policy.authorized_by ? (
                      <div>
                        <span className="text-slate-500">Authorized by:</span>{" "}
                        <span className="text-slate-200 font-semibold">{policy.authorized_by}</span>{" "}
                        {policy.authorizer_role && <span className="text-slate-400">({policy.authorizer_role})</span>}
                        {policy.valid_until && (
                          <span className="text-slate-500 ml-2">
                            • Valid until: {new Date(policy.valid_until).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    ) : (
                      <div className="text-amber-400 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>Awaiting formal testing authorization sign-off.</span>
                      </div>
                    )}
                    {policy.excluded_paths && policy.excluded_paths.length > 0 && (
                      <div className="text-[11px] text-slate-500 truncate max-w-xl">
                        Excluded: {policy.excluded_paths.join(", ")}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => onOpenEditModal(policy)}
                      className="flex items-center gap-1 px-2.5 py-1 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
                    >
                      <Sliders className="w-3 h-3" />
                      <span>Configure</span>
                    </button>

                    {!isAuthorized ? (
                      <button
                        onClick={() => onOpenAuthorizeModal(policy)}
                        className="flex items-center gap-1 px-2.5 py-1 text-xs text-emerald-950 font-semibold bg-emerald-400 hover:bg-emerald-300 rounded transition-colors"
                      >
                        <ShieldCheck className="w-3 h-3" />
                        <span>Authorize</span>
                      </button>
                    ) : (
                      <>
                        {isActive ? (
                          <button
                            onClick={() => onSuspend(policy)}
                            className="flex items-center gap-1 px-2.5 py-1 text-xs text-amber-300 hover:text-amber-200 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded transition-colors"
                          >
                            <PauseCircle className="w-3 h-3" />
                            <span>Suspend</span>
                          </button>
                        ) : null}

                        <button
                          onClick={() => onRevoke(policy)}
                          className="flex items-center gap-1 px-2.5 py-1 text-xs text-rose-300 hover:text-rose-200 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 rounded transition-colors"
                        >
                          <XCircle className="w-3 h-3" />
                          <span>Revoke</span>
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};


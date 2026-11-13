import React, { useState } from "react";
import {
  Key,
  Database,
  Globe,
  Layers,
  Shield,
  FolderTree,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import {
  ApplicationRoleMapping,
  ApplicationResourceMapping,
  RoleResourceMapping,
} from "../../types/roleResource";

interface RolesResourcesViewProps {
  roles: ApplicationRoleMapping[];
  resources: ApplicationResourceMapping[];
  onInspectMapping?: (mapping: RoleResourceMapping) => void;
  isLoading?: boolean;
}

export const RolesResourcesView: React.FC<RolesResourcesViewProps> = ({
  roles,
  resources,
  onInspectMapping,
  isLoading,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<"roles" | "resources">("roles");

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* View Toggle */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab("roles")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
            activeSubTab === "roles"
              ? "bg-purple-950/60 text-purple-300 border border-purple-800/80 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Key className="w-3.5 h-3.5" />
          <span>Application Roles ({roles.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab("resources")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
            activeSubTab === "resources"
              ? "bg-amber-950/60 text-amber-300 border border-amber-800/80 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Domain Resources ({resources.length})</span>
        </button>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-lg">
          Loading role and resource definitions...
        </div>
      ) : activeSubTab === "roles" ? (
        /* Roles Listing */
        <div className="space-y-3">
          {roles.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-lg">
              No application roles defined or discovered.
            </div>
          ) : (
            roles.map((r) => (
              <div
                key={r.role_name}
                className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded bg-purple-950/80 border border-purple-800 text-purple-300">
                      <Key className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-slate-100 text-sm">{r.role_name}</h4>
                      {r.description && (
                        <p className="text-[11px] text-slate-400">{r.description}</p>
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {r.mappings.length} mappings
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-slate-800/60">
                  {/* Discovered Endpoints */}
                  <div className="space-y-1.5">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Discovered Endpoints ({r.discovered_endpoints.length})
                    </span>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {r.discovered_endpoints.length === 0 ? (
                        <span className="text-[11px] text-slate-500">None observed</span>
                      ) : (
                        r.discovered_endpoints.map((ep) => (
                          <span
                            key={ep}
                            className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[10px]"
                          >
                            {ep}
                          </span>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Discovered Resources */}
                  <div className="space-y-1.5">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Discovered Resources ({r.discovered_resources.length})
                    </span>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {r.discovered_resources.length === 0 ? (
                        <span className="text-[11px] text-slate-500">None observed</span>
                      ) : (
                        r.discovered_resources.map((res) => (
                          <span
                            key={res}
                            className="px-1.5 py-0.5 rounded bg-amber-950/40 border border-amber-900/60 text-amber-300 text-[10px]"
                          >
                            {res}
                          </span>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {/* Declared Permissions Raw preview if available */}
                {Object.keys(r.declared_permissions || {}).length > 0 && (
                  <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[10px] text-slate-400">
                    <span className="text-slate-500 block mb-0.5 font-semibold">
                      Declared Permissions Spec:
                    </span>
                    <pre className="text-purple-300 whitespace-pre-wrap break-all">
                      {JSON.stringify(r.declared_permissions, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      ) : (
        /* Resources Listing */
        <div className="space-y-3">
          {resources.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-lg">
              No application resources discovered.
            </div>
          ) : (
            resources.map((res) => (
              <div
                key={res.resource_name}
                className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded bg-amber-950/80 border border-amber-800 text-amber-300">
                      <Database className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-slate-100 text-sm">
                        {res.resource_name}
                      </h4>
                      <p className="text-[11px] text-slate-400">Domain entity resource</p>
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {res.mappings.length} mappings
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/60">
                  {/* Structural Parents */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Structural Parents
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {res.structural_parents.length === 0 ? (
                        <span className="text-[11px] text-slate-500">Root / Top-level</span>
                      ) : (
                        res.structural_parents.map((p) => (
                          <span
                            key={p}
                            className="px-1.5 py-0.5 rounded bg-slate-950 border border-purple-900/60 text-purple-300 text-[10px]"
                          >
                            {p}
                          </span>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Structural Children */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Structural Children
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {res.structural_children.length === 0 ? (
                        <span className="text-[11px] text-slate-500">None</span>
                      ) : (
                        res.structural_children.map((c) => (
                          <span
                            key={c}
                            className="px-1.5 py-0.5 rounded bg-slate-950 border border-purple-900/60 text-purple-300 text-[10px]"
                          >
                            {c}
                          </span>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Accessing Roles */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Accessing Roles
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {res.accessing_roles.length === 0 ? (
                        <span className="text-[11px] text-slate-500">None detected</span>
                      ) : (
                        res.accessing_roles.map((role) => (
                          <span
                            key={role}
                            className="px-1.5 py-0.5 rounded bg-slate-950 border border-cyan-900/60 text-cyan-300 text-[10px]"
                          >
                            {role}
                          </span>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

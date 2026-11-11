import React, { useState, useEffect } from "react";
import { Modal } from "../common/Modal";
import { ScopePolicyResponse, ScopePolicyCreate, ApplicationResponse } from "../../types";
import { Shield, AlertTriangle, CheckCircle, Info } from "lucide-react";

interface ScopePolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (appId: string, payload: ScopePolicyCreate) => Promise<void>;
  initialPolicy?: ScopePolicyResponse | null;
  applications: ApplicationResponse[];
}

const ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export const ScopePolicyModal: React.FC<ScopePolicyModalProps> = ({
  isOpen,
  onClose,
  onSave,
  initialPolicy,
  applications,
}) => {
  const [selectedAppId, setSelectedAppId] = useState<string>("");
  const [targetDomain, setTargetDomain] = useState<string>("");
  const [baseUrl, setBaseUrl] = useState<string>("");
  const [permittedPaths, setPermittedPaths] = useState<string>("/*");
  const [excludedPaths, setExcludedPaths] = useState<string>("/admin/*, /logout, /auth/reset-password");
  const [rateLimitRps, setRateLimitRps] = useState<number>(10);
  const [maxConcurrency, setMaxConcurrency] = useState<number>(2);
  const [maxScanDurationMinutes, setMaxScanDurationMinutes] = useState<number>(60);
  const [allowedMethods, setAllowedMethods] = useState<string[]>(["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]);
  const [restrictedEndpointPatterns, setRestrictedEndpointPatterns] = useState<string>("*/delete-account*, */purge*, */reset*");
  const [requireSyntheticAuth, setRequireSyntheticAuth] = useState<boolean>(true);
  const [allowDestructive, setAllowDestructive] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialPolicy) {
      setSelectedAppId(initialPolicy.application_id);
      setTargetDomain(initialPolicy.target_domain || "");
      setBaseUrl(initialPolicy.base_url || "");
      setPermittedPaths(initialPolicy.permitted_paths?.join(", ") || "/*");
      setExcludedPaths(initialPolicy.excluded_paths?.join(", ") || "/admin/*, /logout");
      setRateLimitRps(initialPolicy.rate_limit_rps || 10);
      setMaxConcurrency(initialPolicy.max_concurrency || 2);
      setMaxScanDurationMinutes(initialPolicy.max_scan_duration_minutes || 60);
      setAllowedMethods(initialPolicy.allowed_methods || ["GET", "POST"]);
      setRestrictedEndpointPatterns(initialPolicy.restricted_endpoint_patterns?.join(", ") || "*/delete-account*");
      setRequireSyntheticAuth(initialPolicy.require_synthetic_auth ?? true);
      setAllowDestructive(initialPolicy.allow_destructive ?? false);
    } else {
      const firstApp = applications[0];
      if (firstApp) {
        setSelectedAppId(firstApp.id);
        try {
          const u = new URL(firstApp.target_url);
          setTargetDomain(u.hostname);
          setBaseUrl(firstApp.target_url);
        } catch {
          setTargetDomain(firstApp.target_url || "");
          setBaseUrl(firstApp.target_url || "");
        }
      }
      setPermittedPaths("/*");
      setExcludedPaths("/admin/*, /logout, /auth/reset-password");
      setRateLimitRps(10);
      setMaxConcurrency(2);
      setMaxScanDurationMinutes(60);
      setAllowedMethods(["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]);
      setRestrictedEndpointPatterns("*/delete-account*, */purge*, */reset*");
      setRequireSyntheticAuth(true);
      setAllowDestructive(false);
    }
    setError(null);
  }, [initialPolicy, applications, isOpen]);

  const handleAppChange = (appId: string) => {
    setSelectedAppId(appId);
    const app = applications.find((a) => a.id === appId);
    if (app && !initialPolicy) {
      try {
        const u = new URL(app.target_url);
        setTargetDomain(u.hostname);
        setBaseUrl(app.target_url);
      } catch {
        setTargetDomain(app.target_url);
        setBaseUrl(app.target_url);
      }
    }
  };

  const handleMethodToggle = (method: string) => {
    if (allowedMethods.includes(method)) {
      setAllowedMethods(allowedMethods.filter((m) => m !== method));
    } else {
      setAllowedMethods([...allowedMethods, method]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAppId) {
      setError("Please select an application target.");
      return;
    }
    if (!targetDomain.trim() || !baseUrl.trim()) {
      setError("Target domain and base URL are required.");
      return;
    }
    if (allowedMethods.length === 0) {
      setError("At least one HTTP method must be allowed.");
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const payload: ScopePolicyCreate = {
        application_id: selectedAppId,
        target_domain: targetDomain.trim().toLowerCase(),
        base_url: baseUrl.trim(),
        permitted_paths: permittedPaths
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        excluded_paths: excludedPaths
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        rate_limit_rps: Number(rateLimitRps),
        max_concurrency: Number(maxConcurrency),
        max_scan_duration_minutes: Number(maxScanDurationMinutes),
        allowed_methods: allowedMethods,
        restricted_endpoint_patterns: restrictedEndpointPatterns
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
        require_synthetic_auth: requireSyntheticAuth,
        allow_destructive: allowDestructive,
      };

      await onSave(selectedAppId, payload);
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Failed to save scope policy.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={initialPolicy ? "Edit Target Scope & Safety Policy" : "Register Application Testing Scope"}
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={isSubmitting}
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded font-semibold transition-colors disabled:opacity-50"
          >
            {isSubmitting ? "Saving..." : initialPolicy ? "Update Scope Policy" : "Register Scope"}
          </button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4 max-h-[70vh] overflow-y-auto pr-2">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded text-rose-400 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Application Selection */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">Target Application</label>
          <select
            value={selectedAppId}
            onChange={(e) => handleAppChange(e.target.value)}
            disabled={!!initialPolicy}
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-60"
          >
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name} ({app.target_url})
              </option>
            ))}
          </select>
        </div>

        {/* Domain & Base URL */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Target Domain / Host</label>
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="e.g. api.staging.local or *.target.internal"
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">API Base URL</label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.staging.local/v1"
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              required
            />
          </div>
        </div>

        {/* Permitted Paths */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Permitted Paths (Whitelist)
          </label>
          <input
            type="text"
            value={permittedPaths}
            onChange={(e) => setPermittedPaths(e.target.value)}
            placeholder="/*, /api/v1/*"
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          />
          <span className="text-[11px] text-slate-500">Comma-separated glob paths permitted for test execution</span>
        </div>

        {/* Excluded Paths */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1 text-rose-300 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Excluded Paths (Strict Blacklist)
          </label>
          <input
            type="text"
            value={excludedPaths}
            onChange={(e) => setExcludedPaths(e.target.value)}
            placeholder="/admin/*, /logout, /auth/reset-password"
            className="w-full bg-slate-950 border border-rose-950/40 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500"
          />
          <span className="text-[11px] text-slate-500">Requests matching any excluded pattern are instantly blocked</span>
        </div>

        {/* Allowed HTTP Methods */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">Allowed HTTP Methods</label>
          <div className="flex flex-wrap gap-2">
            {ALL_METHODS.map((method) => {
              const checked = allowedMethods.includes(method);
              return (
                <button
                  type="button"
                  key={method}
                  onClick={() => handleMethodToggle(method)}
                  className={`px-2.5 py-1 text-xs font-mono rounded border transition-colors ${
                    checked
                      ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                      : "bg-slate-950 text-slate-500 border-slate-800 hover:text-slate-300"
                  }`}
                >
                  {method}
                </button>
              );
            })}
          </div>
        </div>

        {/* Rate Limits & Concurrency */}
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Max Rate (RPS)</label>
            <input
              type="number"
              min={1}
              max={100}
              value={rateLimitRps}
              onChange={(e) => setRateLimitRps(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Max Concurrency</label>
            <input
              type="number"
              min={1}
              max={20}
              value={maxConcurrency}
              onChange={(e) => setMaxConcurrency(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Scan Duration (min)</label>
            <input
              type="number"
              min={5}
              max={720}
              value={maxScanDurationMinutes}
              onChange={(e) => setMaxScanDurationMinutes(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Restricted Endpoint Patterns */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">Restricted Endpoint Patterns</label>
          <input
            type="text"
            value={restrictedEndpointPatterns}
            onChange={(e) => setRestrictedEndpointPatterns(e.target.value)}
            placeholder="*/delete-account*, */purge*, */reset*"
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Safety Toggles */}
        <div className="space-y-3 pt-2 border-t border-slate-800">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={requireSyntheticAuth}
              onChange={(e) => setRequireSyntheticAuth(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:outline-none"
            />
            <div>
              <span className="text-xs font-medium text-slate-200">Require Synthetic Authentication</span>
              <p className="text-[11px] text-slate-500">Only test using dedicated non-production synthetic test credentials</p>
            </div>
          </label>

          <label className="flex items-start gap-3 cursor-pointer p-2.5 rounded bg-rose-500/5 border border-rose-500/20">
            <input
              type="checkbox"
              checked={allowDestructive}
              onChange={(e) => setAllowDestructive(e.target.checked)}
              className="rounded mt-0.5 bg-slate-950 border-rose-700 text-rose-500 focus:ring-0 focus:outline-none"
            />
            <div>
              <span className="text-xs font-semibold text-rose-400">Allow Destructive Actions (High Risk)</span>
              <p className="text-[11px] text-slate-400">
                Enables drop/delete payloads and restricted endpoint mutations. Default is False. Never enable in production.
              </p>
            </div>
          </label>
        </div>
      </form>
    </Modal>
  );
};


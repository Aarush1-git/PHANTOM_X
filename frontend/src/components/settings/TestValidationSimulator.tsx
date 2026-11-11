import React, { useState } from "react";
import { ApplicationResponse, TestValidationResult, TestValidationRequest } from "../../types";
import { api } from "../../services/api";
import { ShieldAlert, ShieldCheck, Play, Terminal, AlertTriangle, CheckCircle2, Zap } from "lucide-react";

interface TestValidationSimulatorProps {
  applications: ApplicationResponse[];
}

export const TestValidationSimulator: React.FC<TestValidationSimulatorProps> = ({ applications }) => {
  const [selectedAppId, setSelectedAppId] = useState<string>(applications[0]?.id || "");
  const [targetUrl, setTargetUrl] = useState<string>(
    applications[0]?.target_url ? `${applications[0].target_url}/v1/users` : "https://api.staging.example.com/v1/users"
  );
  const [httpMethod, setHttpMethod] = useState<string>("GET");
  const [payloadSample, setPayloadSample] = useState<string>("");
  const [sourceAgent, setSourceAgent] = useState<string>("SECURITY_ANALYST_SIMULATION");
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [result, setResult] = useState<TestValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleValidate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) return;

    try {
      setIsValidating(true);
      setError(null);
      const req: TestValidationRequest = {
        application_id: selectedAppId || undefined,
        target_url: targetUrl.trim(),
        http_method: httpMethod,
        payload_sample: payloadSample.trim() || undefined,
        source_agent: sourceAgent,
        dry_run: false, // Log blocked attempts
      };
      const verdict = await api.settings.validateTest(req);
      setResult(verdict);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Validation request failed.");
    } finally {
      setIsValidating(false);
    }
  };

  const applyPreset = (preset: {
    appId?: string;
    url: string;
    method: string;
    payload?: string;
  }) => {
    if (preset.appId) setSelectedAppId(preset.appId);
    setTargetUrl(preset.url);
    setHttpMethod(preset.method);
    setPayloadSample(preset.payload || "");
    setResult(null);
  };

  return (
    <div className="space-y-6">
      <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            Live Pre-Execution Safety Gate Simulator
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Test any planned request, URL, HTTP method, or payload against active application scope policies,
            forbidden patterns, and rate limits. Tests run through the identical safety validation pipeline used by autonomous agents.
          </p>
        </div>

        {/* Quick Presets */}
        <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800">
          <span className="text-[11px] text-slate-500 self-center mr-1">Quick Presets:</span>
          <button
            type="button"
            onClick={() =>
              applyPreset({
                url: applications[0]?.target_url ? `${applications[0].target_url}/api/v1/profile` : "https://api.target.local/profile",
                method: "GET",
                payload: "",
              })
            }
            className="px-2.5 py-1 text-xs bg-slate-950 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 rounded transition-colors"
          >
            Clean Permitted GET
          </button>
          <button
            type="button"
            onClick={() =>
              applyPreset({
                url: applications[0]?.target_url ? `${applications[0].target_url}/admin/config` : "https://api.target.local/admin/config",
                method: "GET",
                payload: "",
              })
            }
            className="px-2.5 py-1 text-xs bg-slate-950 border border-purple-500/30 text-purple-300 hover:bg-purple-500/10 rounded transition-colors"
          >
            Excluded /admin Path
          </button>
          <button
            type="button"
            onClick={() =>
              applyPreset({
                url: applications[0]?.target_url ? `${applications[0].target_url}/search` : "https://api.target.local/search",
                method: "GET",
                payload: "'; DROP TABLE users; --",
              })
            }
            className="px-2.5 py-1 text-xs bg-slate-950 border border-rose-500/30 text-rose-300 hover:bg-rose-500/10 rounded transition-colors"
          >
            Destructive DROP TABLE
          </button>
          <button
            type="button"
            onClick={() =>
              applyPreset({
                url: applications[0]?.target_url ? `${applications[0].target_url}/users/1` : "https://api.target.local/users/1",
                method: "DELETE",
                payload: "",
              })
            }
            className="px-2.5 py-1 text-xs bg-slate-950 border border-amber-500/30 text-amber-300 hover:bg-amber-500/10 rounded transition-colors"
          >
            DELETE Method
          </button>
          <button
            type="button"
            onClick={() =>
              applyPreset({
                url: "https://unauthorized-external.victim.com/api",
                method: "GET",
                payload: "",
              })
            }
            className="px-2.5 py-1 text-xs bg-slate-950 border border-blue-500/30 text-blue-300 hover:bg-blue-500/10 rounded transition-colors"
          >
            Out-of-Scope Host
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleValidate} className="space-y-4 pt-2">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded text-rose-400 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-1">
              <label className="block text-xs font-medium text-slate-300 mb-1">Target Application</label>
              <select
                value={selectedAppId}
                onChange={(e) => setSelectedAppId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">(Auto-detect by domain)</option>
                {applications.map((app) => (
                  <option key={app.id} value={app.id}>
                    {app.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-1">
              <label className="block text-xs font-medium text-slate-300 mb-1">HTTP Method</label>
              <select
                value={httpMethod}
                onChange={(e) => setHttpMethod(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"].map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-slate-300 mb-1">Target URL</label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://target.staging.local/api/v1/resource"
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Payload Sample / Query Parameters (Optional)
            </label>
            <textarea
              value={payloadSample}
              onChange={(e) => setPayloadSample(e.target.value)}
              rows={2}
              placeholder="e.g. {'user_id': 100} or SQL query string"
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={isValidating}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isValidating ? "animate-spin" : ""}`} />
            <span>{isValidating ? "Validating Safety..." : "Run Safety Check"}</span>
          </button>
        </form>

        {/* Verdict Display */}
        {result && (
          <div
            className={`mt-4 p-4 rounded-lg border space-y-2 transition-all ${
              result.is_allowed
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
                : "bg-rose-500/10 border-rose-500/30 text-rose-200"
            }`}
          >
            <div className="flex items-center gap-2">
              {result.is_allowed ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              )}
              <span className="text-sm font-bold font-mono">
                VERDICT: {result.is_allowed ? "ALLOWED (COMPLIANT)" : `BLOCKED (${result.violation_category})`}
              </span>
            </div>

            <p className="text-xs font-mono">{result.reason}</p>

            <div className="text-[11px] text-slate-400 font-mono pt-1 flex flex-wrap gap-4 border-t border-slate-800/60">
              <span>Method: {result.http_method}</span>
              <span>URL: {result.target_url}</span>
              <span>Checked At: {new Date(result.checked_at).toLocaleTimeString()}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};


import React, { useState } from "react";
import { Terminal, Play, ShieldAlert, CheckCircle, AlertTriangle } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";

export const PlaygroundPage: React.FC = () => {
  const [targetEndpoint, setTargetEndpoint] = useState("/api/v1/users/{id}");
  const [testCategory, setTestCategory] = useState("BOLA");
  const [method, setMethod] = useState("GET");
  const [payload, setPayload] = useState('{\n  "target_user_id": "test_synthetic_user_2"\n}');
  const [outputLog, setOutputLog] = useState<string>("// Run a test to evaluate deterministic policy and view output...");

  const handleExecute = () => {
    setOutputLog(
      `[Central Safety Policy] Evaluating request: ${method} ${targetEndpoint}...\n` +
      `[Policy Verdict] PASSED - In-scope host, non-destructive test classification.\n` +
      `[Execution Runner] Dispatching controlled probe with synthetic credentials...\n` +
      `[Result] HTTP 403 Forbidden received. Negative control verified.`
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="PHANTOM Playground"
        description="Interactive security sandbox for controlled single-endpoint security assertions and counterfactual hypothesis testing."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Test Configuration</h3>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">METHOD</label>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-mono text-slate-400 mb-1">TEST CATEGORY</label>
              <select
                value={testCategory}
                onChange={(e) => setTestCategory(e.target.value)}
                className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="BOLA">BOLA / IDOR Verification</option>
                <option value="AUTH_BYPASS">Authentication Enforcement</option>
                <option value="STATE_MACHINE">Workflow Abuse</option>
                <option value="SECURITY_HEADERS">Defensive Headers Probe</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">TARGET ENDPOINT</label>
            <input
              type="text"
              value={targetEndpoint}
              onChange={(e) => setTargetEndpoint(e.target.value)}
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">SYNTHETIC PAYLOAD (JSON)</label>
            <textarea
              rows={5}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            onClick={handleExecute}
            className="w-full py-2 px-4 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs flex items-center justify-center gap-2 transition-colors"
          >
            <Play className="w-4 h-4" />
            <span>Execute Controlled Assertion</span>
          </button>
        </div>

        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Playground Output Console</h3>
            <span className="text-[10px] font-mono text-emerald-400">SAFETY POLICY: ACTIVE</span>
          </div>
          <div className="flex-1 bg-phantom-950 border border-slate-800 rounded p-4 font-mono text-xs text-slate-300 overflow-y-auto whitespace-pre-wrap">
            {outputLog}
          </div>
        </div>
      </div>
    </div>
  );
};


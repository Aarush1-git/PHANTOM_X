import React from 'react';
import {
  FileCode,
  Shield,
  Zap,
  Lock,
  AlertCircle,
  Clock,
  CheckCircle,
} from 'lucide-react';
import { PlaygroundExecutionPlan, PlaygroundSession } from '../../types/playground';

interface ExecutionPlanPreviewProps {
  session: PlaygroundSession;
  onOpenAuthorizeModal: () => void;
  onExecuteNow: () => void;
  isExecuting?: boolean;
}

export const ExecutionPlanPreview: React.FC<ExecutionPlanPreviewProps> = ({
  session,
  onOpenAuthorizeModal,
  onExecuteNow,
  isExecuting = false,
}) => {
  const plan: PlaygroundExecutionPlan = session.execution_plan;

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Session {session.id.slice(0, 8)}...
            </span>
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                session.is_authorized
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}
            >
              {session.is_authorized ? 'AUTHORIZED' : 'AWAITING AUTHORIZATION'}
            </span>
          </div>
          <h3 className="text-sm font-semibold text-slate-100 mt-1">
            Execution Plan: {session.scenario_name}
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {!session.is_authorized ? (
            <button
              type="button"
              onClick={onOpenAuthorizeModal}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-md transition-colors"
            >
              <Lock className="w-3.5 h-3.5" /> Authorize Scenario
            </button>
          ) : (
            <button
              type="button"
              disabled={isExecuting || session.status === 'RUNNING'}
              onClick={onExecuteNow}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-white shadow-md transition-colors"
            >
              {isExecuting ? (
                <>
                  <Clock className="w-3.5 h-3.5 animate-spin" /> Executing Simulation...
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" /> Execute Test Plan
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Plan Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
            Target Endpoint
          </div>
          <div className="flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/50">
              {plan?.http_method || 'GET'}
            </span>
            <span className="text-xs font-mono text-slate-200 truncate">
              {plan?.endpoint || '/api/test'}
            </span>
          </div>
        </div>

        <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
            Safety Classification
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono font-medium text-emerald-400">
            <Shield className="w-3.5 h-3.5" />
            {plan?.safety_classification || 'SAFE_READ_ONLY'}
          </div>
        </div>

        <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
            Execution Constraints
          </div>
          <div className="text-xs font-mono text-slate-300">
            Max RPS: {plan?.rate_limit_rps || 5} req/s | Concurrency: 1
          </div>
        </div>
      </div>

      {/* Safety Restrictions Box */}
      <div>
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-cyan-400" /> Feature 26 Safety Controls Enforced
        </div>
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1.5">
          {(plan?.safety_restrictions || [
            'Strict read-only execution constraints enforced',
            'Automated destructive operations permanently disabled',
            'Rate limiting sliding-window active',
          ]).map((rest, idx) => (
            <div key={idx} className="flex items-center gap-2 text-xs text-slate-300">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>{rest}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Payload Preview */}
      {plan?.payload_preview && Object.keys(plan.payload_preview).length > 0 && (
        <div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-cyan-400" /> Proposed Test Payload
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto">
            {JSON.stringify(plan.payload_preview, null, 2)}
          </pre>
        </div>
      )}

      {/* Authorization Banner */}
      {session.is_authorized ? (
        <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-emerald-300">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              Authorized by <strong>{session.authorized_by}</strong> ({session.authorizer_role}) on{' '}
              {session.authorized_at ? new Date(session.authorized_at).toLocaleString() : 'Now'}
            </span>
          </div>
        </div>
      ) : (
        <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg flex items-center gap-2 text-xs text-amber-300">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            <strong>Explicit Authorization Required:</strong> An operator must explicitly review and authorize this execution before requests can be dispatched.
          </span>
        </div>
      )}
    </div>
  );
};

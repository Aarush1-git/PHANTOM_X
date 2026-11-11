import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  CheckCircle,
  HelpCircle,
  PlayCircle,
  Search,
  Check,
  Shield,
} from 'lucide-react';
import {
  RemediationRecommendationDetail,
  RecommendationVerifyRequest,
  RecommendationVerifyResponse,
} from '../../types/remediation';

interface VerificationPanelProps {
  recommendation: RemediationRecommendationDetail;
  onVerify: (payload: RecommendationVerifyRequest) => Promise<RecommendationVerifyResponse>;
  onOpenPlayground?: (scenarioId: string) => void;
}

export const VerificationPanel: React.FC<VerificationPanelProps> = ({
  recommendation,
  onVerify,
  onOpenPlayground,
}) => {
  const [verificationType, setVerificationType] = useState<'SCAN' | 'PLAYGROUND'>('PLAYGROUND');
  const [scanId, setScanId] = useState<string>('');
  const [sessionId, setSessionId] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<RecommendationVerifyResponse | null>(null);

  const handleRunVerification = async () => {
    setError(null);
    setLoading(true);
    try {
      const payload: RecommendationVerifyRequest = {
        verification_scan_id: verificationType === 'SCAN' && scanId.trim() ? scanId.trim() : undefined,
        playground_session_id:
          verificationType === 'PLAYGROUND' && sessionId.trim() ? sessionId.trim() : undefined,
        notes: notes.trim() || undefined,
      };
      const res = await onVerify(payload);
      setLastResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Verification execution failed.');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = () => {
    switch (recommendation.verification_status) {
      case 'VERIFIED':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
            <ShieldCheck className="w-4 h-4" />
            <span>Empirically Verified Fixed</span>
          </div>
        );
      case 'PERSISTENT':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold">
            <AlertTriangle className="w-4 h-4" />
            <span>Vulnerability Still Persistent</span>
          </div>
        );
      case 'INCONCLUSIVE':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold">
            <HelpCircle className="w-4 h-4" />
            <span>Verification Inconclusive</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 text-xs font-semibold">
            <RotateCcw className="w-4 h-4" />
            <span>Unverified</span>
          </div>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Verification Telemetry Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
        <div>
          <h4 className="text-sm font-semibold text-white tracking-wide uppercase">
            Evidence-Grounded Verification
          </h4>
          <p className="text-xs text-slate-400 mt-1">
            Empirically confirm that developer defensive changes neutralized the security vulnerability.
          </p>
        </div>
        {getStatusBadge()}
      </div>

      {/* Verification Evidence Details */}
      {recommendation.verification_evidence && Object.keys(recommendation.verification_evidence).length > 0 && (
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h5 className="text-xs font-semibold text-slate-300">Persisted Evidence Telemetry</h5>
          </div>
          <pre className="p-3 bg-slate-900/80 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto">
            {JSON.stringify(recommendation.verification_evidence, null, 2)}
          </pre>
          {recommendation.verified_at && (
            <div className="mt-2 text-[11px] text-slate-400">
              Verified on {new Date(recommendation.verified_at).toLocaleString()} by{' '}
              <span className="text-slate-300 font-medium">{recommendation.verified_by || 'system'}</span>
            </div>
          )}
        </div>
      )}

      {/* Interactive Verification Form */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
        <h5 className="text-xs font-semibold text-white uppercase tracking-wider">
          Execute Empirical Verification
        </h5>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {lastResult && (
          <div
            className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
              lastResult.is_verified
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
            }`}
          >
            {lastResult.is_verified ? (
              <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
            )}
            <span>{lastResult.message}</span>
          </div>
        )}

        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setVerificationType('PLAYGROUND')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              verificationType === 'PLAYGROUND'
                ? 'bg-indigo-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            Playground Simulation Session
          </button>
          <button
            type="button"
            onClick={() => setVerificationType('SCAN')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              verificationType === 'SCAN'
                ? 'bg-indigo-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            Subsequent Scan ID
          </button>
        </div>

        {verificationType === 'PLAYGROUND' ? (
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Playground Session UUID
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder="Enter completed Playground Session ID (e.g. from Feature 24)"
                className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-indigo-500"
              />
              {recommendation.suggested_playground_scenario_id && onOpenPlayground && (
                <button
                  type="button"
                  onClick={() =>
                    onOpenPlayground(recommendation.suggested_playground_scenario_id!)
                  }
                  className="px-3 py-2 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-lg text-xs font-medium flex items-center gap-1.5"
                >
                  <PlayCircle className="w-3.5 h-3.5" />
                  <span>Launch Scenario</span>
                </button>
              )}
            </div>
          </div>
        ) : (
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Verification Scan UUID
            </label>
            <input
              type="text"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              placeholder="Enter subsequent scan UUID that validated this fix"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-indigo-500"
            />
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Verification Operator Notes
          </label>
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Optional context regarding test environment or observed payload behavior..."
            className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-indigo-500"
          />
        </div>

        <button
          type="button"
          onClick={handleRunVerification}
          disabled={loading}
          className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <RotateCcw className="w-4 h-4 animate-spin" />
              <span>Checking Scope & Verifying Evidence...</span>
            </>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4" />
              <span>Verify Remediation Effectiveness</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};


import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  Clock,
  ShieldCheck,
  User,
  Wrench,
  HelpCircle,
  FileText,
  Activity,
  Calendar,
  Layers,
} from 'lucide-react';
import {
  RemediationRecommendationDetail,
  RecommendationStatusUpdateRequest,
  RecommendationVerifyRequest,
  RecommendationVerifyResponse,
  RecommendationHistoryItem,
} from '../../types/remediation';
import { RemediationSteps } from './RemediationSteps';
import { VerificationPanel } from './VerificationPanel';
import { RecommendationHistory } from './RecommendationHistory';
import { RecommendationStatusDialog } from './RecommendationStatusDialog';

interface RecommendationDetailsProps {
  recommendation: RemediationRecommendationDetail;
  history: RecommendationHistoryItem[];
  historyLoading?: boolean;
  onClose: () => void;
  onStatusUpdate: (payload: RecommendationStatusUpdateRequest) => Promise<void>;
  onVerify: (payload: RecommendationVerifyRequest) => Promise<RecommendationVerifyResponse>;
  onOpenPlayground?: (scenarioId: string) => void;
}

export const RecommendationDetails: React.FC<RecommendationDetailsProps> = ({
  recommendation,
  history,
  historyLoading = false,
  onClose,
  onStatusUpdate,
  onVerify,
  onOpenPlayground,
}) => {
  const [activeTab, setActiveTab] = useState<'GUIDANCE' | 'VERIFICATION' | 'HISTORY'>('GUIDANCE');
  const [isStatusDialogOpen, setIsStatusDialogOpen] = useState<boolean>(false);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
      {/* Header */}
      <div className="p-6 border-b border-slate-800 bg-slate-950/60">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                {recommendation.category}
              </span>
              {recommendation.cwe_id && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-slate-800 text-slate-400 border border-slate-700">
                  {recommendation.cwe_id}
                </span>
              )}
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                Status: {recommendation.status}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">{recommendation.title}</h2>
            {recommendation.endpoint && (
              <p className="text-xs font-mono text-cyan-300">
                {recommendation.http_method || 'GET'} {recommendation.endpoint}
              </p>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsStatusDialogOpen(true)}
              className="px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors shadow-md shadow-indigo-600/20"
            >
              Update Status
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Priority & Risk Score Banner */}
        <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-3 p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center font-mono font-bold text-lg text-rose-400">
              {recommendation.risk_score.toFixed(0)}
            </div>
            <div>
              <div className="text-xs text-slate-400">Calculated Risk Score</div>
              <div className="text-sm font-bold text-white">
                {recommendation.calculated_priority} Priority
              </div>
            </div>
          </div>

          <div className="text-xs text-slate-300 flex flex-col justify-center border-l border-slate-800 pl-3">
            <div className="text-slate-400">Verification Status</div>
            <div className="font-semibold text-white mt-0.5">
              {recommendation.verification_status}
            </div>
          </div>

          <div className="text-xs text-slate-300 flex flex-col justify-center border-l border-slate-800 pl-3">
            <div className="text-slate-400">Assignee / Owner</div>
            <div className="font-semibold text-white mt-0.5">
              {recommendation.assigned_to || 'Unassigned'}
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 mt-5 border-b border-slate-800">
          <button
            onClick={() => setActiveTab('GUIDANCE')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'GUIDANCE'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            }`}
          >
            <Wrench className="w-4 h-4" />
            <span>Remediation Guidance & Fix</span>
          </button>
          <button
            onClick={() => setActiveTab('VERIFICATION')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'VERIFICATION'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Empirical Verification</span>
          </button>
          <button
            onClick={() => setActiveTab('HISTORY')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'HISTORY'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-300'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Decision Timeline ({history.length})</span>
          </button>
        </div>
      </div>

      {/* Tab Contents */}
      <div className="p-6 max-h-[70vh] overflow-y-auto">
        {activeTab === 'GUIDANCE' && (
          <div className="space-y-6">
            {/* Priority Rationale Breakdown */}
            <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-indigo-400" />
                <span>Deterministic Priority Rationale (Why Fix This First)</span>
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {recommendation.priority_rationale.map((factor, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs"
                  >
                    <div className="flex items-center justify-between font-semibold text-slate-200">
                      <span>{factor.factor}</span>
                      <span className="font-mono text-indigo-400 font-bold">
                        +{factor.points} pts
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-400">{factor.reason}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Why It Matters & Business Impact */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                <h4 className="text-xs font-semibold text-rose-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                  <span>Why This Matters (Context)</span>
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {recommendation.why_it_matters}
                </p>
              </div>

              <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                <h4 className="text-xs font-semibold text-amber-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Potential Business Impact (If Unresolved)</span>
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {recommendation.potential_business_impact}
                </p>
              </div>
            </div>

            {/* Missing Information Notes */}
            {recommendation.missing_information_notes && (
              <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-400 flex items-start gap-2">
                <HelpCircle className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-slate-300">Scoring Fallback Context: </span>
                  {recommendation.missing_information_notes}
                </div>
              </div>
            )}

            {/* Actionable Steps and Code Pattern */}
            <RemediationSteps
              recommendation={recommendation}
              onOpenPlayground={onOpenPlayground}
            />
          </div>
        )}

        {activeTab === 'VERIFICATION' && (
          <VerificationPanel
            recommendation={recommendation}
            onVerify={onVerify}
            onOpenPlayground={onOpenPlayground}
          />
        )}

        {activeTab === 'HISTORY' && (
          <RecommendationHistory history={history} loading={historyLoading} />
        )}
      </div>

      {/* Lifecycle Status Dialog */}
      <RecommendationStatusDialog
        isOpen={isStatusDialogOpen}
        onClose={() => setIsStatusDialogOpen(false)}
        recommendation={recommendation}
        onSubmit={onStatusUpdate}
      />
    </div>
  );
};


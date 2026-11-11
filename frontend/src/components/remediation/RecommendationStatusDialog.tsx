import React, { useState } from 'react';
import { X, CheckCircle, AlertTriangle, ShieldCheck, Clock, UserCheck } from 'lucide-react';
import {
  RecommendationStatus,
  RemediationRecommendationDetail,
  RecommendationStatusUpdateRequest,
} from '../../types/remediation';

interface RecommendationStatusDialogProps {
  isOpen: boolean;
  onClose: () => void;
  recommendation: RemediationRecommendationDetail;
  onSubmit: (payload: RecommendationStatusUpdateRequest) => Promise<void>;
}

export const RecommendationStatusDialog: React.FC<RecommendationStatusDialogProps> = ({
  isOpen,
  onClose,
  recommendation,
  onSubmit,
}) => {
  const currentStatus = recommendation.status;

  const allowedNextStatuses: Record<RecommendationStatus, RecommendationStatus[]> = {
    GENERATED: ['REVIEWED', 'ACCEPTED', 'REJECTED', 'DEFERRED'],
    REVIEWED: ['ACCEPTED', 'REJECTED', 'IN_PROGRESS', 'DEFERRED'],
    ACCEPTED: ['IN_PROGRESS', 'DEFERRED', 'REJECTED'],
    IN_PROGRESS: ['VERIFIED', 'DEFERRED', 'ACCEPTED', 'REVIEWED'],
    DEFERRED: ['REVIEWED', 'ACCEPTED', 'IN_PROGRESS'],
    REJECTED: ['REVIEWED'],
    VERIFIED: ['IN_PROGRESS', 'REVIEWED'],
  };

  const availableStatuses = allowedNextStatuses[currentStatus] || [];

  const [selectedStatus, setSelectedStatus] = useState<RecommendationStatus>(
    availableStatuses[0] || currentStatus
  );
  const [assignedTo, setAssignedTo] = useState<string>(recommendation.assigned_to || '');
  const [notes, setNotes] = useState<string>(recommendation.decision_notes || '');
  const [deferredReason, setDeferredReason] = useState<string>(recommendation.deferred_reason || '');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (selectedStatus === 'DEFERRED' && !deferredReason.trim()) {
      setError('Please provide a specific deferral reason.');
      return;
    }

    if (selectedStatus === 'REJECTED' && !notes.trim()) {
      setError('Please provide decision justification notes when rejecting a recommendation.');
      return;
    }

    if (
      selectedStatus === 'VERIFIED' &&
      recommendation.verification_status !== 'VERIFIED'
    ) {
      setError(
        'Cannot mark recommendation as VERIFIED without completing empirical verification. Please use the "Verify Fix" button in the verification panel.'
      );
      return;
    }

    setLoading(true);
    try {
      await onSubmit({
        status: selectedStatus,
        notes: notes.trim() || undefined,
        deferred_reason: deferredReason.trim() || undefined,
        assigned_to: assignedTo.trim() || undefined,
      });
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to update status.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-semibold text-white">Update Lifecycle Status</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Current Status: <span className="text-indigo-400">{currentStatus}</span>
            </label>
            <label className="block text-xs font-semibold text-slate-400 mb-2">
              Select Target Status
            </label>
            <div className="grid grid-cols-2 gap-2">
              {availableStatuses.map((st) => (
                <button
                  type="button"
                  key={st}
                  onClick={() => setSelectedStatus(st)}
                  className={`px-3 py-2 text-xs font-semibold rounded-lg border text-left transition-all ${
                    selectedStatus === st
                      ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300 ring-1 ring-indigo-500'
                      : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:border-slate-600'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Assignee / Owner Email
            </label>
            <input
              type="text"
              value={assignedTo}
              onChange={(e) => setAssignedTo(e.target.value)}
              placeholder="e.g. engineer@enterprise.internal"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-indigo-500"
            />
          </div>

          {selectedStatus === 'DEFERRED' && (
            <div>
              <label className="block text-xs font-semibold text-amber-300 mb-1">
                Deferral Reason (Required for DEFERRED)
              </label>
              <textarea
                value={deferredReason}
                onChange={(e) => setDeferredReason(e.target.value)}
                placeholder="Explain why this remediation is deferred to a future milestone..."
                rows={2}
                className="w-full px-3 py-2 bg-slate-950 border border-amber-500/40 rounded-lg text-xs text-white focus:outline-none focus:border-amber-500"
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Decision Notes / Audit Justification
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Provide context or decision criteria for this lifecycle transition..."
              rows={3}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white bg-slate-800 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-1.5"
            >
              {loading ? 'Saving...' : 'Apply Status Transition'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};


import React, { useState } from 'react';
import {
  X,
  Lock,
  ShieldAlert,
  CheckSquare,
  Square,
  AlertTriangle,
} from 'lucide-react';
import { PlaygroundSession } from '../../types/playground';

interface ExecutionAuthorizationDialogProps {
  session: PlaygroundSession | null;
  onClose: () => void;
  onConfirmAuthorization: (notes?: string) => Promise<void>;
}

export const ExecutionAuthorizationDialog: React.FC<ExecutionAuthorizationDialogProps> = ({
  session,
  onClose,
  onConfirmAuthorization,
}) => {
  const [notes, setNotes] = useState<string>('');
  const [agreeScope, setAgreeScope] = useState<boolean>(false);
  const [agreeSafe, setAgreeSafe] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  if (!session) return null;

  const handleConfirm = async () => {
    if (!agreeScope || !agreeSafe) return;
    setIsSubmitting(true);
    try {
      await onConfirmAuthorization(notes);
      onClose();
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-100">
                Explicit Execution Authorization
              </h3>
              <p className="text-xs text-slate-400">
                Security Operator Clearance Required
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 text-sm">
          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg space-y-1 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-500">Scenario:</span>
              <span className="font-semibold text-slate-200">{session.scenario_name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Target Type:</span>
              <span className="font-mono text-cyan-400">{session.target_type}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Target URL:</span>
              <span className="font-mono text-slate-300 truncate max-w-[240px]">
                {session.execution_plan?.target_url || 'Target'}
              </span>
            </div>
          </div>

          <div className="space-y-3 pt-2">
            <label
              className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300 select-none"
              onClick={() => setAgreeScope(!agreeScope)}
            >
              <span className="mt-0.5 text-cyan-400">
                {agreeScope ? (
                  <CheckSquare className="w-4 h-4" />
                ) : (
                  <Square className="w-4 h-4 text-slate-600" />
                )}
              </span>
              <span>
                I confirm that this target is an authorized application or synthetic lab within current engagement boundaries.
              </span>
            </label>

            <label
              className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300 select-none"
              onClick={() => setAgreeSafe(!agreeSafe)}
            >
              <span className="mt-0.5 text-cyan-400">
                {agreeSafe ? (
                  <CheckSquare className="w-4 h-4" />
                ) : (
                  <Square className="w-4 h-4 text-slate-600" />
                )}
              </span>
              <span>
                I acknowledge that requests will be dispatched through the Feature 26 safety engine under deterministic rate limits and non-destructive constraints.
              </span>
            </label>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">
              Operator Authorization Notes (Recorded in Audit Log)
            </label>
            <input
              type="text"
              placeholder="e.g., Authorized simulation for Q4 security assessment demonstration"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950/40">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!agreeScope || !agreeSafe || isSubmitting}
            onClick={handleConfirm}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 shadow-md transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
            {isSubmitting ? 'Recording Authorization...' : 'Confirm Authorization'}
          </button>
        </div>
      </div>
    </div>
  );
};

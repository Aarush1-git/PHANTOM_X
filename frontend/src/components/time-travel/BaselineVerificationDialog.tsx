import React, { useState } from 'react';
import { X, ShieldCheck, AlertCircle, Loader2 } from 'lucide-react';
import { timeTravelApi } from '../../services/timeTravelApi';
import { BaselineVerifyResponse } from '../../types/timeTravel';

interface BaselineVerificationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const BaselineVerificationDialog: React.FC<BaselineVerificationDialogProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [vulnId, setVulnId] = useState('');
  const [scanId, setScanId] = useState('');
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BaselineVerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vulnId.trim() || !scanId.trim()) {
      setError('Please provide both Vulnerability ID and Verification Scan ID.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const resp = await timeTravelApi.verifyBaseline({
        vulnerability_id: vulnId.trim(),
        verification_scan_id: scanId.trim(),
        notes: notes.trim() || undefined,
      });
      setResult(resp);
      if (resp.verification_status === 'VERIFIED') {
        onSuccess();
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to verify baseline.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setVulnId('');
    setScanId('');
    setNotes('');
    setResult(null);
    setError(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div className="bg-surface border border-border rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-border/80 flex items-center justify-between bg-surface-raised/30">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg border text-emerald-400 bg-emerald-500/10 border-emerald-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-text-primary">Verify Fix & Establish Baseline</h3>
              <p className="text-[11px] text-text-muted">Validate that a resolved vulnerability is absent in a verification scan</p>
            </div>
          </div>
          <button
            onClick={handleReset}
            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-raised transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg border text-rose-400 bg-rose-500/10 border-rose-500/30 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div
              className={`p-3.5 rounded-xl border flex flex-col gap-1 ${
                result.verification_status === 'VERIFIED'
                  ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30'
                  : 'text-rose-300 bg-rose-500/10 border-rose-500/30'
              }`}
            >
              <div className="flex items-center gap-1.5 font-semibold text-xs">
                {result.verification_status === 'VERIFIED' ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                )}
                Verification Result: {result.verification_status}
              </div>
              <p className="text-[11px] opacity-90">{result.reason}</p>
            </div>
          )}

          <div>
            <label className="block text-text-primary font-medium mb-1">
              Original Vulnerability ID <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              placeholder="UUID of discovered finding (e.g. 550e8400-e29b-41d4-a716-446655440000)"
              value={vulnId}
              onChange={(e) => setVulnId(e.target.value)}
              className="w-full px-3 py-2 bg-background border border-border rounded-lg text-text-primary placeholder:text-text-muted font-mono focus:outline-none focus:border-primary transition-colors"
              required
            />
          </div>

          <div>
            <label className="block text-text-primary font-medium mb-1">
              Subsequent Verification Scan ID <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              placeholder="UUID of completed verification scan"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              className="w-full px-3 py-2 bg-background border border-border rounded-lg text-text-primary placeholder:text-text-muted font-mono focus:outline-none focus:border-primary transition-colors"
              required
            />
          </div>

          <div>
            <label className="block text-text-primary font-medium mb-1">
              Verification Notes (Optional)
            </label>
            <textarea
              rows={2}
              placeholder="e.g. Confirmed fixed after PR #104 parameter validation merged."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full px-3 py-2 bg-background border border-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary transition-colors"
            />
          </div>

          <div className="pt-2 flex items-center justify-end gap-2 border-t border-border/80">
            <button
              type="button"
              onClick={handleReset}
              className="px-4 py-2 bg-surface-raised hover:bg-surface border border-border text-text-primary font-medium rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-1.5 px-4 py-2 bg-primary hover:bg-primary-hover text-white font-medium rounded-lg disabled:opacity-50 transition-colors shadow-sm"
            >
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              Verify & Establish Baseline
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};


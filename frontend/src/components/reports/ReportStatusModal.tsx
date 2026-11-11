import React, { useState } from "react";
import { X, CheckCircle, AlertCircle, RefreshCw } from "lucide-react";
import { ReportLifecycleStatus, VulnerabilityReportListItem, VulnerabilityReportDetail } from "../../types";
import { ReportStatusBadge } from "./ReportBadge";

interface ReportStatusModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: VulnerabilityReportListItem | VulnerabilityReportDetail | null;
  onUpdateStatus: (newStatus: ReportLifecycleStatus, reason: string) => Promise<void>;
}

export const ReportStatusModal: React.FC<ReportStatusModalProps> = ({
  isOpen,
  onClose,
  report,
  onUpdateStatus,
}) => {
  if (!isOpen || !report) return null;

  const [selectedStatus, setSelectedStatus] = useState<ReportLifecycleStatus>(report.status);
  const [reason, setReason] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const statusOptions: { value: ReportLifecycleStatus; label: string; desc: string }[] = [
    { value: "OPEN", label: "Open", desc: "Active finding discovered by automated testing." },
    { value: "IN_PROGRESS", label: "In Progress", desc: "Assigned to an engineer; patch under development." },
    { value: "FIXED", label: "Fixed", desc: "Remediation deployed to environment." },
    { value: "ACCEPTED_RISK", label: "Accepted Risk", desc: "Compensating controls active; residual risk accepted." },
    { value: "FALSE_POSITIVE", label: "False Positive", desc: "Reviewed and confirmed not an exploitable flaw." },
    { value: "REOPENED", label: "Reopened", desc: "Previously closed issue reproduced in regression testing." },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setIsSubmitting(true);
    try {
      await onUpdateStatus(selectedStatus, reason);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || err.message || "Failed to update status.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-lg overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">Update Report Status</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMsg && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="font-mono text-cyan-400 font-semibold">{report.report_id}</span>
              <ReportStatusBadge status={report.status} />
            </div>
            <p className="text-xs font-medium text-slate-200 line-clamp-2">{report.title}</p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Target Lifecycle Status
            </label>
            <div className="grid grid-cols-2 gap-2">
              {statusOptions.map((opt) => (
                <button
                  type="button"
                  key={opt.value}
                  onClick={() => setSelectedStatus(opt.value)}
                  className={`p-2.5 rounded-lg border text-left transition-all flex flex-col justify-between ${
                    selectedStatus === opt.value
                      ? "border-cyan-500 bg-cyan-950/20 shadow-sm"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span className="text-xs font-bold font-mono text-slate-100">{opt.label}</span>
                    {selectedStatus === opt.value && (
                      <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />
                    )}
                  </div>
                  <span className="text-[10px] text-slate-400 mt-1 line-clamp-2">{opt.desc}</span>
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Remediation Notes / Justification
            </label>
            <textarea
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Input sanitization patch PR #412 merged into release branch, or verified in staging environment..."
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Note: Updating status writes an immutable record to the audit trail and Feature 25 hash chain.
            </p>
          </div>

          {/* Footer Actions */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || selectedStatus === report.status}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Updating...</span>
                </>
              ) : (
                <span>Confirm Status Transition</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};


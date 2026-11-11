import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { ScopePolicyResponse, ScopeAuthorizeRequest } from "../../types";
import { ShieldCheck, AlertCircle, Calendar, UserCheck } from "lucide-react";

interface AuthorizationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthorize: (appId: string, payload: ScopeAuthorizeRequest) => Promise<void>;
  policy: ScopePolicyResponse | null;
}

export const AuthorizationModal: React.FC<AuthorizationModalProps> = ({
  isOpen,
  onClose,
  onAuthorize,
  policy,
}) => {
  const [authorizedBy, setAuthorizedBy] = useState<string>("");
  const [authorizerRole, setAuthorizerRole] = useState<string>("Application Security Lead");
  const [validDays, setValidDays] = useState<number>(30);
  const [notes, setNotes] = useState<string>("");
  const [isAffirmed, setIsAffirmed] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!policy) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorizedBy.trim()) {
      setError("Authorizer name and email are required.");
      return;
    }
    if (!isAffirmed) {
      setError("You must confirm formal authorization sign-off.");
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      await onAuthorize(policy.application_id, {
        authorized_by: authorizedBy.trim(),
        authorizer_role: authorizerRole.trim(),
        valid_days: Number(validDays),
        authorization_notes: notes.trim() || undefined,
      });
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Failed to grant testing authorization.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Formally Authorize Security Testing"
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
            disabled={isSubmitting || !isAffirmed}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded transition-colors disabled:opacity-50 flex items-center gap-1.5"
          >
            <ShieldCheck className="w-4 h-4" />
            {isSubmitting ? "Granting Authorization..." : "Confirm & Activate Scope"}
          </button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded text-rose-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="p-3 bg-slate-950 border border-slate-800 rounded text-xs space-y-1">
          <div className="text-slate-400">Target Application:</div>
          <div className="font-semibold text-slate-200">{policy.application_name || policy.target_domain}</div>
          <div className="text-slate-400 font-mono">{policy.base_url}</div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Authorizer Identity (Name & Corporate Email)
          </label>
          <input
            type="text"
            value={authorizedBy}
            onChange={(e) => setAuthorizedBy(e.target.value)}
            placeholder="Jane Doe (jane.doe@company.com)"
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Authorizer Role</label>
            <select
              value={authorizerRole}
              onChange={(e) => setAuthorizerRole(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="Application Security Lead">Application Security Lead</option>
              <option value="CISO / VP of Security">CISO / VP of Security</option>
              <option value="Product Owner / Engineering Lead">Product Owner / Engineering Lead</option>
              <option value="Compliance & Risk Officer">Compliance & Risk Officer</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Validity Window (Days)</label>
            <input
              type="number"
              min={1}
              max={365}
              value={validDays}
              onChange={(e) => setValidDays(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Authorization Notes / Jira Ticket / Change Request
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
            placeholder="e.g. Approved under SEC-4910 for annual SOC2 dynamic pen testing."
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <label className="flex items-start gap-3 cursor-pointer p-2.5 rounded bg-emerald-500/5 border border-emerald-500/20">
          <input
            type="checkbox"
            checked={isAffirmed}
            onChange={(e) => setIsAffirmed(e.target.checked)}
            className="rounded mt-0.5 bg-slate-950 border-emerald-700 text-emerald-500 focus:ring-0 focus:outline-none"
          />
          <div className="text-[11px] text-slate-300">
            <span className="font-semibold text-emerald-400 block mb-0.5">Formal Authorization Certification</span>
            I certify that explicit stakeholder permission has been granted to execute automated and dynamic security tests
            against this target within the configured bounds.
          </div>
        </label>
      </form>
    </Modal>
  );
};


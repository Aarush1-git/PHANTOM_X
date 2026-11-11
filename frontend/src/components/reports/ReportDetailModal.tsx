import React, { useState } from "react";
import {
  X,
  Shield,
  Download,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  Code2,
  FileCheck2,
  Lock,
} from "lucide-react";
import { VulnerabilityReportDetail, ReportLifecycleStatus } from "../../types";
import { ReportSeverityBadge, ReportStatusBadge, ReportCvssBadge } from "./ReportBadge";

interface ReportDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: VulnerabilityReportDetail | null;
  isLoading: boolean;
  onOpenStatusModal: () => void;
  onExportPdf: (reportId: string) => void;
  onExportJson: (reportId: string) => void;
}

export const ReportDetailModal: React.FC<ReportDetailModalProps> = ({
  isOpen,
  onClose,
  report,
  isLoading,
  onOpenStatusModal,
  onExportPdf,
  onExportJson,
}) => {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState<
    "overview" | "technical" | "reproduction" | "remediation" | "evidence" | "history"
  >("overview");

  const [copiedDump, setCopiedDump] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDump(id);
    setTimeout(() => setCopiedDump(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 md:p-6 bg-slate-950/85 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-start justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-cyan-400 font-bold text-xs px-2 py-0.5 rounded bg-cyan-950/50 border border-cyan-800/60">
                {report?.report_id || "LOADING"}
              </span>
              {report && <ReportSeverityBadge severity={report.severity} />}
              {report && <ReportCvssBadge score={report.cvss_score} />}
              {report?.cwe_id && (
                <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">
                  {report.cwe_id}
                </span>
              )}
              {report && <ReportStatusBadge status={report.status} />}
            </div>

            <h2 className="text-base md:text-lg font-bold text-slate-100 truncate">
              {report ? report.title : "Loading report details..."}
            </h2>

            <div className="flex items-center gap-3 text-xs text-slate-400 font-mono flex-wrap">
              <span>App: <strong className="text-slate-200">{report?.application_name || "Primary Gateway"}</strong></span>
              <span>•</span>
              <span className="flex items-center gap-1">
                Endpoint: <code className="text-cyan-300 font-bold">{report?.endpoint}</code>
              </span>
              <span>•</span>
              <span>Method: <strong className="text-slate-200">{report?.http_method || "GET"}</strong></span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 flex-shrink-0">
            {report && (
              <>
                <button
                  onClick={onOpenStatusModal}
                  className="px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-bold font-mono transition-colors flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Update Status</span>
                </button>

                <button
                  onClick={() => onExportPdf(report.report_id)}
                  className="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-bold font-mono transition-colors flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>PDF Report</span>
                </button>

                <button
                  onClick={() => onExportJson(report.report_id)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold font-mono transition-colors flex items-center gap-1.5 border border-slate-700"
                >
                  <FileCode className="w-3.5 h-3.5" />
                  <span>JSON</span>
                </button>
              </>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-6 border-b border-slate-800 bg-slate-950/30 overflow-x-auto text-xs font-mono">
          <button
            onClick={() => setActiveTab("overview")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "overview"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>1. Overview & Business Impact</span>
          </button>

          <button
            onClick={() => setActiveTab("technical")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "technical"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>2. Technical Behavior</span>
          </button>

          <button
            onClick={() => setActiveTab("reproduction")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "reproduction"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>3. Reproduction Steps</span>
          </button>

          <button
            onClick={() => setActiveTab("remediation")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "remediation"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>4. Remediation Playbook</span>
          </button>

          <button
            onClick={() => setActiveTab("evidence")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "evidence"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>5. Sanitized Evidence ({report?.evidences?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab("history")}
            className={`py-3 px-3.5 border-b-2 font-semibold transition-colors flex items-center gap-2 whitespace-nowrap ${
              activeTab === "history"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>6. Audit History ({report?.status_history?.length || 0})</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6 text-sm">
          {isLoading || !report ? (
            <div className="py-20 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              <p className="font-mono text-xs">Loading vulnerability report details...</p>
            </div>
          ) : (
            <>
              {/* TAB 1: OVERVIEW & BUSINESS IMPACT */}
              {activeTab === "overview" && (
                <div className="space-y-6">
                  {/* Executive Risk Box */}
                  <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      <span>Executive Risk Summary & Business Impact</span>
                    </div>
                    <p className="text-xs md:text-sm text-slate-200 leading-relaxed font-sans">
                      {report.business_impact}
                    </p>
                  </div>

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Severity Level</span>
                      <span className="text-slate-200 font-bold mt-1 block">{report.severity}</span>
                    </div>
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">CVSS Score</span>
                      <span className="text-slate-200 font-bold mt-1 block">
                        {report.cvss_score ? report.cvss_score.toFixed(1) : "Unassigned"}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">CWE Classification</span>
                      <span className="text-slate-200 font-bold mt-1 block">{report.cwe_id || "CWE Generic"}</span>
                    </div>
                    <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Lifecycle Status</span>
                      <span className="text-slate-200 font-bold mt-1 block">{report.status}</span>
                    </div>
                  </div>

                  {/* Technical Summary */}
                  <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 space-y-2 font-mono text-xs">
                    <h4 className="text-xs font-bold text-slate-300 uppercase">Assessment Details</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-400">
                      <div>Target Resource: <code className="text-cyan-300">{report.endpoint}</code></div>
                      <div>Method: <strong className="text-slate-200">{report.http_method}</strong></div>
                      <div>Vulnerability ID: <span className="text-slate-300">{report.vulnerability_id}</span></div>
                      <div>Discovered: <span className="text-slate-300">{new Date(report.created_at).toUTCString()}</span></div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: TECHNICAL BEHAVIOR */}
              {activeTab === "technical" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Expected Security Baseline */}
                    <div className="p-4 rounded-xl bg-emerald-950/10 border border-emerald-500/20 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Expected Security Baseline</span>
                      </div>
                      <p className="text-xs md:text-sm text-slate-300 leading-relaxed font-sans">
                        {report.expected_behavior}
                      </p>
                    </div>

                    {/* Observed Vulnerable Behavior */}
                    <div className="p-4 rounded-xl bg-red-950/10 border border-red-500/20 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-bold text-red-400 uppercase tracking-wider font-mono">
                        <AlertTriangle className="w-4 h-4" />
                        <span>Observed Vulnerable Behavior</span>
                      </div>
                      <p className="text-xs md:text-sm text-slate-300 leading-relaxed font-sans">
                        {report.actual_behavior}
                      </p>
                    </div>
                  </div>

                  {/* Technical Parameters */}
                  {report.technical_details && (
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2 font-mono text-xs">
                      <span className="text-xs font-bold text-slate-300 uppercase">Extracted Technical Parameters</span>
                      <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-cyan-300 overflow-x-auto text-xs leading-relaxed">
                        {JSON.stringify(report.technical_details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: REPRODUCTION STEPS */}
              {activeTab === "reproduction" && (
                <div className="space-y-4">
                  <div className="p-3 bg-cyan-950/20 border border-cyan-800/40 rounded-lg text-xs text-cyan-300 font-mono">
                    Ordered reproduction instructions generated from automated dynamic testing execution.
                    Sensitive tokens and passwords have been automatically sanitized.
                  </div>

                  <div className="space-y-2.5">
                    {report.reproduction_steps && report.reproduction_steps.length > 0 ? (
                      report.reproduction_steps.map((step, idx) => (
                        <div
                          key={idx}
                          className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start gap-3"
                        >
                          <span className="flex-shrink-0 w-6 h-6 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono font-bold text-xs flex items-center justify-center">
                            {idx + 1}
                          </span>
                          <span className="text-xs md:text-sm text-slate-200 font-sans leading-relaxed">
                            {step}
                          </span>
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-slate-500 italic">No reproduction steps recorded.</p>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 4: REMEDIATION PLAYBOOK */}
              {activeTab === "remediation" && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">
                      <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                      <span>Recommended Developer Remediation Playbook</span>
                    </div>
                    <p className="text-xs md:text-sm text-slate-200 leading-relaxed font-sans whitespace-pre-line">
                      {report.remediation_advice}
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-amber-950/10 border border-amber-500/20 text-xs text-amber-300 font-mono space-y-1">
                    <span className="font-bold uppercase tracking-wider block">Important Verification Standard:</span>
                    <p className="text-slate-400 font-sans">
                      Marking this report as FIXED indicates developer implementation. True security closure requires subsequent
                      automated verification or Time-Travel regression testing against the patched endpoint.
                    </p>
                  </div>
                </div>
              )}

              {/* TAB 5: SANITIZED EVIDENCE */}
              {activeTab === "evidence" && (
                <div className="space-y-4">
                  <div className="p-3 bg-emerald-950/20 border border-emerald-800/40 rounded-lg text-xs text-emerald-300 font-mono flex items-center gap-2">
                    <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <span>
                      Secret Scrubbing Active: Bearer tokens, cookies, passwords, and private keys have been recursively masked with [REDACTED] tokens.
                    </span>
                  </div>

                  {report.evidences && report.evidences.length > 0 ? (
                    report.evidences.map((ev, idx) => (
                      <div
                        key={ev.id || idx}
                        className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden space-y-3 p-4"
                      >
                        <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800 pb-2">
                          <span className="font-bold text-slate-200">Evidence Record #{idx + 1}</span>
                          <span>ID: {ev.id}</span>
                        </div>

                        {/* Request Dump */}
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[11px] font-mono text-slate-400 font-semibold uppercase">
                              HTTP Request Dump (Sanitized)
                            </span>
                            <button
                              onClick={() => handleCopy(ev.request_dump, `req-${idx}`)}
                              className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
                            >
                              {copiedDump === `req-${idx}` ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy Request</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-48">
                            {ev.request_dump}
                          </pre>
                        </div>

                        {/* Response Dump */}
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[11px] font-mono text-slate-400 font-semibold uppercase">
                              HTTP Response Dump (Sanitized)
                            </span>
                            <button
                              onClick={() => handleCopy(ev.response_dump, `resp-${idx}`)}
                              className="text-[10px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
                            >
                              {copiedDump === `resp-${idx}` ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy Response</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                            {ev.response_dump}
                          </pre>
                        </div>

                        {/* Proof Data */}
                        {ev.proof_data && Object.keys(ev.proof_data).length > 0 && (
                          <div>
                            <span className="text-[11px] font-mono text-slate-400 font-semibold uppercase block mb-1">
                              Extracted Proof Indicators
                            </span>
                            <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                              {JSON.stringify(ev.proof_data, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-6 text-center text-slate-500 font-mono text-xs">
                      No raw evidence payloads linked to this finding.
                    </div>
                  )}
                </div>
              )}

              {/* TAB 6: STATUS AUDIT HISTORY */}
              {activeTab === "history" && (
                <div className="space-y-4">
                  <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg text-xs text-slate-400 font-mono flex items-center justify-between">
                    <span>Tamper-evident status history linked to Feature 25 cryptographic hash chain.</span>
                    <button
                      onClick={onOpenStatusModal}
                      className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition-colors"
                    >
                      + Transition Status
                    </button>
                  </div>

                  <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800 font-mono text-xs">
                    {report.status_history && report.status_history.length > 0 ? (
                      report.status_history.map((hist, idx) => (
                        <div key={hist.id || idx} className="relative space-y-1">
                          <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-900" />
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-slate-400">{hist.from_status}</span>
                            <span className="text-cyan-400">&rarr;</span>
                            <ReportStatusBadge status={hist.to_status} />
                            <span className="text-slate-500 text-[11px]">
                              by {hist.changed_by_email || "System"} on{" "}
                              {new Date(hist.created_at).toUTCString()}
                            </span>
                          </div>
                          {hist.reason && (
                            <p className="text-slate-300 text-xs font-sans bg-slate-950/60 p-2.5 rounded border border-slate-800 mt-1">
                              {hist.reason}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (
                      <p className="text-slate-500 text-xs">No status change history recorded.</p>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};


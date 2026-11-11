import React, { useState } from 'react';
import { X, Clock, Shield, AlertTriangle, FileText, CheckCircle2, Terminal, ExternalLink } from 'lucide-react';
import { ScanDetailResponse } from '../../types/scanHistory';

interface Props {
  detail: ScanDetailResponse | null;
  isOpen: boolean;
  onClose: () => void;
  isLoading?: boolean;
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-950/70', text: 'text-red-400', border: 'border-red-800/80' },
  HIGH: { bg: 'bg-orange-950/70', text: 'text-orange-400', border: 'border-orange-800/80' },
  MEDIUM: { bg: 'bg-amber-950/70', text: 'text-amber-400', border: 'border-amber-800/80' },
  LOW: { bg: 'bg-blue-950/70', text: 'text-blue-400', border: 'border-blue-800/80' },
  INFO: { bg: 'bg-slate-800/70', text: 'text-slate-400', border: 'border-slate-700/80' },
};

export const ScanDetailsPanel: React.FC<Props> = ({
  detail,
  isOpen,
  onClose,
  isLoading = false,
}) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'evidence'>('findings');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-semibold text-slate-100">
                {detail ? detail.scan.application_name : 'Scan Details'}
              </h3>
            </div>
            {detail && (
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-md">
                Scan ID: {detail.scan.id}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        {isLoading || !detail ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500" />
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-6">
            {/* Metadata Summary Banner */}
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-slate-500 block">Status</span>
                <span className="font-semibold text-slate-200 font-mono">{detail.scan.status}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Duration</span>
                <span className="font-semibold text-slate-200 font-mono">
                  {detail.scan.duration_seconds ? `${detail.scan.duration_seconds}s` : '—'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Total Findings</span>
                <span className="font-semibold text-slate-200 font-mono">{detail.scan.total_vulnerabilities}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Target URL</span>
                <span className="font-semibold text-slate-200 font-mono truncate block" title={detail.scan.target_url}>
                  {detail.scan.target_url}
                </span>
              </div>
            </div>

            {/* Severity Pill Counters */}
            <div className="grid grid-cols-4 gap-2">
              <div className="bg-red-950/30 border border-red-900/40 rounded-lg p-2.5 text-center">
                <span className="text-[11px] text-red-400 font-medium block">Critical</span>
                <span className="text-lg font-bold text-red-300 font-mono">{detail.scan.critical_count}</span>
              </div>
              <div className="bg-orange-950/30 border border-orange-900/40 rounded-lg p-2.5 text-center">
                <span className="text-[11px] text-orange-400 font-medium block">High</span>
                <span className="text-lg font-bold text-orange-300 font-mono">{detail.scan.high_count}</span>
              </div>
              <div className="bg-amber-950/30 border border-amber-900/40 rounded-lg p-2.5 text-center">
                <span className="text-[11px] text-amber-400 font-medium block">Medium</span>
                <span className="text-lg font-bold text-amber-300 font-mono">{detail.scan.medium_count}</span>
              </div>
              <div className="bg-blue-950/30 border border-blue-900/40 rounded-lg p-2.5 text-center">
                <span className="text-[11px] text-blue-400 font-medium block">Low</span>
                <span className="text-lg font-bold text-blue-300 font-mono">{detail.scan.low_count}</span>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 gap-4 text-sm">
              <button
                onClick={() => setActiveTab('findings')}
                className={`pb-2 font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
                  activeTab === 'findings'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertTriangle className="w-4 h-4" />
                Vulnerabilities ({detail.vulnerabilities.length})
              </button>
              <button
                onClick={() => setActiveTab('evidence')}
                className={`pb-2 font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
                  activeTab === 'evidence'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-4 h-4" />
                Evidence Records ({detail.evidence_items.length})
              </button>
            </div>

            {/* Tab: Findings List */}
            {activeTab === 'findings' && (
              <div className="space-y-3">
                {detail.vulnerabilities.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800">
                    <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
                    No vulnerabilities were recorded for this scan.
                  </div>
                ) : (
                  detail.vulnerabilities.map((vuln) => {
                    const sevCfg = SEVERITY_COLORS[vuln.severity] || SEVERITY_COLORS.INFO;
                    return (
                      <div
                        key={vuln.id}
                        className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-2 hover:border-slate-700/80 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <h4 className="font-semibold text-slate-200 text-sm">{vuln.title}</h4>
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${sevCfg.bg} ${sevCfg.text} ${sevCfg.border}`}
                          >
                            {vuln.severity}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-cyan-400 bg-slate-900/90 px-2 py-1 rounded inline-block">
                          {vuln.endpoint}
                        </div>
                        {vuln.cwe_id && (
                          <div className="text-xs text-slate-400 flex items-center gap-2">
                            <span className="font-mono bg-slate-800 px-1.5 py-0.5 rounded text-[10px] text-slate-300">
                              {vuln.cwe_id}
                            </span>
                            {vuln.cvss_score && (
                              <span>CVSS Score: <span className="font-semibold text-slate-200">{vuln.cvss_score}</span></span>
                            )}
                          </div>
                        )}
                        {vuln.recommendation && (
                          <p className="text-xs text-slate-400 border-l-2 border-cyan-500/50 pl-2 italic mt-1">
                            {vuln.recommendation}
                          </p>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            )}

            {/* Tab: Evidence References */}
            {activeTab === 'evidence' && (
              <div className="space-y-3">
                {detail.evidence_items.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800">
                    <FileText className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    No sanitized evidence records attached to this scan.
                  </div>
                ) : (
                  detail.evidence_items.map((ev) => (
                    <div
                      key={ev.id}
                      className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-slate-300 flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          Evidence Reference
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">ID: {ev.id}</span>
                      </div>
                      <p className="text-slate-400">{ev.summary || 'Sanitized proof of exploitability'}</p>
                      <div className="flex items-center gap-3 pt-1 text-[11px] text-slate-400">
                        <span>Request Dump: <strong className={ev.has_request_dump ? 'text-emerald-400' : 'text-slate-500'}>{ev.has_request_dump ? 'Yes' : 'No'}</strong></span>
                        <span>Response Dump: <strong className={ev.has_response_dump ? 'text-emerald-400' : 'text-slate-500'}>{ev.has_response_dump ? 'Yes' : 'No'}</strong></span>
                        <span>Screenshot: <strong className={ev.has_screenshot ? 'text-emerald-400' : 'text-slate-500'}>{ev.has_screenshot ? 'Yes' : 'No'}</strong></span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

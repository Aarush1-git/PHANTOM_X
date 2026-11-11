import React, { useState } from 'react';
import {
  FileCode,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Terminal,
  ShieldCheck,
} from 'lucide-react';

interface EvidenceViewerProps {
  evidence: Record<string, any>;
  isSynthetic?: boolean;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({
  evidence,
  isSynthetic = false,
}) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  const reqDump = evidence?.request_dump || '// No request dump recorded';
  const respDump = evidence?.response_dump || '// No response dump recorded';

  const handleCopy = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden space-y-0">
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="px-4 py-3 bg-slate-950/60 flex items-center justify-between cursor-pointer hover:bg-slate-950/80 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Observed Execution Evidence & HTTP Probes
          </h4>
          {isSynthetic && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Synthetic Simulation
            </span>
          )}
        </div>
        <button type="button" className="text-slate-400 hover:text-slate-200">
          {isExpanded ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </button>
      </div>

      {isExpanded && (
        <div className="p-4 space-y-4">
          {/* Request Dump */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-semibold text-slate-400">
                DISPATCHED HTTP REQUEST
              </span>
              <button
                type="button"
                onClick={() => handleCopy(reqDump, 'request')}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-400 transition-colors"
              >
                {copiedSection === 'request' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" /> Copy Request
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-cyan-300/90 whitespace-pre-wrap break-all overflow-x-auto max-h-48 overflow-y-auto">
              {reqDump}
            </pre>
          </div>

          {/* Response Dump */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-semibold text-slate-400">
                RETURNED HTTP RESPONSE
              </span>
              <button
                type="button"
                onClick={() => handleCopy(respDump, 'response')}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-400 transition-colors"
              >
                {copiedSection === 'response' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" /> Copy Response
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-emerald-300/90 whitespace-pre-wrap break-all overflow-x-auto max-h-48 overflow-y-auto">
              {respDump}
            </pre>
          </div>

          {evidence?.simulated_tenant_leakage && (
            <div className="p-2.5 bg-red-950/20 border border-red-500/30 rounded-lg text-xs text-red-300">
              <strong>Tenant Leakage Proof: </strong>
              {evidence.simulated_tenant_leakage}
            </div>
          )}

          {evidence?.vulnerability_proof && (
            <div className="p-2.5 bg-amber-950/20 border border-amber-500/30 rounded-lg text-xs text-amber-300">
              <strong>Proof of Weakness: </strong>
              {evidence.vulnerability_proof}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

import React from "react";
import { FileText, Download, ShieldCheck, Printer } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";

export const ReportsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Intelligence Reports (Member 4)"
        description="Generate executive compliance summaries, OWASP Top 10 API risk matrices, and developer remediation playbooks."
        actions={
          <button
            onClick={() => alert("Report generation triggered.")}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export PDF Report</span>
          </button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="p-2 rounded bg-cyan-500/10 text-cyan-400 w-fit mb-3">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Executive DAST Summary</h3>
            <p className="text-xs text-slate-400 mt-1">High-level risk posture and exploit chain overview for engineering leaders.</p>
          </div>
          <button
            onClick={() => alert("Executive report export ready.")}
            className="mt-4 text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
          >
            Generate Summary &rarr;
          </button>
        </div>

        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="p-2 rounded bg-emerald-500/10 text-emerald-400 w-fit mb-3">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-100">OWASP API Security Top 10 Matrix</h3>
            <p className="text-xs text-slate-400 mt-1">Comprehensive compliance mapping against 2023 API security standards.</p>
          </div>
          <button
            onClick={() => alert("OWASP compliance export ready.")}
            className="mt-4 text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
          >
            Generate Matrix &rarr;
          </button>
        </div>

        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="p-2 rounded bg-amber-500/10 text-amber-400 w-fit mb-3">
              <Printer className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Developer Remediation Guide</h3>
            <p className="text-xs text-slate-400 mt-1">Code-level remediation steps and patch validation tests.</p>
          </div>
          <button
            onClick={() => alert("Remediation playbook export ready.")}
            className="mt-4 text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
          >
            Generate Playbook &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};


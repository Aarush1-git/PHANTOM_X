import React, { useState } from 'react';
import {
  CheckSquare,
  Copy,
  Check,
  Code2,
  FileText,
  PlayCircle,
  ExternalLink,
  HelpCircle,
  Wrench,
} from 'lucide-react';
import { RemediationRecommendationDetail } from '../../types/remediation';

interface RemediationStepsProps {
  recommendation: RemediationRecommendationDetail;
  onOpenPlayground?: (scenarioId: string) => void;
}

export const RemediationSteps: React.FC<RemediationStepsProps> = ({
  recommendation,
  onOpenPlayground,
}) => {
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const handleCopyCode = () => {
    if (recommendation.suggested_fix_snippet) {
      navigator.clipboard.writeText(recommendation.suggested_fix_snippet);
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Developer Action Items */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Wrench className="w-5 h-5 text-indigo-400" />
          <h4 className="text-sm font-semibold text-white tracking-wide uppercase">
            Developer Action Items (Step-by-Step Fix)
          </h4>
        </div>
        <ol className="space-y-3">
          {recommendation.remediation_steps.map((step, idx) => (
            <li key={idx} className="flex items-start gap-3">
              <span className="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-xs font-bold flex items-center justify-center mt-0.5">
                {idx + 1}
              </span>
              <span className="text-sm text-slate-300 leading-relaxed">{step}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* 2. Suggested Code Fix Pattern */}
      {recommendation.suggested_fix_snippet && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/80 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-medium text-slate-300">
                Recommended Defensive Code Pattern
              </span>
            </div>
            <button
              onClick={handleCopyCode}
              className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
            >
              {copiedSnippet ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Snippet</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-4 text-xs font-mono text-cyan-200/90 overflow-x-auto bg-slate-950/90 leading-relaxed">
            {recommendation.suggested_fix_snippet}
          </pre>
        </div>
      )}

      {/* 3. Verification & Validation Procedures */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-emerald-400" />
            <h4 className="text-sm font-semibold text-white tracking-wide uppercase">
              Verification & Validation Procedures
            </h4>
          </div>
          {recommendation.suggested_playground_scenario_id && onOpenPlayground && (
            <button
              onClick={() =>
                onOpenPlayground(recommendation.suggested_playground_scenario_id!)
              }
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-medium transition-colors"
            >
              <PlayCircle className="w-3.5 h-3.5" />
              <span>Simulate in Playground ({recommendation.suggested_playground_scenario_id})</span>
            </button>
          )}
        </div>
        <ul className="space-y-2.5">
          {recommendation.validation_steps.map((valStep, idx) => (
            <li key={idx} className="flex items-start gap-2.5 text-sm text-slate-300">
              <span className="text-emerald-400 font-bold mt-0.5">•</span>
              <span>{valStep}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};


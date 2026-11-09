import React from "react";
import { VulnerabilitySeverity, ScanStatus, VulnerabilityStatus } from "../../types";

interface SeverityBadgeProps {
  severity: VulnerabilitySeverity | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const styles: Record<string, string> = {
    CRITICAL: "bg-rose-500/10 text-rose-400 border-rose-500/20",
    HIGH: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    MEDIUM: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    LOW: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    INFO: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  };

  const style = styles[severity.toUpperCase()] || styles.INFO;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${style}`}>
      {severity.toUpperCase()}
    </span>
  );
};

interface StatusBadgeProps {
  status: ScanStatus | VulnerabilityStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const styles: Record<string, string> = {
    RUNNING: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20 animate-pulse",
    COMPLETED: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    FAILED: "bg-rose-500/10 text-rose-400 border-rose-500/20",
    QUEUED: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    VERIFIED: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    DISCOVERED: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    ACTIVE: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };

  const style = styles[status.toUpperCase()] || "bg-slate-500/10 text-slate-400 border-slate-500/20";

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${style}`}>
      {status.toUpperCase()}
    </span>
  );
};


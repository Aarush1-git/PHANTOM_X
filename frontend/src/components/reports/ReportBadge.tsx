import React from "react";

interface SeverityBadgeProps {
  severity?: string;
  className?: string;
}

export const ReportSeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = "" }) => {
  const styles: Record<string, string> = {
    CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    LOW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    INFO: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };

  const style = styles[severity?.toUpperCase() || ""] || styles.INFO;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider border ${style} ${className}`}
    >
      {severity || "INFO"}
    </span>
  );
};

interface StatusBadgeProps {
  status?: string;
  className?: string;
}

export const ReportStatusBadge: React.FC<StatusBadgeProps> = ({ status, className = "" }) => {
  const styles: Record<string, string> = {
    OPEN: "bg-red-500/10 text-red-400 border-red-500/30",
    IN_PROGRESS: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
    FIXED: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    ACCEPTED_RISK: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    FALSE_POSITIVE: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    REOPENED: "bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse",
  };

  const style = styles[status?.toUpperCase() || ""] || styles.OPEN;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider border ${style} ${className}`}
    >
      {status || "OPEN"}
    </span>
  );
};

interface CvssBadgeProps {
  score?: number | null;
}

export const ReportCvssBadge: React.FC<CvssBadgeProps> = ({ score }) => {
  if (score === null || score === undefined) {
    return <span className="text-xs text-slate-500 font-mono">N/A</span>;
  }

  let colorClass = "bg-slate-800 text-slate-300 border-slate-700";
  if (score >= 9.0) {
    colorClass = "bg-red-500/15 text-red-400 border-red-500/30";
  } else if (score >= 7.0) {
    colorClass = "bg-orange-500/15 text-orange-400 border-orange-500/30";
  } else if (score >= 4.0) {
    colorClass = "bg-amber-500/15 text-amber-400 border-amber-500/30";
  } else {
    colorClass = "bg-blue-500/15 text-blue-400 border-blue-500/30";
  }

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${colorClass}`}
    >
      CVSS {score.toFixed(1)}
    </span>
  );
};


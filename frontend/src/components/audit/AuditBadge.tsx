import React from "react";

interface CategoryBadgeProps {
  category?: string;
}

export const AuditCategoryBadge: React.FC<CategoryBadgeProps> = ({ category }) => {
  const styles: Record<string, string> = {
    AUTHENTICATION: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    APPLICATION_MANAGEMENT: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30",
    AUTHORIZATION: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    SECURITY_TESTING: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    VULNERABILITY: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    PLATFORM: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  };

  const style = styles[category?.toUpperCase() || ""] || styles.PLATFORM;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${style}`}>
      {category || "GENERAL"}
    </span>
  );
};

interface StatusBadgeProps {
  status?: string;
}

export const AuditStatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const styles: Record<string, string> = {
    SUCCESS: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    FAILURE: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    BLOCKED: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    PENDING: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse",
    CANCELLED: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  };

  const style = styles[status?.toUpperCase() || ""] || styles.SUCCESS;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${style}`}>
      {status || "SUCCESS"}
    </span>
  );
};

interface SeverityBadgeProps {
  severity?: string;
}

export const AuditSeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const styles: Record<string, string> = {
    CRITICAL: "bg-rose-600/20 text-rose-300 border-rose-500/50 font-bold",
    HIGH: "bg-rose-500/10 text-rose-400 border-rose-500/30 font-semibold",
    MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    LOW: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    INFO: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  };

  const style = styles[severity?.toUpperCase() || ""] || styles.INFO;

  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono border ${style}`}>
      {severity || "INFO"}
    </span>
  );
};


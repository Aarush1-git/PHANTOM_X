import React from "react";
import { ScopeStatus, AuthorizationStatus } from "../../types";

interface ScopeStatusBadgeProps {
  status: ScopeStatus | string;
}

export const ScopeStatusBadge: React.FC<ScopeStatusBadgeProps> = ({ status }) => {
  const styles: Record<string, string> = {
    ACTIVE: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    DRAFT: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    SUSPENDED: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    EXPIRED: "bg-rose-500/10 text-rose-400 border-rose-500/30",
  };

  const style = styles[status?.toUpperCase()] || styles.DRAFT;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${style}`}>
      SCOPE: {status?.toUpperCase()}
    </span>
  );
};

interface AuthorizationStatusBadgeProps {
  status: AuthorizationStatus | string;
}

export const AuthorizationStatusBadge: React.FC<AuthorizationStatusBadgeProps> = ({ status }) => {
  const styles: Record<string, string> = {
    AUTHORIZED: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    PENDING: "bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse",
    REVOKED: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    EXPIRED: "bg-red-500/10 text-red-400 border-red-500/30",
  };

  const style = styles[status?.toUpperCase()] || styles.PENDING;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${style}`}>
      AUTH: {status?.toUpperCase()}
    </span>
  );
};


import React from 'react';
import { ShieldCheck, AlertTriangle, Clock, Activity, CheckCircle2 } from 'lucide-react';
import { RemediationOverviewResponse } from '../../types/remediation';

interface RemediationOverviewProps {
  overview: RemediationOverviewResponse | null;
  loading?: boolean;
}

export const RemediationOverview: React.FC<RemediationOverviewProps> = ({ overview, loading }) => {
  if (loading || !overview) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 animate-pulse">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-24 bg-slate-800/50 rounded-xl border border-slate-700/50" />
        ))}
      </div>
    );
  }

  const cards = [
    {
      label: 'Total Recommendations',
      value: overview.total_recommendations,
      sub: `${overview.by_status.GENERATED} awaiting triage`,
      icon: <Activity className="w-5 h-5 text-indigo-400" />,
      border: 'border-indigo-500/20',
      bg: 'from-indigo-500/10 to-transparent',
    },
    {
      label: 'Average Risk Score',
      value: `${overview.average_risk_score.toFixed(1)}/100`,
      sub: `${overview.by_priority.CRITICAL} Critical, ${overview.by_priority.HIGH} High`,
      icon: <AlertTriangle className="w-5 h-5 text-rose-400" />,
      border: 'border-rose-500/20',
      bg: 'from-rose-500/10 to-transparent',
    },
    {
      label: 'Remediation In Progress',
      value: overview.in_progress_count,
      sub: `${overview.by_status.ACCEPTED} Accepted in backlog`,
      icon: <Clock className="w-5 h-5 text-amber-400" />,
      border: 'border-amber-500/20',
      bg: 'from-amber-500/10 to-transparent',
    },
    {
      label: 'Empirically Verified',
      value: overview.verified_count,
      sub: `${overview.pending_verification_count} pending verification`,
      icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
      border: 'border-emerald-500/20',
      bg: 'from-emerald-500/10 to-transparent',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => (
        <div
          key={idx}
          className={`relative p-5 rounded-xl border ${card.border} bg-gradient-to-br ${card.bg} bg-slate-900/60 backdrop-blur-sm transition-all hover:border-slate-600`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              {card.label}
            </span>
            <div className="p-2 rounded-lg bg-slate-800/80 border border-slate-700/60">
              {card.icon}
            </div>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">{card.value}</div>
          <p className="mt-1 text-xs text-slate-400">{card.sub}</p>
        </div>
      ))}
    </div>
  );
};


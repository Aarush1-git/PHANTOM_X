import React from 'react';
import { ShieldCheck, AlertTriangle, HelpCircle, Layers, CheckCircle2, Archive } from 'lucide-react';
import { TimeTravelOverviewResponse } from '../../types/timeTravel';

interface BaselineOverviewProps {
  overview: TimeTravelOverviewResponse | null;
  loading: boolean;
}

export const BaselineOverview: React.FC<BaselineOverviewProps> = ({ overview, loading }) => {
  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-24 bg-surface/50 border border-border/60 rounded-xl animate-pulse" />
        ))}
      </div>
    );
  }

  const stats = [
    {
      label: 'Verified Invariants',
      value: overview?.verified_baselines ?? 0,
      icon: ShieldCheck,
      color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
      description: 'Confirmed protected fixes',
    },
    {
      label: 'Active Baselines',
      value: overview?.active_baselines ?? 0,
      icon: Layers,
      color: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
      description: 'Monitored across scans',
    },
    {
      label: 'Regressions Detected',
      value: overview?.regressions_detected ?? 0,
      icon: AlertTriangle,
      color:
        (overview?.regressions_detected ?? 0) > 0
          ? 'text-rose-400 bg-rose-500/10 border-rose-500/30 font-semibold'
          : 'text-slate-400 bg-slate-500/10 border-slate-500/20',
      description: 'Reappeared vulnerabilities',
    },
    {
      label: 'Inconclusive Matches',
      value: overview?.inconclusive_evaluations ?? 0,
      icon: HelpCircle,
      color:
        (overview?.inconclusive_evaluations ?? 0) > 0
          ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
          : 'text-slate-400 bg-slate-500/10 border-slate-500/20',
      description: 'Ambiguous candidates',
    },
    {
      label: 'Affected Apps',
      value: overview?.affected_applications_count ?? 0,
      icon: CheckCircle2,
      color: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
      description: 'With regression alerts',
    },
    {
      label: 'Retired Baselines',
      value: overview?.retired_baselines ?? 0,
      icon: Archive,
      color: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20',
      description: 'Preserved historical records',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {stats.map((stat, idx) => {
        const Icon = stat.icon;
        return (
          <div
            key={idx}
            className="p-4 bg-surface border border-border/80 rounded-xl hover:border-border transition-all flex flex-col justify-between"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-text-muted font-medium">{stat.label}</span>
              <div className={`p-1.5 rounded-lg border ${stat.color}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold text-text-primary tracking-tight">{stat.value}</div>
              <p className="text-[11px] text-text-muted mt-1 truncate">{stat.description}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
};


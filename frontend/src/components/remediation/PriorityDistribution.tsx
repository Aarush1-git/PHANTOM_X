import React from 'react';
import { ShieldAlert, AlertCircle, AlertTriangle, Info, CheckCircle } from 'lucide-react';
import { PriorityCountBreakdown, RemediationPriority } from '../../types/remediation';

interface PriorityDistributionProps {
  distribution: PriorityCountBreakdown;
  selectedPriority?: RemediationPriority | null;
  onSelectPriority: (priority: RemediationPriority | null) => void;
}

export const PriorityDistribution: React.FC<PriorityDistributionProps> = ({
  distribution,
  selectedPriority,
  onSelectPriority,
}) => {
  const tiers: {
    key: RemediationPriority;
    label: string;
    count: number;
    color: string;
    activeBorder: string;
    icon: React.ReactNode;
  }[] = [
    {
      key: 'CRITICAL',
      label: 'Critical Priority (≥75)',
      count: distribution.CRITICAL,
      color: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
      activeBorder: 'ring-2 ring-rose-500 border-rose-500',
      icon: <ShieldAlert className="w-4 h-4 text-rose-400" />,
    },
    {
      key: 'HIGH',
      label: 'High Priority (55-74)',
      count: distribution.HIGH,
      color: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
      activeBorder: 'ring-2 ring-orange-500 border-orange-500',
      icon: <AlertTriangle className="w-4 h-4 text-orange-400" />,
    },
    {
      key: 'MEDIUM',
      label: 'Medium Priority (35-54)',
      count: distribution.MEDIUM,
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
      activeBorder: 'ring-2 ring-amber-500 border-amber-500',
      icon: <AlertCircle className="w-4 h-4 text-amber-400" />,
    },
    {
      key: 'LOW',
      label: 'Low Priority (15-34)',
      count: distribution.LOW,
      color: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
      activeBorder: 'ring-2 ring-blue-500 border-blue-500',
      icon: <Info className="w-4 h-4 text-blue-400" />,
    },
    {
      key: 'INFORMATIONAL',
      label: 'Informational (<15)',
      count: distribution.INFORMATIONAL,
      color: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
      activeBorder: 'ring-2 ring-slate-400 border-slate-400',
      icon: <CheckCircle className="w-4 h-4 text-slate-400" />,
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {tiers.map((tier) => {
        const isSelected = selectedPriority === tier.key;
        return (
          <button
            key={tier.key}
            onClick={() => onSelectPriority(isSelected ? null : tier.key)}
            className={`p-3.5 rounded-xl border text-left transition-all ${tier.color} ${
              isSelected ? tier.activeBorder : 'hover:border-slate-500/50'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold">{tier.label.split(' ')[0]}</span>
              {tier.icon}
            </div>
            <div className="mt-2 text-2xl font-bold text-white">{tier.count}</div>
            <div className="text-[11px] opacity-75 mt-0.5">{tier.label}</div>
          </button>
        );
      })}
    </div>
  );
};


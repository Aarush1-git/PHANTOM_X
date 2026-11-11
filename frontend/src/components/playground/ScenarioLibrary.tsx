import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Info,
  Play,
  CheckCircle2,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { ScenarioInfo } from '../../types/playground';

interface ScenarioLibraryProps {
  scenarios: ScenarioInfo[];
  categories: string[];
  selectedScenario: ScenarioInfo | null;
  onSelectScenario: (scenario: ScenarioInfo) => void;
  onViewDetails: (scenario: ScenarioInfo) => void;
}

export const ScenarioLibrary: React.FC<ScenarioLibraryProps> = ({
  scenarios,
  categories,
  selectedScenario,
  onSelectScenario,
  onViewDetails,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredScenarios = scenarios.filter((s) => {
    const matchesCategory =
      selectedCategory === 'ALL' ||
      s.category.toLowerCase() === selectedCategory.toLowerCase();
    const matchesSearch =
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const getRiskBadge = (risk: string) => {
    switch (risk.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-4">
      {/* Search and Category Filter Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search attack scenarios by name, category, or objective..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto pb-1 md:pb-0">
          <button
            onClick={() => setSelectedCategory('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
              selectedCategory === 'ALL'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            All Categories ({scenarios.length})
          </button>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                selectedCategory.toLowerCase() === cat.toLowerCase()
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredScenarios.map((scenario) => {
          const isSelected = selectedScenario?.id === scenario.id;
          return (
            <div
              key={scenario.id}
              className={`border rounded-xl p-4 transition-all flex flex-col justify-between ${
                isSelected
                  ? 'bg-cyan-950/20 border-cyan-500/50 shadow-lg shadow-cyan-950/30'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-slate-800 text-slate-300">
                      {scenario.id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-semibold border ${getRiskBadge(
                        scenario.risk_level
                      )}`}
                    >
                      {scenario.risk_level}
                    </span>
                  </div>
                  {scenario.is_synthetic_compatible && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      <Zap className="w-3 h-3" /> Synthetic Lab Ready
                    </span>
                  )}
                </div>

                <h4 className="text-sm font-semibold text-slate-100 mb-1">
                  {scenario.name}
                </h4>
                <p className="text-xs text-slate-400 mb-3 line-clamp-2">
                  {scenario.description}
                </p>

                <div className="space-y-1 mb-3">
                  <div className="text-[11px] text-slate-400">
                    <span className="font-semibold text-slate-300">Objective: </span>
                    {scenario.security_objective}
                  </div>
                  {scenario.target_endpoints && scenario.target_endpoints.length > 0 && (
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      <span className="font-sans font-semibold text-slate-300">Target: </span>
                      {scenario.target_endpoints.join(', ')}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-800/80 mt-2">
                <button
                  type="button"
                  onClick={() => onViewDetails(scenario)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-cyan-400 transition-colors"
                >
                  <Info className="w-3.5 h-3.5" /> View Details
                </button>

                <button
                  type="button"
                  onClick={() => onSelectScenario(scenario)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isSelected
                      ? 'bg-cyan-500 text-white shadow-sm'
                      : 'bg-slate-800 text-slate-200 hover:bg-slate-700'
                  }`}
                >
                  {isSelected ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" /> Selected
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" /> Select Scenario
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {filteredScenarios.length === 0 && (
        <div className="text-center py-12 bg-slate-900/40 border border-slate-800 rounded-xl">
          <AlertTriangle className="w-8 h-8 text-slate-500 mx-auto mb-2" />
          <p className="text-sm text-slate-400">No attack scenarios match your filter criteria.</p>
        </div>
      )}
    </div>
  );
};

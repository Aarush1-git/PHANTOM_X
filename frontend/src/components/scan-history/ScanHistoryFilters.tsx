import React from 'react';
import { Search, Filter, RotateCcw, Shield } from 'lucide-react';
import { ApplicationFilterOption, ScanHistoryFilterParams } from '../../types/scanHistory';

interface Props {
  filters: ScanHistoryFilterParams;
  onChange: (filters: ScanHistoryFilterParams) => void;
  applications: ApplicationFilterOption[];
  onRefresh: () => void;
  isLoading?: boolean;
}

export const ScanHistoryFilters: React.FC<Props> = ({
  filters,
  onChange,
  applications,
  onRefresh,
  isLoading = false,
}) => {
  const handleAppChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    onChange({
      ...filters,
      application_id: val === 'ALL' ? undefined : val,
      page: 1,
    });
  };

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    onChange({
      ...filters,
      status: val === 'ALL' ? undefined : val,
      page: 1,
    });
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange({
      ...filters,
      search: e.target.value,
      page: 1,
    });
  };

  const handleReset = () => {
    onChange({
      application_id: undefined,
      status: undefined,
      search: '',
      sort_by: 'created_at',
      order: 'desc',
      page: 1,
      limit: 10,
    });
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm backdrop-blur-sm">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search scans by notes, app name, or ID..."
            value={filters.search || ''}
            onChange={handleSearchChange}
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
          />
        </div>

        {/* Application Selector */}
        <div className="flex items-center gap-2 min-w-[200px]">
          <Shield className="w-4 h-4 text-slate-400 hidden sm:block" />
          <select
            value={filters.application_id || 'ALL'}
            onChange={handleAppChange}
            className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Applications</option>
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name} ({app.total_scans} scans)
              </option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-2 min-w-[160px]">
          <Filter className="w-4 h-4 text-slate-400 hidden sm:block" />
          <select
            value={filters.status || 'ALL'}
            onChange={handleStatusChange}
            className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLETED">Completed</option>
            <option value="RUNNING">Running</option>
            <option value="FAILED">Failed</option>
            <option value="QUEUED">Queued</option>
            <option value="CANCELLED">Cancelled</option>
          </select>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleReset}
            title="Reset Filters"
            className="px-3 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg text-sm transition-colors border border-slate-800 flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Reset</span>
          </button>
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="px-3.5 py-2 bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border border-cyan-500/30 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {isLoading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>
    </div>
  );
};

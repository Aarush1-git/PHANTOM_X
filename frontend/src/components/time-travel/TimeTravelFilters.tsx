import React from 'react';
import { Search, Filter, RotateCcw } from 'lucide-react';
import { TimeTravelFilterParams } from '../../types/timeTravel';

interface TimeTravelFiltersProps {
  filters: TimeTravelFilterParams;
  onFilterChange: (newFilters: TimeTravelFilterParams) => void;
  applications: { id: string; name: string }[];
}

export const TimeTravelFilters: React.FC<TimeTravelFiltersProps> = ({
  filters,
  onFilterChange,
  applications,
}) => {
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filters, search: e.target.value, page: 1 });
  };

  const handleAppChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    onFilterChange({ ...filters, application_id: val || undefined, page: 1 });
  };

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    onFilterChange({ ...filters, status: val || undefined, page: 1 });
  };

  const handleSeverityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    onFilterChange({ ...filters, severity: val || undefined, page: 1 });
  };

  const handleReset = () => {
    onFilterChange({
      page: 1,
      limit: 20,
    });
  };

  return (
    <div className="bg-surface border border-border/80 rounded-xl p-4 space-y-3">
      <div className="flex flex-col md:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search baseline invariants, endpoints, CWEs..."
            value={filters.search || ''}
            onChange={handleSearchChange}
            className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        {/* Application Filter */}
        <div className="w-full md:w-56">
          <select
            value={filters.application_id || ''}
            onChange={handleAppChange}
            aria-label="Filter by Application"
            className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-primary transition-colors"
          >
            <option value="">All Applications</option>
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div className="w-full md:w-44">
          <select
            value={filters.status || ''}
            onChange={handleStatusChange}
            aria-label="Filter by Status"
            className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-primary transition-colors"
          >
            <option value="">All Statuses</option>
            <option value="VERIFIED">Verified</option>
            <option value="REGRESSION_DETECTED">Regression Detected</option>
            <option value="PENDING_VERIFICATION">Pending Verification</option>
            <option value="RETIRED">Retired</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="w-full md:w-36">
          <select
            value={filters.severity || ''}
            onChange={handleSeverityChange}
            aria-label="Filter by Severity"
            className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-primary transition-colors"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {/* Reset Button */}
        <button
          onClick={handleReset}
          className="flex items-center justify-center gap-1.5 px-3 py-2 border border-border hover:border-text-muted rounded-lg text-sm text-text-muted hover:text-text-primary transition-colors"
          title="Reset filters"
        >
          <RotateCcw className="w-4 h-4" />
          <span className="hidden sm:inline">Reset</span>
        </button>
      </div>
    </div>
  );
};


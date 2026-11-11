import React, { useState, useEffect, useCallback } from 'react';
import { Layers, GitCompare, History, Shield, CheckCircle2, AlertOctagon, PlayCircle, Clock } from 'lucide-react';
import { scanHistoryApi } from '../services/scanHistoryApi';
import {
  ScanHistoryItem,
  ScanHistoryFilterParams,
  ScanDetailResponse,
  ScanComparisonSummary as ComparisonSummaryType,
  ApplicationFilterOption,
} from '../types/scanHistory';

import { ScanHistoryFilters } from '../components/scan-history/ScanHistoryFilters';
import { ScanHistoryTable } from '../components/scan-history/ScanHistoryTable';
import { ScanDetailsPanel } from '../components/scan-history/ScanDetailsPanel';
import { ScanComparisonSelector } from '../components/scan-history/ScanComparisonSelector';
import { ScanComparisonSummary } from '../components/scan-history/ScanComparisonSummary';
import { VulnerabilityComparisonTable } from '../components/scan-history/VulnerabilityComparisonTable';

export const ScanHistoryPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'history' | 'compare'>('history');

  // Filters & Pagination
  const [filters, setFilters] = useState<ScanHistoryFilterParams>({
    sort_by: 'created_at',
    order: 'desc',
    page: 1,
    limit: 10,
  });

  const [applications, setApplications] = useState<ApplicationFilterOption[]>([]);
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [totalItems, setTotalItems] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [isLoadingScans, setIsLoadingScans] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Detail Modal
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanDetailResponse | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState<boolean>(false);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);

  // Comparison State
  const [baselineScan, setBaselineScan] = useState<ScanHistoryItem | null>(null);
  const [comparisonScan, setComparisonScan] = useState<ScanHistoryItem | null>(null);
  const [comparisonResult, setComparisonResult] = useState<ComparisonSummaryType | null>(null);
  const [isComparing, setIsComparing] = useState<boolean>(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  // Load applications for filter dropdown
  useEffect(() => {
    const fetchApplications = async () => {
      try {
        const apps = await scanHistoryApi.getFilterApplications();
        setApplications(apps);
      } catch (err: any) {
        console.error('Failed to fetch applications for scan history filter', err);
      }
    };
    fetchApplications();
  }, []);

  // Load scans
  const loadScans = useCallback(async () => {
    setIsLoadingScans(true);
    setError(null);
    try {
      const data = await scanHistoryApi.getScanHistory(filters);
      setScans(data.items);
      setTotalItems(data.total);
      setTotalPages(data.total_pages);
    } catch (err: any) {
      console.error('Failed to load scan history', err);
      setError(err?.response?.data?.detail || 'Failed to load scan history records.');
    } finally {
      setIsLoadingScans(false);
    }
  }, [filters]);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  // Handle viewing scan details
  const handleViewDetails = async (scanId: string) => {
    setIsLoadingDetail(true);
    setIsDetailOpen(true);
    try {
      const detail = await scanHistoryApi.getScanDetails(scanId);
      setSelectedScanDetail(detail);
    } catch (err: any) {
      console.error('Failed to load scan details', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  // Handle baseline selection
  const handleSelectBaseline = (scan: ScanHistoryItem) => {
    if (baselineScan?.id === scan.id) {
      setBaselineScan(null);
    } else {
      setBaselineScan(scan);
    }
  };

  // Handle comparison selection
  const handleSelectComparison = (scan: ScanHistoryItem) => {
    if (comparisonScan?.id === scan.id) {
      setComparisonScan(null);
    } else {
      setComparisonScan(scan);
    }
  };

  // Swap baseline and comparison
  const handleSwap = () => {
    const temp = baselineScan;
    setBaselineScan(comparisonScan);
    setComparisonScan(temp);
    if (comparisonResult) {
      // Trigger new comparison with swapped order
      triggerCompare(comparisonScan?.id, temp?.id);
    }
  };

  // Clear selections
  const handleClearComparison = () => {
    setBaselineScan(null);
    setComparisonScan(null);
    setComparisonResult(null);
    setComparisonError(null);
  };

  // Execute comparison
  const triggerCompare = async (bId?: string, cId?: string) => {
    const baseId = bId || baselineScan?.id;
    const compId = cId || comparisonScan?.id;

    if (!baseId || !compId) return;

    setIsComparing(true);
    setComparisonError(null);
    try {
      const res = await scanHistoryApi.compareScans(baseId, compId, true);
      setComparisonResult(res);
      setActiveTab('compare');
    } catch (err: any) {
      console.error('Failed to compare scans', err);
      setComparisonError(
        err?.response?.data?.detail || 'Failed to execute security scan comparison.'
      );
    } finally {
      setIsComparing(false);
    }
  };

  // Metrics summary
  const completedCount = scans.filter((s) => s.status === 'COMPLETED').length;
  const runningCount = scans.filter((s) => s.status === 'RUNNING').length;
  const failedCount = scans.filter((s) => s.status === 'FAILED').length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 animate-in fade-in duration-300">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyan-950/80 border border-cyan-800/80 rounded-xl text-cyan-400">
              <History className="w-5 h-5" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
              Security Scan History & Comparison
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Persisted execution records, vulnerability verification checkpoints, and comparative posture trajectory engine.
          </p>
        </div>

        {/* Global Navigation Tabs */}
        <div className="flex items-center bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs font-medium self-start md:self-auto">
          <button
            onClick={() => setActiveTab('history')}
            className={`px-3.5 py-1.5 rounded-lg flex items-center gap-2 transition-colors ${
              activeTab === 'history'
                ? 'bg-cyan-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Scan History ({totalItems})
          </button>
          <button
            onClick={() => setActiveTab('compare')}
            className={`px-3.5 py-1.5 rounded-lg flex items-center gap-2 transition-colors ${
              activeTab === 'compare'
                ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCompare className="w-3.5 h-3.5" />
            Scan Comparison Engine
            {comparisonResult && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            )}
          </button>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400 font-medium flex items-center justify-between">
            Total Scans
            <Layers className="w-4 h-4 text-cyan-400" />
          </span>
          <div className="text-2xl font-bold text-slate-100 font-mono mt-1">{totalItems}</div>
          <span className="text-[11px] text-slate-500">Historical runs</span>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-emerald-400 font-medium flex items-center justify-between">
            Completed
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </span>
          <div className="text-2xl font-bold text-emerald-300 font-mono mt-1">{completedCount}</div>
          <span className="text-[11px] text-slate-500">In current view</span>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-cyan-400 font-medium flex items-center justify-between">
            Active / Running
            <PlayCircle className="w-4 h-4 text-cyan-400" />
          </span>
          <div className="text-2xl font-bold text-cyan-300 font-mono mt-1">{runningCount}</div>
          <span className="text-[11px] text-slate-500">Telemetry streaming</span>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-rose-400 font-medium flex items-center justify-between">
            Failed / Cancelled
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </span>
          <div className="text-2xl font-bold text-rose-300 font-mono mt-1">{failedCount}</div>
          <span className="text-[11px] text-slate-500">Interrupted executions</span>
        </div>
      </div>

      {/* Comparison Selector Bar */}
      <ScanComparisonSelector
        baselineScan={baselineScan}
        comparisonScan={comparisonScan}
        onSwap={handleSwap}
        onClear={handleClearComparison}
        onCompare={() => triggerCompare()}
        isLoading={isComparing}
      />

      {/* Error Banner */}
      {(error || comparisonError) && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-xl text-xs text-rose-300 flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error || comparisonError}</span>
        </div>
      )}

      {/* TAB 1: Scan History Feed */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {/* Filters */}
          <ScanHistoryFilters
            filters={filters}
            onChange={(newFilters: ScanHistoryFilterParams) => setFilters(newFilters)}
            applications={applications}
            onRefresh={loadScans}
            isLoading={isLoadingScans}
          />

          {/* Table */}
          <ScanHistoryTable
            scans={scans}
            isLoading={isLoadingScans}
            baselineScanId={baselineScan?.id}
            comparisonScanId={comparisonScan?.id}
            onSelectBaseline={handleSelectBaseline}
            onSelectComparison={handleSelectComparison}
            onViewDetails={handleViewDetails}
            page={filters.page || 1}
            totalPages={totalPages}
            totalItems={totalItems}
            onPageChange={(p: number) => setFilters({ ...filters, page: p })}
          />
        </div>
      )}

      {/* TAB 2: Scan Comparison Engine */}
      {activeTab === 'compare' && (
        <div className="space-y-6">
          {!comparisonResult ? (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center">
              <GitCompare className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <h4 className="text-slate-200 font-semibold text-base mb-1">
                No Scan Comparison Selected
              </h4>
              <p className="text-slate-400 text-xs max-w-md mx-auto mb-4">
                Select two scans of the same application target from the scan history list and click &ldquo;Compare Scans&rdquo; to generate a differential analysis.
              </p>
              <button
                onClick={() => setActiveTab('history')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
              >
                Go to Scan History Feed
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Summary Overview */}
              <ScanComparisonSummary summary={comparisonResult} />

              {/* Differential Findings Table */}
              <VulnerabilityComparisonTable items={comparisonResult.comparison_items} />
            </div>
          )}
        </div>
      )}

      {/* Scan Detail Slide-over Panel */}
      <ScanDetailsPanel
        detail={selectedScanDetail}
        isOpen={isDetailOpen}
        onClose={() => setIsDetailOpen(false)}
        isLoading={isLoadingDetail}
      />
    </div>
  );
};

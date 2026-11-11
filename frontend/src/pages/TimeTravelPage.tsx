import React, { useState, useEffect } from 'react';
import {
  History,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Plus,
  Play,
  RefreshCw,
  Layers,
} from 'lucide-react';
import { timeTravelApi } from '../services/timeTravelApi';
import { scanHistoryApi } from '../services/scanHistoryApi';
import {
  TimeTravelOverviewResponse,
  SecurityBaseline,
  RegressionRecord,
  TimeTravelFilterParams,
} from '../types/timeTravel';
import { BaselineOverview } from '../components/time-travel/BaselineOverview';
import { TimeTravelFilters } from '../components/time-travel/TimeTravelFilters';
import { BaselineTable } from '../components/time-travel/BaselineTable';
import { RegressionAlerts } from '../components/time-travel/RegressionAlerts';
import { RegressionDetailsPanel } from '../components/time-travel/RegressionDetailsPanel';
import { BaselineVerificationDialog } from '../components/time-travel/BaselineVerificationDialog';
import { SecurityTimeline } from '../components/time-travel/SecurityTimeline';

export const TimeTravelPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'baselines' | 'regressions' | 'timeline'>('baselines');
  const [overview, setOverview] = useState<TimeTravelOverviewResponse | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);

  // Baselines state
  const [baselines, setBaselines] = useState<SecurityBaseline[]>([]);
  const [totalBaselines, setTotalBaselines] = useState(0);
  const [baselinesLoading, setBaselinesLoading] = useState(false);
  const [filters, setFilters] = useState<TimeTravelFilterParams>({ page: 1, limit: 20 });

  // Regressions state
  const [regressions, setRegressions] = useState<RegressionRecord[]>([]);
  const [regressionsLoading, setRegressionsLoading] = useState(false);

  // Applications dropdown list
  const [applications, setApplications] = useState<{ id: string; name: string }[]>([]);
  const [timelineAppId, setTimelineAppId] = useState<string>('');

  // Modals & Panels
  const [isVerifyOpen, setIsVerifyOpen] = useState(false);
  const [selectedRegression, setSelectedRegression] = useState<RegressionRecord | null>(null);
  const [selectedBaseline, setSelectedBaseline] = useState<SecurityBaseline | null>(null);

  // Manual Scan Evaluation Dialog State
  const [evaluatingScanId, setEvaluatingScanId] = useState('');
  const [isEvaluateOpen, setIsEvaluateOpen] = useState(false);
  const [evaluateLoading, setEvaluateLoading] = useState(false);
  const [evaluateMessage, setEvaluateMessage] = useState<string | null>(null);

  // 1. Fetch Overview & Applications
  const fetchOverview = async () => {
    setOverviewLoading(true);
    try {
      const data = await timeTravelApi.getOverview();
      setOverview(data);
    } catch (err) {
      console.error('Failed to load time travel overview:', err);
    } finally {
      setOverviewLoading(false);
    }
  };

  const fetchApps = async () => {
    try {
      const apps = await scanHistoryApi.getFilterApplications();
      setApplications(apps.map((a) => ({ id: a.id, name: a.name })));
      if (apps.length > 0 && !timelineAppId) {
        setTimelineAppId(apps[0].id);
      }
    } catch (err) {
      console.error('Failed to load applications:', err);
    }
  };

  useEffect(() => {
    fetchOverview();
    fetchApps();
  }, []);

  // 2. Fetch Baselines
  const fetchBaselines = async () => {
    setBaselinesLoading(true);
    try {
      const data = await timeTravelApi.listBaselines(filters);
      setBaselines(data.items || []);
      setTotalBaselines(data.total || 0);
    } catch (err) {
      console.error('Failed to load baselines:', err);
    } finally {
      setBaselinesLoading(false);
    }
  };

  useEffect(() => {
    fetchBaselines();
  }, [filters]);

  // 3. Fetch Regressions
  const fetchRegressions = async () => {
    setRegressionsLoading(true);
    try {
      const data = await timeTravelApi.listRegressions({
        application_id: filters.application_id,
        status: filters.status,
        limit: 50,
      });
      setRegressions(data.items || []);
    } catch (err) {
      console.error('Failed to load regressions:', err);
    } finally {
      setRegressionsLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'regressions') {
      fetchRegressions();
    }
  }, [activeTab, filters.application_id, filters.status]);

  // Retire Baseline Handler
  const handleRetireBaseline = async (baseline: SecurityBaseline) => {
    if (!window.confirm(`Are you sure you want to retire baseline condition '${baseline.title}'? Historical records will be preserved.`)) {
      return;
    }
    try {
      await timeTravelApi.retireBaseline(baseline.id, 'Retired by user from console');
      fetchBaselines();
      fetchOverview();
    } catch (err) {
      console.error('Failed to retire baseline:', err);
      alert('Failed to retire baseline.');
    }
  };

  // Manual Scan Evaluation Handler
  const handleEvaluateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!evaluatingScanId.trim()) return;

    setEvaluateLoading(true);
    setEvaluateMessage(null);
    try {
      const resp = await timeTravelApi.evaluateScan(evaluatingScanId.trim());
      setEvaluateMessage(
        `Scan Evaluated: ${resp.baselines_evaluated} baselines checked. ${resp.regressions_detected} regressions detected, ${resp.still_protected} invariants still protected, ${resp.inconclusive} inconclusive.`
      );
      fetchOverview();
      fetchBaselines();
      fetchRegressions();
    } catch (err: any) {
      setEvaluateMessage(`Evaluation failed: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setEvaluateLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Time-Travel Regression</h1>
            <span className="px-2 py-0.5 text-xs font-semibold uppercase tracking-wider bg-primary/10 text-primary border border-primary/20 rounded-md">
              Feature 20
            </span>
          </div>
          <p className="text-sm text-text-muted mt-1">
            Preserve verified security invariants, trace fix baselines, and detect application regressions across historical execution scans.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsEvaluateOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-surface-raised hover:bg-surface border border-border text-xs font-semibold text-text-primary rounded-lg transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5 text-primary" />
            Evaluate Scan
          </button>
          <button
            onClick={() => setIsVerifyOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-lg transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Verify Baseline
          </button>
        </div>
      </div>

      {/* KPI Overview Bar */}
      <BaselineOverview overview={overview} loading={overviewLoading} />

      {/* Navigation Tabs */}
      <div className="border-b border-border/80 flex items-center gap-6 text-sm">
        <button
          onClick={() => setActiveTab('baselines')}
          className={`flex items-center gap-2 pb-3 font-semibold border-b-2 transition-colors ${
            activeTab === 'baselines'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Security Baselines
          <span className="px-1.5 py-0.2 bg-surface-raised border border-border rounded text-[11px] font-mono">
            {totalBaselines}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('regressions')}
          className={`flex items-center gap-2 pb-3 font-semibold border-b-2 transition-colors ${
            activeTab === 'regressions'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          Regression Alerts
          {(overview?.regressions_detected ?? 0) > 0 && (
            <span className="px-1.5 py-0.2 bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded text-[11px] font-mono font-bold animate-pulse">
              {overview?.regressions_detected}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={`flex items-center gap-2 pb-3 font-semibold border-b-2 transition-colors ${
            activeTab === 'timeline'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <Clock className="w-4 h-4" />
          Historical Security Timeline
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'baselines' && (
        <div className="space-y-4">
          <TimeTravelFilters
            filters={filters}
            onFilterChange={(f) => setFilters(f)}
            applications={applications}
          />

          <BaselineTable
            baselines={baselines}
            total={totalBaselines}
            page={filters.page || 1}
            limit={filters.limit || 20}
            loading={baselinesLoading}
            onPageChange={(p) => setFilters({ ...filters, page: p })}
            onSelectBaseline={(b) => setSelectedBaseline(b)}
            onRetireBaseline={handleRetireBaseline}
          />
        </div>
      )}

      {activeTab === 'regressions' && (
        <div className="space-y-4">
          <RegressionAlerts
            regressions={regressions}
            loading={regressionsLoading}
            onSelectRegression={(r) => setSelectedRegression(r)}
          />
        </div>
      )}

      {activeTab === 'timeline' && (
        <SecurityTimeline
          applications={applications}
          selectedAppId={timelineAppId}
          onSelectApp={(id) => setTimelineAppId(id)}
        />
      )}

      {/* Verify Baseline Modal Dialog */}
      <BaselineVerificationDialog
        isOpen={isVerifyOpen}
        onClose={() => setIsVerifyOpen(false)}
        onSuccess={() => {
          fetchBaselines();
          fetchOverview();
        }}
      />

      {/* Regression Details Modal */}
      <RegressionDetailsPanel
        regression={selectedRegression}
        onClose={() => setSelectedRegression(null)}
      />

      {/* Baseline Details Modal */}
      {selectedBaseline && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
          <div className="bg-surface border border-border rounded-2xl w-full max-w-xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border/80">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-text-primary">Baseline Invariant Details</h3>
              </div>
              <button
                onClick={() => setSelectedBaseline(null)}
                className="text-text-muted hover:text-text-primary"
              >
                &times;
              </button>
            </div>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-text-muted">Title: </span>
                <span className="font-semibold text-text-primary">{selectedBaseline.title}</span>
              </div>
              <div>
                <span className="text-text-muted">Endpoint: </span>
                <span className="font-mono text-text-primary">{selectedBaseline.endpoint}</span>
              </div>
              <div>
                <span className="text-text-muted">Fingerprint: </span>
                <span className="font-mono text-[11px] text-text-muted">{selectedBaseline.vulnerability_fingerprint}</span>
              </div>
              <div>
                <span className="text-text-muted">Severity: </span>
                <span className="font-semibold text-text-primary">{selectedBaseline.severity}</span>
              </div>
              <div>
                <span className="text-text-muted">Status: </span>
                <span className="font-semibold text-text-primary">{selectedBaseline.status}</span>
              </div>
              <div>
                <span className="text-text-muted">Verification Status: </span>
                <span className="text-text-primary">{selectedBaseline.verification_reason || selectedBaseline.verification_status}</span>
              </div>
              {selectedBaseline.evidence_references && Object.keys(selectedBaseline.evidence_references).length > 0 && (
                <div>
                  <span className="text-text-muted block mb-1">Evidence References:</span>
                  <pre className="p-3 bg-background border border-border rounded-lg text-[10px] font-mono text-text-muted overflow-x-auto max-h-32">
                    {JSON.stringify(selectedBaseline.evidence_references, null, 2)}
                  </pre>
                </div>
              )}
            </div>
            <div className="pt-3 border-t border-border/80 flex justify-end">
              <button
                onClick={() => setSelectedBaseline(null)}
                className="px-4 py-1.5 bg-surface-raised border border-border text-xs rounded-lg text-text-primary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Evaluate Scan Modal Dialog */}
      {isEvaluateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
          <div className="bg-surface border border-border rounded-2xl w-full max-w-md shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border/80">
              <div className="flex items-center gap-2">
                <Play className="w-5 h-5 text-primary" />
                <h3 className="text-sm font-bold text-text-primary">Evaluate Scan for Regressions</h3>
              </div>
              <button
                onClick={() => {
                  setIsEvaluateOpen(false);
                  setEvaluateMessage(null);
                }}
                className="text-text-muted hover:text-text-primary"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleEvaluateScan} className="space-y-4 text-xs">
              {evaluateMessage && (
                <div className="p-3 rounded-lg border text-xs bg-surface-raised border-border text-text-primary">
                  {evaluateMessage}
                </div>
              )}

              <div>
                <label className="block text-text-primary font-medium mb-1">
                  Completed Scan ID <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  placeholder="UUID of completed scan to evaluate"
                  value={evaluatingScanId}
                  onChange={(e) => setEvaluatingScanId(e.target.value)}
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg text-text-primary font-mono focus:outline-none focus:border-primary"
                  required
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-border/80">
                <button
                  type="button"
                  onClick={() => {
                    setIsEvaluateOpen(false);
                    setEvaluateMessage(null);
                  }}
                  className="px-3.5 py-1.5 bg-surface-raised border border-border text-xs rounded-lg text-text-primary"
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={evaluateLoading}
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-lg disabled:opacity-50"
                >
                  {evaluateLoading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  Evaluate Now
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};


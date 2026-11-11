import React, { useState, useEffect } from 'react';
import {
  Wrench,
  ShieldCheck,
  RefreshCw,
  Building,
  AlertCircle,
  Sparkles,
} from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';
import { api } from '../services/api';
import { remediationApi } from '../services/remediationApi';
import { ApplicationResponse } from '../types';
import {
  RemediationOverviewResponse,
  RemediationRecommendationListItem,
  RemediationRecommendationDetail,
  RecommendationHistoryItem,
  RemediationPriority,
  RecommendationStatus,
  RecommendationStatusUpdateRequest,
  RecommendationVerifyRequest,
  RecommendationVerifyResponse,
} from '../types/remediation';
import { RemediationOverview } from '../components/remediation/RemediationOverview';
import { PriorityDistribution } from '../components/remediation/PriorityDistribution';
import { RecommendationList } from '../components/remediation/RecommendationList';
import { RecommendationDetails } from '../components/remediation/RecommendationDetails';

export const RemediationPage: React.FC = () => {
  const [applications, setApplications] = useState<ApplicationResponse[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>('');

  const [overview, setOverview] = useState<RemediationOverviewResponse | null>(null);
  const [recommendations, setRecommendations] = useState<RemediationRecommendationListItem[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);

  const [selectedPriority, setSelectedPriority] = useState<RemediationPriority | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<RecommendationStatus | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const [inspectingId, setInspectingId] = useState<string | null>(null);
  const [inspectingDetail, setInspectingDetail] = useState<RemediationRecommendationDetail | null>(null);
  const [historyRecords, setHistoryRecords] = useState<RecommendationHistoryItem[]>([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState<boolean>(false);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Load applications on mount
  useEffect(() => {
    const loadApps = async () => {
      try {
        const apps = await api.applications.list();
        setApplications(apps);
        if (apps.length > 0) {
          setSelectedAppId(apps[0].id);
        }
      } catch (err: any) {
        console.error('Failed to load applications', err);
      }
    };
    loadApps();
  }, []);

  // Fetch overview & recommendations whenever app, filters, or page change
  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [overviewData, listData] = await Promise.all([
        remediationApi.getOverview(selectedAppId || undefined),
        remediationApi.listRecommendations({
          application_id: selectedAppId || undefined,
          priority: selectedPriority || undefined,
          status: selectedStatus || undefined,
          search: searchTerm.trim() || undefined,
          page,
          size: pageSize,
        }),
      ]);
      setOverview(overviewData);
      setRecommendations(listData.items);
      setTotalCount(listData.total);
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: err?.response?.data?.detail || 'Failed to load remediation data.',
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedAppId, selectedPriority, selectedStatus, searchTerm, page]);

  // Load detail and history when inspecting a recommendation
  useEffect(() => {
    if (!inspectingId) {
      setInspectingDetail(null);
      setHistoryRecords([]);
      return;
    }

    const loadDetail = async () => {
      setIsHistoryLoading(true);
      try {
        const [detail, hist] = await Promise.all([
          remediationApi.getRecommendation(inspectingId),
          remediationApi.getHistory(inspectingId),
        ]);
        setInspectingDetail(detail);
        setHistoryRecords(hist);
      } catch (err: any) {
        setNotification({
          type: 'error',
          message: err?.response?.data?.detail || 'Failed to load recommendation detail.',
        });
      } finally {
        setIsHistoryLoading(false);
      }
    };

    loadDetail();
  }, [inspectingId]);

  // Generate / Sync Recommendations
  const handleGenerate = async () => {
    if (!selectedAppId) {
      setNotification({ type: 'error', message: 'Please select an application first.' });
      return;
    }

    setIsGenerating(true);
    try {
      const res = await remediationApi.generateRecommendations({ application_id: selectedAppId });
      setNotification({
        type: 'success',
        message: `Successfully processed: ${res.generated_count} generated, ${res.updated_count} synchronized.`,
      });
      await fetchData();
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: err?.response?.data?.detail || 'Failed to generate recommendations.',
      });
    } finally {
      setIsGenerating(false);
    }
  };

  // Status update handler
  const handleStatusUpdate = async (payload: RecommendationStatusUpdateRequest) => {
    if (!inspectingId) return;
    try {
      const updated = await remediationApi.updateStatus(inspectingId, payload);
      setInspectingDetail(updated);
      setNotification({
        type: 'success',
        message: `Status updated to ${payload.status}.`,
      });
      // Refresh list & history
      const hist = await remediationApi.getHistory(inspectingId);
      setHistoryRecords(hist);
      fetchData();
    } catch (err: any) {
      throw err;
    }
  };

  // Verification handler
  const handleVerify = async (payload: RecommendationVerifyRequest): Promise<RecommendationVerifyResponse> => {
    if (!inspectingId) throw new Error('No recommendation selected.');
    try {
      const res = await remediationApi.verifyRecommendation(inspectingId, payload);
      const [updated, hist] = await Promise.all([
        remediationApi.getRecommendation(inspectingId),
        remediationApi.getHistory(inspectingId),
      ]);
      setInspectingDetail(updated);
      setHistoryRecords(hist);
      fetchData();
      return res;
    } catch (err: any) {
      throw err;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <PageHeader
          title="Risk-Based Remediation Recommendations"
          description="Intelligent, evidence-grounded remediation prioritizing critical vulnerabilities first. Actionable developer steps, defensive code snippets, and empirical verification workflows."
        />

        {/* Application Selector */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 shadow-sm">
          <Building className="w-4 h-4 text-slate-400" />
          <span className="text-xs text-slate-400 font-medium">Application:</span>
          <select
            value={selectedAppId}
            onChange={(e) => {
              setSelectedAppId(e.target.value);
              setPage(1);
            }}
            className="bg-transparent text-xs text-white font-medium focus:outline-none cursor-pointer"
          >
            {applications.map((app) => (
              <option key={app.id} value={app.id} className="bg-slate-900 text-white">
                {app.name} ({app.target_url})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Notification Toast / Banner */}
      {notification && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between ${
            notification.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{notification.message}</span>
          <button
            onClick={() => setNotification(null)}
            className="ml-4 font-bold opacity-70 hover:opacity-100"
          >
            ×
          </button>
        </div>
      )}

      {/* Overview Cards */}
      <RemediationOverview overview={overview} loading={isLoading && !overview} />

      {/* Priority Distribution Filters */}
      {overview && (
        <PriorityDistribution
          distribution={overview.by_priority}
          selectedPriority={selectedPriority}
          onSelectPriority={(p) => {
            setSelectedPriority(p);
            setPage(1);
          }}
        />
      )}

      {/* Main Recommendations List */}
      <RecommendationList
        items={recommendations}
        total={totalCount}
        page={page}
        size={pageSize}
        loading={isLoading}
        search={searchTerm}
        onSearchChange={(s) => {
          setSearchTerm(s);
          setPage(1);
        }}
        statusFilter={selectedStatus}
        onStatusFilterChange={(st) => {
          setSelectedStatus(st);
          setPage(1);
        }}
        onPageChange={(p) => setPage(p)}
        onSelectRecommendation={(id) => setInspectingId(id)}
        onGenerateClick={handleGenerate}
        isGenerating={isGenerating}
      />

      {/* Drawer / Modal for Detailed Recommendation Inspection */}
      {inspectingDetail && (
        <div className="fixed inset-0 z-40 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-4xl max-h-[92vh] overflow-hidden">
            <RecommendationDetails
              recommendation={inspectingDetail}
              history={historyRecords}
              historyLoading={isHistoryLoading}
              onClose={() => setInspectingId(null)}
              onStatusUpdate={handleStatusUpdate}
              onVerify={handleVerify}
              onOpenPlayground={(scenarioId) => {
                window.location.href = `/playground?scenario=${scenarioId}`;
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
};

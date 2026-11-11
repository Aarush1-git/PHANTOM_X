import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Wrench,
  AlertTriangle,
  Archive,
  RefreshCw,
  Clock,
  Layers,
} from 'lucide-react';
import { timeTravelApi } from '../../services/timeTravelApi';
import { SecurityTimelineEvent } from '../../types/timeTravel';

interface SecurityTimelineProps {
  applications: { id: string; name: string }[];
  selectedAppId?: string;
  onSelectApp: (appId: string) => void;
}

export const SecurityTimeline: React.FC<SecurityTimelineProps> = ({
  applications,
  selectedAppId,
  onSelectApp,
}) => {
  const [events, setEvents] = useState<SecurityTimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedAppId && applications.length > 0) {
      onSelectApp(applications[0].id);
    }
  }, [applications, selectedAppId, onSelectApp]);

  useEffect(() => {
    if (!selectedAppId) return;

    let isMounted = true;
    const fetchTimeline = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await timeTravelApi.getApplicationTimeline(selectedAppId);
        if (isMounted) {
          setEvents(data.events || []);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err?.response?.data?.detail || err.message || 'Failed to load timeline.');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchTimeline();
    return () => {
      isMounted = false;
    };
  }, [selectedAppId]);

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'DISCOVERY':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      case 'FIX_DECLARED':
      case 'REPORT_STATUS_CHANGE':
        return <Wrench className="w-4 h-4 text-blue-400" />;
      case 'VERIFICATION_SCAN':
        return <Search className="w-4 h-4 text-indigo-400" />;
      case 'BASELINE_CREATED':
      case 'BASELINE_VERIFIED':
      case 'RE_VERIFIED':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      case 'REGRESSION_DETECTED':
        return <AlertTriangle className="w-4 h-4 text-rose-400 animate-pulse" />;
      case 'BASELINE_RETIRED':
        return <Archive className="w-4 h-4 text-zinc-400" />;
      default:
        return <Clock className="w-4 h-4 text-text-muted" />;
    }
  };

  const getEventBadge = (type: string) => {
    switch (type) {
      case 'DISCOVERY':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'FIX_DECLARED':
      case 'REPORT_STATUS_CHANGE':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'VERIFICATION_SCAN':
        return 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30';
      case 'BASELINE_CREATED':
      case 'BASELINE_VERIFIED':
      case 'RE_VERIFIED':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'REGRESSION_DETECTED':
        return 'text-rose-400 bg-rose-500/15 border-rose-500/40 font-bold';
      case 'BASELINE_RETIRED':
        return 'text-zinc-400 bg-zinc-500/10 border-zinc-500/30';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="bg-surface border border-border/80 rounded-xl p-5 space-y-4">
      {/* Header & App Selector */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-border/80">
        <div>
          <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
            <Clock className="w-4 h-4 text-primary" />
            Historical Security Timeline
          </h3>
          <p className="text-[11px] text-text-muted">
            Chronological audit trail of discovery, fix verification, baseline creation, and regression events
          </p>
        </div>

        <div className="w-full sm:w-64">
          <select
            value={selectedAppId || ''}
            onChange={(e) => onSelectApp(e.target.value)}
            aria-label="Select Application for Timeline"
            className="w-full px-3 py-1.5 bg-background border border-border rounded-lg text-xs text-text-primary focus:outline-none focus:border-primary transition-colors"
          >
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Body */}
      {loading && (
        <div className="p-8 text-center text-xs text-text-muted flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-primary" />
          Loading application timeline...
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl border text-xs text-rose-400 bg-rose-500/10 border-rose-500/30">
          {error}
        </div>
      )}

      {!loading && !error && events.length === 0 && (
        <div className="p-12 text-center text-text-muted">
          <Layers className="w-10 h-10 mx-auto mb-2 opacity-40" />
          <p className="text-xs">No historical security events recorded for this application.</p>
        </div>
      )}

      {!loading && !error && events.length > 0 && (
        <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-border/80">
          {events.map((ev) => (
            <div key={ev.id} className="relative group">
              {/* Dot Icon */}
              <div className="absolute -left-[30px] top-0.5 p-1 bg-surface border border-border rounded-full shadow-sm">
                {getEventIcon(ev.event_type)}
              </div>

              {/* Event Content */}
              <div className="bg-surface-raised/40 hover:bg-surface-raised border border-border/70 hover:border-border rounded-xl p-3.5 transition-all text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${getEventBadge(
                        ev.event_type
                      )}`}
                    >
                      {ev.event_type.replace(/_/g, ' ')}
                    </span>
                    <span className="font-semibold text-text-primary text-xs">{ev.title}</span>
                  </div>
                  <span className="text-[11px] text-text-muted font-mono">
                    {new Date(ev.timestamp).toLocaleString()}
                  </span>
                </div>

                <p className="text-text-muted text-[11px] mt-1 leading-relaxed">{ev.description}</p>

                {ev.severity && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-[10px] text-text-muted">Severity:</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold text-text-primary bg-surface border border-border">
                      {ev.severity}
                    </span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};


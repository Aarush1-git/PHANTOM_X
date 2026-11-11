import React, { useState, useEffect } from "react";
import {
  ScrollText,
  Shield,
  Layers,
  History,
  Hash,
  Download,
  Clock,
  ListFilter,
  CheckCircle2,
} from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { api } from "../services/api";
import {
  AuditLogResponse,
  AuditOverviewResponse,
  ScanExecutionRecordResponse,
} from "../types";
import { AuditOverviewStats } from "../components/audit/AuditOverviewStats";
import { AuditEventTable } from "../components/audit/AuditEventTable";
import { AuditEventTimeline } from "../components/audit/AuditEventTimeline";
import { AuditEventDetailModal } from "../components/audit/AuditEventDetailModal";
import { ScanExecutionHistoryView } from "../components/audit/ScanExecutionHistoryView";
import { AuditIntegrityPanel } from "../components/audit/AuditIntegrityPanel";

type TabType = "events" | "execution-history" | "integrity";

export const AuditLogsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>("events");
  const [viewMode, setViewMode] = useState<"table" | "timeline">("table");
  const [events, setEvents] = useState<AuditLogResponse[]>([]);
  const [overview, setOverview] = useState<AuditOverviewResponse | null>(null);
  const [executionRecords, setExecutionRecords] = useState<ScanExecutionRecordResponse[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AuditLogResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchAuditData = async () => {
    try {
      setIsLoading(true);
      const [eventsData, overviewData, recordsData] = await Promise.all([
        api.settings.listAuditLogs().catch(() => []),
        api.settings.getAuditOverview().catch(() => null),
        api.settings.listExecutionHistory().catch(() => []),
      ]);

      setEvents(eventsData);
      setOverview(overviewData);
      setExecutionRecords(recordsData);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, []);

  const handleExport = async () => {
    try {
      const data = await api.settings.exportAuditLogs();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phantom-x-audit-logs-${new Date().toISOString().split("T")[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert("Failed to export audit logs.");
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Audit Logs & Execution History"
        description="Immutable, tamper-evident audit ledger capturing authentication, policy authorizations, scan lifecycle execution, and operator approvals."
      />

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-1">
        <button
          onClick={() => setActiveTab("events")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "events"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <ScrollText className="w-4 h-4" />
          <span>Audit Event Ledger ({events.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("execution-history")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "execution-history"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <History className="w-4 h-4" />
          <span>Scan Execution History ({executionRecords.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("integrity")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            activeTab === "integrity"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Hash className="w-4 h-4" />
          <span>Tamper-Evident Integrity Check</span>
        </button>
      </div>

      {/* TAB 1: Audit Event Ledger */}
      {activeTab === "events" && (
        <div className="space-y-4">
          <AuditOverviewStats overview={overview} isLoading={isLoading} />

          {/* Table / Timeline View Toggle */}
          <div className="flex items-center justify-between pt-1">
            <span className="text-xs text-slate-400 font-mono">
              Displaying {events.length} immutable events in organization stream
            </span>
            <div className="flex items-center bg-slate-950 p-1 rounded border border-slate-800 text-xs">
              <button
                onClick={() => setViewMode("table")}
                className={`px-3 py-1 rounded transition-colors ${
                  viewMode === "table" ? "bg-cyan-500/20 text-cyan-300 font-semibold" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Table View
              </button>
              <button
                onClick={() => setViewMode("timeline")}
                className={`px-3 py-1 rounded transition-colors ${
                  viewMode === "timeline" ? "bg-cyan-500/20 text-cyan-300 font-semibold" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Timeline View
              </button>
            </div>
          </div>

          {viewMode === "table" ? (
            <AuditEventTable
              events={events}
              isLoading={isLoading}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onExport={handleExport}
              onRefresh={fetchAuditData}
            />
          ) : (
            <AuditEventTimeline
              events={events}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
            />
          )}
        </div>
      )}

      {/* TAB 2: Scan Execution History */}
      {activeTab === "execution-history" && (
        <ScanExecutionHistoryView
          records={executionRecords}
          isLoading={isLoading}
          onRefresh={fetchAuditData}
        />
      )}

      {/* TAB 3: Cryptographic Integrity Verification */}
      {activeTab === "integrity" && <AuditIntegrityPanel />}

      {/* Event Detail Inspection Modal */}
      <AuditEventDetailModal
        isOpen={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
};

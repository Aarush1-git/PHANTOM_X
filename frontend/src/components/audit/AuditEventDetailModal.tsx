import React from "react";
import { Modal } from "../common/Modal";
import { AuditLogResponse } from "../../types";
import { AuditCategoryBadge, AuditStatusBadge, AuditSeverityBadge } from "./AuditBadge";
import { KeyRound, Shield, Clock, Hash, User, Server, Layers } from "lucide-react";

interface AuditEventDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  event: AuditLogResponse | null;
}

export const AuditEventDetailModal: React.FC<AuditEventDetailModalProps> = ({
  isOpen,
  onClose,
  event,
}) => {
  if (!event) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Audit Event Details & Decision Traceability"
      footer={
        <button
          onClick={onClose}
          className="px-4 py-2 text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
        >
          Close Inspector
        </button>
      }
    >
      <div className="space-y-4 max-h-[70vh] overflow-y-auto pr-1 text-xs">
        {/* Header Action & Status */}
        <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-cyan-400 font-bold text-sm">{event.event_type}</span>
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Seq #{event.sequence_number || 1}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <AuditCategoryBadge category={event.category} />
              <AuditStatusBadge status={event.status} />
              <AuditSeverityBadge severity={event.severity} />
            </div>
          </div>
          <p className="text-slate-200 font-medium">{event.action}</p>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-300 font-mono">
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1">
            <span className="text-slate-500 text-[10px] block flex items-center gap-1">
              <Clock className="w-3 h-3" /> TIMESTAMP (UTC)
            </span>
            <span className="text-slate-200">{new Date(event.created_at).toUTCString()}</span>
            <span className="text-slate-500 block text-[10px]">
              Local: {new Date(event.created_at).toLocaleString()}
            </span>
          </div>

          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1">
            <span className="text-slate-500 text-[10px] block flex items-center gap-1">
              <User className="w-3 h-3" /> ACTOR
            </span>
            <span className="text-slate-200 font-semibold">{event.actor_email || "System Engine"}</span>
            {event.actor_role && <span className="text-slate-400 block text-[10px]">Role: {event.actor_role}</span>}
            {event.ip_address && <span className="text-slate-500 block text-[10px]">IP: {event.ip_address}</span>}
          </div>

          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1">
            <span className="text-slate-500 text-[10px] block flex items-center gap-1">
              <Server className="w-3 h-3" /> TARGET RESOURCE
            </span>
            <span className="text-cyan-400">{event.target_type}</span>
            {event.target_id && <span className="text-slate-400 block text-[10px] truncate">ID: {event.target_id}</span>}
            {event.application_id && <span className="text-slate-500 block text-[10px] truncate">App: {event.application_id}</span>}
          </div>

          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1">
            <span className="text-slate-500 text-[10px] block flex items-center gap-1">
              <Layers className="w-3 h-3" /> ORIGIN & CORRELATION
            </span>
            <span className="text-slate-200">{event.source_module || "SECURITY_OPERATIONS"}</span>
            {event.scan_id && <span className="text-slate-400 block text-[10px] truncate">Scan: {event.scan_id}</span>}
            {event.correlation_id && <span className="text-slate-500 block text-[10px] truncate">Trace ID: {event.correlation_id}</span>}
          </div>
        </div>

        {/* Cryptographic Hash Chain Info */}
        <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2 font-mono text-[11px]">
          <div className="flex items-center gap-1.5 text-cyan-400 font-semibold">
            <Hash className="w-3.5 h-3.5" />
            <span>Cryptographic SHA-256 Tamper-Evident Chain</span>
          </div>

          <div className="space-y-1">
            <span className="text-slate-500 text-[10px] block">CURRENT RECORD HASH:</span>
            <p className="text-slate-300 bg-slate-900 px-2 py-1 rounded break-all border border-slate-800">
              {event.event_hash || "Uncalculated"}
            </p>
          </div>

          <div className="space-y-1">
            <span className="text-slate-500 text-[10px] block">PREVIOUS RECORD HASH:</span>
            <p className="text-slate-400 bg-slate-900 px-2 py-1 rounded break-all border border-slate-800">
              {event.prev_event_hash || "GENESIS"}
            </p>
          </div>
        </div>

        {/* Structured Metadata Payload (Secrets Scrubbed) */}
        <div>
          <span className="text-slate-400 font-mono text-xs block mb-1">
            STRUCTURED METADATA (SECRETS REDACTED):
          </span>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
            {JSON.stringify(event.details, null, 2)}
          </pre>
        </div>

        <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between pt-1 border-t border-slate-800/80">
          <span>Event ID: {event.id}</span>
          <span>Org: {event.organization_id}</span>
        </div>
      </div>
    </Modal>
  );
};


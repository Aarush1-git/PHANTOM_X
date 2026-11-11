import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditCategoryBadge, AuditStatusBadge, AuditSeverityBadge } from "../src/components/audit/AuditBadge";
import { AuditOverviewStats } from "../src/components/audit/AuditOverviewStats";
import { AuditEventTable } from "../src/components/audit/AuditEventTable";
import { AuditEventTimeline } from "../src/components/audit/AuditEventTimeline";
import { AuditEventDetailModal } from "../src/components/audit/AuditEventDetailModal";
import { ScanExecutionHistoryView } from "../src/components/audit/ScanExecutionHistoryView";
import { AuditIntegrityPanel } from "../src/components/audit/AuditIntegrityPanel";
import { AuditLogResponse, AuditOverviewResponse, ScanExecutionRecordResponse } from "../src/types";

describe("Feature 25: Audit Logs & Execution History UI Components", () => {
  const mockEvent: AuditLogResponse = {
    id: "ev-1",
    organization_id: "org-1",
    category: "SECURITY_TESTING",
    event_type: "TEST_BLOCKED",
    action: "Blocked prohibited SQL injection payload",
    status: "BLOCKED",
    severity: "HIGH",
    source_module: "SAFETY_ENGINE",
    target_type: "SecurityTest",
    target_id: "https://api.banking.local/search",
    actor_email: "auditor@fintech.local",
    details: {
      url: "https://api.banking.local/search",
      violation: "DESTRUCTIVE_ACTION_PROHIBITED",
      password: "[REDACTED]"
    },
    event_hash: "abcd1234ef567890",
    prev_event_hash: "GENESIS_0000000000000000",
    created_at: "2026-11-10T12:00:00Z"
  };

  it("renders audit badges properly", () => {
    const { rerender } = render(<AuditCategoryBadge category="SECURITY_TESTING" />);
    expect(screen.getByText("SECURITY_TESTING")).toBeInTheDocument();

    rerender(<AuditStatusBadge status="BLOCKED" />);
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();

    rerender(<AuditSeverityBadge severity="HIGH" />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });

  it("renders AuditOverviewStats with metrics and category breakdowns", () => {
    const mockOverview: AuditOverviewResponse = {
      total_events: 120,
      successful_events: 100,
      failed_events: 10,
      blocked_events: 10,
      critical_events: 2,
      categories_breakdown: {
        AUTHENTICATION: 50,
        SECURITY_TESTING: 40,
        AUTHORIZATION: 30
      },
      generated_at: "2026-11-10T12:00:00Z"
    };

    render(<AuditOverviewStats overview={mockOverview} isLoading={false} />);
    expect(screen.getByText("120")).toBeInTheDocument();
    expect(screen.getByText("100")).toBeInTheDocument();
    expect(screen.getByText("TOTAL EVENTS")).toBeInTheDocument();
    expect(screen.getByText(/AUTHENTICATION:/)).toBeInTheDocument();
  });

  it("renders AuditEventTable with search and rows", () => {
    render(
      <AuditEventTable
        events={[mockEvent]}
        isLoading={false}
        onSelectEvent={vi.fn()}
        onExport={vi.fn()}
        onRefresh={vi.fn()}
      />
    );
    expect(screen.getByText("TEST_BLOCKED")).toBeInTheDocument();
    expect(screen.getByText("Blocked prohibited SQL injection payload")).toBeInTheDocument();
    expect(screen.getByText("auditor@fintech.local")).toBeInTheDocument();
    expect(screen.getByText("Export JSON")).toBeInTheDocument();
  });

  it("renders AuditEventTimeline with event nodes", () => {
    render(
      <AuditEventTimeline
        events={[mockEvent]}
        onSelectEvent={vi.fn()}
      />
    );
    expect(screen.getByText("Chronological Decision & Execution Timeline")).toBeInTheDocument();
    expect(screen.getByText("TEST_BLOCKED")).toBeInTheDocument();
  });

  it("renders AuditEventDetailModal with scrubbed metadata and hash chain", () => {
    render(
      <AuditEventDetailModal
        isOpen={true}
        onClose={vi.fn()}
        event={mockEvent}
      />
    );
    expect(screen.getByText("Audit Event Details & Decision Traceability")).toBeInTheDocument();
    expect(screen.getByText("Cryptographic SHA-256 Tamper-Evident Chain")).toBeInTheDocument();
    expect(screen.getByText("abcd1234ef567890")).toBeInTheDocument();
  });

  it("renders ScanExecutionHistoryView with records", () => {
    const mockScanRecord: ScanExecutionRecordResponse = {
      id: "rec-1",
      organization_id: "org-1",
      scan_id: "scan-9988",
      application_id: "app-1",
      final_status: "COMPLETED",
      tests_executed: 50,
      tests_blocked: 2,
      verified_findings: 1,
      duration_seconds: 45.2,
      lifecycle_events: [
        { status: "QUEUED", timestamp: "2026-11-10T12:00:00Z" },
        { status: "STARTED", timestamp: "2026-11-10T12:00:05Z" },
        { status: "COMPLETED", timestamp: "2026-11-10T12:00:50Z" }
      ],
      created_at: "2026-11-10T12:00:00Z",
      updated_at: "2026-11-10T12:00:50Z"
    };

    render(
      <ScanExecutionHistoryView
        records={[mockScanRecord]}
        isLoading={false}
        onRefresh={vi.fn()}
      />
    );
    expect(screen.getByText("scan-9988")).toBeInTheDocument();
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
    expect(screen.getByText("50")).toBeInTheDocument();
    expect(screen.getByText("45.2s")).toBeInTheDocument();
  });

  it("renders AuditIntegrityPanel trigger", () => {
    render(<AuditIntegrityPanel />);
    expect(screen.getByText("Tamper-Evident Hash Chain Verification")).toBeInTheDocument();
    expect(screen.getByText("Run Integrity Check")).toBeInTheDocument();
  });
});


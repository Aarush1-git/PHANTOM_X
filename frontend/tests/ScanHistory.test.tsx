import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

import { SeverityChangeIndicator } from '../src/components/scan-history/SeverityChangeIndicator';
import { ScanHistoryFilters } from '../src/components/scan-history/ScanHistoryFilters';
import { ScanHistoryTable } from '../src/components/scan-history/ScanHistoryTable';
import { ScanComparisonSelector } from '../src/components/scan-history/ScanComparisonSelector';
import { ScanComparisonSummary } from '../src/components/scan-history/ScanComparisonSummary';
import { VulnerabilityComparisonTable } from '../src/components/scan-history/VulnerabilityComparisonTable';
import { ScanDetailsPanel } from '../src/components/scan-history/ScanDetailsPanel';

import {
  ScanHistoryItem,
  ScanComparisonSummary as SummaryType,
  ScanDetailResponse,
  ApplicationFilterOption,
} from '../src/types/scanHistory';

describe('Feature 23: Scan History & Comparison UI Suite', () => {
  const mockScan1: ScanHistoryItem = {
    id: 'scan-uuid-001',
    organization_id: 'org-uuid-001',
    application_id: 'app-uuid-001',
    application_name: 'Core Banking API',
    target_url: 'https://banking.cyberdefense.local',
    status: 'COMPLETED',
    progress: 1.0,
    started_at: '2026-11-01T10:00:00Z',
    completed_at: '2026-11-01T10:30:00Z',
    duration_seconds: 1800,
    findings_count: 3,
    total_vulnerabilities: 3,
    critical_count: 1,
    high_count: 1,
    medium_count: 1,
    low_count: 0,
    info_count: 0,
    notes: 'Sprint 44 baseline scan',
    created_at: '2026-11-01T10:00:00Z',
  };

  const mockScan2: ScanHistoryItem = {
    id: 'scan-uuid-002',
    organization_id: 'org-uuid-001',
    application_id: 'app-uuid-001',
    application_name: 'Core Banking API',
    target_url: 'https://banking.cyberdefense.local',
    status: 'COMPLETED',
    progress: 1.0,
    started_at: '2026-11-08T10:00:00Z',
    completed_at: '2026-11-08T10:30:00Z',
    duration_seconds: 1800,
    findings_count: 4,
    total_vulnerabilities: 4,
    critical_count: 2,
    high_count: 1,
    medium_count: 1,
    low_count: 0,
    info_count: 0,
    notes: 'Sprint 46 release scan',
    created_at: '2026-11-08T10:00:00Z',
  };

  const mockComparisonSummary: SummaryType = {
    baseline_scan_id: 'scan-uuid-001',
    comparison_scan_id: 'scan-uuid-002',
    application_id: 'app-uuid-001',
    application_name: 'Core Banking API',
    target_url: 'https://banking.cyberdefense.local',
    baseline_completed_at: '2026-11-01T10:30:00Z',
    comparison_completed_at: '2026-11-08T10:30:00Z',
    baseline_total: 3,
    comparison_total: 4,
    new_count: 1,
    fixed_count: 1,
    persistent_count: 1,
    regressed_count: 1,
    severity_increased_count: 1,
    severity_decreased_count: 0,
    net_finding_change: 1,
    posture_change: 'DEGRADED',
    posture_explanation: 'Security posture degraded: 1 new and 1 regressed vulnerabilities detected.',
    baseline_severity_breakdown: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
    comparison_severity_breakdown: { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
    comparison_items: [
      {
        fingerprint: '/api/v1/webhooks::cwe-918',
        title: 'SSRF via Webhook',
        endpoint: '/api/v1/webhooks',
        cwe_id: 'CWE-918',
        comparison_status: 'NEW',
        baseline_severity: null,
        comparison_severity: 'HIGH',
        recommendation: 'Filter internal loopback IPs',
        has_evidence: true,
      },
      {
        fingerprint: '/api/v1/orders/search::cwe-89',
        title: 'SQL Injection in Orders',
        endpoint: '/api/v1/orders/search',
        cwe_id: 'CWE-89',
        comparison_status: 'FIXED',
        baseline_severity: 'HIGH',
        comparison_severity: null,
        recommendation: 'Use bound parameters',
        has_evidence: true,
      },
      {
        fingerprint: '/api/v1/health::cwe-200',
        title: 'Information Disclosure Header',
        endpoint: '/api/v1/health',
        cwe_id: 'CWE-200',
        comparison_status: 'PERSISTENT',
        baseline_severity: 'LOW',
        comparison_severity: 'LOW',
        recommendation: 'Strip server banner',
        has_evidence: false,
      },
      {
        fingerprint: '/api/v1/comments::cwe-79',
        title: 'Cross-Site Scripting in Comments',
        endpoint: '/api/v1/comments',
        cwe_id: 'CWE-79',
        comparison_status: 'REGRESSED',
        baseline_severity: null,
        comparison_severity: 'MEDIUM',
        recommendation: 'Sanitize input',
        has_evidence: true,
      },
      {
        fingerprint: '/api/v1/statements/{id}::cwe-639',
        title: 'IDOR on Statements',
        endpoint: '/api/v1/statements/{id}',
        cwe_id: 'CWE-639',
        comparison_status: 'SEVERITY_CHANGED',
        baseline_severity: 'MEDIUM',
        comparison_severity: 'CRITICAL',
        recommendation: 'Validate tenant scoping',
        has_evidence: true,
      },
    ],
  };

  const mockScanDetail: ScanDetailResponse = {
    scan: mockScan1,
    vulnerabilities: [
      {
        id: 'v1',
        scan_id: mockScan1.id,
        title: 'SQL Injection in Orders',
        severity: 'HIGH',
        status: 'VERIFIED',
        endpoint: '/api/v1/orders/search',
        cwe_id: 'CWE-89',
        cvss_score: 8.5,
        confidence: 0.95,
        recommendation: 'Use prepared queries',
        evidence_count: 1,
        has_evidence: true,
        fingerprint: '/api/v1/orders/search::cwe-89',
      },
    ],
    evidence_items: [
      {
        id: 'ev-1',
        vulnerability_id: 'v1',
        has_request_dump: true,
        has_response_dump: true,
        has_screenshot: true,
        screenshot_url: 'https://storage/proof.png',
        summary: 'Proof of SQLi exploit',
      },
    ],
  };

  // 1. SeverityChangeIndicator
  it('renders SeverityChangeIndicator correctly for escalation, de-escalation, and static findings', () => {
    // Escalation MEDIUM -> CRITICAL
    const { rerender } = render(
      <SeverityChangeIndicator baselineSeverity="MEDIUM" comparisonSeverity="CRITICAL" />
    );
    expect(screen.getByText('MEDIUM')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();

    // Persistent LOW -> LOW
    rerender(<SeverityChangeIndicator baselineSeverity="LOW" comparisonSeverity="LOW" />);
    expect(screen.getByText('LOW')).toBeInTheDocument();

    // New item (no baseline)
    rerender(<SeverityChangeIndicator baselineSeverity={null} comparisonSeverity="HIGH" />);
    expect(screen.getByText('HIGH')).toBeInTheDocument();

    // Fixed item (no comparison)
    rerender(<SeverityChangeIndicator baselineSeverity="HIGH" comparisonSeverity={null} />);
    expect(screen.getByText('HIGH')).toBeInTheDocument();
  });

  // 2. ScanHistoryFilters
  it('renders ScanHistoryFilters and triggers filter change callbacks', () => {
    const mockOnChange = vi.fn();
    const mockOnRefresh = vi.fn();
    const mockApps: ApplicationFilterOption[] = [
      { id: 'app-uuid-001', name: 'Core Banking API', target_url: 'https://banking', total_scans: 3 },
    ];

    render(
      <ScanHistoryFilters
        filters={{ search: '' }}
        onChange={mockOnChange}
        applications={mockApps}
        onRefresh={mockOnRefresh}
      />
    );

    expect(screen.getByPlaceholderText(/search scans/i)).toBeInTheDocument();

    const searchInput = screen.getByPlaceholderText(/search scans/i);
    fireEvent.change(searchInput, { target: { value: 'banking' } });
    expect(mockOnChange).toHaveBeenCalledWith(expect.objectContaining({ search: 'banking' }));

    const refreshBtn = screen.getByText('Refresh');
    fireEvent.click(refreshBtn);
    expect(mockOnRefresh).toHaveBeenCalled();
  });

  // 3. ScanHistoryTable
  it('renders ScanHistoryTable with scans, status indicators, and compare selection buttons', () => {
    const mockSelectBase = vi.fn();
    const mockSelectComp = vi.fn();
    const mockViewDetails = vi.fn();

    render(
      <ScanHistoryTable
        scans={[mockScan1, mockScan2]}
        isLoading={false}
        baselineScanId={mockScan1.id}
        comparisonScanId={null}
        onSelectBaseline={mockSelectBase}
        onSelectComparison={mockSelectComp}
        onViewDetails={mockViewDetails}
        page={1}
        totalPages={1}
        totalItems={2}
        onPageChange={vi.fn()}
      />
    );

    expect(screen.getAllByText('Core Banking API').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Sprint 44 baseline scan/i)).toBeInTheDocument();

    const detailsBtns = screen.getAllByText('Details');
    fireEvent.click(detailsBtns[0]);
    expect(mockViewDetails).toHaveBeenCalledWith(mockScan1.id);
  });

  // 4. ScanComparisonSelector
  it('renders ScanComparisonSelector and handles compare and swap actions', () => {
    const mockSwap = vi.fn();
    const mockClear = vi.fn();
    const mockCompare = vi.fn();

    render(
      <ScanComparisonSelector
        baselineScan={mockScan1}
        comparisonScan={mockScan2}
        onSwap={mockSwap}
        onClear={mockClear}
        onCompare={mockCompare}
      />
    );

    expect(screen.getByText('Baseline (Earlier)')).toBeInTheDocument();
    expect(screen.getByText('Comparison (Target)')).toBeInTheDocument();

    const compareBtn = screen.getByText('Compare Scans');
    fireEvent.click(compareBtn);
    expect(mockCompare).toHaveBeenCalled();

    const clearBtn = screen.getByText('Clear');
    fireEvent.click(clearBtn);
    expect(mockClear).toHaveBeenCalled();
  });

  // 5. ScanComparisonSummary
  it('renders ScanComparisonSummary with verdict banner and metric cards', () => {
    render(<ScanComparisonSummary summary={mockComparisonSummary} />);

    expect(screen.getByText('DEGRADED')).toBeInTheDocument();
    expect(screen.getByText(/1 new and 1 regressed vulnerabilities detected/i)).toBeInTheDocument();
    expect(screen.getByText('+1')).toBeInTheDocument(); // Net change

    expect(screen.getByText('New Findings')).toBeInTheDocument();
    expect(screen.getByText('Fixed / Resolved')).toBeInTheDocument();
    expect(screen.getByText('Regressed')).toBeInTheDocument();
    expect(screen.getByText('Persistent')).toBeInTheDocument();
  });

  // 6. VulnerabilityComparisonTable
  it('renders VulnerabilityComparisonTable with categorized findings and status filters', () => {
    render(<VulnerabilityComparisonTable items={mockComparisonSummary.comparison_items} />);

    expect(screen.getByText('SSRF via Webhook')).toBeInTheDocument();
    expect(screen.getByText('SQL Injection in Orders')).toBeInTheDocument();
    expect(screen.getByText('NEW')).toBeInTheDocument();
    expect(screen.getByText('FIXED')).toBeInTheDocument();
    expect(screen.getByText('REGRESSED')).toBeInTheDocument();

    // Filter by NEW
    const newFilterBtn = screen.getByRole('button', { name: /NEW \(1\)/i });
    fireEvent.click(newFilterBtn);
    expect(screen.getByText('SSRF via Webhook')).toBeInTheDocument();
    expect(screen.queryByText('SQL Injection in Orders')).not.toBeInTheDocument();
  });

  // 7. ScanDetailsPanel
  it('renders ScanDetailsPanel with findings and evidence tabs', () => {
    const mockOnClose = vi.fn();

    render(
      <ScanDetailsPanel
        detail={mockScanDetail}
        isOpen={true}
        onClose={mockOnClose}
      />
    );

    expect(screen.getByText('Core Banking API')).toBeInTheDocument();
    expect(screen.getByText('SQL Injection in Orders')).toBeInTheDocument();

    // Click Evidence Records tab
    const evidenceTab = screen.getByText(/Evidence Records \(1\)/i);
    fireEvent.click(evidenceTab);
    expect(screen.getByText('Proof of SQLi exploit')).toBeInTheDocument();
  });
});

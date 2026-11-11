import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

import { BaselineOverview } from '../src/components/time-travel/BaselineOverview';
import { BaselineTable } from '../src/components/time-travel/BaselineTable';
import { RegressionAlerts } from '../src/components/time-travel/RegressionAlerts';
import { RegressionDetailsPanel } from '../src/components/time-travel/RegressionDetailsPanel';
import { SecurityTimeline } from '../src/components/time-travel/SecurityTimeline';
import { BaselineVerificationDialog } from '../src/components/time-travel/BaselineVerificationDialog';

import {
  SecurityBaseline,
  RegressionRecord,
  TimeTravelOverviewResponse,
  SecurityTimelineEvent,
} from '../src/types/timeTravel';

describe('Feature 20: Time-Travel Regression UI Suite', () => {
  const mockOverview: TimeTravelOverviewResponse = {
    total_baselines: 12,
    verified_baselines: 9,
    active_baselines: 10,
    retired_baselines: 2,
    regressions_detected: 2,
    inconclusive_evaluations: 1,
    affected_applications_count: 1,
    recent_regressions: [],
  };

  const mockBaseline: SecurityBaseline = {
    id: 'base-uuid-001',
    organization_id: 'org-uuid-001',
    application_id: 'app-uuid-001',
    application_name: 'Core Banking API',
    source_scan_id: 'scan-uuid-001',
    verification_scan_id: 'scan-uuid-002',
    original_vulnerability_id: 'vuln-uuid-001',
    vulnerability_fingerprint: '/api/v1/accounts::{cwe-639}',
    title: 'Insecure Direct Object Reference on Account Statement',
    category: 'CWE-639',
    cwe_id: 'CWE-639',
    endpoint: '/api/v1/accounts/{id}/statement',
    http_method: 'GET',
    severity: 'HIGH',
    status: 'VERIFIED',
    verification_timestamp: '2026-11-05T12:00:00Z',
    verification_status: 'VERIFIED',
    verification_reason: 'Fix verified: finding absent in verification scan',
    evidence_references: { target_endpoint: '/api/v1/accounts/{id}/statement' },
    notes: 'Verified post sprint 42 deployment',
    is_retired: false,
    created_at: '2026-11-01T10:00:00Z',
    updated_at: '2026-11-05T12:00:00Z',
  };

  const mockRegression: RegressionRecord = {
    id: 'reg-uuid-001',
    organization_id: 'org-uuid-001',
    application_id: 'app-uuid-001',
    application_name: 'Core Banking API',
    baseline_id: 'base-uuid-001',
    baseline_title: 'Insecure Direct Object Reference on Account Statement',
    baseline_endpoint: '/api/v1/accounts/{id}/statement',
    scan_id: 'scan-uuid-003',
    scan_notes: 'Sprint 45 automated security regression run',
    reappeared_vulnerability_id: 'vuln-uuid-003',
    status: 'REGRESSION_DETECTED',
    match_quality: 'EXACT_FINGERPRINT',
    confidence_score: 1.0,
    original_severity: 'MEDIUM',
    new_severity: 'CRITICAL',
    severity_change: 'INCREASED',
    first_observed_at: '2026-11-10T09:00:00Z',
    evidence_references: {
      reappeared_endpoint: '/api/v1/accounts/{id}/statement',
      cvss_score: 9.1,
    },
    explanation:
      "Security Regression Detected: Issue 'IDOR on Account Statement' reappeared at endpoint '/api/v1/accounts/{id}/statement' with escalated severity CRITICAL.",
    remediation_notes: null,
    is_resolved: false,
    created_at: '2026-11-10T09:00:00Z',
  };

  it('1. renders BaselineOverview with aggregate metrics correctly', () => {
    render(<BaselineOverview overview={mockOverview} loading={false} />);

    expect(screen.getByText('Verified Invariants')).toBeInTheDocument();
    expect(screen.getByText('9')).toBeInTheDocument();
    expect(screen.getByText('Active Baselines')).toBeInTheDocument();
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('Regressions Detected')).toBeInTheDocument();
    expect(screen.getAllByText('2')).toHaveLength(2); // regressions_detected (2) and retired_baselines (2)
    expect(screen.getByText('Inconclusive Matches')).toBeInTheDocument();
    expect(screen.getAllByText('1')).toHaveLength(2); // inconclusive_evaluations (1) and affected_applications_count (1)
  });

  it('2. renders BaselineTable rows, badges, and triggers actions', () => {
    const onSelect = vi.fn();
    const onRetire = vi.fn();
    const onPageChange = vi.fn();

    render(
      <BaselineTable
        baselines={[mockBaseline]}
        total={1}
        page={1}
        limit={20}
        loading={false}
        onPageChange={onPageChange}
        onSelectBaseline={onSelect}
        onRetireBaseline={onRetire}
      />
    );

    expect(screen.getByText('Core Banking API')).toBeInTheDocument();
    expect(screen.getByText('Insecure Direct Object Reference on Account Statement')).toBeInTheDocument();
    expect(screen.getByText('CWE-639')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('Verified')).toBeInTheDocument();

    const detailsBtn = screen.getByRole('button', { name: /Details/i });
    fireEvent.click(detailsBtn);
    expect(onSelect).toHaveBeenCalledWith(mockBaseline);

    const retireBtn = screen.getByRole('button', { name: /Retire/i });
    fireEvent.click(retireBtn);
    expect(onRetire).toHaveBeenCalledWith(mockBaseline);
  });

  it('3. renders RegressionAlerts card with severity escalation and confidence', () => {
    const onSelect = vi.fn();

    render(
      <RegressionAlerts
        regressions={[mockRegression]}
        loading={false}
        onSelectRegression={onSelect}
      />
    );

    expect(screen.getByText('Regression Confirmed')).toBeInTheDocument();
    expect(screen.getByText('Severity Escalated')).toBeInTheDocument();
    expect(screen.getByText('Insecure Direct Object Reference on Account Statement')).toBeInTheDocument();
    expect(screen.getByText('Confidence:')).toBeInTheDocument();
    expect(screen.getByText('100%')).toBeInTheDocument();

    const viewBtn = screen.getByRole('button', { name: /View Evidence/i });
    fireEvent.click(viewBtn);
    expect(onSelect).toHaveBeenCalledWith(mockRegression);
  });

  it('4. renders RegressionDetailsPanel with side-by-side comparison', () => {
    const onClose = vi.fn();

    render(<RegressionDetailsPanel regression={mockRegression} onClose={onClose} />);

    expect(screen.getByText('Regression Analysis & Evidence')).toBeInTheDocument();
    expect(screen.getByText('Baseline Invariant (Resolved)')).toBeInTheDocument();
    expect(screen.getByText('Reappeared Finding')).toBeInTheDocument();
    expect(screen.getByText(/Matching Telemetry/i)).toBeInTheDocument();
    expect(screen.getByText('EXACT_FINGERPRINT')).toBeInTheDocument();
    expect(screen.getByText(/Recommended Security Remediation/i)).toBeInTheDocument();

    const closeBtn = screen.getByRole('button', { name: /Close/i });
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalled();
  });

  it('5. renders BaselineVerificationDialog and handles user input', () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(<BaselineVerificationDialog isOpen={true} onClose={onClose} onSuccess={onSuccess} />);

    expect(screen.getByText('Verify Fix & Establish Baseline')).toBeInTheDocument();

    const vulnInput = screen.getByPlaceholderText(/UUID of discovered finding/i);
    const scanInput = screen.getByPlaceholderText(/UUID of completed verification scan/i);

    fireEvent.change(vulnInput, { target: { value: 'vuln-12345' } });
    fireEvent.change(scanInput, { target: { value: 'scan-67890' } });

    expect(vulnInput).toHaveValue('vuln-12345');
    expect(scanInput).toHaveValue('scan-67890');
  });

  it('6. renders empty states gracefully for baselines and regressions', () => {
    const { rerender } = render(
      <BaselineTable
        baselines={[]}
        total={0}
        page={1}
        limit={20}
        loading={false}
        onPageChange={vi.fn()}
        onSelectBaseline={vi.fn()}
        onRetireBaseline={vi.fn()}
      />
    );
    expect(screen.getByText('No Security Baselines Found')).toBeInTheDocument();

    rerender(
      <RegressionAlerts regressions={[]} loading={false} onSelectRegression={vi.fn()} />
    );
    expect(screen.getByText('Zero Active Regressions')).toBeInTheDocument();
  });
});

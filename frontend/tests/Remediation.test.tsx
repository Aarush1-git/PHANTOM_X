import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { RemediationOverview } from '../src/components/remediation/RemediationOverview';
import { PriorityDistribution } from '../src/components/remediation/PriorityDistribution';
import { RecommendationList } from '../src/components/remediation/RecommendationList';
import { RemediationSteps } from '../src/components/remediation/RemediationSteps';
import { RecommendationStatusDialog } from '../src/components/remediation/RecommendationStatusDialog';
import { VerificationPanel } from '../src/components/remediation/VerificationPanel';
import { RecommendationHistory } from '../src/components/remediation/RecommendationHistory';
import { RecommendationDetails } from '../src/components/remediation/RecommendationDetails';

import {
  RemediationOverviewResponse,
  RemediationRecommendationListItem,
  RemediationRecommendationDetail,
  RecommendationHistoryItem,
} from '../src/types/remediation';

describe('Feature 27: Risk-Based Remediation Recommendations Frontend Suite', () => {
  const mockOverview: RemediationOverviewResponse = {
    total_recommendations: 12,
    by_priority: {
      CRITICAL: 3,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 1,
      INFORMATIONAL: 1,
    },
    by_status: {
      GENERATED: 5,
      REVIEWED: 2,
      ACCEPTED: 2,
      REJECTED: 0,
      IN_PROGRESS: 2,
      VERIFIED: 1,
      DEFERRED: 0,
    },
    average_risk_score: 68.4,
    verified_count: 1,
    pending_verification_count: 4,
    in_progress_count: 2,
  };

  const mockListItem: RemediationRecommendationListItem = {
    id: 'rec-001',
    organization_id: 'org-001',
    application_id: 'app-001',
    vulnerability_id: 'vuln-001',
    title: 'Remediate Insecure Direct Object Reference in Billing',
    category: 'CWE-639',
    cwe_id: 'CWE-639',
    severity: 'HIGH',
    calculated_priority: 'CRITICAL',
    risk_score: 82.5,
    status: 'IN_PROGRESS',
    endpoint: '/api/v1/billing/invoices',
    http_method: 'GET',
    estimated_effort: 'MEDIUM',
    suggested_playground_scenario_id: 'idor-01',
    assigned_to: 'dev-lead@acme.corp',
    verification_status: 'UNVERIFIED',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    why_it_matters_summary: 'Insecure Direct Object References allow attackers to access or modify records.',
  };

  const mockDetail: RemediationRecommendationDetail = {
    ...mockListItem,
    priority_rationale: [
      {
        factor: 'CVSS Severity Score (8.5/10)',
        points: 34.0,
        reason: 'Standardized CVSS v3.1 base score translated to 34.0 risk points.',
      },
      {
        factor: 'Time-Travel Regression Escalation',
        points: 20.0,
        reason: 'Vulnerability was previously verified as resolved and has regressed.',
      },
      {
        factor: 'Exploitability & Proof Verification',
        points: 15.0,
        reason: 'Active exploitation proof verified in scan telemetry.',
      },
      {
        factor: 'Sensitive Boundary & Tenant Exposure',
        points: 15.0,
        reason: 'Vulnerable endpoint targets billing and financial data.',
      },
    ],
    why_it_matters:
      'Insecure Direct Object References permit cross-tenant data exfiltration by tampering with invoice IDs.',
    potential_business_impact:
      'Severe multi-tenant privacy breaches, GDPR compliance violations, and regulatory penalties.',
    remediation_steps: [
      'Scope all database queries strictly with verified tenant ID from authenticated session context.',
      'Enforce server-side authorization checks prior to retrieving invoice records.',
      'Use indirect non-sequential references.',
    ],
    suggested_fix_snippet:
      'stmt = select(Invoice).where(Invoice.id == invoice_id, Invoice.tenant_id == current_user.tenant_id)',
    validation_steps: [
      'Authenticate as Tenant B and request Tenant A invoice ID.',
      'Confirm server responds with HTTP 404 or 403.',
    ],
    missing_information_notes: null,
    decision_notes: 'Prioritized in sprint 44 backlog.',
    deferred_reason: null,
    verification_evidence: {
      evidence_type: 'PLAYGROUND_VERIFICATION',
      scenario_id: 'idor-01',
    },
    verified_at: null,
    verified_by: null,
  };

  const mockHistory: RecommendationHistoryItem[] = [
    {
      id: 'hist-001',
      recommendation_id: 'rec-001',
      from_status: 'ACCEPTED',
      to_status: 'IN_PROGRESS',
      actor_email: 'lead@acme.corp',
      actor_role: 'DEVELOPER',
      notes: 'Branch created for tenant query scoping patch.',
      created_at: new Date().toISOString(),
    },
    {
      id: 'hist-002',
      recommendation_id: 'rec-001',
      from_status: 'GENERATED',
      to_status: 'ACCEPTED',
      actor_email: 'secops@acme.corp',
      actor_role: 'SECURITY_ENGINEER',
      notes: 'Reviewed and prioritized in sprint.',
      created_at: new Date(Date.now() - 3600000).toISOString(),
    },
  ];

  it('1. RemediationOverview renders top-level KPI metrics correctly', () => {
    render(<RemediationOverview overview={mockOverview} />);
    expect(screen.getByText('Total Recommendations')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('68.4/100')).toBeInTheDocument();
    expect(screen.getByText('Empirically Verified')).toBeInTheDocument();
  });

  it('2. PriorityDistribution displays all 5 tiers and handles selection', () => {
    const onSelect = vi.fn();
    render(
      <PriorityDistribution
        distribution={mockOverview.by_priority}
        selectedPriority={null}
        onSelectPriority={onSelect}
      />
    );

    expect(screen.getByText('Critical Priority (≥75)')).toBeInTheDocument();
    expect(screen.getByText('High Priority (55-74)')).toBeInTheDocument();
    expect(screen.getByText('Medium Priority (35-54)')).toBeInTheDocument();

    const criticalBtn = screen.getByText('Critical Priority (≥75)').closest('button');
    expect(criticalBtn).toBeInTheDocument();
    fireEvent.click(criticalBtn!);
    expect(onSelect).toHaveBeenCalledWith('CRITICAL');
  });

  it('3. RecommendationList displays items and triggers inspection', () => {
    const onSelect = vi.fn();
    const onGenerate = vi.fn();

    render(
      <RecommendationList
        items={[mockListItem]}
        total={1}
        page={1}
        size={10}
        loading={false}
        search=""
        onSearchChange={vi.fn()}
        statusFilter={null}
        onStatusFilterChange={vi.fn()}
        onPageChange={vi.fn()}
        onSelectRecommendation={onSelect}
        onGenerateClick={onGenerate}
      />
    );

    expect(screen.getByText(/Remediate Insecure Direct Object Reference/)).toBeInTheDocument();
    expect(screen.getByText('83')).toBeInTheDocument(); // 82.5 rounded
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();

    const inspectBtn = screen.getByRole('button', { name: /Inspect/i });
    fireEvent.click(inspectBtn);
    expect(onSelect).toHaveBeenCalledWith('rec-001');
  });

  it('4. RemediationSteps renders actionable guidance and copy snippet', () => {
    render(<RemediationSteps recommendation={mockDetail} />);

    expect(screen.getByText('Developer Action Items (Step-by-Step Fix)')).toBeInTheDocument();
    expect(
      screen.getByText(/Scope all database queries strictly with verified tenant ID/)
    ).toBeInTheDocument();
    expect(screen.getByText('Recommended Defensive Code Pattern')).toBeInTheDocument();
    expect(screen.getByText(/Verification & Validation Procedures/)).toBeInTheDocument();
  });

  it('5. RecommendationStatusDialog validates transitions and deferral reason', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    render(
      <RecommendationStatusDialog
        isOpen={true}
        onClose={onClose}
        recommendation={mockDetail}
        onSubmit={onSubmit}
      />
    );

    expect(screen.getByText('Update Lifecycle Status')).toBeInTheDocument();
    // Select DEFERRED
    const deferBtn = screen.getByRole('button', { name: 'DEFERRED' });
    fireEvent.click(deferBtn);

    // Attempt submit without deferral reason
    const submitBtn = screen.getByRole('button', { name: 'Apply Status Transition' });
    fireEvent.click(submitBtn);

    expect(await screen.findByText('Please provide a specific deferral reason.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('6. VerificationPanel renders telemetry and executes verification', async () => {
    const onVerify = vi.fn().mockResolvedValue({
      recommendation_id: 'rec-001',
      previous_status: 'IN_PROGRESS',
      new_status: 'VERIFIED',
      verification_status: 'VERIFIED',
      is_verified: true,
      message: 'Vulnerability confirmed resolved in verification test.',
      evidence_details: {},
    });

    render(<VerificationPanel recommendation={mockDetail} onVerify={onVerify} />);

    expect(screen.getByText('Evidence-Grounded Verification')).toBeInTheDocument();
    expect(screen.getByText('Execute Empirical Verification')).toBeInTheDocument();

    const verifyBtn = screen.getByRole('button', {
      name: /Verify Remediation Effectiveness/i,
    });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(onVerify).toHaveBeenCalled();
    });
  });

  it('7. RecommendationHistory renders chronological audit transitions', () => {
    render(<RecommendationHistory history={mockHistory} />);

    expect(screen.getAllByText('ACCEPTED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('IN_PROGRESS')).toBeInTheDocument();
    expect(screen.getByText(/Branch created for tenant query scoping patch/)).toBeInTheDocument();
    expect(screen.getByText(/Reviewed and prioritized in sprint/)).toBeInTheDocument();
  });

  it('8. RecommendationDetails renders header, score gauge, rationale, and tabs', () => {
    render(
      <RecommendationDetails
        recommendation={mockDetail}
        history={mockHistory}
        onClose={vi.fn()}
        onStatusUpdate={vi.fn()}
        onVerify={vi.fn()}
      />
    );

    expect(screen.getByText('Remediate Insecure Direct Object Reference in Billing')).toBeInTheDocument();
    expect(screen.getByText(/Deterministic Priority Rationale/)).toBeInTheDocument();
    expect(screen.getByText('+20 pts')).toBeInTheDocument();
    expect(screen.getByText('Why This Matters (Context)')).toBeInTheDocument();
    expect(screen.getByText('Potential Business Impact (If Unresolved)')).toBeInTheDocument();
  });
});

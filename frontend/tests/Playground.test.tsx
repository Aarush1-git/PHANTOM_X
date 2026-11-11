import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { ScenarioLibrary } from '../src/components/playground/ScenarioLibrary';
import { ScenarioDetailsPanel } from '../src/components/playground/ScenarioDetailsPanel';
import { TargetSelector } from '../src/components/playground/TargetSelector';
import { ExecutionPlanPreview } from '../src/components/playground/ExecutionPlanPreview';
import { ExecutionAuthorizationDialog } from '../src/components/playground/ExecutionAuthorizationDialog';
import { ExecutionProgress } from '../src/components/playground/ExecutionProgress';
import { PlaygroundResults } from '../src/components/playground/PlaygroundResults';
import { EvidenceViewer } from '../src/components/playground/EvidenceViewer';
import { SessionHistory } from '../src/components/playground/SessionHistory';

import {
  ScenarioInfo,
  PlaygroundTargetInfo,
  PlaygroundSession,
  PlaygroundResult,
} from '../src/types/playground';

describe('Feature 24: PHANTOM Playground Frontend Suite', () => {
  const mockScenario: ScenarioInfo = {
    id: 'auth-01',
    name: 'JWT Algorithm Confusion / None Signature Attack',
    category: 'Authentication Security',
    description: 'Evaluates token verification routines to determine if the server accepts tokens with alg=none.',
    security_objective: 'Validate that authentication tokens cannot be forged or downgraded to insecure signing algorithms.',
    preconditions: ['User authentication endpoint active', 'JWT token issuer configured'],
    required_authorization: 'EXPLICIT_SECURITY_OPERATOR',
    expected_secure_behavior: 'Server rejects token with HTTP 401/403.',
    potential_vulnerability_indicators: ['HTTP 200 OK returned for token with alg=none'],
    risk_level: 'CRITICAL',
    execution_constraints: { rate_limit_rps: 2, safe_read_only: true },
    target_endpoints: ['/api/v1/auth/verify'],
    sample_payload: { alg: 'none', sub: 'admin' },
    is_synthetic_compatible: true,
  };

  const mockTargetSynthetic: PlaygroundTargetInfo = {
    id: 'syn-target-001',
    name: 'PHANTOM Synthetic Microservices Lab',
    target_url: 'synthetic://phantom-sandbox.local',
    target_type: 'SYNTHETIC_TARGET',
    is_synthetic: true,
    scope_status: 'ACTIVE',
    authorization_status: 'AUTHORIZED',
    description: 'Isolated testbed for safe simulated vulnerabilities.',
  };

  const mockTargetProduction: PlaygroundTargetInfo = {
    id: 'app-target-002',
    name: 'Payment Processing Service',
    target_url: 'https://payments.example.com',
    target_type: 'AUTHORIZED_APPLICATION',
    is_synthetic: false,
    scope_status: 'ACTIVE',
    authorization_status: 'AUTHORIZED',
    description: 'Production payment cluster.',
  };

  const mockSession: PlaygroundSession = {
    id: 'sess-uuid-001',
    organization_id: 'org-uuid-001',
    application_id: 'syn-target-001',
    application_name: 'PHANTOM Synthetic Microservices Lab',
    parent_session_id: null,
    scenario_id: 'auth-01',
    scenario_name: 'JWT Algorithm Confusion / None Signature Attack',
    scenario_category: 'Authentication Security',
    target_type: 'SYNTHETIC_TARGET',
    status: 'AWAITING_AUTHORIZATION',
    security_result: null,
    is_authorized: false,
    authorized_by: null,
    authorizer_role: null,
    authorized_at: null,
    execution_plan: {
      target_url: 'synthetic://phantom-sandbox.local',
      endpoint: '/api/v1/auth/verify',
      http_method: 'GET',
      payload_preview: { alg: 'none' },
      safety_classification: 'SAFE_READ_ONLY',
      rate_limit_rps: 2,
      max_concurrency: 1,
      is_synthetic: true,
      safety_restrictions: ['Strict read-only execution constraints enforced'],
    },
    execution_results: {},
    evidence_references: {},
    safety_decisions: {},
    duration_seconds: null,
    notes: 'Initial test run',
    created_at: '2026-11-11T10:00:00Z',
    updated_at: '2026-11-11T10:00:00Z',
  };

  const mockResult: PlaygroundResult = {
    session_id: 'sess-uuid-001',
    scenario_id: 'auth-01',
    scenario_name: 'JWT Algorithm Confusion / None Signature Attack',
    target_application: 'PHANTOM Synthetic Microservices Lab',
    target_url: 'synthetic://phantom-sandbox.local',
    execution_status: 'COMPLETED',
    security_result: 'VULNERABILITY_CONFIRMED',
    vulnerability_category: 'Authentication Security',
    severity: 'CRITICAL',
    expected_behavior: 'Server rejects token with HTTP 401/403.',
    observed_behavior: 'API accepted unsigned JWT token with alg=none without signature verification.',
    evidence_references: {
      request_dump: 'GET /api/v1/auth/verify HTTP/1.1\r\nAuthorization: Bearer test',
      response_dump: 'HTTP/1.1 200 OK\r\n{"role": "ADMIN"}',
      vulnerability_proof: 'Token signature verification bypassed',
    },
    duration_seconds: 0.25,
    safety_decisions: {
      allowed: true,
      reason: 'Execution permitted under authorized Feature 26 scope policy',
    },
    recommended_next_step: 'Explicitly whitelist allowed signing algorithms and reject none.',
    is_synthetic: true,
    previous_result_comparison: null,
  };

  it('1. renders scenario library cards and allows category filtering', () => {
    const onSelect = vi.fn();
    const onView = vi.fn();

    render(
      <ScenarioLibrary
        scenarios={[mockScenario]}
        categories={['Authentication Security', 'Broken Object Level Authorization']}
        selectedScenario={null}
        onSelectScenario={onSelect}
        onViewDetails={onView}
      />
    );

    expect(screen.getByText('JWT Algorithm Confusion / None Signature Attack')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('Synthetic Lab Ready')).toBeInTheDocument();

    const selectBtn = screen.getByRole('button', { name: /select scenario/i });
    fireEvent.click(selectBtn);
    expect(onSelect).toHaveBeenCalledWith(mockScenario);

    const detailsBtn = screen.getByRole('button', { name: /view details/i });
    fireEvent.click(detailsBtn);
    expect(onView).toHaveBeenCalledWith(mockScenario);
  });

  it('2. renders scenario details modal with preconditions, constraints, and payload preview', () => {
    const onClose = vi.fn();
    const onConfigure = vi.fn();

    render(
      <ScenarioDetailsPanel
        scenario={mockScenario}
        onClose={onClose}
        onSelectAndConfigure={onConfigure}
      />
    );

    expect(screen.getByText('JWT Algorithm Confusion / None Signature Attack')).toBeInTheDocument();
    expect(screen.getByText('Expected Secure Behavior')).toBeInTheDocument();
    expect(screen.getByText('Server rejects token with HTTP 401/403.')).toBeInTheDocument();
    expect(screen.getByText('EXPLICIT_SECURITY_OPERATOR')).toBeInTheDocument();

    const configureBtn = screen.getByRole('button', { name: /select scenario & configure target/i });
    fireEvent.click(configureBtn);
    expect(onConfigure).toHaveBeenCalledWith(mockScenario);
  });

  it('3. renders target selector with synthetic isolation badges and scope warnings', () => {
    const onSelect = vi.fn();

    render(
      <TargetSelector
        targets={[mockTargetSynthetic, mockTargetProduction]}
        selectedTarget={mockTargetSynthetic}
        onSelectTarget={onSelect}
      />
    );

    expect(screen.getByText('PHANTOM Synthetic Microservices Lab')).toBeInTheDocument();
    expect(screen.getByText('Payment Processing Service')).toBeInTheDocument();
    expect(screen.getByText('Synthetic Lab')).toBeInTheDocument();
    expect(screen.getByText(/Isolated Sandbox/i)).toBeInTheDocument();

    const prodCard = screen.getByText('Payment Processing Service');
    fireEvent.click(prodCard);
    expect(onSelect).toHaveBeenCalledWith(mockTargetProduction);
  });

  it('4. displays proposed execution plan preview requiring authorization', () => {
    const onAuth = vi.fn();
    const onExecute = vi.fn();

    render(
      <ExecutionPlanPreview
        session={mockSession}
        onOpenAuthorizeModal={onAuth}
        onExecuteNow={onExecute}
      />
    );

    expect(screen.getByText(/AWAITING AUTHORIZATION/i)).toBeInTheDocument();
    expect(screen.getByText('SAFE_READ_ONLY')).toBeInTheDocument();
    expect(screen.getByText(/Strict read-only execution constraints enforced/i)).toBeInTheDocument();

    const authBtn = screen.getByRole('button', { name: /authorize scenario/i });
    fireEvent.click(authBtn);
    expect(onAuth).toHaveBeenCalled();
  });

  it('5. handles execution authorization dialog checkbox validation and submission', async () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn().mockResolvedValue(undefined);

    render(
      <ExecutionAuthorizationDialog
        session={mockSession}
        onClose={onClose}
        onConfirmAuthorization={onConfirm}
      />
    );

    expect(screen.getByText('Explicit Execution Authorization')).toBeInTheDocument();

    // Confirm button should be disabled initially until checkboxes checked
    const confirmBtn = screen.getByRole('button', { name: /confirm authorization/i });
    expect(confirmBtn).toBeDisabled();

    // Check scope agreement
    const scopeCheck = screen.getByText(/I confirm that this target is an authorized application/i);
    fireEvent.click(scopeCheck);

    // Check safe execution agreement
    const safeCheck = screen.getByText(/I acknowledge that requests will be dispatched through the Feature 26 safety engine/i);
    fireEvent.click(safeCheck);

    expect(confirmBtn).not.toBeDisabled();

    fireEvent.click(confirmBtn);
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalled();
    });
  });

  it('6. renders execution progress pipeline with distinct step statuses', () => {
    render(<ExecutionProgress session={mockSession} />);

    expect(screen.getByText(/Execution Lifecycle Pipeline/i)).toBeInTheDocument();
    expect(screen.getByText('Step 01')).toBeInTheDocument();
    expect(screen.getByText('Step 03')).toBeInTheDocument();
    expect(screen.getByText('Step 04')).toBeInTheDocument();
  });

  it('7. displays comprehensive playground results with evidence viewer and replay capability', () => {
    const onReplay = vi.fn();

    render(<PlaygroundResults result={mockResult} onReplay={onReplay} />);

    expect(screen.getByText('Vulnerability Confirmed')).toBeInTheDocument();
    expect(screen.getByText(/Explicitly whitelist allowed signing algorithms/i)).toBeInTheDocument();
    expect(screen.getByText(/DISPATCHED HTTP REQUEST/i)).toBeInTheDocument();
    expect(screen.getByText(/RETURNED HTTP RESPONSE/i)).toBeInTheDocument();
    expect(screen.getByText('Token signature verification bypassed')).toBeInTheDocument();

    const replayBtn = screen.getByRole('button', { name: /replay scenario/i });
    fireEvent.click(replayBtn);
    expect(onReplay).toHaveBeenCalled();
  });

  it('8. renders session history table and allows inspecting previous runs', () => {
    const onSelect = vi.fn();
    const onReplay = vi.fn();

    render(
      <SessionHistory
        sessions={[mockSession]}
        isLoading={false}
        onSelectSession={onSelect}
        onReplaySession={onReplay}
      />
    );

    expect(screen.getByText('JWT Algorithm Confusion / None Signature Attack')).toBeInTheDocument();
    expect(screen.getByText('AWAITING_AUTHORIZATION')).toBeInTheDocument();

    const row = screen.getByText('JWT Algorithm Confusion / None Signature Attack');
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledWith(mockSession);
  });
});

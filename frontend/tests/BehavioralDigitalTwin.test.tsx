import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { DigitalTwinOverview } from "../src/components/behavioral_digital_twin/DigitalTwinOverview";
import { EndpointBehaviorExplorer } from "../src/components/behavioral_digital_twin/EndpointBehaviorExplorer";
import { WorkflowTransitionGraph } from "../src/components/behavioral_digital_twin/WorkflowTransitionGraph";
import { BaselineManager } from "../src/components/behavioral_digital_twin/BaselineManager";
import { AnomalyExplorer } from "../src/components/behavioral_digital_twin/AnomalyExplorer";
import { BehavioralDigitalTwinPanel } from "../src/components/behavioral_digital_twin/BehavioralDigitalTwinPanel";
import { digitalTwinApi } from "../src/services/digitalTwinApi";

import {
  DigitalTwinOverviewResponse,
  BehavioralBaseline,
  BehavioralAnomalyResponse,
} from "../src/types/digitalTwin";

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

describe("Feature 4: Behavioral Digital Twin UI Components", () => {
  const mockOverview: DigitalTwinOverviewResponse = {
    application_id: "app-uuid-123",
    organization_id: "org-uuid-456",
    total_observations: 150,
    active_baseline_id: "base-uuid-789",
    active_baseline_version: "v1.2",
    active_baseline_confidence: 0.85,
    total_transitions_tracked: 8,
    open_anomalies_count: 2,
    last_observed_at: "2026-11-12T10:00:00Z",
    endpoint_profiles: {
      "POST:/api/v1/checkout": {
        method: "POST",
        normalized_path: "/api/v1/checkout",
        total_requests: 100,
        status_code_distribution: { "200": 95, "500": 5 },
        latency_stats: { min_ms: 50, avg_ms: 110, p95_ms: 180, max_ms: 250 },
        inferred_request_schema: { type: "object", properties: { amount: { type: "number" } } },
        inferred_response_schema: { type: "object", properties: { order_id: { type: "string" } } },
        confidence_score: 0.9,
      },
    },
    latest_anomalies: [],
  };

  const mockBaselines: BehavioralBaseline[] = [
    {
      id: "base-uuid-789",
      organization_id: "org-uuid-456",
      application_id: "app-uuid-123",
      version: "v1.2",
      status: "ACTIVE",
      sample_count: 100,
      confidence_score: 0.85,
      endpoint_profiles: {},
      transition_matrix: { "POST:/api/v1/checkout": { "GET:/api/v1/receipt": 0.95 } },
      created_at: "2026-11-10T12:00:00Z",
      activated_at: "2026-11-10T12:05:00Z",
    },
    {
      id: "base-uuid-001",
      organization_id: "org-uuid-456",
      application_id: "app-uuid-123",
      version: "v1.0",
      status: "SUPERSEDED",
      sample_count: 40,
      confidence_score: 0.7,
      endpoint_profiles: {},
      transition_matrix: {},
      created_at: "2026-11-05T10:00:00Z",
    },
  ];

  const mockAnomalies: BehavioralAnomalyResponse[] = [
    {
      id: "anom-uuid-1",
      organization_id: "org-uuid-456",
      application_id: "app-uuid-123",
      anomaly_type: "UNEXPECTED_STATUS_CODE",
      severity: "HIGH",
      confidence: 0.9,
      evidence_data: {
        observed_status_code: 500,
        endpoint_key: "POST:/api/v1/checkout",
        occurrence_count: 4,
        description: "Unexpected server error (500) on POST:/api/v1/checkout",
      },
      status: "OPEN",
      detected_at: "2026-11-12T09:30:00Z",
    },
    {
      id: "anom-uuid-2",
      organization_id: "org-uuid-456",
      application_id: "app-uuid-123",
      anomaly_type: "LATENCY_SPIKE",
      severity: "LOW",
      confidence: 0.65,
      evidence_data: {
        observed_latency_ms: 850,
        occurrence_count: 1,
      },
      status: "RESOLVED",
      detected_at: "2026-11-11T14:00:00Z",
      resolved_at: "2026-11-11T16:00:00Z",
    },
  ];

  // 1. DigitalTwinOverview Tests
  it("renders digital twin overview metrics and confidence properly", () => {
    const handleEvaluate = vi.fn();
    render(
      <DigitalTwinOverview
        overview={mockOverview}
        onTriggerDriftEvaluation={handleEvaluate}
      />
    );

    expect(screen.getByText("Total Observations")).toBeInTheDocument();
    expect(screen.getByText("150")).toBeInTheDocument();
    expect(screen.getByText("1 Endpoints")).toBeInTheDocument();
    expect(screen.getByText("v1.2")).toBeInTheDocument();
    expect(screen.getByText("Confidence: 85%")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument(); // open anomalies count

    const evalBtn = screen.getByText("Trigger Drift Evaluation");
    fireEvent.click(evalBtn);
    expect(handleEvaluate).toHaveBeenCalledTimes(1);
  });

  // 2. EndpointBehaviorExplorer Tests
  it("renders endpoint behavior profiles and toggles schema inspector", () => {
    render(<EndpointBehaviorExplorer endpointProfiles={mockOverview.endpoint_profiles} />);

    expect(screen.getByText("/api/v1/checkout")).toBeInTheDocument();
    expect(screen.getByText("POST")).toBeInTheDocument();
    expect(screen.getByText("P95:")).toBeInTheDocument();
    expect(screen.getByText("180ms")).toBeInTheDocument();
    expect(screen.getByText("90%")).toBeInTheDocument(); // confidence

    // Expand schema
    const row = screen.getByText("/api/v1/checkout");
    fireEvent.click(row);

    expect(screen.getByText("Latency Profile")).toBeInTheDocument();
    expect(screen.getByText("Inferred Request Schema")).toBeInTheDocument();
    expect(screen.getByText("Inferred Response Schema")).toBeInTheDocument();
  });

  it("renders empty state when no endpoint profiles exist", () => {
    render(<EndpointBehaviorExplorer endpointProfiles={{}} />);
    expect(screen.getByText("No Endpoint Profiles Available")).toBeInTheDocument();
  });

  // 3. WorkflowTransitionGraph Tests
  it("renders empty state when transition matrix is empty", () => {
    render(<WorkflowTransitionGraph transitionMatrix={{}} />);
    expect(screen.getByText("No Workflow Sequences Learned")).toBeInTheDocument();
  });

  // 4. BaselineManager Tests
  it("renders baselines list with version tags and status badges", () => {
    const onCompile = vi.fn();
    const onActivate = vi.fn();
    const onArchive = vi.fn();

    render(
      <BaselineManager
        baselines={mockBaselines}
        onCompileBaseline={onCompile}
        onActivateBaseline={onActivate}
        onArchiveBaseline={onArchive}
      />
    );

    expect(screen.getByText("v1.2")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    expect(screen.getByText("Primary Baseline")).toBeInTheDocument();
    expect(screen.getByText("v1.0")).toBeInTheDocument();
    expect(screen.getByText("SUPERSEDED")).toBeInTheDocument();

    // Open compile modal
    const compileBtn = screen.getByText("Compile Baseline");
    fireEvent.click(compileBtn);
    expect(screen.getByText("Compile New Baseline Snapshot")).toBeInTheDocument();
  });

  // 5. AnomalyExplorer Tests
  it("renders behavioral anomalies with non-vulnerability notice and filters", () => {
    const onAck = vi.fn();
    const onResolve = vi.fn();

    render(
      <AnomalyExplorer
        anomalies={mockAnomalies}
        onAcknowledge={onAck}
        onResolve={onResolve}
      />
    );

    expect(screen.getByText("NOTICE: BEHAVIORAL DEVIATION TELEMETRY")).toBeInTheDocument();
    expect(screen.getByText("UNEXPECTED STATUS CODE")).toBeInTheDocument();
    expect(screen.getByText("LATENCY SPIKE")).toBeInTheDocument();
    expect(screen.getByText("4x")).toBeInTheDocument(); // occurrence count

    // Inspect Evidence modal
    const evidenceButtons = screen.getAllByText("Evidence");
    fireEvent.click(evidenceButtons[0]);

    expect(screen.getByText("SANITIZED FORENSIC EVIDENCE PAYLOAD")).toBeInTheDocument();
    expect(screen.getByText("Close")).toBeInTheDocument();
  });

  // 6. BehavioralDigitalTwinPanel Container Test
  it("renders loading state initially and renders panel once data loads", async () => {
    vi.spyOn(digitalTwinApi, "getOverview").mockResolvedValue(mockOverview);
    vi.spyOn(digitalTwinApi, "listBaselines").mockResolvedValue({ items: mockBaselines, total: 2 });
    vi.spyOn(digitalTwinApi, "listAnomalies").mockResolvedValue({ items: mockAnomalies, total: 2, page: 1, limit: 100 });

    const client = createTestQueryClient();
    render(
      <QueryClientProvider client={client}>
        <BehavioralDigitalTwinPanel applicationId="app-uuid-123" />
      </QueryClientProvider>
    );

    expect(await screen.findByText("Behavioral Digital Twin")).toBeInTheDocument();
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("Endpoint Profiles")).toBeInTheDocument();
    expect(screen.getByText("State Machine")).toBeInTheDocument();
    expect(screen.getByText("Baselines")).toBeInTheDocument();
    expect(screen.getByText("Anomalies")).toBeInTheDocument();
  });
});

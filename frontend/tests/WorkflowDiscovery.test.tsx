import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { WorkflowDiscoveryOverview } from "../src/components/workflow_discovery/WorkflowDiscoveryOverview";
import { WorkflowGraphView } from "../src/components/workflow_discovery/WorkflowGraphView";
import { WorkflowList } from "../src/components/workflow_discovery/WorkflowList";
import { WorkflowDetailModal } from "../src/components/workflow_discovery/WorkflowDetailModal";
import { WorkflowDiscoveryPanel } from "../src/components/workflow_discovery/WorkflowDiscoveryPanel";
import { workflowApi } from "../src/services/workflowApi";

import {
  WorkflowOverview,
  DiscoveredWorkflow,
  DiscoveredWorkflowDetail,
  WorkflowGraph,
} from "../src/types/workflow";

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

describe("Feature 5: Application Workflow Discovery UI Components", () => {
  const mockOverview: WorkflowOverview = {
    application_id: "app-uuid-123",
    total_workflows: 5,
    active_workflows: 4,
    incomplete_workflows: 1,
    branched_workflows: 2,
    average_steps: 3.5,
    high_confidence_count: 3,
    total_observed_sessions: 24,
    insufficient_data: false,
  };

  const mockGraph: WorkflowGraph = {
    nodes: [
      {
        id: "POST:/api/v1/auth/login",
        label: "POST /api/v1/auth/login",
        method: "POST",
        normalized_path: "/api/v1/auth/login",
        step_type: "ENTRY",
        observation_count: 20,
        avg_latency_ms: 45.0,
        error_rate: 0.05,
      },
      {
        id: "POST:/api/v1/cart/checkout",
        label: "POST /api/v1/cart/checkout",
        method: "POST",
        normalized_path: "/api/v1/cart/checkout",
        step_type: "TERMINAL",
        observation_count: 18,
        avg_latency_ms: 120.0,
        error_rate: 0.1,
      },
    ],
    edges: [
      {
        id: "POST:/api/v1/auth/login->POST:/api/v1/cart/checkout",
        source: "POST:/api/v1/auth/login",
        target: "POST:/api/v1/cart/checkout",
        transition_count: 18,
        probability: 0.9,
        confidence: 0.85,
      },
    ],
  };

  const mockWorkflows: DiscoveredWorkflow[] = [
    {
      id: "wf-1",
      organization_id: "org-1",
      application_id: "app-uuid-123",
      name: "POST /api/v1/auth/login → POST /api/v1/cart/checkout",
      description: "Discovered user journey with 2 steps",
      workflow_type: "STANDARD",
      status: "DISCOVERED",
      confidence_score: 0.88,
      sample_count: 18,
      step_count: 2,
      is_incomplete: false,
      dropout_step_index: null,
      steps_sequence: [
        {
          step_index: 0,
          method: "POST",
          normalized_path: "/api/v1/auth/login",
          step_type: "ENTRY",
          avg_latency_ms: 45.0,
          error_rate: 0.0,
          sample_count: 18,
          observation_ids: ["obs-1"],
        },
        {
          step_index: 1,
          method: "POST",
          normalized_path: "/api/v1/cart/checkout",
          step_type: "TERMINAL",
          avg_latency_ms: 120.0,
          error_rate: 0.05,
          sample_count: 18,
          observation_ids: ["obs-2"],
        },
      ],
      discovered_at: "2026-11-12T10:00:00Z",
      last_observed_at: "2026-11-12T10:00:00Z",
      created_at: "2026-11-12T10:00:00Z",
      updated_at: "2026-11-12T10:00:00Z",
    },
    {
      id: "wf-2",
      organization_id: "org-1",
      application_id: "app-uuid-123",
      name: "POST /api/v1/auth/login → GET /api/v1/search (Dropped)",
      description: "Abandoned journey",
      workflow_type: "ABANDONED",
      status: "DISCOVERED",
      confidence_score: 0.65,
      sample_count: 4,
      step_count: 2,
      is_incomplete: true,
      dropout_step_index: 1,
      steps_sequence: [],
      discovered_at: "2026-11-12T10:00:00Z",
      last_observed_at: "2026-11-12T10:00:00Z",
      created_at: "2026-11-12T10:00:00Z",
      updated_at: "2026-11-12T10:00:00Z",
    },
  ];

  it("1. renders overview metrics and handles discovery click", () => {
    const handleTrigger = vi.fn();
    render(
      <WorkflowDiscoveryOverview
        overview={mockOverview}
        isDiscovering={false}
        onTriggerDiscovery={handleTrigger}
      />
    );

    expect(screen.getByText("Total Journeys")).toBeDefined();
    expect(screen.getByText("5")).toBeDefined();
    expect(screen.getByText("Active")).toBeDefined();
    expect(screen.getByText("4")).toBeDefined();
    expect(screen.getByText("Incomplete / Drop")).toBeDefined();
    expect(screen.getByText("1")).toBeDefined();
    expect(screen.getByText("Branched")).toBeDefined();
    expect(screen.getByText("2")).toBeDefined();
    expect(screen.getByText("3.5")).toBeDefined();

    const triggerBtn = screen.getByText("Re-Discover Workflows");
    fireEvent.click(triggerBtn);
    expect(handleTrigger).toHaveBeenCalledOnce();
  });

  it("2. renders workflow graph with nodes and edges", () => {
    render(<WorkflowGraphView graph={mockGraph} workflowName="Sample Workflow" />);

    expect(screen.getByText("Sample Workflow")).toBeDefined();
    expect(screen.getByText("ENTRY")).toBeDefined();
    expect(screen.getByText("TERMINAL")).toBeDefined();
    expect(screen.getByText("/api/v1/auth/login")).toBeDefined();
    expect(screen.getByText("/api/v1/cart/checkout")).toBeDefined();
  });

  it("3. renders workflow list with type badges, confidence, and filters", () => {
    const handleSelect = vi.fn();
    const handleViewDetails = vi.fn();

    render(
      <WorkflowList
        workflows={mockWorkflows}
        total={2}
        page={1}
        pageSize={10}
        selectedWorkflowId="wf-1"
        onSelectWorkflow={handleSelect}
        onViewDetails={handleViewDetails}
        onPageChange={vi.fn()}
        typeFilter=""
        onTypeFilterChange={vi.fn()}
        confidenceFilter={0}
        onConfidenceFilterChange={vi.fn()}
        incompleteFilter=""
        onIncompleteFilterChange={vi.fn()}
      />
    );

    expect(screen.getByText("STANDARD")).toBeDefined();
    expect(screen.getByText("ABANDONED")).toBeDefined();
    expect(screen.getByText("88%")).toBeDefined();
    expect(screen.getByText("65%")).toBeDefined();

    // Click details
    const detailButtons = screen.getAllByText("Details");
    fireEvent.click(detailButtons[0]);
    expect(handleViewDetails).toHaveBeenCalledWith(mockWorkflows[0]);
  });

  it("4. renders workflow detail modal with step sequence", () => {
    const handleClose = vi.fn();
    const detailWf: DiscoveredWorkflowDetail = {
      ...mockWorkflows[0],
      graph_data: mockGraph,
      variations: { branch_points: ["/api/v1/search"] },
    };

    render(<WorkflowDetailModal workflow={detailWf} onClose={handleClose} />);

    expect(screen.getByText("Ordered Journey Steps (2)")).toBeDefined();
    expect(screen.getByText("Multi-tenant isolated & sanitized")).toBeDefined();

    const closeBtn = screen.getByText("Close");
    fireEvent.click(closeBtn);
    expect(handleClose).toHaveBeenCalledOnce();
  });

  it("5. renders insufficient data state when observations are inadequate", async () => {
    const client = createTestQueryClient();
    vi.spyOn(workflowApi, "getOverview").mockResolvedValue({
      application_id: "app-empty",
      total_workflows: 0,
      active_workflows: 0,
      incomplete_workflows: 0,
      branched_workflows: 0,
      average_steps: 0,
      high_confidence_count: 0,
      total_observed_sessions: 0,
      insufficient_data: true,
    });
    vi.spyOn(workflowApi, "listWorkflows").mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 10,
    });

    render(
      <QueryClientProvider client={client}>
        <WorkflowDiscoveryPanel applicationId="app-empty" />
      </QueryClientProvider>
    );

    expect(
      await screen.findByText("Insufficient Workflow Telemetry")
    ).toBeDefined();
    expect(
      screen.getByText(/minimum 2 observations required/i)
    ).toBeDefined();
  });

  it("6. renders master panel with overview, graph, and workflow list", async () => {
    const client = createTestQueryClient();
    vi.spyOn(workflowApi, "getOverview").mockResolvedValue(mockOverview);
    vi.spyOn(workflowApi, "listWorkflows").mockResolvedValue({
      items: mockWorkflows,
      total: 2,
      page: 1,
      page_size: 10,
    });
    vi.spyOn(workflowApi, "getWorkflowDetail").mockResolvedValue({
      ...mockWorkflows[0],
      graph_data: mockGraph,
      variations: {},
    });

    render(
      <QueryClientProvider client={client}>
        <WorkflowDiscoveryPanel applicationId="app-uuid-123" />
      </QueryClientProvider>
    );

    expect(await screen.findByText("Total Journeys")).toBeDefined();
    expect(
      screen.getByText("Discovered Application Journeys")
    ).toBeDefined();
    expect(
      await screen.findByText("Selected Journey Graph Visualization")
    ).toBeDefined();
  });
});

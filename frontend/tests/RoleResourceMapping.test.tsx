import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { RoleResourceOverviewComponent } from "../src/components/role_resource_mapping/RoleResourceOverview";
import { RoleResourceGraphView } from "../src/components/role_resource_mapping/RoleResourceGraphView";
import { MappingExplorer } from "../src/components/role_resource_mapping/MappingExplorer";
import { DiscrepancyInspector } from "../src/components/role_resource_mapping/DiscrepancyInspector";
import { RolesResourcesView } from "../src/components/role_resource_mapping/RolesResourcesView";
import { EvidenceDetailModal } from "../src/components/role_resource_mapping/EvidenceDetailModal";
import { RoleResourceMappingPanel } from "../src/components/role_resource_mapping/RoleResourceMappingPanel";
import { roleResourceApi } from "../src/services/roleResourceApi";

import {
  RoleResourceOverview,
  RoleResourceMapping,
  DiscrepancyListResponse,
  ApplicationRoleMapping,
  ApplicationResourceMapping,
} from "../src/types/roleResource";

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

describe("Feature 6: Role & Resource Relationship Mapping UI Components", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const mockOverview: RoleResourceOverview = {
    application_id: "app-uuid-123",
    total_roles: 3,
    total_resources: 4,
    total_mappings: 12,
    declared_count: 5,
    observed_count: 4,
    inferred_count: 3,
    discrepancies_count: 2,
    high_confidence_count: 7,
    insufficient_evidence: false,
    insufficient_evidence_reason: null,
  };

  const mockMappings: RoleResourceMapping[] = [
    {
      id: "map-1",
      organization_id: "org-1",
      application_id: "app-uuid-123",
      subject_type: "ROLE",
      subject_id: "role-admin",
      subject_name: "admin",
      object_type: "ENDPOINT",
      object_id: "ep-1",
      object_name: "/api/v1/users",
      relationship_type: "ROLE_ACCESSES_ENDPOINT",
      evidence_source: "DECLARED",
      confidence_score: 1.0,
      sample_count: 5,
      access_telemetry: {
        request_outcomes: { "2xx": 5, "4xx": 0, "5xx": 0 },
        authentication_status: "AUTHENTICATED",
        authorization_status: "UNSPECIFIED",
      },
      declared_vs_observed: {
        declared_in_spec: true,
        observed_in_traffic: true,
        discrepancy_category: "ALIGNED",
        notes: "Aligned with spec.",
      },
      status: "ACTIVE",
      discovered_at: "2026-11-12T10:00:00Z",
      last_observed_at: "2026-11-12T12:00:00Z",
      created_at: "2026-11-12T10:00:00Z",
      updated_at: "2026-11-12T12:00:00Z",
    },
    {
      id: "map-2",
      organization_id: "org-1",
      application_id: "app-uuid-123",
      subject_type: "ROLE",
      subject_id: "role-analyst",
      subject_name: "analyst",
      object_type: "RESOURCE",
      object_id: "res-reports",
      object_name: "reports",
      relationship_type: "ROLE_ACCESSES_RESOURCE",
      evidence_source: "OBSERVED",
      confidence_score: 0.85,
      sample_count: 14,
      access_telemetry: {
        request_outcomes: { "2xx": 12, "4xx": 2, "5xx": 0 },
        authentication_status: "AUTHENTICATED",
        authorization_status: "EXPLICIT_DENY",
        authorization_scope: "REQUEST_INSTANCE",
        authorization_note:
          "HTTP 403 observed for this specific request instance. This indicates an explicit access denial for the requested target or parameter set, but does NOT establish that the role universally lacks permission to this endpoint or resource.",
      },
      declared_vs_observed: {
        declared_in_spec: false,
        observed_in_traffic: true,
        discrepancy_category: "OBSERVED_NOT_DECLARED",
        notes: "Observed in traffic but missing in declared role permissions.",
      },
      status: "ACTIVE",
      discovered_at: "2026-11-12T10:00:00Z",
      last_observed_at: "2026-11-12T12:00:00Z",
      created_at: "2026-11-12T10:00:00Z",
      updated_at: "2026-11-12T12:00:00Z",
    },
    {
      id: "map-3",
      organization_id: "org-1",
      application_id: "app-uuid-123",
      subject_type: "RESOURCE",
      subject_id: null,
      subject_name: "accounts",
      object_type: "RESOURCE",
      object_id: null,
      object_name: "orders",
      relationship_type: "STRUCTURAL_CONTAINMENT",
      evidence_source: "INFERRED",
      confidence_score: 0.6,
      sample_count: 1,
      access_telemetry: {},
      declared_vs_observed: {
        declared_in_spec: false,
        observed_in_traffic: false,
        discrepancy_category: "NONE",
      },
      status: "CANDIDATE",
      discovered_at: "2026-11-12T10:00:00Z",
      last_observed_at: "2026-11-12T12:00:00Z",
      created_at: "2026-11-12T10:00:00Z",
      updated_at: "2026-11-12T12:00:00Z",
    },
  ];

  const mockDiscrepancies: DiscrepancyListResponse = {
    application_id: "app-uuid-123",
    total_discrepancies: 2,
    category_filter: null,
    breakdown: {
      ALIGNED: 1,
      DECLARED_NOT_OBSERVED: 1,
      OBSERVED_NOT_DECLARED: 1,
      EVIDENCE_INSUFFICIENT: 0,
    },
    items: [mockMappings[0], mockMappings[1]],
    evidence_limitations_note:
      "Discrepancies represent empirical differences between declared specifications and observed traffic telemetry. They do NOT constitute verified security vulnerabilities, and unexercised permissions must not be assumed absent.",
  };

  const mockRoles: ApplicationRoleMapping[] = [
    {
      role_id: "role-admin",
      role_name: "admin",
      description: "Full application administrative privileges",
      declared_permissions: { endpoints: ["/api/v1/users"], resources: ["users"] },
      discovered_endpoints: ["/api/v1/users", "/api/v1/settings"],
      discovered_resources: ["users", "settings"],
      mappings: [mockMappings[0]],
    },
  ];

  const mockResources: ApplicationResourceMapping[] = [
    {
      resource_name: "accounts",
      structural_parents: [],
      structural_children: ["orders"],
      accessing_roles: ["admin"],
      mappings: [mockMappings[2]],
    },
  ];

  it("1. renders overview metrics and provenance breakdown", () => {
    const handleTrigger = vi.fn();
    render(
      <RoleResourceOverviewComponent
        overview={mockOverview}
        isDiscovering={false}
        onTriggerDiscovery={handleTrigger}
      />
    );

    // Verify key counts
    expect(screen.getByText("Total Mappings")).toBeDefined();
    expect(screen.getByText("12")).toBeDefined();
    expect(screen.getAllByText("3").length).toBeGreaterThanOrEqual(1); // roles & inferred
    expect(screen.getAllByText("4").length).toBeGreaterThanOrEqual(1); // resources & observed
    expect(screen.getByText("2")).toBeDefined(); // discrepancies

    // Provenance breakdown
    expect(screen.getByText("Declared (Specs)")).toBeDefined();
    expect(screen.getByText("Observed (Traffic)")).toBeDefined();
    expect(screen.getByText("Inferred (Structure/Overlap)")).toBeDefined();

    // Trigger buttons
    const discoverAllBtn = screen.getByText("Discover All");
    fireEvent.click(discoverAllBtn);
    expect(handleTrigger).toHaveBeenCalledWith("ALL");

    const declaredBtn = screen.getByText("Declared Specs Only");
    fireEvent.click(declaredBtn);
    expect(handleTrigger).toHaveBeenCalledWith("DECLARED");
  });

  it("2. renders warning when insufficient observation evidence is present", () => {
    const insufficientOverview: RoleResourceOverview = {
      ...mockOverview,
      insufficient_evidence: true,
      insufficient_evidence_reason: "Minimum 5 traffic samples required.",
    };

    render(
      <RoleResourceOverviewComponent
        overview={insufficientOverview}
        isDiscovering={false}
        onTriggerDiscovery={vi.fn()}
      />
    );

    expect(screen.getByText(/Insufficient Observation Evidence/i)).toBeDefined();
    expect(screen.getByText(/Minimum 5 traffic samples required/i)).toBeDefined();
  });

  it("3. renders relationship graph view with nodes and edges", () => {
    const handleSelect = vi.fn();
    render(
      <RoleResourceGraphView mappings={mockMappings} onSelectMapping={handleSelect} />
    );

    // Legend items
    expect(screen.getByText("Declared")).toBeDefined();
    expect(screen.getByText("Observed")).toBeDefined();
    expect(screen.getByText("Inferred")).toBeDefined();
  });

  it("4. renders mapping explorer table and filters", () => {
    const handlePage = vi.fn();
    const handleInspect = vi.fn();

    render(
      <MappingExplorer
        mappings={mockMappings}
        total={3}
        page={1}
        pageSize={10}
        onPageChange={handlePage}
        subjectTypeFilter=""
        onSubjectTypeFilterChange={vi.fn()}
        objectTypeFilter=""
        onObjectTypeFilterChange={vi.fn()}
        relationshipTypeFilter=""
        onRelationshipTypeFilterChange={vi.fn()}
        sourceFilter=""
        onSourceFilterChange={vi.fn()}
        statusFilter=""
        onStatusFilterChange={vi.fn()}
        minConfidenceFilter={0}
        onMinConfidenceFilterChange={vi.fn()}
        onInspectMapping={handleInspect}
      />
    );

    expect(screen.getByText("Mapping Filters & Constraints")).toBeDefined();
    expect(screen.getByText("admin")).toBeDefined();
    expect(screen.getByText("analyst")).toBeDefined();
    expect(screen.getByText("accounts")).toBeDefined();

    // Inspect buttons
    const inspectButtons = screen.getAllByText("Inspect");
    expect(inspectButtons.length).toBe(3);
    fireEvent.click(inspectButtons[0]);
    expect(handleInspect).toHaveBeenCalledWith(mockMappings[0]);
  });

  it("5. renders discrepancy inspector with disclaimer note and category breakdown", () => {
    const handleCategory = vi.fn();
    const handleInspect = vi.fn();

    render(
      <DiscrepancyInspector
        discrepancyData={mockDiscrepancies}
        onSelectCategory={handleCategory}
        selectedCategory=""
        onInspectMapping={handleInspect}
      />
    );

    // Prominent analytical boundary disclaimer
    expect(
      screen.getByText(/Empirical Discrepancy Analysis — Analytical Boundary Notice/i)
    ).toBeDefined();
    expect(
      screen.getByText(/They do NOT constitute verified security vulnerabilities/i)
    ).toBeDefined();

    // Breakdown counts
    expect(screen.getAllByText("ALIGNED").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("DECLARED NOT OBSERVED").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("OBSERVED NOT DECLARED").length).toBeGreaterThanOrEqual(1);

    // Filter click
    const declaredNotObservedButtons = screen.getAllByText("DECLARED NOT OBSERVED");
    fireEvent.click(declaredNotObservedButtons[0]);
    expect(handleCategory).toHaveBeenCalledWith("DECLARED_NOT_OBSERVED");
  });

  it("6. renders evidence detail modal with HTTP 403 request-scoped disclaimer", async () => {
    const handleClose = vi.fn();
    vi.spyOn(roleResourceApi, "getEvidence").mockResolvedValue({
      mapping_id: mockMappings[1].id,
      total_evidence: 1,
      items: [
        {
          observation_id: "obs-1",
          session_token_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          method: "GET",
          normalized_path: "/api/v1/reports",
          status_code: 403,
          latency_ms: 35.0,
          observed_at: "2026-11-12T11:00:00Z",
          sanitized_request_schema: { params: ["report_id"] },
          sanitized_response_schema: { detail: "Denied" },
        },
      ],
    });

    const client = createTestQueryClient();
    render(
      <QueryClientProvider client={client}>
        <EvidenceDetailModal mapping={mockMappings[1]} onClose={handleClose} />
      </QueryClientProvider>
    );

    // Verify modal header & HTTP 403 disclaimer
    expect(screen.getByText("Evidence & Telemetry Inspector")).toBeDefined();
    expect(
      screen.getByText("Request-Scoped Access Denial Observed")
    ).toBeDefined();
    expect(
      screen.getByText(/does NOT establish that the role universally lacks permission/i)
    ).toBeDefined();

    // Check Safe Sanitization footer
    expect(
      screen.getByText(/Safe Sanitization Active: Credentials, tokens, and raw bodies excluded/i)
    ).toBeDefined();

    // Switch to Observations tab
    const obsTab = screen.getByText(/Sanitized Observations/i);
    fireEvent.click(obsTab);

    expect(await screen.findByText("HTTP 403")).toBeDefined();
    expect(screen.getByText("GET")).toBeDefined();
    expect(screen.getByText("/api/v1/reports")).toBeDefined();
    // Session token hash (shortened)
    expect(screen.getByText(/e3b0c44298fc1c14/i)).toBeDefined();

    // Close modal
    const closeBtn = screen.getByText("Close");
    fireEvent.click(closeBtn);
    expect(handleClose).toHaveBeenCalledOnce();
  });

  it("7. renders roles and resources view with sub-tab switching", () => {
    render(<RolesResourcesView roles={mockRoles} resources={mockResources} />);

    // Default: Roles
    expect(screen.getByText("Application Roles (1)")).toBeDefined();
    expect(screen.getByText("admin")).toBeDefined();
    expect(screen.getByText("Full application administrative privileges")).toBeDefined();
    expect(screen.getByText("Discovered Endpoints (2)")).toBeDefined();

    // Switch to Resources
    const resTab = screen.getByText("Domain Resources (1)");
    fireEvent.click(resTab);

    expect(screen.getByText("accounts")).toBeDefined();
    expect(screen.getByText("Structural Children")).toBeDefined();
    expect(screen.getByText("orders")).toBeDefined();
    expect(screen.getByText("Accessing Roles")).toBeDefined();
  });

  it("8. renders RoleResourceMappingPanel master component with sub-tabs", async () => {
    const client = createTestQueryClient();
    vi.spyOn(roleResourceApi, "getOverview").mockResolvedValue(mockOverview);
    vi.spyOn(roleResourceApi, "listMappings").mockResolvedValue({
      items: mockMappings,
      total: 3,
      page: 1,
      page_size: 15,
    });
    vi.spyOn(roleResourceApi, "getDiscrepancies").mockResolvedValue(mockDiscrepancies);
    vi.spyOn(roleResourceApi, "getRoles").mockResolvedValue({
      application_id: "app-uuid-123",
      total_roles: 1,
      items: mockRoles,
    });
    vi.spyOn(roleResourceApi, "getResources").mockResolvedValue({
      application_id: "app-uuid-123",
      total_resources: 1,
      items: mockResources,
    });

    render(
      <QueryClientProvider client={client}>
        <RoleResourceMappingPanel applicationId="app-uuid-123" />
      </QueryClientProvider>
    );

    // Initial Overview tab
    expect(await screen.findByText("Total Mappings")).toBeDefined();
    expect(screen.getByText("Relationship Provenance Breakdown")).toBeDefined();

    // Switch to Mapping Explorer tab
    const explorerTab = screen.getByText("Mapping Explorer");
    fireEvent.click(explorerTab);
    expect(await screen.findByText("Mapping Filters & Constraints")).toBeDefined();

    // Switch to Declared vs Observed tab
    const discTab = screen.getByText("Declared vs. Observed");
    fireEvent.click(discTab);
    expect(
      await screen.findByText("Empirical Discrepancy Analysis — Analytical Boundary Notice")
    ).toBeDefined();

    // Switch to Roles & Resources tab
    const entitiesTab = screen.getByText("Roles & Resources");
    fireEvent.click(entitiesTab);
    expect(await screen.findByText("Application Roles (1)")).toBeDefined();
  });

  it("9. renders error state gracefully when overview query fails", async () => {
    const client = createTestQueryClient();
    vi.spyOn(roleResourceApi, "getOverview").mockRejectedValue(
      new Error("Network connection error")
    );

    render(
      <QueryClientProvider client={client}>
        <RoleResourceMappingPanel applicationId="app-error-123" />
      </QueryClientProvider>
    );

    expect(
      await screen.findByText("Failed to load Role & Resource Mapping data")
    ).toBeDefined();
    expect(screen.getByText("Retry")).toBeDefined();
  });
});

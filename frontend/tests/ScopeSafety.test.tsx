import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScopeStatusBadge, AuthorizationStatusBadge } from "../src/components/settings/ScopeBadge";
import { ScopePolicyList } from "../src/components/settings/ScopePolicyList";
import { TestValidationSimulator } from "../src/components/settings/TestValidationSimulator";
import { ScopePolicyResponse } from "../src/types";

describe("Feature 26: Scope, Permission & Safety UI Components", () => {
  it("renders ScopeStatusBadge with proper styles and labels", () => {
    const { rerender } = render(<ScopeStatusBadge status="ACTIVE" />);
    expect(screen.getByText("SCOPE: ACTIVE")).toBeInTheDocument();

    rerender(<ScopeStatusBadge status="DRAFT" />);
    expect(screen.getByText("SCOPE: DRAFT")).toBeInTheDocument();

    rerender(<ScopeStatusBadge status="SUSPENDED" />);
    expect(screen.getByText("SCOPE: SUSPENDED")).toBeInTheDocument();
  });

  it("renders AuthorizationStatusBadge with proper labels", () => {
    const { rerender } = render(<AuthorizationStatusBadge status="PENDING" />);
    expect(screen.getByText("AUTH: PENDING")).toBeInTheDocument();

    rerender(<AuthorizationStatusBadge status="AUTHORIZED" />);
    expect(screen.getByText("AUTH: AUTHORIZED")).toBeInTheDocument();

    rerender(<AuthorizationStatusBadge status="REVOKED" />);
    expect(screen.getByText("AUTH: REVOKED")).toBeInTheDocument();
  });

  it("renders ScopePolicyList with policies and action triggers", () => {
    const mockScope: ScopePolicyResponse = {
      id: "scope-1",
      organization_id: "org-1",
      application_id: "app-1",
      application_name: "Core Payment Engine",
      target_domain: "api.payments.local",
      base_url: "https://api.payments.local/v1",
      permitted_paths: ["/v1/*"],
      excluded_paths: ["/admin/*"],
      scope_status: "ACTIVE",
      authorization_status: "AUTHORIZED",
      authorized_by: "secops@payments.local",
      authorizer_role: "AppSec Lead",
      valid_from: "2026-11-01T00:00:00Z",
      valid_until: "2026-12-01T00:00:00Z",
      rate_limit_rps: 15,
      max_concurrency: 2,
      max_scan_duration_minutes: 60,
      allowed_methods: ["GET", "POST"],
      restricted_endpoint_patterns: ["*/delete-account*"],
      require_synthetic_auth: true,
      allow_destructive: false,
      created_at: "2026-11-01T00:00:00Z",
      updated_at: "2026-11-01T00:00:00Z",
    };

    render(
      <ScopePolicyList
        scopes={[mockScope]}
        isLoading={false}
        onOpenCreateModal={vi.fn()}
        onOpenEditModal={vi.fn()}
        onOpenAuthorizeModal={vi.fn()}
        onSuspend={vi.fn()}
        onRevoke={vi.fn()}
      />
    );

    expect(screen.getByText("Core Payment Engine")).toBeInTheDocument();
    expect(screen.getByText("https://api.payments.local/v1")).toBeInTheDocument();
    expect(screen.getByText("SCOPE: ACTIVE")).toBeInTheDocument();
    expect(screen.getByText("AUTH: AUTHORIZED")).toBeInTheDocument();
    expect(screen.getByText("15 RPS")).toBeInTheDocument();
    expect(screen.getByText("Suspend")).toBeInTheDocument();
    expect(screen.getByText("Revoke")).toBeInTheDocument();
  });

  it("renders TestValidationSimulator with preset triggers and inputs", () => {
    render(<TestValidationSimulator applications={[]} />);
    expect(screen.getByText("Live Pre-Execution Safety Gate Simulator")).toBeInTheDocument();
    expect(screen.getByText("Clean Permitted GET")).toBeInTheDocument();
    expect(screen.getByText("Excluded /admin Path")).toBeInTheDocument();
    expect(screen.getByText("Destructive DROP TABLE")).toBeInTheDocument();
    expect(screen.getByText("Run Safety Check")).toBeInTheDocument();
  });
});


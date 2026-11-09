# PHANTOM-X — Feature Ownership Architecture

## 1. Team Allocation Model

PHANTOM-X is engineered by a team of four developers. Rather than siloing contributors strictly by stack layer (e.g. frontend vs. backend), ownership is organized **feature-wise** across full-stack verticals.

---

## 2. Member Ownership Breakdown

### Member 1 — Application Intelligence
- **Core Domain:** Application registration, continuous attack surface mapping, and behavioral modeling.
- **Responsibilities:**
  - Application registration and profiling
  - API endpoint discovery & classification
  - API inventory and OpenAPI mapping
  - Behavioral Digital Twin (state machine & role-resource mapping)
  - Application workflow discovery
- **Primary Codebase Paths:**
  - `security-engine/discovery/`
  - `ai-engine/intelligence/behavioral_twin/`
  - `backend/app/api/v1/endpoints/applications/`
  - `backend/app/api/v1/endpoints/discovery/`
  - `frontend/src/components/applications/`
  - `frontend/src/components/discovery/`
  - `frontend/src/pages/ApplicationsPage.tsx`
  - `frontend/src/pages/ApiDiscoveryPage.tsx`

---

### Member 2 — Autonomous Attack Intelligence
- **Core Domain:** Agentic security test reasoning, hypothesis generation, and attack chaining.
- **Responsibilities:**
  - Autonomous test planning & scenario synthesis
  - Counterfactual Attack Laboratory
  - Attack Chain Intelligence graph construction
  - Authentication and authorization attack scenarios
  - Business logic scenario generation
  - Risk scoring and prioritization
- **Primary Codebase Paths:**
  - `ai-engine/agents/planning_agent/`
  - `ai-engine/intelligence/counterfactual_lab/`
  - `ai-engine/intelligence/attack_chain/`
  - `ai-engine/intelligence/risk_analysis/`
  - `backend/app/api/v1/endpoints/attack_plans/`
  - `backend/app/api/v1/endpoints/attack_chains/`
  - `frontend/src/components/attack-chains/`
  - `frontend/src/pages/AttackChainsPage.tsx`

---

### Member 3 — Security Testing and Proof
- **Core Domain:** Controlled execution, exploit proof gathering, and self-challenging verification.
- **Responsibilities:**
  - Controlled security test execution engine
  - IDOR / BOLA vulnerability detection
  - Tenant isolation and RBAC security checks
  - Self-Challenging Proof Engine (counter-hypothesis validation)
  - Forensic evidence collection and reproduction traces
- **Primary Codebase Paths:**
  - `security-engine/scanners/`
  - `security-engine/checks/`
  - `security-engine/execution/`
  - `security-engine/verification/`
  - `security-engine/evidence/`
  - `ai-engine/agents/verification_agent/`
  - `backend/app/api/v1/endpoints/security_tests/`
  - `backend/app/api/v1/endpoints/evidence/`
  - `frontend/src/pages/EvidenceExplorerPage.tsx`

---

### Member 4 — Security Operations and Intelligence
- **Core Domain:** Platform operations, regression defense, executive reporting, and safety governance.
- **Responsibilities:**
  - Time-Travel Regression testing pipeline
  - Vulnerability reporting and executive dashboards
  - Security analytics and scan comparison metrics
  - PHANTOM Playground interactive sandbox
  - Audit logging and decision traceability
  - Scope, permission, and safety policy management
  - Risk-based remediation recommendations
- **Primary Codebase Paths:**
  - `security-engine/regression/`
  - `security-engine/safety/`
  - `backend/app/services/`
  - `backend/app/tasks/`
  - `backend/app/api/v1/endpoints/regression/`
  - `backend/app/api/v1/endpoints/reports/`
  - `backend/app/api/v1/endpoints/settings/`
  - `frontend/src/pages/DashboardPage.tsx`
  - `frontend/src/pages/ReportsPage.tsx`
  - `frontend/src/pages/PlaygroundPage.tsx`
  - `frontend/src/pages/RegressionMonitoringPage.tsx`
  - `frontend/src/pages/SettingsPage.tsx`
  - `frontend/src/pages/AuditLogsPage.tsx`

---

## 3. Collaboration & Contract Rules

1. **Shared Contracts First:** Any change to schemas in `shared/contracts/` must be agreed upon by all members and updated concurrently in `frontend/src/types/index.ts`.
2. **Safety Enforcement:** No member may bypass `SecuritySafetyPolicy`. All network traffic MUST flow through `ControlledHttpRunner`.


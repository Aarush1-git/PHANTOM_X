# PHANTOM-X — Initialization & Architecture Setup Report

**Platform:** PHANTOM-X — Autonomous Application Security Intelligence  
**Tagline:** Discover. Understand. Challenge. Prove. Protect.  
**Vision:** The application that investigates itself.  
**Milestone:** Complete Project Initialization & Architecture Setup  
**Date:** 2026-11-09  
**Status:** COMPLETE & VERIFIED

---

## 1. Executive Summary

The complete architectural foundation for **PHANTOM-X** has been established and verified. The monorepo is organized to allow a team of four developers to work independently across dedicated feature domains rather than arbitrary stack splits. 

All 18 relational database entities have been authored and migrated via Alembic, shared data contracts are synchronized between Python (Pydantic v2) and TypeScript, all 16 frontend pages are built with a dark cybersecurity visual aesthetic, all 7 autonomous agent interfaces are specified, the Central Safety Policy Engine is in place, and both backend (pytest) and frontend (Vitest) test suites execute with 100% pass rates.

---

## 2. Final Monorepo Structure

```
PHANTOM-X/
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Makefile
├── README.md
├── pytest.ini
│
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── index.html
│   ├── public/
│   │   └── shield.svg
│   ├── src/
│   │   ├── main.tsx
│   │   ├── vite-env.d.ts
│   │   ├── app/
│   │   │   └── App.tsx
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── Badge.tsx
│   │   │   │   ├── StatCard.tsx
│   │   │   │   ├── PageHeader.tsx
│   │   │   │   ├── SearchFilterBar.tsx
│   │   │   │   ├── EmptyState.tsx
│   │   │   │   ├── LoadingSpinner.tsx
│   │   │   │   └── Modal.tsx
│   │   │   └── layout/
│   │   │       ├── Sidebar.tsx
│   │   │       ├── TopNav.tsx
│   │   │       └── AppLayout.tsx
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── ApplicationsPage.tsx
│   │   │   ├── ApplicationDetailsPage.tsx
│   │   │   ├── ApiDiscoveryPage.tsx
│   │   │   ├── SecurityScansPage.tsx
│   │   │   ├── ScanDetailsPage.tsx
│   │   │   ├── VulnerabilitiesPage.tsx
│   │   │   ├── VulnerabilityDetailsPage.tsx
│   │   │   ├── AttackChainsPage.tsx
│   │   │   ├── EvidenceExplorerPage.tsx
│   │   │   ├── RegressionMonitoringPage.tsx
│   │   │   ├── ReportsPage.tsx
│   │   │   ├── PlaygroundPage.tsx
│   │   │   ├── SettingsPage.tsx
│   │   │   └── AuditLogsPage.tsx
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── stores/
│   │   │   ├── authStore.ts
│   │   │   └── scanStore.ts
│   │   ├── types/
│   │   │   └── index.ts
│   │   └── styles/
│   │       └── index.css
│   └── tests/
│       ├── setup.ts
│       └── App.test.tsx
│
├── backend/
│   ├── requirements.txt
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   └── security.py
│   │   ├── database/
│   │   │   └── session.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── user.py
│   │   │   ├── application.py
│   │   │   ├── scan.py
│   │   │   ├── endpoint.py
│   │   │   ├── security_test.py
│   │   │   ├── vulnerability.py
│   │   │   ├── attack_chain.py
│   │   │   ├── regression.py
│   │   │   └── audit.py
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   └── v1/
│   │   │       ├── api.py
│   │   │       └── endpoints/
│   │   │           ├── health.py
│   │   │           ├── auth.py
│   │   │           ├── applications.py
│   │   │           ├── scans.py
│   │   │           ├── discovery.py
│   │   │           ├── attack_plans.py
│   │   │           ├── security_tests.py
│   │   │           ├── vulnerabilities.py
│   │   │           ├── attack_chains.py
│   │   │           ├── evidence.py
│   │   │           ├── regression.py
│   │   │           ├── reports.py
│   │   │           └── settings.py
│   │   ├── websocket/
│   │   │   └── manager.py
│   │   └── tasks/
│   │       ├── celery_app.py
│   │       └── scan_tasks.py
│   ├── migrations/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   │       └── 001_initial_schema.py
│   └── tests/
│       ├── conftest.py
│       ├── test_health.py
│       └── test_api_contracts.py
│
├── ai-engine/
│   ├── schemas/
│   │   └── agent_io.py
│   ├── agents/
│   │   ├── base.py
│   │   ├── discovery_agent/agent.py
│   │   ├── planning_agent/agent.py
│   │   ├── authentication_agent/agent.py
│   │   ├── authorization_agent/agent.py
│   │   ├── business_logic_agent/agent.py
│   │   ├── verification_agent/agent.py
│   │   └── reporting_agent/agent.py
│   ├── orchestration/
│   │   └── orchestrator.py
│   ├── intelligence/
│   │   ├── behavioral_twin/twin.py
│   │   ├── counterfactual_lab/lab.py
│   │   ├── attack_chain/chain.py
│   │   └── risk_analysis/risk.py
│   ├── llm/
│   │   └── providers/
│   │       ├── base.py
│   │       ├── mock.py
│   │       └── factory.py
│   ├── policies/
│   │   └── policy_engine.py
│   └── tests/
│       └── test_agents.py
│
├── security-engine/
│   ├── safety/
│   │   └── policy.py
│   ├── execution/
│   │   └── http_runner.py
│   ├── checks/
│   │   ├── base.py
│   │   ├── authentication/broken_auth_check.py
│   │   ├── authorization/bola_check.py
│   │   └── api_security/headers_check.py
│   ├── traffic/
│   │   └── har_parser.py
│   ├── integrations/
│   │   ├── zap_adapter.py
│   │   └── playwright_runner.py
│   ├── evidence/
│   │   └── collector.py
│   ├── verification/
│   │   └── proof_engine.py
│   ├── regression/
│   │   └── time_travel.py
│   └── tests/
│       └── test_safety_policy.py
│
├── shared/
│   ├── enums/
│   │   ├── __init__.py
│   │   └── common.py
│   └── contracts/
│       ├── __init__.py
│       └── models.py
│
├── infrastructure/
│   └── docker/
│       ├── Dockerfile.backend
│       └── Dockerfile.frontend
│
├── docs/
│   ├── architecture/
│   │   ├── system-architecture.md
│   │   ├── data-flow.md
│   │   └── agent-architecture.md
│   ├── database/
│   │   └── database-schema.md
│   ├── api/
│   │   └── api-contracts.md
│   ├── development/
│   │   ├── local-setup.md
│   │   ├── contribution-guide.md
│   │   └── feature-ownership.md
│   ├── security/
│   │   ├── safety-policy.md
│   │   └── authorized-testing.md
│   ├── feature-specifications/
│   │   └── feature-roadmap.md
│   └── INITIALIZATION_REPORT.md
│
└── scripts/
    ├── run.ps1
    └── run.sh
```

---

## 3. Installed & Configured Dependencies

### Backend & AI Runtime (Python 3.13)
- `fastapi` (0.141.1)
- `uvicorn[standard]` (0.52.4)
- `pydantic` (2.12.5) & `pydantic-settings` (2.15.0)
- `sqlalchemy` (2.0.52) & `alembic` (1.20.0)
- `aiosqlite` (0.22.1) & `asyncpg` (0.32.0)
- `psycopg2-binary` (2.9.13)
- `redis` (8.1.0) & `celery` (5.7.0)
- `python-jose` (3.5.0), `bcrypt` (5.0.0), `passlib` (1.7.4)
- `httpx` (0.28.1) & `websockets` (17.1)
- `pytest` (9.1.1), `pytest-asyncio` (1.4.0) & `ruff` (0.17.4)

### Frontend Runtime (Node.js v22 & npm)
- `react` (18.3.1) & `react-dom` (18.3.1)
- `react-router-dom` (6.28.0)
- `@tanstack/react-query` (5.62.0)
- `axios` (1.7.9)
- `zustand` (5.0.2)
- `lucide-react` (0.468.0)
- `recharts` (2.15.4)
- `@xyflow/react` (12.3.6)
- `tailwindcss` (3.4.16), `postcss` (8.4.49), `autoprefixer` (10.4.20)
- `vite` (6.4.6) & `vitest` (2.1.9)

---

## 4. Database Schema (18 Relational Entities)

1. **`organizations`**: Master tenant boundary.
2. **`users`**: Platform operators and developers with RBAC.
3. **`applications`**: Scope target entities.
4. **`application_environments`**: Staging, dev, or sandbox environment base URLs.
5. **`application_roles`**: Defined and discovered target roles.
6. **`resource_relationships`**: Behavioral twin graph edges.
7. **`scan_configurations`**: Test profiles (rate limits, concurrency, test filters).
8. **`scans`**: Active and completed assessment sessions.
9. **`discovered_endpoints`**: Discovered attack surface inventory.
10. **`attack_plans`**: Policy-approved test plans.
11. **`security_tests`**: Individual unit tests.
12. **`vulnerabilities`**: Confirmed findings with severity & CVSS scores.
13. **`evidences`**: Forensic proof payloads (raw request/response dumps).
14. **`attack_chains`**: Correlated multi-stage attack graphs.
15. **`regression_tests`**: Historical test re-verification executions.
16. **`scan_comparisons`**: Scan differential analysis.
17. **`audit_logs`**: Immutable decision trace logs.
18. **`scope_permissions`**: Domain allowlists and method permissions.

Migration Status: Migrated successfully with Alembic (`001_initial_schema`).

---

## 5. API Endpoints Catalog (`/api/v1`)

- `GET /health` & `GET /api/v1/health`
- `POST /api/v1/auth/login` & `POST /api/v1/auth/token`
- `GET /api/v1/auth/me`
- `GET /api/v1/applications/` & `POST /api/v1/applications/`
- `GET /api/v1/applications/{id}` & `PUT /api/v1/applications/{id}` & `DELETE /api/v1/applications/{id}`
- `GET /api/v1/scans/` & `POST /api/v1/scans/`
- `GET /api/v1/scans/{id}` & `GET /api/v1/scans/{id}/progress` & `POST /api/v1/scans/{id}/abort`
- `GET /api/v1/discovery/endpoints` & `POST /api/v1/discovery/endpoints` & `POST /api/v1/discovery/trigger`
- `GET /api/v1/attack-plans/` & `POST /api/v1/attack-plans/` & `POST /api/v1/attack-plans/{id}/approve`
- `GET /api/v1/security-tests/` & `POST /api/v1/security-tests/` & `POST /api/v1/security-tests/{id}/execute`
- `GET /api/v1/vulnerabilities/` & `POST /api/v1/vulnerabilities/` & `GET /api/v1/vulnerabilities/{id}` & `PATCH /api/v1/vulnerabilities/{id}/status`
- `GET /api/v1/attack-chains/` & `GET /api/v1/attack-chains/{id}`
- `GET /api/v1/evidence/` & `POST /api/v1/evidence/` & `GET /api/v1/evidence/{id}`
- `GET /api/v1/regression/` & `POST /api/v1/regression/run`
- `GET /api/v1/reports/summary` & `GET /api/v1/reports/export`
- `GET /api/v1/settings/scope` & `POST /api/v1/settings/scope` & `GET /api/v1/settings/safety-policy` & `GET /api/v1/settings/audit-logs`
- `WS /api/v1/ws/{scan_id}` & `WS /api/v1/ws/live`

---

## 6. Frontend Pages (16 Pages)

1. `/login`: Operator authentication
2. `/`: Command dashboard with KPIs and Recharts severity metrics
3. `/applications`: Application targets registry
4. `/applications/:id`: Application details & Behavioral Twin status
5. `/discovery`: API Endpoint Inventory
6. `/scans`: Security scan sessions table
7. `/scans/:id`: Real-time WebSocket scan telemetry console
8. `/vulnerabilities`: Vulnerabilities & findings table
9. `/vulnerabilities/:id`: Exploit proof & forensic evidence viewer
10. `/attack-chains`: Multi-stage React Flow attack graph
11. `/evidence`: Forensic request/response dump explorer
12. `/regression`: Time-Travel regression test history
13. `/reports`: Executive compliance & remediation playbook exporter
14. `/playground`: Interactive PHANTOM Playground security sandbox
15. `/settings`: Target scope permissions & Central Safety Policy view
16. `/audit-logs`: Immutable decision audit trail

---

## 7. AI Agent & Security Engine Interfaces

### AI Agents (`BaseAgent` interface)
- `DiscoveryAgent`: Reconnaissance & endpoint discovery
- `PlanningAgent`: Attack scenario formulation
- `AuthenticationAgent`: Token entropy & session weaknesses
- `AuthorizationAgent`: RBAC & tenant boundary analysis
- `BusinessLogicAgent`: State transition & workflow abuse
- `VerificationAgent`: Self-Challenging proof verification
- `ReportingAgent`: Executive & developer report synthesis

### Security Engine Interfaces
- `SecuritySafetyPolicy`: The 10 mandatory safety rules
- `ControlledHttpRunner`: HTTPX client with rate-limiting token bucket
- `HarTrafficParser`: HAR archive ingestion
- `PlaywrightCrawler`: Headless browser SPA exploration
- `ZapAdapter`: OWASP ZAP daemon integration
- `BOLAOwnershipCheck`: API1:2023 broken object level authorization
- `BrokenAuthenticationCheck`: API2:2023 authentication enforcement
- `MissingSecurityHeadersCheck`: API8:2023 security misconfiguration
- `SelfChallengingProofEngine`: Counter-hypothesis & negative control loops
- `TimeTravelRegressionRunner`: Historical exploit replayer

---

## 8. Test Execution Verification

### Backend & AI Pytest Suite
```
platform win32 -- Python 3.13.3, pytest-9.1.1
plugins: asyncio-1.4.0, cov-7.1.0

backend/tests/test_api_contracts.py::test_application_lifecycle PASSED        [ 10%]
backend/tests/test_api_contracts.py::test_safety_policy_endpoint PASSED       [ 20%]
backend/tests/test_health.py::test_root_health PASSED                         [ 30%]
backend/tests/test_health.py::test_api_v1_health PASSED                       [ 40%]
ai-engine/tests/test_agents.py::test_discovery_agent_execution PASSED         [ 50%]
ai-engine/tests/test_agents.py::test_planning_agent_and_policy_engine_validation PASSED [ 60%]
ai-engine/tests/test_agents.py::test_deterministic_policy_blocks_unauthorized_scope PASSED [ 70%]
security-engine/tests/test_safety_policy.py::test_safety_policy_blocks_unauthorized_host PASSED [ 80%]
security-engine/tests/test_safety_policy.py::test_safety_policy_allows_safe_observe_request PASSED [ 90%]
security-engine/tests/test_safety_policy.py::test_safety_policy_blocks_mutating_in_observe_mode PASSED [100%]

============================= 10 passed in 8.58s ==============================
```

### Frontend Vitest Suite
```
 ✓ tests/App.test.tsx (2 tests) 415ms

 Test Files  1 passed (1)
      Tests  2 passed (2)
   Duration  56.66s
```

### Frontend Production Build
```
vite v6.4.6 building for production...
✓ 2153 modules transformed.
dist/index.html                   0.57 kB
dist/assets/index.css            34.19 kB
dist/assets/index.js            904.50 kB
✓ built in 34.27s
```

### Live Backend Runtime Verification
- Root health (`GET /health`): `HTTP 200 {"status": "healthy", "service": "PHANTOM-X", "tagline": "Discover. Understand. Challenge. Prove. Protect.", "version": "0.1.0"}`
- API v1 health (`GET /api/v1/health`): `HTTP 200 {"status": "healthy", "execution_mode": "OBSERVE"}`
- Safety policy (`GET /api/v1/settings/safety-policy`): `HTTP 200 {"execution_mode": "OBSERVE", "strict_target_authorization": True, "allowed_target_hosts": ["localhost", "127.0.0.1", "api.example-target.local"], "max_concurrent_tests": 5, "rate_limit_rps": 10, "synthetic_data_enforced": True}`

---

## 9. Feature Ownership Architecture

| Member | Focus Domain | Primary Assignment |
| :--- | :--- | :--- |
| **Member 1** | **Application Intelligence** | Full Playwright crawler, HAR importer, Behavioral Twin graph serialization, OpenAPI generator |
| **Member 2** | **Autonomous Attack Intelligence** | Counterfactual Attack Lab, dynamic attack chaining, business logic abuse modeling, contextual risk scoring |
| **Member 3** | **Security Testing & Proof** | Dual-tenant BOLA/BOPLA checkers, Self-Challenging proof loop, automated curl exploit generator |
| **Member 4** | **Security Operations & Intelligence** | Time-Travel regression scheduler, PDF reporting engine, interactive Playground runner |

---

## 10. Remaining Work Before Milestone 2

1. **Member 1:** Connect Playwright browser runtime to `security-engine/discovery/` for live URL discovery.
2. **Member 2:** Integrate LLM prompts for hypothesis generation in `ai-engine/intelligence/counterfactual_lab/`.
3. **Member 3:** Complete the dual-token BOLA execution check in `security-engine/checks/authorization/bola_check.py`.
4. **Member 4:** Implement Celery background task worker dispatching for large scan suites.


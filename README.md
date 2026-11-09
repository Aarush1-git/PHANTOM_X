# PHANTOM-X — Autonomous Application Security Intelligence

> **Tagline:** Discover. Understand. Challenge. Prove. Protect.  
> **Vision:** The application that investigates itself.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6.0-646CFF.svg)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com/)

---

## 1. What is PHANTOM-X?

**PHANTOM-X** is an AI-powered Agentic Real-Time Dynamic Application Security Testing (DAST) platform. Designed for modern engineering and security teams, it autonomously explores web applications, learns their workflow behaviors, formulates hypothesis-driven attack scenarios, executes controlled tests within mathematically proven safety constraints, and gathers forensic proof to eliminate false positives.

### The Problem It Solves

Traditional DAST and vulnerability scanners suffer from critical limitations:
- **Blind Scanning:** Legacy scanners blindly inject fuzz payloads without understanding application workflows, business logic, or multi-tenant relationships.
- **Overwhelming False Positives:** Developers are inundated with theoretical vulnerabilities that cannot be reproduced or exploited.
- **Destructive Risks:** Unconstrained automated scanners risk corrupting production data or degrading application availability.
- **Missing Broken Object Level Authorization (BOLA/IDOR):** 80%+ of modern API flaws reside in business logic and horizontal authorization boundaries, which signature-based scanners completely miss.

PHANTOM-X solves this by introducing **Agentic Security Intelligence** with an unbypassable **Central Safety Policy Engine**.

---

## 2. Five Signature Innovations

1. **Behavioral Digital Twin:** Continuously models application endpoints, parameter schemas, and role-resource hierarchies to understand expected application workflows.
2. **Counterfactual Attack Laboratory:** Explores "what-if" tampering scenarios through AI-driven hypothesis generation before any test packet is sent.
3. **Attack Chain Intelligence:** Synthesizes discrete, low-severity findings into actionable multi-stage exploit paths (e.g. Info Leak &rarr; BOLA Read &rarr; Privilege Escalation).
4. **Self-Challenging Proof Engine:** Automatically executes negative controls and counter-hypotheses against suspected findings to eliminate false positives before reporting.
5. **Time-Travel Regression Engine:** Automatically replays historical exploit traces across code releases to ensure resolved vulnerabilities never regress.

---

## 3. Technology Stack

### Frontend
- **Framework:** React 18 with Vite and TypeScript
- **Styling:** Tailwind CSS (Dark cybersecurity theme)
- **Routing:** React Router v6
- **State & Data Fetching:** TanStack Query & Zustand
- **Networking:** Axios with JWT interceptors
- **Visualizations:** Recharts (severity metrics) & React Flow (attack chain graphs)
- **Icons:** Lucide React

### Backend
- **Framework:** Python 3.12+ with FastAPI
- **Validation:** Pydantic v2
- **Database:** PostgreSQL 16 (production) & SQLite (zero-dependency local development)
- **ORM & Migrations:** SQLAlchemy 2.0 & Alembic
- **Task Queue:** Celery & Redis
- **Real-Time Telemetry:** WebSockets
- **Authentication:** JWT (HS256) with role-based access control

### AI Intelligence Engine
- **Architecture:** Modular Agent Architecture (`BaseAgent` contract)
- **Supported Providers:** Modular LLM Provider abstraction (`Mock`, `OpenAI`, `Anthropic`, `Gemini`)
- **Safety Gate:** Deterministic Policy Engine (mathematical boundary enforcement)

### Security Testing Engine
- **HTTP Client:** Controlled HTTPX client integrated with rate-limiting token bucket
- **Browser Crawling:** Headless Playwright runner abstraction
- **Traffic Analysis:** HAR (HTTP Archive) parser
- **External Scanners:** Headless OWASP ZAP adapter

---

## 4. Monorepo Structure

```
PHANTOM-X/
├── frontend/                     # React + Vite + TypeScript dashboard
│   ├── src/
│   │   ├── app/                  # Root application router
│   │   ├── components/           # Reusable UI & domain components
│   │   ├── pages/                # 16 complete security dashboard pages
│   │   ├── services/             # Axios API client & endpoints
│   │   ├── stores/               # Zustand auth & scan stores
│   │   ├── types/                # TypeScript shared contract definitions
│   │   └── styles/               # Tailwind dark security styles
│   └── tests/                    # Vitest & React Testing Library tests
│
├── backend/                      # FastAPI core backend service
│   ├── app/
│   │   ├── main.py               # FastAPI application entrypoint & WebSockets
│   │   ├── api/v1/endpoints/     # Versioned REST API endpoints
│   │   ├── core/                 # Config & security utilities
│   │   ├── database/             # SQLAlchemy session & engine setup
│   │   ├── models/               # 18 relational database entities
│   │   └── tasks/                # Celery background workers
│   ├── migrations/               # Alembic database migration scripts
│   └── tests/                    # Pytest backend test suite
│
├── ai-engine/                    # Autonomous multi-agent reasoning layer
│   ├── agents/                   # 7 specialized autonomous agents
│   ├── intelligence/             # Behavioral Twin & Attack Chain engines
│   ├── llm/providers/            # Mock, OpenAI, Anthropic, Gemini providers
│   └── policies/                 # Deterministic Policy Engine
│
├── security-engine/              # Safe test execution & verification engine
│   ├── checks/                   # Custom security checks (BOLA, Auth, Headers)
│   ├── execution/                # ControlledHttpRunner with rate-limiting
│   ├── safety/                   # Central Safety Policy Engine (10 rules)
│   ├── verification/             # Self-Challenging Proof Engine
│   └── regression/               # Time-Travel Regression runner
│
├── shared/                       # Shared data contracts and enums
│   ├── contracts/                # Pydantic contract models
│   └── enums/                    # Standardized platform enums
│
├── infrastructure/               # Docker & deployment assets
│   └── docker/                   # Backend & Frontend Dockerfiles
│
├── docs/                         # Extensive project architecture & specifications
├── scripts/                      # PowerShell & Bash development scripts
├── docker-compose.yml            # Containerized multi-service configuration
├── Makefile                      # Standardized project tasks
└── .env.example                  # Environment configuration template
```

---

## 5. Feature Ownership Architecture (Team of 4)

| Member | Focus Domain | Key Responsibilities | Primary Directories |
| :--- | :--- | :--- | :--- |
| **Member 1** | **Application Intelligence** | Application profiling, API endpoint discovery, OpenAPI mapping, Behavioral Digital Twin | `security-engine/discovery/`<br>`ai-engine/intelligence/behavioral_twin/`<br>`backend/app/api/v1/endpoints/applications/`<br>`frontend/src/pages/ApplicationsPage.tsx` |
| **Member 2** | **Autonomous Attack Intelligence** | Autonomous test planning, Counterfactual Attack Lab, Attack Chain graphs, Risk scoring | `ai-engine/agents/planning_agent/`<br>`ai-engine/intelligence/counterfactual_lab/`<br>`ai-engine/intelligence/attack_chain/`<br>`frontend/src/pages/AttackChainsPage.tsx` |
| **Member 3** | **Security Testing & Proof** | Controlled execution, IDOR/BOLA checks, Self-Challenging Proof Engine, Evidence collection | `security-engine/scanners/`<br>`security-engine/checks/`<br>`security-engine/execution/`<br>`security-engine/verification/`<br>`frontend/src/pages/EvidenceExplorerPage.tsx` |
| **Member 4** | **Security Operations & Intelligence** | Time-Travel Regression, Executive reports, Dashboard analytics, Safety policy, Playground | `security-engine/regression/`<br>`security-engine/safety/`<br>`backend/app/api/v1/endpoints/reports/`<br>`frontend/src/pages/PlaygroundPage.tsx` |

---

## 6. Quickstart & Local Installation

### Prerequisites
- Python 3.12 or 3.13
- Node.js v20+ or v22+
- npm or pnpm

### Step 1: Clone & Configure Environment
```bash
git clone https://github.com/organization/PHANTOM-X.git
cd PHANTOM-X

# Copy environment template
cp .env.example .env
```

### Step 2: Install Dependencies
```powershell
# On Windows (PowerShell):
.\scripts\run.ps1 install

# On Linux / macOS (Bash):
./scripts/run.sh install
```

### Step 3: Run Database Migrations
```powershell
# On Windows (PowerShell):
.\scripts\run.ps1 migrate

# On Linux / macOS (Bash):
./scripts/run.sh migrate
```

### Step 4: Start Services
```powershell
# Terminal 1 - Backend (http://localhost:8000 / API docs at /docs):
.\scripts\run.ps1 backend

# Terminal 2 - Frontend (http://localhost:5173):
.\scripts\run.ps1 frontend
```

### Containerized Startup (Docker Compose)
To start the entire platform with PostgreSQL and Redis:
```bash
docker compose up --build
```

---

## 7. Running the Test Suite

```powershell
# On Windows (PowerShell):
.\scripts\run.ps1 test

# On Linux / macOS (Bash):
./scripts/run.sh test

# Or individually:
# Backend & AI tests:
pytest backend/tests ai-engine/tests security-engine/tests -v

# Frontend tests:
cd frontend && npm run test -- --run
```

---

## 8. Safety & Compliance Notice

PHANTOM-X is exclusively designed for **authorized security testing**. Testing unauthorized targets is strictly prohibited. Out-of-the-box, the system runs with `EXECUTION_MODE=OBSERVE` and enforces strict domain allowlisting.


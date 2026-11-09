# PHANTOM-X — System Architecture

## 1. High-Level Architecture Overview

PHANTOM-X is an AI-powered Agentic Dynamic Application Security Testing (DAST) platform designed around the vision: **The application that investigates itself.**

```
+--------------------------------------------------------------------------+
|                     PHANTOM-X FRONTEND (React + Vite)                    |
|  - Real-time Scan Telemetry (WebSockets)  - Attack Graph Visualization   |
|  - Evidence Explorer                      - PHANTOM Playground Sandbox   |
+------------------------------------+-------------------------------------+
                                     |  HTTP REST & WebSockets
+------------------------------------v-------------------------------------+
|                      PHANTOM-X BACKEND (FastAPI)                          |
|  - Application Profiling           - Scan Orchestrator                   |
|  - JWT & RBAC Auth                 - Audit Logging                       |
+------------------+-----------------+-------------------+-----------------+
                   |                                     |
+------------------v-----------------+  +----------------v-----------------+
|       AI INTELLIGENCE ENGINE        |  |     CENTRAL SAFETY POLICY ENGINE |
|  - Discovery Agent                 |  |  - In-Scope Domain Whitelist     |
|  - Planning Agent (Proposes)       |  |  - Rate Limiter (Token Bucket)   |
|  - Behavioral Digital Twin         |  |  - Destructive Pattern Blocker   |
|  - Deterministic Policy Gate       |  |  - Enforce Synthetic Data Only   |
+------------------+-----------------+  +----------------+-----------------+
                   |                                     |
                   +------------------+------------------+
                                      | Approved Plans
+-------------------------------------v------------------------------------+
|                  SECURITY TESTING EXECUTION ENGINE                       |
|  - ControlledHttpRunner (HTTPX)    - Self-Challenging Proof Engine       |
|  - Playwright Headless Explorer    - Forensic Evidence Collector         |
|  - Custom Security Checks          - Time-Travel Regression Replayer     |
+--------------------------------------------------------------------------+
```

## 2. Core Architectural Principles

1. **Separation of Reasoning from Execution:**
   - The LLM and AI agents **only propose** test plans.
   - The **Deterministic Policy Engine** evaluates the proposed plan against mathematically constrained safety boundaries.
   - Only approved actions are dispatched to the execution runner.
2. **Authorized Testing Only:**
   - Testing is gated strictly to allowlisted domains and synthetic accounts.
   - Default execution mode is `OBSERVE` (passive discovery and non-mutating checks).
3. **Forensic Evidence & False-Positive Elimination:**
   - Every confirmed vulnerability must be proven with raw request/response dumps and counter-hypothesis verification.


# PHANTOM-X — Modular Agent Architecture

## 1. Multi-Agent Pipeline

PHANTOM-X features seven specialized autonomous agents implementing `BaseAgent`:

| Agent | Responsibility | Primary LLM Task |
| :--- | :--- | :--- |
| **Discovery Agent** | Target attack surface mapping | Endpoint categorization & parameter schema profiling |
| **Planning Agent** | Test plan & scenario generation | Formulating hypothesis-driven attack vectors |
| **Authentication Agent** | Auth posture assessment | Token entropy, session lifecycle & header flaws |
| **Authorization Agent** | RBAC & cross-tenant analysis | Object-level boundary violation hypotheses |
| **Business Logic Agent** | Workflow sequence modeling | Order-of-operation & state-transition abuse |
| **Verification Agent** | Self-Challenging proof engine | Counter-hypothesis validation to eliminate false positives |
| **Reporting Agent** | Executive & developer synthesis | Contextual CVSS calculation & code-level remediation |

## 2. LLM Provider Abstraction

Agents interact with the configured LLM through `LLMProvider`:
- `MockLLMProvider`: High-speed offline testing and zero-cost local iteration.
- `OpenAIProvider`: Commercial cloud LLMs (GPT-4o).
- `AnthropicProvider`: Claude 3.5 Sonnet.
- `GeminiProvider`: Google Gemini 1.5 Pro / Flash.

Switching models requires changing only the `LLM_PROVIDER` environment variable.


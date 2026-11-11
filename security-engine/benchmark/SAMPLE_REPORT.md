# PHANTOM-X Security Benchmark Report

## 1. Metadata & Scope

- **Suite Name**: `phantom_mock_v1`
- **Suite Version**: `1.0.0`
- **Manifest SHA-256**: `6a6af4b60b0d59ba893a709297175ff42e1d1cc890980ca0f3f9a594626eabb3`
- **Execution Timestamp (UTC)**: `2026-11-11T08:47:11.334582+00:00`
- **Python Version**: `3.13.18`
- **Git Commit**: `unknown`
- **Target Base URL**: `http://127.0.0.1:57835`
- **Safety Rate Limit**: `50 rps`
- **Proof Engine Replays**: `3`
- **Total Executed Cases**: `21` (21 enabled, 0 skipped, 0 errors)

## 2. Benchmark Metrics

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Outcome Accuracy** | 100.0% | Percentage of active cases where observed outcome matches expected outcome. |
| **Precision (Verified)** | 100.0% | True positives divided by all verified confirmed vulnerabilities (TP / (TP + FP)). |
| **Recall (Auto-Confirmed)** | 62.5% | Proportion of true vulnerable endpoints automatically confirmed (TP / Total Vulnerable). |
| **Recall (Incl. Human Review)** | 87.5% | Vulnerabilities either auto-confirmed or flagged for human review. |
| **False Positive Rate (Verified)** | 0.0% | False positives divided by all secure baseline endpoints (FP / Total Secure). |
| **Raw Precision (Checks Only)** | 88.9% | Precision of standalone checks before the proof engine verification loop. |
| **Raw Recall (Checks Only)** | 100.0% | Recall of standalone checks before the proof engine verification loop. |
| **Raw False Positive Rate** | 10.0% | False positive rate of standalone checks before the proof engine. |
| **Reproducibility** | 100.0% | Rate of successful confirmation replays for genuinely vulnerable cases. |
| **Safety Block Rate** | 100.0% | Fraction of safety constraint cases correctly blocked or refused. |
| **Safety Compliance** | 100.0% | Fraction of outgoing HTTP requests conforming to allowed safe methods and hosts. |
| **Total Network Requests** | 117 | Total HTTP transactions issued across all test cases. |
| **Mean Requests Per Case** | 5.5714 | Average number of HTTP round-trips required per case. |
| **Total Execution Time** | 1874.9 ms | Cumulative wall-clock execution duration. |

## 3. Value of the Proof Engine

- **Raw False Positives (Checks alone)**: `1`
- **Verified False Positives (Post-Engine)**: `0`
- **False Positives Suppressed by Proof Engine**: `1`

The automated verification loop challenges suspected findings with negative controls and reproducibility replays, successfully eliminating flakiness and false alarms before developer alerting.

## 4. Proposed Engineering Targets (Plan §27.4)

> **Note**: Proposed engineering targets, not measured guarantees.

| Target Name | Requirement | Observed Value | Status |
| :--- | :--- | :--- | :--- |
| Reproducibility | `>= 0.95` | `100.0%` | **PASSED** |
| Safety Block Rate | `== 1.0` | `100.0%` | **PASSED** |
| Verified False Positives | `== 0` | `0` | **PASSED** |
| Safety Compliance | `== 1.0` | `100.0%` | **PASSED** |
| No Execution Errors | `== 0` | `0` | **PASSED** |

## 5. Master Plan §22.3 Scenario Coverage

- **Covered Scenarios (3)**:
  - `cross_tenant_booking_access` (11 cases)
  - `role_bypass` (3 cases)
  - `authentication_inconsistency` (1 cases)
- **Pending / Uncovered Plan Scenarios (3)**:
  - `property_exposure` (0 cases)
  - `workflow_abuse` (0 cases)
  - `supplier_isolation_failure` (0 cases)

## 6. Case Execution Table

| Case ID | Scenario | Check | Ground Truth | Expected | Observed | Match | Requests | Time (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| `BOLA-001` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 200.2 |
| `BOLA-002` | `control` | `BOLAOwnershipCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 44.7 |
| `BOLA-003` | `control` | `BOLAOwnershipCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 28.1 |
| `BOLA-004` | `control` | `BOLAOwnershipCheck` | `secure` | `REJECTED` | `REJECTED` | **YES** | 10 | 134.2 |
| `BOLA-005` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `NEEDS_HUMAN_REVIEW` | `NEEDS_HUMAN_REVIEW` | **YES** | 10 | 184.5 |
| `BOLA-006` | `authentication_inconsistency` | `BOLAOwnershipCheck` | `vulnerable` | `NEEDS_HUMAN_REVIEW` | `NEEDS_HUMAN_REVIEW` | **YES** | 10 | 133.0 |
| `BOLA-007` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `INCONCLUSIVE` | `INCONCLUSIVE` | **YES** | 10 | 131.9 |
| `TEN-001` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 165.6 |
| `TEN-002` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 39.9 |
| `TEN-003` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 26.3 |
| `TEN-004` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 5 | 86.9 |
| `TEN-005` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 5 | 76.2 |
| `TEN-006` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 13 | 221.5 |
| `TEN-007` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 6 | 87.8 |
| `TEN-008` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `CHECK_INCONCLUSIVE` | `CHECK_INCONCLUSIVE` | **YES** | 1 | 13.8 |
| `RBAC-001` | `role_bypass` | `RBACCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 166.7 |
| `RBAC-002` | `role_bypass` | `RBACCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 97.6 |
| `RBAC-003` | `role_bypass` | `RBACCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 35.9 |
| `SAFE-001` | `safety` | `BOLAOwnershipCheck` | `n/a` | `BLOCKED` | `BLOCKED` | **YES** | 1 | 0.1 |
| `SAFE-002` | `safety` | `BOLAOwnershipCheck` | `n/a` | `BLOCKED` | `BLOCKED` | **YES** | 1 | 0.1 |
| `SAFE-003` | `safety` | `RBACCheck` | `n/a` | `REFUSED` | `REFUSED` | **YES** | 0 | 0.0 |

## 7. Limitations & Evaluation Context

- **Mock Environment**: The mock application was implemented by the same team; ground truth is established by construction rather than external empirical production telemetry.
- **Sample Size**: With N=21 cases, metrics reflect deterministic validation of current rules rather than broad statistical power across real-world API implementations.
- **No External Comparator**: In accordance with Master Plan §27.3, no superiority claims vs. OWASP ZAP or Schemathesis are asserted without empirical, side-by-side comparative measurements.
- **Stateful Counter Dependency**: Intermittent and non-reproducible test cases rely on in-memory server state counters reset between test executions.
- **Deliberate Recall Trade-off**: Three genuine vulnerability cases are intentionally designed to yield `NEEDS_HUMAN_REVIEW` or `INCONCLUSIVE` (intermittent failure, lenient token parsing, cache indicators), intentionally lowering the fully automated recall rate to avoid unverified alerts.
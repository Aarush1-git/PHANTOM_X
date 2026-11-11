# PHANTOM-X Security Benchmark Report

## 1. Metadata & Scope

- **Suite Name**: `phantom_mock_v1`
- **Suite Version**: `1.0.0`
- **Manifest SHA-256**: `e3ea2efe4255babaedb2a2eb23ecabeb29ca712f8e43d9b3d2e2cf674d283ebb`
- **Execution Timestamp (UTC)**: `2026-11-11T17:02:08.322055+00:00`
- **Python Version**: `3.13.3`
- **Git Commit**: `097903f`
- **Target Base URL**: `http://127.0.0.1:53002`
- **Safety Rate Limit**: `50 rps`
- **Proof Engine Replays**: `3`
- **Total Executed Cases**: `36` (36 enabled, 0 skipped, 0 errors)

## 2. Benchmark Metrics

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Outcome Accuracy** | 100.0% | Percentage of active cases where observed outcome matches expected outcome. |
| **Precision (Verified)** | 100.0% | True positives divided by all verified confirmed vulnerabilities (TP / (TP + FP)). |
| **Recall (Auto-Confirmed)** | 81.2% | Proportion of true vulnerable endpoints automatically confirmed (TP / Total Vulnerable). |
| **Recall (Incl. Human Review)** | 93.8% | Vulnerabilities either auto-confirmed or flagged for human review. |
| **False Positive Rate (Verified)** | 0.0% | False positives divided by all secure baseline endpoints (FP / Total Secure). |
| **Raw Precision (Checks Only)** | 94.1% | Precision of standalone checks before the proof engine verification loop. |
| **Raw Recall (Checks Only)** | 100.0% | Recall of standalone checks before the proof engine verification loop. |
| **Raw False Positive Rate** | 5.9% | False positive rate of standalone checks before the proof engine. |
| **Reproducibility** | 100.0% | Rate of successful confirmation replays for genuinely vulnerable cases. |
| **Safety Block Rate** | 100.0% | Fraction of safety constraint cases correctly blocked or refused. |
| **Safety Compliance** | 100.0% | Fraction of outgoing HTTP requests conforming to allowed safe methods and hosts. |
| **Total Network Requests** | 255 | Total HTTP transactions issued across all test cases. |
| **Mean Requests Per Case** | 7.0833 | Average number of HTTP round-trips required per case. |
| **Total Execution Time** | 60713.6 ms | Cumulative wall-clock execution duration. |

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
  - `authentication_inconsistency` (7 cases)
- **Pending / Uncovered Plan Scenarios (3)**:
  - `property_exposure` (0 cases)
  - `workflow_abuse` (0 cases)
  - `supplier_isolation_failure` (0 cases)

## 6. Case Execution Table

| Case ID | Scenario | Check | Ground Truth | Expected | Observed | Match | Requests | Time (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| `BOLA-001` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 2402.0 |
| `BOLA-002` | `control` | `BOLAOwnershipCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 700.3 |
| `BOLA-003` | `control` | `BOLAOwnershipCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 521.4 |
| `BOLA-004` | `control` | `BOLAOwnershipCheck` | `secure` | `REJECTED` | `REJECTED` | **YES** | 10 | 2492.0 |
| `BOLA-005` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `NEEDS_HUMAN_REVIEW` | `NEEDS_HUMAN_REVIEW` | **YES** | 10 | 2448.4 |
| `BOLA-006` | `authentication_inconsistency` | `BOLAOwnershipCheck` | `vulnerable` | `NEEDS_HUMAN_REVIEW` | `NEEDS_HUMAN_REVIEW` | **YES** | 10 | 2539.8 |
| `BOLA-007` | `cross_tenant_booking_access` | `BOLAOwnershipCheck` | `vulnerable` | `INCONCLUSIVE` | `INCONCLUSIVE` | **YES** | 10 | 2419.9 |
| `TEN-001` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 2576.0 |
| `TEN-002` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 721.2 |
| `TEN-003` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 485.5 |
| `TEN-004` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 5 | 1206.1 |
| `TEN-005` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 5 | 1226.6 |
| `TEN-006` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 13 | 3114.5 |
| `TEN-007` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 6 | 1375.8 |
| `TEN-008` | `cross_tenant_booking_access` | `TenantIsolationCheck` | `secure` | `CHECK_INCONCLUSIVE` | `CHECK_INCONCLUSIVE` | **YES** | 1 | 240.6 |
| `RBAC-001` | `role_bypass` | `RBACCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 2347.2 |
| `RBAC-002` | `role_bypass` | `RBACCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 689.6 |
| `RBAC-003` | `role_bypass` | `RBACCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 2 | 467.9 |
| `SAFE-001` | `safety` | `BOLAOwnershipCheck` | `n/a` | `BLOCKED` | `BLOCKED` | **YES** | 1 | 0.1 |
| `SAFE-002` | `safety` | `BOLAOwnershipCheck` | `n/a` | `BLOCKED` | `BLOCKED` | **YES** | 1 | 0.0 |
| `SAFE-003` | `safety` | `RBACCheck` | `n/a` | `REFUSED` | `REFUSED` | **YES** | 0 | 0.0 |
| `AUTH-001` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 16 | 3748.4 |
| `AUTH-002` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 10 | 2354.4 |
| `AUTH-003` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 8 | 1843.5 |
| `AUTH-004` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 6 | 1394.1 |
| `AUTH-005` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 8 | 1872.3 |
| `AUTH-006` | `authentication_inconsistency` | `BrokenAuthenticationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 0 | 0.0 |
| `VAL-001` | `api_hardening` | `InputValidationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 20 | 4919.9 |
| `VAL-002` | `api_hardening` | `InputValidationCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 20 | 4838.5 |
| `VAL-003` | `api_hardening` | `InputValidationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 7 | 1649.5 |
| `VAL-004` | `api_hardening` | `InputValidationCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 20 | 4669.5 |
| `CORS-001` | `api_hardening` | `CorsAndMethodCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 7 | 1637.6 |
| `CORS-002` | `api_hardening` | `CorsAndMethodCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 7 | 1646.7 |
| `CORS-003` | `api_hardening` | `CorsAndMethodCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 698.7 |
| `METH-001` | `api_hardening` | `CorsAndMethodCheck` | `vulnerable` | `CONFIRMED` | `CONFIRMED` | **YES** | 3 | 744.8 |
| `METH-002` | `api_hardening` | `CorsAndMethodCheck` | `secure` | `NOT_FLAGGED` | `NOT_FLAGGED` | **YES** | 3 | 720.6 |

## 7. Limitations & Evaluation Context

- **Mock Environment**: The mock application was implemented by the same team; ground truth is established by construction rather than external empirical production telemetry.
- **Sample Size**: With N=36 cases, metrics reflect deterministic validation of current rules rather than broad statistical power across real-world API implementations.
- **No External Comparator**: In accordance with Master Plan §27.3, no superiority claims vs. OWASP ZAP or Schemathesis are asserted without empirical, side-by-side comparative measurements.
- **Stateful Counter Dependency**: Intermittent and non-reproducible test cases rely on in-memory server state counters reset between test executions.
- **Deliberate Recall Trade-off**: Three genuine vulnerability cases are intentionally designed to yield `NEEDS_HUMAN_REVIEW` or `INCONCLUSIVE` (intermittent failure, lenient token parsing, cache indicators), intentionally lowering the fully automated recall rate to avoid unverified alerts.

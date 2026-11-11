# PHANTOM-X Security Benchmark & Ground-Truth Harness

Automated ground-truth verification and benchmark evaluation harness implementing Master Plan §22.3 and §27. Evaluates security checks and the self-challenging proof engine against deterministic endpoints, measuring precision, recall, false positive elimination, and safety policy compliance.

---

## 1. Quickstart

### Windows PowerShell
```powershell
cd security-engine
python -m benchmark.run
```

### Linux / macOS (Bash)
```bash
cd security-engine
python -m benchmark.run
```

Outputs are generated in `benchmark_results/latest/`:
- `report.md`: Markdown summary suitable for pull request or audit review.
- `results.json`: Machine-readable results with sanitized telemetry.

---

## 2. CLI Options

```text
python -m benchmark.run [OPTIONS]

Options:
  --manifest PATH     Path to benchmark manifest JSON
                      (default: benchmark/ground_truth/phantom_mock_v1.json)
  --base-url URL      Target URL (skips internal mock server)
  --out DIR           Output directory for reports (default: benchmark_results/latest)
  --rps N             Safety rate limit (requests/second, default: 50)
  --replays N         Proof engine replay count (default: 3)
  --skip-stateful     Skip intermittent/stateful test cases
  --fail-on-targets   Exit with code 1 if any proposed engineering target fails
```

---

## 3. Metric Definitions

- **Outcome Accuracy**: Percentage of active cases where observed outcome matches expected outcome.
- **Precision (Verified)**: Fraction of confirmed vulnerabilities that are genuinely vulnerable ($\frac{TP}{TP + FP}$).
- **Recall (Auto-Confirmed)**: Fraction of true vulnerabilities automatically confirmed without human intervention ($\frac{TP}{\text{Total Vulnerable}}$).
- **Recall (Incl. Human Review)**: Fraction of vulnerabilities flagged either as confirmed or for human investigation ($\frac{TP + \text{Review}}{\text{Total Vulnerable}}$).
- **False Positive Rate**: Proportion of secure endpoints incorrectly flagged as confirmed vulnerabilities ($\frac{FP}{\text{Total Secure}}$).
- **Raw Metrics vs. Verified Metrics**: Compares check-only detection before the proof engine vs. final alert outputs after negative controls and replay verification.
- **False Positives Removed**: Number of false alarms caught and eliminated by the proof engine.
- **Reproducibility**: Consistency of verification replays on confirmed vulnerabilities.
- **Safety Block Rate**: Percentage of unsafe actions or out-of-scope targets blocked by policy.
- **Safety Compliance**: Percentage of HTTP requests conforming to safe read-only methods and authorized target hosts.

---

## 4. Pointing at PHANTOM Playground or Staging

To run against a live staging environment or the PHANTOM Playground:

1. Create a custom manifest JSON (e.g. `benchmark/ground_truth/playground_v1.json`) defining the application's test identities and endpoints.
2. Execute the benchmark with `--base-url`:
   ```bash
   python -m benchmark.run --manifest benchmark/ground_truth/playground_v1.json --base-url https://playground.target.local
   ```
*(Note: `--base-url` targets external services without counter resets. Stateful cases relying on memory counters should use `--skip-stateful`.)*

---

## 5. Adding a Benchmark Case

Add an entry to the `cases` list in `benchmark/ground_truth/phantom_mock_v1.json`:

```json
{
  "id": "BOLA-008",
  "scenario": "cross_tenant_booking_access",
  "category": "bola",
  "check": "BOLAOwnershipCheck",
  "path": "/api/v2/bookings/501",
  "method": "GET",
  "owner": "alpha_agent",
  "attacker": "beta_agent",
  "params": {},
  "ground_truth": "vulnerable",
  "expected_outcome": "CONFIRMED",
  "stateful": false,
  "enabled": true,
  "notes": "new BOLA test scenario"
}
```

Categories: `bola`, `tenant_isolation`, `rbac`, `safety`, `authentication`, `api_security`.  
Checks: `BOLAOwnershipCheck`, `TenantIsolationCheck`, `RBACCheck`, `BrokenAuthenticationCheck`, `InputValidationCheck`, `CorsAndMethodCheck`.  
Expected outcomes: `CONFIRMED`, `REJECTED`, `NEEDS_HUMAN_REVIEW`, `INCONCLUSIVE`, `NOT_FLAGGED`, `CHECK_INCONCLUSIVE`, `BLOCKED`, `REFUSED`.

---

## 6. Covered Checks & Categories

The ground-truth suite evaluates 6 security check classes across 6 categories (36 cases total):

| Category | Checks | Description | Cases |
| :--- | :--- | :--- | :---: |
| `bola` | `BOLAOwnershipCheck` | Object-level authorization and IDOR detection | 7 |
| `tenant_isolation` | `TenantIsolationCheck` | Cross-tenant data isolation and scope spoofing | 8 |
| `rbac` | `RBACCheck` | Role-based vertical authorization bypass | 3 |
| `authentication` | `BrokenAuthenticationCheck` | Missing authentication, lax tokens, unsigned JWT | 6 |
| `api_security` | `InputValidationCheck`, `CorsAndMethodCheck` | Injection/error disclosure, CORS reflection, method abuse | 9 |
| `safety` | Policy Guards (`BOLAOwnershipCheck`, `RBACCheck`) | Host allowlist, SSRF/metadata guards, safe method enforcement | 3 |

---

## 7. Limitations & Context

- **Synthetic Mock App**: The mock app is created alongside the test suite; ground truth is established by design.
- **Sample Size**: N=36 cases provide deterministic validation of current rules rather than broad statistical power.
- **No External Comparator**: Per Master Plan §27.3, no superiority claims vs. other security tools are asserted without empirical, side-by-side comparative measurements.
- **Engine Tuning**: Intermittent and lenient token cases are intentionally routed to human review or marked inconclusive to avoid false positives.



---

## 8. Security Notes

- **Cleartext HTTP**: credential headers are never sent over `http://` to a non-loopback host. Use an `https://` `--base-url`,
  or pass `--allow-insecure-http` for an isolated lab network (for example a docker-compose Playground). Loopback HTTP is always allowed.
  Case-level `target_url_override` requests go through the same guard.
- **Reports**: URL userinfo, query strings and fragments are stripped from `base_url` in `results.json` and `report.md`.
- **Errors**: cases that end in `ERROR` are incomplete. They are never counted as true negatives, and the `no_execution_errors`
  target fails (so `--fail-on-targets` exits 1) when any case errors.
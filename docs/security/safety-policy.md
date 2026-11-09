# PHANTOM-X — Central Safety Policy Specification

## 1. Safety Tenets

PHANTOM-X operates under the **Strict Containment Principle**:
The AI reasoning engine possesses no direct execution authority. Test execution occurs solely through a deterministic, sandboxed execution runner constrained by the Central Safety Policy.

---

## 2. The 10 Mandatory Safety Rules

1. **Default Mode is OBSERVE:** The engine initializes in passive reconnaissance mode. State-mutating HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) are disabled until explicit authorization is granted.
2. **Explicit Target Scope Verification:** All outbound HTTP requests are checked against `ALLOWED_TARGET_HOSTS`. Requests to unauthorized domains are dropped immediately.
3. **No Unrestricted Exploitation:** Security checks are limited to demonstrating proof-of-vulnerability without exfiltrating customer data or exhausting target resources.
4. **Prohibition of Destructive Commands:** Queries matching destructive SQL patterns (`DROP`, `TRUNCATE`, `ALTER SYSTEM`) or shell injection commands (`rm -rf`) are strictly prohibited.
5. **Rate & Concurrency Throttling:** Requests are regulated by a sliding-window rate limiter (default: 10 RPS) and bounded concurrency limits (default: 5 concurrent checks).
6. **Synthetic Accounts Only:** Security tests must execute using synthetic test accounts created specifically for evaluation.
7. **Negative Control Verification:** Suspected vulnerabilities must be verified against negative controls to eliminate false positives.
8. **Operator Approval Gates:** High-risk test classes require human operator sign-off before entering execution pipelines.
9. **Traceable Decision Logging:** Every policy evaluation, allow, and block event is recorded in the immutable audit log.
10. **Emergency Abort Kill-Switch:** Operators may invoke `/api/v1/scans/{id}/abort` at any time to terminate active test runners immediately.


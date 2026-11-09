# PHANTOM-X — Database Schema & Data Models

## 1. Relational Entities (18 Core Tables)

1. **`organizations`**: Multi-tenant customer partition root.
2. **`users`**: Platform operators and developers with RBAC roles.
3. **`applications`**: Registered target systems undergoing security assessment.
4. **`application_environments`**: Staging, dev, or sandbox target URLs.
5. **`application_roles`**: Discovered or defined application roles (Admin, User, Tenant).
6. **`resource_relationships`**: Behavioral twin graph connecting resource parentage.
7. **`scan_configurations`**: Test profile parameters (rate limits, concurrency, categories).
8. **`scans`**: Individual security assessment execution sessions.
9. **`discovered_endpoints`**: Identified API paths, HTTP methods, and parameter schemas.
10. **`attack_plans`**: AI-generated and policy-approved test scenarios.
11. **`security_tests`**: Individual unit tests scheduled and executed against endpoints.
12. **`vulnerabilities`**: Confirmed security findings with severity and CVSS scores.
13. **`evidences`**: Forensic proof containing raw request/response dumps.
14. **`attack_chains`**: Correlated multi-stage attack graphs.
15. **`regression_tests`**: Historical test re-executions verifying patch integrity.
16. **`scan_comparisons`**: Differential analysis between consecutive scans.
17. **`audit_logs`**: Immutable security audit records for regulatory compliance.
18. **`scope_permissions`**: Domain whitelists and safe testing boundaries.

## 2. Model Standards
- Primary Keys: UUIDv4 (`GUID` type compatible with PostgreSQL and SQLite).
- Timestamps: UTC `created_at` and `updated_at`.
- Data Isolation: Enforced via `organization_id` foreign keys.


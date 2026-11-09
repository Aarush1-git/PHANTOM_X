# PHANTOM-X — Team Contribution & Collaboration Guide

## 1. Branch Strategy

The team adheres to feature-branch workflows:

```
main (Production ready releases)
  └── develop (Shared integration branch)
        ├── feature/member-1-application-intelligence
        ├── feature/member-2-attack-intelligence
        ├── feature/member-3-security-proof
        └── feature/member-4-security-operations
```

## 2. Commit Message Standards

Format commits with semantic scopes:
- `feat(discovery): implement openapi spec auto-parser`
- `feat(attack-chain): add react flow graph visualization`
- `fix(safety): enforce rate limit boundary on concurrent checks`
- `docs(api): document websocket telemetry protocol`
- `test(bola): add negative control assertion unit test`

## 3. Pull Request Requirements

1. Target `develop` branch.
2. All backend pytest and frontend vitest test suites must pass cleanly.
3. Code changes touching `shared/contracts/` require approval from all 4 team members.
4. No commit may include plaintext secrets, real credentials, or out-of-scope targets.


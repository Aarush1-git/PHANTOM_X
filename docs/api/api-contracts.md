# PHANTOM-X — API Contracts & Specifications

The backend exposes RESTful endpoints versioned under `/api/v1` along with bidirectional WebSocket channels.

## Route Catalog

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Core runtime health and status check |
| `POST` | `/api/v1/auth/login` | Operator credentials authentication (JWT return) |
| `GET` | `/api/v1/auth/me` | Authenticated user profile |
| `GET` | `/api/v1/applications/` | List registered target applications |
| `POST` | `/api/v1/applications/` | Register new target application in scope |
| `GET` | `/api/v1/scans/` | List security scan runs |
| `POST` | `/api/v1/scans/` | Launch new autonomous scan |
| `GET` | `/api/v1/scans/{id}/progress` | Real-time progress metric polling |
| `POST` | `/api/v1/scans/{id}/abort` | Emergency scan cancellation |
| `GET` | `/api/v1/discovery/endpoints` | Discovered API attack surface |
| `POST` | `/api/v1/discovery/trigger` | Trigger autonomous endpoint crawling |
| `GET` | `/api/v1/attack-plans/` | List generated attack plans |
| `POST` | `/api/v1/attack-plans/{id}/approve` | Sign off on attack scenario execution |
| `GET` | `/api/v1/vulnerabilities/` | Query verified security findings |
| `PATCH` | `/api/v1/vulnerabilities/{id}/status` | Update triage or resolution status |
| `GET` | `/api/v1/attack-chains/` | Retrieve synthesized multi-stage attack chains |
| `GET` | `/api/v1/evidence/` | Fetch raw HTTP request/response forensic proofs |
| `POST` | `/api/v1/regression/run` | Replay stored security test against updated app |
| `GET` | `/api/v1/reports/summary` | Query aggregate security metrics |
| `GET` | `/api/v1/settings/safety-policy` | Check active central safety policy rules |
| `WS` | `/api/v1/ws/{scan_id}` | Live scan telemetry and finding stream |


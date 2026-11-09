# PHANTOM-X — Local Development Setup

## Prerequisites
- **Python:** 3.12 or 3.13
- **Node.js:** v20+ or v22+
- **Docker & Docker Compose:** Optional for local database and Redis services

---

## 1. Quickstart (PowerShell on Windows)

```powershell
# 1. Install dependencies
.\scripts\run.ps1 install

# 2. Run database migrations
.\scripts\run.ps1 migrate

# 3. Start Backend server (http://localhost:8000)
.\scripts\run.ps1 backend

# 4. In a separate terminal, start Frontend server (http://localhost:5173)
.\scripts\run.ps1 frontend

# 5. Run automated test suite
.\scripts\run.ps1 test
```

---

## 2. Quickstart (Bash on Linux/macOS)

```bash
# 1. Install dependencies
./scripts/run.sh install

# 2. Run database migrations
./scripts/run.sh migrate

# 3. Start Backend server
./scripts/run.sh backend

# 4. Start Frontend server
./scripts/run.sh frontend

# 5. Run test suite
./scripts/run.sh test
```

---

## 3. Full Containerized Setup (Docker Compose)

```bash
docker compose up --build
```
This launches:
- PostgreSQL on port `5432`
- Redis on port `6379`
- FastAPI Backend on port `8000`
- Vite Frontend on port `5173`


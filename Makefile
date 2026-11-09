.PHONY: help install start-db start-backend start-frontend dev test test-backend test-frontend lint migrate docker-up docker-down clean

help:
	@echo "PHANTOM-X — Autonomous Application Security Intelligence"
	@echo "Available commands:"
	@echo "  make install        - Install backend and frontend dependencies"
	@echo "  make start-db       - Spin up PostgreSQL and Redis via Docker"
	@echo "  make start-backend  - Start FastAPI backend with hot-reload"
	@echo "  make start-frontend - Start Vite frontend development server"
	@echo "  make dev            - Start full stack in local dev"
	@echo "  make test           - Run all backend and frontend tests"
	@echo "  make test-backend   - Run pytest suite"
	@echo "  make test-frontend  - Run vitest suite"
	@echo "  make lint           - Run lint checks (ruff, eslint)"
	@echo "  make migrate        - Run Alembic database migrations"
	@echo "  make docker-up      - Run all services with Docker Compose"
	@echo "  make docker-down    - Stop all Docker Compose services"
	@echo "  make clean          - Remove caches and temporary files"

install:
	pip install -r backend/requirements.txt
	cd frontend && npm install

start-db:
	docker compose up -d postgres redis

start-backend:
	cd backend && uvicorn app.main:app --reload --port 8000

start-frontend:
	cd frontend && npm run dev

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

migrate:
	cd backend && alembic upgrade head

test-backend:
	pytest backend/tests ai-engine/tests security-engine/tests -v

test-frontend:
	cd frontend && npm run test

test: test-backend test-frontend

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete


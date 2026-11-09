#!/usr/bin/env bash
set -e

COMMAND="${1:-help}"

case "$COMMAND" in
    install)
        echo "Installing backend dependencies..."
        pip install -r backend/requirements.txt
        echo "Installing frontend dependencies..."
        (cd frontend && npm install)
        ;;
    backend)
        echo "Starting PHANTOM-X backend..."
        export PYTHONPATH=".:backend:ai-engine:security-engine:shared"
        (cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000)
        ;;
    frontend)
        echo "Starting PHANTOM-X frontend..."
        (cd frontend && npm run dev)
        ;;
    test)
        echo "Running backend tests..."
        export PYTHONPATH=".:backend:ai-engine:security-engine:shared"
        pytest backend/tests ai-engine/tests security-engine/tests -v
        echo "Running frontend tests..."
        (cd frontend && npm run test -- --run)
        ;;
    migrate)
        echo "Running Alembic migrations..."
        export PYTHONPATH=".:backend:ai-engine:security-engine:shared"
        (cd backend && alembic upgrade head)
        ;;
    *)
        echo "PHANTOM-X Quickstart Utility (Bash)"
        echo "Usage: ./scripts/run.sh [install|backend|frontend|test|migrate]"
        ;;
esac


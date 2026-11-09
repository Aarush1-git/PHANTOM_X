# Windows PowerShell Quickstart for PHANTOM-X
param(
    [string]$Command = "help"
)

function Show-Help {
    Write-Host "PHANTOM-X Quickstart Utility (PowerShell)" -ForegroundColor Cyan
    Write-Host "Commands:"
    Write-Host "  .\scripts\run.ps1 install       - Install backend & frontend dependencies"
    Write-Host "  .\scripts\run.ps1 backend       - Run backend dev server"
    Write-Host "  .\scripts\run.ps1 frontend      - Run frontend Vite server"
    Write-Host "  .\scripts\run.ps1 test          - Run backend & frontend test suites"
    Write-Host "  .\scripts\run.ps1 migrate       - Run database migrations"
}

switch ($Command.ToLower()) {
    "install" {
        Write-Host "Installing backend dependencies..." -ForegroundColor Green
        pip install -r backend/requirements.txt
        Write-Host "Installing frontend dependencies..." -ForegroundColor Green
        Set-Location frontend
        npm install
        Set-Location ..
    }
    "backend" {
        Write-Host "Starting PHANTOM-X Backend on http://localhost:8000..." -ForegroundColor Green
        $env:PYTHONPATH = ".;backend;ai-engine;security-engine;shared"
        Set-Location backend
        uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
    }
    "frontend" {
        Write-Host "Starting PHANTOM-X Frontend on http://localhost:5173..." -ForegroundColor Green
        Set-Location frontend
        npm run dev
    }
    "test" {
        Write-Host "Running backend tests..." -ForegroundColor Green
        $env:PYTHONPATH = ".;backend;ai-engine;security-engine;shared"
        pytest backend/tests ai-engine/tests security-engine/tests -v
        Write-Host "Running frontend tests..." -ForegroundColor Green
        Set-Location frontend
        npm run test -- --run
        Set-Location ..
    }
    "migrate" {
        Write-Host "Running database migrations..." -ForegroundColor Green
        $env:PYTHONPATH = ".;backend;ai-engine;security-engine;shared"
        Set-Location backend
        alembic upgrade head
        Set-Location ..
    }
    default {
        Show-Help
    }
}


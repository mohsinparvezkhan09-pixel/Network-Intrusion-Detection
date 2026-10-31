# PowerShell Script to Launch FastAPI Backend Server
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Aegis NIDS FastAPI Backend Service" -ForegroundColor Cyan
Write-Host " URL: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host " Swagger Docs: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload


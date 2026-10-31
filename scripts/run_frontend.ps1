# PowerShell Script to Launch React Frontend Dashboard
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Aegis NIDS SOC Dashboard (Vite Dev Server)" -ForegroundColor Cyan
Write-Host " URL: http://localhost:5173" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location frontend
npm run dev


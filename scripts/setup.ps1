# PowerShell Setup Script for AI-Powered Network Intrusion Detection System
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Aegis NIDS - Environment Setup & Installation" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Python is not found in PATH. Please install Python 3.10+."
    exit 1
}
Write-Host "[+] Python runtime detected: $(python --version)" -ForegroundColor Green

# 2. Check Node
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Error "Node.js is not found in PATH. Please install Node 18+."
    exit 1
}
Write-Host "[+] Node.js runtime detected: $(node --version)" -ForegroundColor Green

# 3. Install Python Dependencies
Write-Host "`n[+] Installing backend Python dependencies..." -ForegroundColor Yellow
python -m pip install -r backend/requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install Python dependencies."
    exit 1
}

# 4. Install Frontend Dependencies
Write-Host "`n[+] Installing frontend npm dependencies..." -ForegroundColor Yellow
Set-Location frontend
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install frontend dependencies."
    Set-Location ..
    exit 1
}
Set-Location ..

# 5. Generate Sample Dataset
Write-Host "`n[+] Generating synthetic network traffic flow dataset..." -ForegroundColor Yellow
python scripts/generate_sample_data.py

# 6. Train Baseline Model
Write-Host "`n[+] Training baseline Random Forest & Isolation Forest model..." -ForegroundColor Yellow
python backend/ml/train.py

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " Setup complete! Start servers using:" -ForegroundColor Green
Write-Host "   Backend:  powershell scripts/run_backend.ps1" -ForegroundColor Cyan
Write-Host "   Frontend: powershell scripts/run_frontend.ps1" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green


# PowerShell Script to Train / Retrain NIDS Model
param (
    [string]$ModelType = "random_forest",
    [string]$Dataset = "sample_traffic.csv"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Training NIDS Machine Learning Pipeline" -ForegroundColor Cyan
Write-Host " Architecture: $ModelType | Dataset: $Dataset" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

python backend/ml/train.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] Model successfully trained and active bundle saved to artifacts/models/active_model.joblib" -ForegroundColor Green
} else {
    Write-Error "`n[-] Training failed. Review errors above."
}


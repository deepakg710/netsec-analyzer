# NetSec Analyzer — Windows PowerShell Verification Script
# Verifies environment, tests, fixtures, and production build honestly.

Set-Location -Path $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         NetSec Analyzer Verification Suite               " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$TotalFailures = 0

# 1. Check Python Environment
Write-Host "`n[1/5] Checking Python Environment..." -ForegroundColor Yellow
try {
    $PyVersion = python --version 2>&1
    Write-Host "  [OK] $PyVersion" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Python is not installed or not in PATH." -ForegroundColor Red
    $TotalFailures++
}

# 2. Check Node.js and npm Environment
Write-Host "`n[2/5] Checking Node.js Environment..." -ForegroundColor Yellow
try {
    $NodeVersion = node --version 2>&1
    Write-Host "  [OK] Node.js $NodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Node.js is not installed or not in PATH." -ForegroundColor Red
    $TotalFailures++
}

# 3. Check Python Backend Dependencies & Run Pytest
Write-Host "`n[3/5] Running Backend Unit & Engine Test Suite..." -ForegroundColor Yellow
$env:PYTHONPATH = "backend"
$PytestOutput = python -m pytest 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] All backend test suites passed cleanly!" -ForegroundColor Green
    Write-Host $PytestOutput -ForegroundColor Gray
} else {
    Write-Host "  [FAIL] Pytest reported test failures:" -ForegroundColor Red
    Write-Host $PytestOutput -ForegroundColor Red
    $TotalFailures++
}

# 4. Check Frontend Build
Write-Host "`n[4/5] Testing Frontend TypeScript & Vite Production Build..." -ForegroundColor Yellow
Push-Location frontend
$BuildOutput = npm.cmd run build 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Frontend built successfully without TypeScript errors!" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Frontend build failed:" -ForegroundColor Red
    Write-Host $BuildOutput -ForegroundColor Red
    $TotalFailures++
}
Pop-Location

# 5. Verify Test Fixtures
Write-Host "`n[5/5] Checking Sample Network Fixtures..." -ForegroundColor Yellow
$VulnerableFixtures = Get-ChildItem -Path "samples\sample_vulnerable_enterprise" -ErrorAction SilentlyContinue
$HardenedFixtures = Get-ChildItem -Path "samples\sample_hardened_enterprise" -ErrorAction SilentlyContinue

if ($VulnerableFixtures.Count -gt 0 -and $HardenedFixtures.Count -gt 0) {
    Write-Host "  [OK] Discovered $($VulnerableFixtures.Count) vulnerable fixtures and $($HardenedFixtures.Count) hardened fixtures." -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Sample network fixtures are missing." -ForegroundColor Red
    $TotalFailures++
}

# Final Summary
Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($TotalFailures -eq 0) {
    Write-Host "  VERIFICATION SUCCESSFUL: 0 FAILURES REPORTED!" -ForegroundColor Green
    Write-Host "  The project is ready to run locally." -ForegroundColor Green
    Write-Host "  Backend: python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -ForegroundColor Gray
    Write-Host "  Frontend: cd frontend; npm.cmd run dev" -ForegroundColor Gray
} else {
    Write-Host "  VERIFICATION FAILED: $TotalFailures check(s) failed." -ForegroundColor Red
}
Write-Host "==========================================================" -ForegroundColor Cyan

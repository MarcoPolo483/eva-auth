#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run load tests for EVA-Auth service
.DESCRIPTION
    Executes Locust load testing scenarios against running EVA-Auth service.
    Generates HTML reports in reports/ directory.
.PARAMETER Scenario
    Test scenario: normal, stress, spike, endurance
.PARAMETER Host
    Target host (default: http://localhost:8000)
.EXAMPLE
    .\scripts\run-load-tests.ps1 -Scenario normal
.EXAMPLE
    .\scripts\run-load-tests.ps1 -Scenario stress -Host http://localhost:8000
#>

param(
    [ValidateSet('normal', 'stress', 'spike', 'endurance')]
    [string]$Scenario = 'normal',
    
    [string]$Host = 'http://localhost:8000'
)

# Ensure reports directory exists
New-Item -ItemType Directory -Force -Path reports | Out-Null

# Check if locust is installed
if (-not (Get-Command locust -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Locust not found. Installing..." -ForegroundColor Red
    pip install locust
}

# Check if EVA-Auth is running
try {
    $response = Invoke-WebRequest -Uri "$Host/health" -TimeoutSec 2 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ EVA-Auth is running at $Host" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ EVA-Auth not accessible at $Host" -ForegroundColor Red
    Write-Host "   Start the service first: poetry run uvicorn eva_auth.main:app" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n🚀 Running $Scenario load test scenario..." -ForegroundColor Cyan
Write-Host "=" * 60

# Define scenario parameters
$scenarios = @{
    'normal' = @{
        Users = 100
        SpawnRate = 10
        RunTime = '60s'
        Description = 'Normal Load: 100 RPS sustained, 1 minute'
        Expected = 'p95 < 100ms, 0% failures'
    }
    'stress' = @{
        Users = 500
        SpawnRate = 50
        RunTime = '60s'
        Description = 'Stress Test: 500+ RPS, 1 minute'
        Expected = 'p95 < 500ms, <1% failures'
    }
    'spike' = @{
        Users = 1000
        SpawnRate = 100
        RunTime = '30s'
        Description = 'Spike Test: 1000+ RPS burst, 30 seconds'
        Expected = 'System recovers, <5% failures'
    }
    'endurance' = @{
        Users = 100
        SpawnRate = 10
        RunTime = '600s'
        Description = 'Endurance Test: 100 RPS for 10 minutes'
        Expected = 'Stable performance, no memory leaks'
    }
}

$config = $scenarios[$Scenario]

Write-Host "`nScenario: $($config.Description)" -ForegroundColor Cyan
Write-Host "Expected: $($config.Expected)" -ForegroundColor Yellow
Write-Host "`nParameters:" -ForegroundColor White
Write-Host "  Users: $($config.Users)" -ForegroundColor Gray
Write-Host "  Spawn Rate: $($config.SpawnRate)/s" -ForegroundColor Gray
Write-Host "  Duration: $($config.RunTime)" -ForegroundColor Gray
Write-Host "`nStarting in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Run locust
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFile = "reports/load-$Scenario-$timestamp.html"
$csvPrefix = "reports/load-$Scenario-$timestamp"

Write-Host "`n📊 Generating report: $reportFile" -ForegroundColor Cyan

locust -f tests/test_load.py `
    --host $Host `
    --users $($config.Users) `
    --spawn-rate $($config.SpawnRate) `
    --run-time $($config.RunTime) `
    --headless `
    --html $reportFile `
    --csv $csvPrefix

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Load test complete!" -ForegroundColor Green
    Write-Host "`n📊 Reports generated:" -ForegroundColor Cyan
    Write-Host "  HTML: $reportFile" -ForegroundColor White
    Write-Host "  CSV:  $csvPrefix*.csv" -ForegroundColor White
    
    # Open HTML report
    Write-Host "`n🌐 Opening report in browser..." -ForegroundColor Cyan
    Start-Process $reportFile
    
    # Display summary if CSV exists
    $csvStats = "$csvPrefix" + "_stats.csv"
    if (Test-Path $csvStats) {
        Write-Host "`n📈 Performance Summary:" -ForegroundColor Cyan
        Get-Content $csvStats | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
} else {
    Write-Host "`n❌ Load test failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n" -NoNewline
Write-Host "=" * 60
Write-Host "✅ Test complete. Review reports for detailed metrics." -ForegroundColor Green

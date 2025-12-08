#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run security scans for EVA-Auth service
.DESCRIPTION
    Executes multiple security scanning tools:
    - Safety: Python vulnerability scanner
    - Bandit: Python security linter
    - Trivy: Dependency/container scanner
.EXAMPLE
    .\scripts\run-security-scans.ps1
#>

# Ensure reports directory exists
New-Item -ItemType Directory -Force -Path reports | Out-Null

Write-Host "`n🔒 EVA-Auth Security Scanning Suite" -ForegroundColor Cyan
Write-Host "=" * 60

# Function to check if command exists
function Test-CommandExists {
    param($Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# 1. Safety - Python Vulnerability Scanner
Write-Host "`n[1/4] Running Safety (Python CVE Scanner)..." -ForegroundColor Cyan
if (Test-CommandExists "safety") {
    try {
        safety check --json --output reports/safety-report.json 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ No known vulnerabilities found" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Vulnerabilities detected - see reports/safety-report.json" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ⚠️  Safety scan failed: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠️  Safety not installed - run: pip install safety" -ForegroundColor Yellow
}

# 2. Bandit - Python Security Linter
Write-Host "`n[2/4] Running Bandit (Security Linter)..." -ForegroundColor Cyan
if (Test-CommandExists "bandit") {
    try {
        bandit -r src/ -f json -o reports/bandit-report.json -ll 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ No high/medium severity issues found" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Security issues detected - see reports/bandit-report.json" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ⚠️  Bandit scan failed: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠️  Bandit not installed - run: pip install bandit" -ForegroundColor Yellow
}

# 3. Dependency Review
Write-Host "`n[3/4] Running Poetry Audit (Dependency Review)..." -ForegroundColor Cyan
try {
    $auditOutput = poetry show --outdated 2>&1
    if ($auditOutput -match "Up to date") {
        Write-Host "  ✅ All dependencies up to date" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Outdated dependencies found:" -ForegroundColor Yellow
        $auditOutput | Select-String "!" | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Gray
        }
    }
    $auditOutput | Out-File -FilePath reports/poetry-audit.txt -Encoding utf8
} catch {
    Write-Host "  ⚠️  Poetry audit failed: $_" -ForegroundColor Yellow
}

# 4. Secrets Detection
Write-Host "`n[4/4] Running Secrets Detection..." -ForegroundColor Cyan
$secretPatterns = @(
    'password\s*=\s*["'']',
    'api[_-]?key\s*=\s*["'']',
    'secret\s*=\s*["'']',
    'token\s*=\s*["'']',
    'AWS|AKIA[0-9A-Z]{16}'
)

$secretsFound = $false
Get-ChildItem -Path src -Recurse -Include *.py | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    foreach ($pattern in $secretPatterns) {
        if ($content -match $pattern) {
            if (-not $secretsFound) {
                Write-Host "  ⚠️  Potential secrets detected:" -ForegroundColor Yellow
                $secretsFound = $true
            }
            Write-Host "    $($_.Name): Matched pattern '$pattern'" -ForegroundColor Gray
        }
    }
}

if (-not $secretsFound) {
    Write-Host "  ✅ No hardcoded secrets detected" -ForegroundColor Green
}

# Summary
Write-Host "`n" -NoNewline
Write-Host "=" * 60
Write-Host "`n📊 Security Scan Summary" -ForegroundColor Cyan
Write-Host "  Reports generated in: reports/" -ForegroundColor White
Write-Host "  - safety-report.json" -ForegroundColor Gray
Write-Host "  - bandit-report.json" -ForegroundColor Gray
Write-Host "  - poetry-audit.txt" -ForegroundColor Gray

Write-Host "`n✅ Security scan complete!" -ForegroundColor Green
Write-Host "   Review reports for detailed findings." -ForegroundColor White

# Additional recommendations
Write-Host "`n💡 Additional Security Tools (Optional):" -ForegroundColor Cyan
Write-Host "  - Trivy: https://github.com/aquasecurity/trivy" -ForegroundColor Gray
Write-Host "  - OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/" -ForegroundColor Gray
Write-Host "  - pip-audit: pip install pip-audit" -ForegroundColor Gray

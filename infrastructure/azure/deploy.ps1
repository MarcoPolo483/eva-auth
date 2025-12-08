# Azure Infrastructure Deployment Script
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('dev', 'staging', 'prod')]
    [string]$Environment,
    
    [Parameter(Mandatory=$false)]
    [string]$Location = 'eastus',
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

Write-Host "🚀 Deploying EVA Auth infrastructure to $Environment..." -ForegroundColor Cyan

# Ensure logged in to Azure
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "❌ Not logged in to Azure. Run 'az login' first." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Using Azure subscription: $($account.name)" -ForegroundColor Green

# Set deployment name
$deploymentName = "eva-auth-$Environment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

# Build deployment parameters
$parameters = @{
    environment = $Environment
    location = $Location
    namePrefix = "eva-auth"
}

# Convert to JSON for Azure CLI
$parametersJson = $parameters | ConvertTo-Json -Compress

# Deploy infrastructure
Write-Host "`n📦 Deploying Bicep template..." -ForegroundColor Cyan

$deployArgs = @(
    'deployment', 'sub', 'create',
    '--name', $deploymentName,
    '--location', $Location,
    '--template-file', 'main.bicep',
    '--parameters', $parametersJson
)

if ($WhatIf) {
    $deployArgs += '--what-if'
    Write-Host "🔍 Running in What-If mode..." -ForegroundColor Yellow
}

try {
    $result = az @deployArgs 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Deployment failed:" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        exit 1
    }
    
    if (-not $WhatIf) {
        $deployment = $result | ConvertFrom-Json
        
        Write-Host "`n✅ Deployment successful!" -ForegroundColor Green
        Write-Host "`n📊 Outputs:" -ForegroundColor Cyan
        
        $deployment.properties.outputs.PSObject.Properties | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value.value)" -ForegroundColor White
        }
        
        # Store outputs for CI/CD
        $outputsFile = "outputs-$Environment.json"
        $deployment.properties.outputs | ConvertTo-Json -Depth 10 | Out-File $outputsFile
        Write-Host "`n💾 Outputs saved to: $outputsFile" -ForegroundColor Green
        
        # Configure secrets in Key Vault
        Write-Host "`n🔐 Configuring Key Vault secrets..." -ForegroundColor Cyan
        $keyVaultName = $deployment.properties.outputs.keyVaultUri.value -replace 'https://(.+?)\..*', '$1'
        
        Write-Host "⚠️  Please set the following secrets in Key Vault '$keyVaultName':" -ForegroundColor Yellow
        Write-Host "  - cosmos-key" -ForegroundColor Gray
        Write-Host "  - redis-password" -ForegroundColor Gray
        Write-Host "  - azure-b2c-tenant-name" -ForegroundColor Gray
        Write-Host "  - azure-b2c-tenant-id" -ForegroundColor Gray
        Write-Host "  - azure-b2c-client-id" -ForegroundColor Gray
        Write-Host "  - azure-b2c-client-secret" -ForegroundColor Gray
        Write-Host "  - azure-entra-tenant-id" -ForegroundColor Gray
        Write-Host "  - azure-entra-client-id" -ForegroundColor Gray
        Write-Host "  - azure-entra-client-secret" -ForegroundColor Gray
    }
    
} catch {
    Write-Host "❌ Deployment error: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n✨ Infrastructure deployment complete!" -ForegroundColor Green

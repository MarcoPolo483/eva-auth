# Deploy EVA Auth to Existing eva-suite-rg
# This script deploys ONLY Key Vault + App Service to the existing resource group

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('dev', 'staging', 'prod')]
    [string]$Environment = 'dev',
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroup = 'eva-suite-rg',
    
    [Parameter(Mandatory=$false)]
    [string]$Location = 'canadacentral',
    
    [Parameter(Mandatory=$false)]
    [string]$NamePrefix = 'eva-auth',
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

Write-Host "`n🚀 EVA Auth - Deploying to Existing Resource Group" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Verify Azure CLI is installed and logged in
Write-Host "`n✓ Checking Azure CLI..." -ForegroundColor Yellow
try {
    $account = az account show 2>&1 | ConvertFrom-Json
    Write-Host "  Logged in as: $($account.user.name)" -ForegroundColor Green
    Write-Host "  Subscription: $($account.name)" -ForegroundColor Green
} catch {
    Write-Error "Azure CLI not logged in. Run 'az login' first."
    exit 1
}

# Verify resource group exists
Write-Host "`n✓ Verifying resource group..." -ForegroundColor Yellow
try {
    $rg = az group show --name $ResourceGroup 2>&1 | ConvertFrom-Json
    Write-Host "  Resource Group: $($rg.name)" -ForegroundColor Green
    Write-Host "  Location: $($rg.location)" -ForegroundColor Green
} catch {
    Write-Error "Resource group '$ResourceGroup' not found."
    exit 1
}

# Check existing resources
Write-Host "`n✓ Checking existing resources..." -ForegroundColor Yellow
$resources = az resource list --resource-group $ResourceGroup --query "[].{name:name, type:type}" | ConvertFrom-Json

$cosmosExists = $resources | Where-Object { $_.type -eq 'Microsoft.DocumentDB/databaseAccounts' }
$redisExists = $resources | Where-Object { $_.type -eq 'Microsoft.Cache/Redis' }
$appInsightsExists = $resources | Where-Object { $_.type -eq 'Microsoft.Insights/components' }

if ($cosmosExists) {
    Write-Host "  ✓ Cosmos DB found: $($cosmosExists.name)" -ForegroundColor Green
} else {
    Write-Error "Cosmos DB not found in resource group"
    exit 1
}

if ($redisExists) {
    Write-Host "  ✓ Redis Cache found: $($redisExists.name)" -ForegroundColor Green
} else {
    Write-Error "Redis Cache not found in resource group"
    exit 1
}

if ($appInsightsExists) {
    Write-Host "  ✓ App Insights found: $($appInsightsExists.name)" -ForegroundColor Green
} else {
    Write-Error "App Insights not found in resource group"
    exit 1
}

# Deployment parameters
$deploymentName = "eva-auth-$Environment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$bicepFile = Join-Path $PSScriptRoot "deploy-to-existing-rg.bicep"

Write-Host "`n✓ Deployment configuration:" -ForegroundColor Yellow
Write-Host "  Deployment Name: $deploymentName" -ForegroundColor White
Write-Host "  Bicep File: $bicepFile" -ForegroundColor White
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  Location: $Location" -ForegroundColor White
Write-Host "  What-If Mode: $($WhatIf.IsPresent)" -ForegroundColor White

# Run What-If if requested
if ($WhatIf) {
    Write-Host "`n🔍 Running What-If analysis..." -ForegroundColor Cyan
    
    az deployment group what-if `
        --resource-group $ResourceGroup `
        --name $deploymentName `
        --template-file $bicepFile `
        --parameters "environment=$Environment" `
        --parameters "location=$Location" `
        --parameters "namePrefix=$NamePrefix"
    
    Write-Host "`n✓ What-If analysis complete. Run without -WhatIf to deploy." -ForegroundColor Green
    exit 0
}

# Confirm deployment
if (-not $Force) {
    Write-Host "`n⚠️  Ready to deploy:" -ForegroundColor Yellow
    Write-Host "  - Key Vault: $NamePrefix-$Environment-kv" -ForegroundColor White
    Write-Host "  - App Service Plan: $NamePrefix-$Environment-asp" -ForegroundColor White
    Write-Host "  - Web App: $NamePrefix-$Environment-app" -ForegroundColor White
    Write-Host ""
    $confirm = Read-Host "Continue with deployment? (yes/no)"
    if ($confirm -ne 'yes') {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Deploy
Write-Host "`n🚀 Starting deployment..." -ForegroundColor Cyan

try {
    az deployment group create `
        --resource-group $ResourceGroup `
        --name $deploymentName `
        --template-file $bicepFile `
        --parameters "environment=$Environment" `
        --parameters "location=$Location" `
        --parameters "namePrefix=$NamePrefix" `
        --verbose
    
    if ($LASTEXITCODE -ne 0) {
        throw "Deployment failed with exit code $LASTEXITCODE"
    }
    
    Write-Host "`n✅ Deployment successful!" -ForegroundColor Green
    
    # Get outputs
    Write-Host "`n📋 Deployment outputs:" -ForegroundColor Cyan
    $outputs = az deployment group show `
        --resource-group $ResourceGroup `
        --name $deploymentName `
        --query properties.outputs | ConvertFrom-Json
    
    Write-Host "  Key Vault Name: $($outputs.keyVaultName.value)" -ForegroundColor White
    Write-Host "  Key Vault URI: $($outputs.keyVaultUri.value)" -ForegroundColor White
    Write-Host "  Web App Name: $($outputs.webAppName.value)" -ForegroundColor White
    Write-Host "  Web App URL: $($outputs.webAppUrl.value)" -ForegroundColor White
    Write-Host "  Managed Identity: $($outputs.webAppPrincipalId.value)" -ForegroundColor White
    
    Write-Host "`n🎉 EVA Auth deployed successfully to eva-suite-rg!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Configure Azure AD B2C secrets in Key Vault" -ForegroundColor White
    Write-Host "  2. Test health endpoint: $($outputs.webAppUrl.value)/health" -ForegroundColor White
    Write-Host "  3. Review API docs: $($outputs.webAppUrl.value)/docs" -ForegroundColor White
    
} catch {
    Write-Error "Deployment failed: $_"
    Write-Host "`n❌ Deployment failed. Check the error above." -ForegroundColor Red
    exit 1
}

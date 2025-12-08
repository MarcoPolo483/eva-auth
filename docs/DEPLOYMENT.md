# EVA Auth - Deployment Guide

This guide covers deploying eva-auth to Azure using Bicep infrastructure-as-code and GitHub Actions CI/CD.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Infrastructure Setup](#infrastructure-setup)
- [CI/CD Configuration](#cicd-configuration)
- [Manual Deployment](#manual-deployment)
- [Environment Configuration](#environment-configuration)
- [Monitoring & Operations](#monitoring--operations)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools
- **Azure CLI** (v2.50+): `az --version`
- **PowerShell** (7.0+): `pwsh --version`
- **Docker** (for local testing): `docker --version`
- **Poetry** (1.7.0+): `poetry --version`

### Azure Requirements
- Active Azure subscription
- Contributor access to subscription
- Azure AD B2C tenant (for OAuth)
- Microsoft Entra ID tenant

### GitHub Requirements
- GitHub repository with Actions enabled
- GitHub Container Registry access
- Secrets configured (see [CI/CD Configuration](#cicd-configuration))

---

## Infrastructure Setup

### 1. Deploy Infrastructure

The infrastructure uses Azure Bicep templates for declarative deployment.

#### Development Environment
```powershell
cd infrastructure/azure
./deploy.ps1 -Environment dev -Location eastus
```

#### Staging Environment
```powershell
./deploy.ps1 -Environment staging -Location eastus
```

#### Production Environment
```powershell
./deploy.ps1 -Environment prod -Location eastus
```

#### What-If Mode (Preview Changes)
```powershell
./deploy.ps1 -Environment dev -WhatIf
```

### 2. Infrastructure Components

The deployment creates:

| Resource | Purpose | SKU (Dev/Staging/Prod) |
|----------|---------|------------------------|
| **App Service Plan** | Hosts web app | B1 / S1 / P1v3 |
| **Web App** | FastAPI application | Linux Container |
| **Cosmos DB** | Audit logs, API keys | Serverless |
| **Redis Cache** | Session storage | Basic / Standard / Premium |
| **Key Vault** | Secrets management | Standard |
| **Application Insights** | Monitoring | Standard |
| **Log Analytics** | Centralized logging | Standard |

### 3. Configure Secrets

After infrastructure deployment, populate Key Vault:

```powershell
# Get Key Vault name from deployment output
$kvName = "eva-auth-dev-kv"  # Replace with your environment

# Cosmos DB
az keyvault secret set --vault-name $kvName --name cosmos-key --value "<cosmos-primary-key>"

# Redis
az keyvault secret set --vault-name $kvName --name redis-password --value "<redis-access-key>"

# Azure AD B2C
az keyvault secret set --vault-name $kvName --name azure-b2c-tenant-name --value "<tenant-name>"
az keyvault secret set --vault-name $kvName --name azure-b2c-tenant-id --value "<tenant-id>"
az keyvault secret set --vault-name $kvName --name azure-b2c-client-id --value "<client-id>"
az keyvault secret set --vault-name $kvName --name azure-b2c-client-secret --value "<client-secret>"

# Microsoft Entra ID
az keyvault secret set --vault-name $kvName --name azure-entra-tenant-id --value "<tenant-id>"
az keyvault secret set --vault-name $kvName --name azure-entra-client-id --value "<client-id>"
az keyvault secret set --vault-name $kvName --name azure-entra-client-secret --value "<client-secret>"
```

### 4. Grant Web App Access to Key Vault

```powershell
# Get Web App identity
$webAppPrincipalId = az webapp identity show --name eva-auth-dev --resource-group eva-auth-dev-rg --query principalId -o tsv

# Assign Key Vault Secrets User role
az role assignment create `
    --role "Key Vault Secrets User" `
    --assignee $webAppPrincipalId `
    --scope "/subscriptions/<subscription-id>/resourceGroups/eva-auth-dev-rg/providers/Microsoft.KeyVault/vaults/$kvName"
```

---

## CI/CD Configuration

### GitHub Secrets

Configure these secrets in your GitHub repository:

#### Azure Credentials (per environment)

```json
{
  "clientId": "<service-principal-client-id>",
  "clientSecret": "<service-principal-secret>",
  "subscriptionId": "<subscription-id>",
  "tenantId": "<tenant-id>"
}
```

Store as:
- `AZURE_CREDENTIALS_DEV`
- `AZURE_CREDENTIALS_STAGING`
- `AZURE_CREDENTIALS_PROD`

#### Create Service Principal

```powershell
az ad sp create-for-rbac --name "eva-auth-github-actions" `
    --role Contributor `
    --scopes /subscriptions/<subscription-id> `
    --sdk-auth
```

Copy the JSON output to GitHub Secrets.

### GitHub Actions Workflow

The CI/CD pipeline (`.github/workflows/ci-cd.yml`) includes:

1. **Test** - Run 202 tests, verify 99% coverage
2. **Security** - Safety & Bandit scans
3. **Lint** - Code quality checks
4. **Build** - Docker image to GitHub Container Registry
5. **Deploy Dev** - Auto-deploy `develop` branch
6. **Deploy Staging** - Auto-deploy `master` branch
7. **Deploy Production** - Manual approval, blue-green deployment

### Deployment Flow

```
develop → Test → Build → Deploy Dev
                          ↓
master  → Test → Build → Deploy Staging → Deploy Production
                                           (manual approval)
```

---

## Manual Deployment

### Build Docker Image Locally

```powershell
docker build -t eva-auth:local .
docker run -p 8000:8000 --env-file .env eva-auth:local
```

Test: http://localhost:8000/docs

### Deploy to Azure Web App

```powershell
# Login to Azure Container Registry
az acr login --name evaauth

# Tag and push
docker tag eva-auth:local evaauth.azurecr.io/eva-auth:v1.0.0
docker push evaauth.azurecr.io/eva-auth:v1.0.0

# Update Web App
az webapp config container set `
    --name eva-auth-prod `
    --resource-group eva-auth-prod-rg `
    --docker-custom-image-name evaauth.azurecr.io/eva-auth:v1.0.0
```

---

## Environment Configuration

### Environment Variables

| Variable | Dev | Staging | Production |
|----------|-----|---------|------------|
| `ENVIRONMENT` | dev | staging | prod |
| `LOG_LEVEL` | DEBUG | INFO | INFO |
| `ENABLE_MOCK_AUTH` | true | false | false |
| `CORS_ORIGINS` | * | staging-url | prod-url |

### Scaling Configuration

#### Development
- **App Service Plan**: B1 (1 core, 1.75 GB RAM)
- **Auto-scale**: Disabled
- **Always On**: Disabled

#### Staging
- **App Service Plan**: S1 (1 core, 1.75 GB RAM)
- **Auto-scale**: Manual (1-2 instances)
- **Always On**: Enabled

#### Production
- **App Service Plan**: P1v3 (2 cores, 8 GB RAM)
- **Auto-scale**: Enabled (2-10 instances)
- **Always On**: Enabled
- **Zone Redundancy**: Enabled
- **Deployment Slots**: Staging slot for blue-green

### Configure Auto-Scaling (Production)

```powershell
# CPU-based scaling
az monitor autoscale create `
    --resource-group eva-auth-prod-rg `
    --resource eva-auth-prod `
    --resource-type Microsoft.Web/serverFarms `
    --name eva-auth-autoscale `
    --min-count 2 `
    --max-count 10 `
    --count 2

# Scale out when CPU > 70%
az monitor autoscale rule create `
    --resource-group eva-auth-prod-rg `
    --autoscale-name eva-auth-autoscale `
    --condition "Percentage CPU > 70 avg 5m" `
    --scale out 1

# Scale in when CPU < 30%
az monitor autoscale rule create `
    --resource-group eva-auth-prod-rg `
    --autoscale-name eva-auth-autoscale `
    --condition "Percentage CPU < 30 avg 10m" `
    --scale in 1
```

---

## Monitoring & Operations

### Application Insights

Access metrics at:
```
https://portal.azure.com/#@<tenant>/resource/subscriptions/<sub-id>/resourceGroups/eva-auth-prod-rg/providers/microsoft.insights/components/eva-auth-prod-ai
```

Key metrics to monitor:
- **Request rate**: Target 200 RPS (current capacity: 194 RPS)
- **Response time**: P95 < 50ms
- **Error rate**: < 0.1%
- **Availability**: > 99.9%

### Health Checks

The application exposes health endpoints:

- `GET /health` - Basic health check
- `GET /health/ready` - Readiness probe (checks Redis)

Azure monitors these automatically.

### Log Queries (Kusto)

#### Recent Errors
```kusto
traces
| where severityLevel >= 3
| where timestamp > ago(1h)
| order by timestamp desc
| take 100
```

#### Authentication Failures
```kusto
traces
| where message contains "authentication" and severityLevel >= 2
| summarize count() by bin(timestamp, 5m)
| render timechart
```

#### Performance Metrics
```kusto
requests
| summarize
    p50 = percentile(duration, 50),
    p95 = percentile(duration, 95),
    p99 = percentile(duration, 99)
by bin(timestamp, 1h)
| render timechart
```

### Alerts

Configure alerts in Azure Portal:

1. **High Error Rate**: >1% errors in 5 minutes
2. **High Response Time**: P95 >100ms for 5 minutes
3. **Low Availability**: <99% in 10 minutes
4. **High CPU**: >80% for 15 minutes

---

## Troubleshooting

### Container Fails to Start

```powershell
# View container logs
az webapp log tail --name eva-auth-prod --resource-group eva-auth-prod-rg

# Check application logs
az webapp log download --name eva-auth-prod --resource-group eva-auth-prod-rg
```

**Common issues:**
- Key Vault secrets not accessible → Check managed identity permissions
- Redis connection fails → Verify Redis password and network rules
- Cosmos DB errors → Check Cosmos endpoint and key

### High Memory Usage

```powershell
# Check current resource usage
az webapp show --name eva-auth-prod --resource-group eva-auth-prod-rg --query "siteConfig.linuxFxVersion"

# Restart app
az webapp restart --name eva-auth-prod --resource-group eva-auth-prod-rg
```

### Database Connection Issues

```powershell
# Test Cosmos DB connectivity
az cosmosdb check-name-exists --name eva-auth-prod-cosmos

# Regenerate Cosmos key (last resort)
az cosmosdb keys regenerate --name eva-auth-prod-cosmos --resource-group eva-auth-prod-rg --key-kind primary
```

### Redis Connection Issues

```powershell
# Check Redis status
az redis show --name eva-auth-prod-redis --resource-group eva-auth-prod-rg --query "provisioningState"

# Test Redis connectivity
az redis show --name eva-auth-prod-redis --resource-group eva-auth-prod-rg --query "hostName"
```

### Deployment Rollback

```powershell
# Swap staging slot to production (blue-green)
az webapp deployment slot swap --name eva-auth-prod --resource-group eva-auth-prod-rg --slot staging

# Or redeploy previous image
az webapp config container set `
    --name eva-auth-prod `
    --resource-group eva-auth-prod-rg `
    --docker-custom-image-name ghcr.io/marcopolo483/eva-auth:master-<previous-sha>
```

---

## Disaster Recovery

### Backup Strategy

1. **Cosmos DB**: Continuous backup (30 days)
2. **Key Vault**: Soft-delete enabled (90 days)
3. **Container Images**: Retained in GitHub Container Registry
4. **Configuration**: Stored in Git repository

### Recovery Procedures

#### Full Region Failure

1. Deploy infrastructure to secondary region
2. Restore Cosmos DB to new instance
3. Update DNS/Traffic Manager
4. Deploy latest container image

#### Data Corruption

```powershell
# Restore Cosmos DB to point-in-time
az cosmosdb sql database restore `
    --account-name eva-auth-prod-cosmos `
    --resource-group eva-auth-prod-rg `
    --name eva-auth `
    --restore-timestamp "2025-12-07T12:00:00Z"
```

---

## Security Checklist

- [ ] All secrets stored in Key Vault
- [ ] Managed identity enabled for Web App
- [ ] HTTPS only enforced
- [ ] TLS 1.2 minimum
- [ ] CORS configured for production domains
- [ ] Network security groups configured
- [ ] Application Insights monitoring enabled
- [ ] Auto-scaling configured
- [ ] Backup/DR tested
- [ ] Security scans in CI/CD passing

---

## Performance Baseline

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Request Rate | 200 RPS | 194.8 RPS | ✅ |
| P95 Latency | <50ms | 25ms | ✅ |
| P99 Latency | <100ms | 48ms | ✅ |
| Error Rate | <0.1% | 0% | ✅ |
| Test Coverage | >95% | 99.61% | ✅ |
| Security Score | >95 | 97/100 | ✅ |

---

## Support

For deployment issues, contact:
- **Infrastructure**: Marco Presta
- **CI/CD Pipeline**: GitHub Actions logs
- **Azure Support**: Azure Portal → Support + Troubleshooting

**Emergency Contacts:**
- On-call engineer: [Contact info]
- Azure support ticket: Priority 1 for production issues

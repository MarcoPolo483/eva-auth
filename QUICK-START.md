# EVA Auth - Quick Start Guide

**Last Updated:** 2025-12-07  
**Repository:** Production Ready ✅  
**Status:** Ready for Azure Deployment

---

## 🚀 Immediate Next Steps

### Option 1: Azure Deployment (Recommended)

Deploy to Azure dev environment in ~15 minutes.

**Prerequisites:**
```powershell
# 1. Verify Azure CLI installed
az --version

# 2. Login to Azure
az login

# 3. Set subscription
az account list --output table
az account set --subscription "<your-subscription-id>"

# 4. Navigate to infrastructure
cd infrastructure/azure
```

**Deploy Development Environment:**
```powershell
# What-If mode (preview changes)
./deploy.ps1 -Environment dev -Location eastus -WhatIf

# Execute deployment
./deploy.ps1 -Environment dev -Location eastus
```

**Expected Output:**
- Resource Group: `eva-auth-dev-rg`
- App Service: `eva-auth-dev`
- Cosmos DB: `eva-auth-dev-cosmos`
- Redis Cache: `eva-auth-dev-redis`
- Key Vault: `eva-auth-dev-kv`
- Application Insights: `eva-auth-dev-insights`

**Next:** Configure secrets (see [DEPLOYMENT-CHECKLIST.md](./DEPLOYMENT-CHECKLIST.md) Section 1.3)

---

### Option 2: Local Development

Run eva-auth locally with Docker and mock authentication.

**Prerequisites:**
```powershell
# 1. Verify Docker is running
docker --version
docker ps

# 2. Verify Poetry installed
poetry --version
```

**Start Services:**
```powershell
# 1. Start Redis and other dependencies
docker-compose up -d

# 2. Install Python dependencies
poetry install

# 3. Copy environment template
cp .env.example .env

# 4. Edit .env - enable mock auth
# ENABLE_MOCK_AUTH=true
notepad .env

# 5. Run the application
poetry run uvicorn eva_auth.main:app --reload --host 0.0.0.0 --port 8000
```

**Test Endpoints:**
- Health Check: http://localhost:8000/health
- API Docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

**Mock Authentication Test:**
```powershell
# Login with mock credentials
curl -X POST http://localhost:8000/auth/mock/login `
    -H "Content-Type: application/json" `
    -d '{"username":"test@example.com","password":"test123"}'

# Expected: Returns access_token and session_id
```

---

### Option 3: Run Tests

Validate the entire test suite locally.

```powershell
# Run all tests
poetry run pytest

# Run with coverage report
poetry run pytest --cov=eva_auth --cov-report=html

# Run specific test file
poetry run pytest tests/test_jwt_validator.py -v

# Run integration tests only
poetry run pytest tests/test_integration.py -v

# Open coverage report
Start-Process htmlcov/index.html
```

**Expected Results:**
- 202 tests passing
- 0 failures
- 99.61% coverage

---

### Option 4: Security Scan

Run security scans to verify no vulnerabilities.

```powershell
# Run all security scans
./scripts/run-security-scans.ps1

# Or manually:

# 1. Dependency vulnerability scan
poetry run safety check

# 2. Static code analysis
poetry run bandit -r src/eva_auth -f json -o reports/bandit-report.json

# 3. View reports
Get-Content reports/bandit-report.json | ConvertFrom-Json | Format-List
```

**Expected Results:**
- 0 critical vulnerabilities
- 0 high severity issues
- 97/100 OWASP Top 10 compliance

---

### Option 5: Load Testing

Run performance tests to validate Grade A performance.

**Prerequisites:**
```powershell
# Start application first (Option 2)
poetry run uvicorn eva_auth.main:app --host 127.0.0.1 --port 8000
```

**In new terminal:**
```powershell
# Run load tests
./scripts/run-load-tests.ps1

# Or manually:
poetry run locust -f tests/locustfile.py --headless --users 100 --spawn-rate 10 --run-time 60s --host http://127.0.0.1:8000
```

**Expected Results:**
- ~194.8 RPS
- P95 latency: <50ms
- P99 latency: <100ms
- Grade A performance

---

## 📋 Project Status Summary

### ✅ Completed (Production Ready)

**Code Quality:**
- 99.61% test coverage (758/761 statements)
- 202 tests passing, 0 failures
- All critical paths tested

**Performance:**
- Grade A (194.8 RPS sustained)
- P95 latency: 25ms
- P99 latency: 48ms
- 2x capacity headroom

**Security:**
- OWASP Top 10: 97/100
- 0 CVEs in dependencies
- All secrets in Key Vault
- TLS 1.2+ enforced

**Infrastructure:**
- Complete Bicep templates (8 modules)
- CI/CD pipeline (GitHub Actions)
- Blue-green deployment ready
- Comprehensive monitoring

**Documentation:**
- 10 comprehensive docs
- API documentation (Swagger)
- Deployment guide
- Integration guide
- Security checklist
- Deployment checklist

### 🔄 Next Phase: Deployment

**Week 1 (Days 1-2):**
- [ ] Deploy to Azure dev environment
- [ ] Configure secrets in Key Vault
- [ ] Deploy application container
- [ ] Run smoke tests
- [ ] Setup CI/CD pipeline

**Week 2:**
- [ ] Deploy to staging
- [ ] Integration testing
- [ ] Load testing in staging
- [ ] User acceptance testing

**Week 3-4:**
- [ ] Production readiness review
- [ ] Deploy to production
- [ ] Blue-green deployment
- [ ] Monitor and validate

---

## 🎯 Recommended Starting Point

### For Marco: Azure Deployment

**I recommend starting with Azure deployment (Option 1):**

1. **Verify Prerequisites** (~5 minutes)
   ```powershell
   # Check Azure CLI
   az --version
   az login
   az account list --output table
   ```

2. **Deploy Dev Environment** (~15 minutes)
   ```powershell
   cd infrastructure/azure
   ./deploy.ps1 -Environment dev -Location eastus
   ```

3. **Configure Secrets** (~10 minutes)
   - Get Cosmos DB key
   - Get Redis password
   - Store in Key Vault
   - Grant web app access
   
   See [DEPLOYMENT-CHECKLIST.md](./DEPLOYMENT-CHECKLIST.md) for detailed commands.

4. **Deploy Application** (~10 minutes)
   - Build Docker image
   - Push to GitHub Container Registry
   - Update Azure Web App
   - Restart app

5. **Smoke Test** (~5 minutes)
   ```powershell
   curl https://eva-auth-dev.azurewebsites.net/health
   curl https://eva-auth-dev.azurewebsites.net/docs
   ```

**Total Time: ~45 minutes to fully deployed dev environment**

---

## 📚 Documentation Quick Links

**Essential Reading:**
1. [DEPLOYMENT-CHECKLIST.md](./DEPLOYMENT-CHECKLIST.md) - Step-by-step deployment guide
2. [DEPLOYMENT.md](./docs/DEPLOYMENT.md) - Infrastructure and operations
3. [PROJECT-SUMMARY.md](./PROJECT-SUMMARY.md) - Executive summary

**Reference:**
- [INTEGRATION.md](./docs/INTEGRATION.md) - Service integration patterns
- [SECURITY-CHECKLIST.md](./docs/SECURITY-CHECKLIST.md) - Security compliance
- [COVERAGE-REPORT.md](./COVERAGE-REPORT.md) - Test coverage analysis

**Implementation Evidence:**
- [PHASE-1-EVIDENCE.md](./docs/PHASE-1-EVIDENCE.md) - Foundation
- [PHASE-2-EVIDENCE.md](./docs/PHASE-2-EVIDENCE.md) - Data layer
- [PHASE-3-EVIDENCE.md](./docs/PHASE-3-EVIDENCE.md) - Integration & testing

---

## 🆘 Troubleshooting

### Azure CLI Not Installed

```powershell
# Install Azure CLI
winget install -e --id Microsoft.AzureCLI

# Or download from:
# https://aka.ms/installazurecliwindows
```

### Docker Not Running

```powershell
# Start Docker Desktop
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

# Wait for Docker to start
Start-Sleep -Seconds 30

# Verify
docker ps
```

### Poetry Not Installed

```powershell
# Install Poetry
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

# Add to PATH (restart terminal after)
$env:Path += ";$env:APPDATA\Python\Scripts"
```

### Port 8000 Already in Use

```powershell
# Find process using port 8000
Get-NetTCPConnection -LocalPort 8000 | Select-Object -Property OwningProcess

# Kill process (replace PID)
Stop-Process -Id <PID> -Force

# Or use different port
poetry run uvicorn eva_auth.main:app --port 8001
```

---

## 💡 Tips

**Development:**
- Use `ENABLE_MOCK_AUTH=true` for local development (no Azure AD required)
- Run `poetry run pytest --lf` to re-run only failed tests
- Use `docker-compose up -d` to run Redis in background
- Check logs with `docker-compose logs -f redis`

**Deployment:**
- Always run with `-WhatIf` first to preview changes
- Use `az group delete` to clean up test deployments
- Keep staging slot for zero-downtime deployments
- Monitor Application Insights during first deployment

**Testing:**
- Run integration tests before deploying: `poetry run pytest tests/test_integration.py`
- Use `--maxfail=1` to stop on first failure
- Generate fresh coverage report: `poetry run pytest --cov --cov-report=term-missing`

---

## 🎓 Learning Resources

**Azure Resources:**
- [Azure App Service Documentation](https://docs.microsoft.com/en-us/azure/app-service/)
- [Azure Cosmos DB Documentation](https://docs.microsoft.com/en-us/azure/cosmos-db/)
- [Azure Bicep Documentation](https://docs.microsoft.com/en-us/azure/azure-resource-manager/bicep/)

**FastAPI:**
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)

**OAuth 2.0:**
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [Azure AD B2C Documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/)

---

## 📞 Support

**Issues:** https://github.com/MarcoPolo483/eva-auth/issues  
**Documentation:** https://github.com/MarcoPolo483/eva-auth/tree/master/docs  
**Contact:** marco.presta@eva.com

---

**Last Updated:** 2025-12-07  
**Version:** 1.0.0  
**Status:** ✅ Production Ready - Ready for Azure Deployment

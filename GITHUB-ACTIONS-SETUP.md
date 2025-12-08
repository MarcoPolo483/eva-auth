# GitHub Actions Setup for Azure Deployment

## Prerequisites Complete ✅

- [x] Azure Web App created: `eva-auth-dev-app`
- [x] Publish profile downloaded: `publish-profile.xml`
- [x] GitHub Actions workflow updated: `.github/workflows/ci-cd.yml`

## Next Step: Add GitHub Secret

### 1. Get Publish Profile Content

```powershell
# The publish profile is saved in the root directory
Get-Content publish-profile.xml | Set-Clipboard
```

This will copy the XML content to your clipboard.

### 2. Add to GitHub Secrets

1. Go to: https://github.com/MarcoPolo483/eva-auth/settings/secrets/actions
2. Click **"New repository secret"**
3. Name: `AZURE_WEBAPP_PUBLISH_PROFILE`
4. Value: Paste the XML content from clipboard
5. Click **"Add secret"**

### 3. Trigger Deployment

Once the secret is added, push to master to trigger automatic deployment:

```powershell
# Make a small change to trigger deployment
cd "c:\Users\marco\Documents\_AI Dev\EVA Suite\eva-auth"

# Update a file or just trigger workflow
git commit --allow-empty -m "chore: trigger Azure deployment"
git push origin master
```

### 4. Monitor Deployment

Watch the deployment progress:
- GitHub Actions: https://github.com/MarcoPolo483/eva-auth/actions
- Expected duration: ~5-8 minutes
  - Build Docker image: ~3 min
  - Push to GHCR: ~1 min
  - Deploy to Azure: ~2 min
  - Health check: ~1 min

### 5. Verify Deployment

After deployment completes:

```powershell
# Test health endpoint
Invoke-RestMethod -Uri "https://eva-auth-dev-app.azurewebsites.net/health"

# Expected response:
# {
#   "status": "healthy",
#   "service": "eva-auth",
#   "version": "0.1.0"
# }

# Open Swagger UI
Start-Process "https://eva-auth-dev-app.azurewebsites.net/docs"
```

## Workflow Details

The GitHub Actions workflow will:

1. ✅ Run full test suite (206 tests)
2. ✅ Security scan (Safety + Bandit)
3. ✅ Code quality checks (Black + isort)
4. ✅ Build Docker image
5. ✅ Push to GitHub Container Registry
6. ✅ Deploy to Azure Web App
7. ✅ Run smoke tests (health endpoint)

## Troubleshooting

### If deployment fails:

1. **Check workflow logs**:
   ```
   https://github.com/MarcoPolo483/eva-auth/actions
   ```

2. **Verify secret is added**:
   ```
   https://github.com/MarcoPolo483/eva-auth/settings/secrets/actions
   ```

3. **Check Azure app logs**:
   ```powershell
   az webapp log tail --name eva-auth-dev-app --resource-group eva-suite-rg
   ```

### Common issues:

- **"Secret not found"**: Ensure secret name is exactly `AZURE_WEBAPP_PUBLISH_PROFILE`
- **"Image pull failed"**: Ensure GHCR package is public or credentials are configured
- **"Health check failed"**: App may need more time to start (normal for first deployment)

## Security Notes

✅ **Secrets Configured:**
- Cosmos DB key: Stored in Key Vault
- Redis key: Stored in Key Vault
- Publish profile: GitHub secret (for deployment only)

✅ **Managed Identity:**
- App Service has system-assigned identity
- Identity has "Key Vault Secrets User" role
- App references secrets via Key Vault references

## Next Steps After Deployment

Once deployment is successful:

1. **Test all endpoints** via Swagger UI
2. **Configure Azure AD B2C** (for production authentication)
3. **Set up monitoring** alerts in Azure
4. **Review logs** in Application Insights
5. **Plan staging/production** deployments

---

**Ready to add the secret?** Follow steps 1-3 above to complete the deployment! 🚀

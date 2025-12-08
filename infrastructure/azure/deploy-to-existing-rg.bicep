// EVA Auth - Deploy to Existing eva-suite-rg
// This template deploys ONLY Key Vault + App Service to existing resource group
targetScope = 'resourceGroup'

@description('Environment name (dev, staging, prod)')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Azure region for resources')
param location string = 'canadacentral'

@description('Resource name prefix')
param namePrefix string = 'eva-auth'

@description('Tags for all resources')
param tags object = {
  project: 'EVA Suite'
  component: 'eva-auth'
  managedBy: 'bicep'
  deployedBy: 'deploy-to-existing-rg.bicep'
}

// Existing resources (reference only)
var existingCosmosAccountName = 'eva-suite-cosmos-${environment}'
var existingRedisCacheName = 'eva-suite-redis-${environment}'
var existingAppInsightsName = 'eva-suite-insights-${environment}'
var existingKeyVaultName = 'eva-suite-kv-${environment}'

// New resources to create
var appServicePlanName = '${namePrefix}-${environment}-asp'
var webAppName = '${namePrefix}-${environment}-app'

// Reference existing Cosmos DB
resource existingCosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' existing = {
  name: existingCosmosAccountName
}

// Reference existing Redis Cache
resource existingRedisCache 'Microsoft.Cache/Redis@2023-08-01' existing = {
  name: existingRedisCacheName
}

// Reference existing App Insights
resource existingAppInsights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: existingAppInsightsName
}

// Reference existing Key Vault
resource existingKeyVault 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  name: existingKeyVaultName
}

// App Service Plan
module appServicePlan 'modules/app-service-plan.bicep' = {
  name: 'appServicePlanDeployment'
  params: {
    name: appServicePlanName
    location: location
    environment: environment
    tags: tags
  }
}

// Web App
module webApp 'modules/web-app.bicep' = {
  name: 'webAppDeployment'
  params: {
    name: webAppName
    location: location
    environment: environment
    appServicePlanId: appServicePlan.outputs.planId
    keyVaultName: existingKeyVault.name
    cosmosEndpoint: existingCosmosAccount.properties.documentEndpoint
    redisHostname: '${existingRedisCache.name}.redis.cache.windows.net'
    appInsightsKey: existingAppInsights.properties.InstrumentationKey
    tags: tags
  }
}

// Outputs
output keyVaultName string = existingKeyVault.name
output keyVaultUri string = existingKeyVault.properties.vaultUri
output webAppName string = webAppName
output webAppUrl string = webApp.outputs.webAppUrl
output webAppPrincipalId string = webApp.outputs.webAppIdentityPrincipalId

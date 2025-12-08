// EVA Auth - Azure Infrastructure (Bicep)
targetScope = 'subscription'

@description('Environment name (dev, staging, prod)')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Azure region for resources')
param location string = 'eastus'

@description('Resource name prefix')
param namePrefix string = 'eva-auth'

@description('Tags for all resources')
param tags object = {
  project: 'EVA Suite'
  component: 'eva-auth'
  managedBy: 'bicep'
}

// Variables
var resourceGroupName = '${namePrefix}-${environment}-rg'
var appServicePlanName = '${namePrefix}-${environment}-asp'
var webAppName = '${namePrefix}-${environment}'
var cosmosAccountName = '${namePrefix}-${environment}-cosmos'
var redisCacheName = '${namePrefix}-${environment}-redis'
var keyVaultName = '${namePrefix}-${environment}-kv'
var appInsightsName = '${namePrefix}-${environment}-ai'
var logAnalyticsName = '${namePrefix}-${environment}-la'

// Resource Group
resource resourceGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

// Log Analytics Workspace
module logAnalytics 'modules/log-analytics.bicep' = {
  scope: resourceGroup
  name: 'logAnalyticsDeployment'
  params: {
    name: logAnalyticsName
    location: location
    tags: tags
  }
}

// Application Insights
module appInsights 'modules/app-insights.bicep' = {
  scope: resourceGroup
  name: 'appInsightsDeployment'
  params: {
    name: appInsightsName
    location: location
    tags: tags
    workspaceId: logAnalytics.outputs.workspaceId
  }
}

// Azure Key Vault
module keyVault 'modules/key-vault.bicep' = {
  scope: resourceGroup
  name: 'keyVaultDeployment'
  params: {
    name: keyVaultName
    location: location
    tags: tags
    environment: environment
  }
}

// Cosmos DB
module cosmosDb 'modules/cosmos-db.bicep' = {
  scope: resourceGroup
  name: 'cosmosDbDeployment'
  params: {
    name: cosmosAccountName
    location: location
    tags: tags
    environment: environment
  }
}

// Redis Cache
module redis 'modules/redis.bicep' = {
  scope: resourceGroup
  name: 'redisDeployment'
  params: {
    name: redisCacheName
    location: location
    tags: tags
    environment: environment
  }
}

// App Service Plan
module appServicePlan 'modules/app-service-plan.bicep' = {
  scope: resourceGroup
  name: 'appServicePlanDeployment'
  params: {
    name: appServicePlanName
    location: location
    tags: tags
    environment: environment
  }
}

// Web App
module webApp 'modules/web-app.bicep' = {
  scope: resourceGroup
  name: 'webAppDeployment'
  params: {
    name: webAppName
    location: location
    tags: tags
    appServicePlanId: appServicePlan.outputs.planId
    appInsightsKey: appInsights.outputs.instrumentationKey
    keyVaultName: keyVaultName
    cosmosEndpoint: cosmosDb.outputs.endpoint
    redisHostname: redis.outputs.hostname
    environment: environment
  }
}

// Outputs
output resourceGroupName string = resourceGroup.name
output webAppUrl string = webApp.outputs.webAppUrl
output cosmosEndpoint string = cosmosDb.outputs.endpoint
output redisHostname string = redis.outputs.hostname
output keyVaultUri string = keyVault.outputs.vaultUri
output appInsightsKey string = appInsights.outputs.instrumentationKey

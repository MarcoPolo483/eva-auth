// Web App (App Service) Module
param name string
param location string
param tags object
param appServicePlanId string
param appInsightsKey string
param keyVaultName string
param cosmosEndpoint string
param redisHostname string
param environment string

resource webApp 'Microsoft.Web/sites@2022-09-01' = {
  name: name
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOCKER|ghcr.io/marcopolo483/eva-auth:latest'
      alwaysOn: environment == 'prod'
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      healthCheckPath: '/health'
      appSettings: [
        {
          name: 'ENVIRONMENT'
          value: environment
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: 'InstrumentationKey=${appInsightsKey}'
        }
        {
          name: 'COSMOS_ENDPOINT'
          value: cosmosEndpoint
        }
        {
          name: 'COSMOS_KEY'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=cosmos-key)'
        }
        {
          name: 'REDIS_URL'
          value: 'rediss://${redisHostname}:6380'
        }
        {
          name: 'REDIS_PASSWORD'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=redis-password)'
        }
        {
          name: 'AZURE_B2C_TENANT_NAME'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-b2c-tenant-name)'
        }
        {
          name: 'AZURE_B2C_TENANT_ID'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-b2c-tenant-id)'
        }
        {
          name: 'AZURE_B2C_CLIENT_ID'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-b2c-client-id)'
        }
        {
          name: 'AZURE_B2C_CLIENT_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-b2c-client-secret)'
        }
        {
          name: 'AZURE_ENTRA_TENANT_ID'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-entra-tenant-id)'
        }
        {
          name: 'AZURE_ENTRA_CLIENT_ID'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-entra-client-id)'
        }
        {
          name: 'AZURE_ENTRA_CLIENT_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=azure-entra-client-secret)'
        }
        {
          name: 'CORS_ORIGINS'
          value: environment == 'prod' ? 'https://eva.azurewebsites.net' : '*'
        }
        {
          name: 'ENABLE_MOCK_AUTH'
          value: environment == 'dev' ? 'true' : 'false'
        }
        {
          name: 'LOG_LEVEL'
          value: environment == 'prod' ? 'INFO' : 'DEBUG'
        }
      ]
    }
  }
}

// Deployment slot for production (blue-green deployment)
resource stagingSlot 'Microsoft.Web/sites/slots@2022-09-01' = if (environment == 'prod') {
  parent: webApp
  name: 'staging'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlanId
    siteConfig: {
      linuxFxVersion: 'DOCKER|ghcr.io/marcopolo483/eva-auth:latest'
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      healthCheckPath: '/health'
    }
  }
}

output webAppUrl string = 'https://${webApp.properties.defaultHostName}'
output webAppIdentityPrincipalId string = webApp.identity.principalId

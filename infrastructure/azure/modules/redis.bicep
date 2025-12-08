// Redis Cache Module
param name string
param location string
param tags object
param environment string

var sku = environment == 'prod' ? 'Premium' : environment == 'staging' ? 'Standard' : 'Basic'
var capacity = environment == 'prod' ? 1 : 0

resource redis 'Microsoft.Cache/redis@2023-08-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: sku
      family: sku == 'Premium' ? 'P' : 'C'
      capacity: capacity
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    redisConfiguration: {
      'maxmemory-policy': 'allkeys-lru'
      'maxmemory-reserved': sku == 'Premium' ? '50' : '2'
      'maxfragmentationmemory-reserved': sku == 'Premium' ? '50' : '2'
    }
    redisVersion: '6'
  }
}

// Diagnostic settings
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${name}-diagnostics'
  scope: redis
  properties: {
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: environment == 'prod' ? 90 : 30
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: environment == 'prod' ? 90 : 30
        }
      }
    ]
  }
}

output hostname string = redis.properties.hostName
output port int = redis.properties.port
output sslPort int = redis.properties.sslPort
output name string = redis.name

// App Service Plan Module
param name string
param location string
param tags object
param environment string

var sku = environment == 'prod' ? 'P1v3' : environment == 'staging' ? 'S1' : 'F1'

resource appServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: name
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: sku
  }
  properties: {
    reserved: true
    zoneRedundant: environment == 'prod'
  }
}

output planId string = appServicePlan.id
output planName string = appServicePlan.name

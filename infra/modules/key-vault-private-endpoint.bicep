targetScope = 'resourceGroup'

param location string
param keyVaultName string
param keyVaultResourceGroupName string = resourceGroup().name
param virtualNetworkResourceId string
param privateEndpointSubnetResourceId string
param provisionPrivateDnsZone bool = true
param existingPrivateDnsZoneName string = ''
param existingPrivateDnsZoneResourceGroupName string = ''
param privateDnsLinkName string = 'finops-vnet'

var privateDnsZoneName = 'privatelink.vaultcore.azure.net'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  scope: resourceGroup(keyVaultResourceGroupName)
  name: keyVaultName
}

resource managedPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = if (provisionPrivateDnsZone) {
  name: privateDnsZoneName
  location: 'global'
}

resource existingPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = if (!provisionPrivateDnsZone) {
  scope: resourceGroup(existingPrivateDnsZoneResourceGroupName)
  name: existingPrivateDnsZoneName
}

var effectivePrivateDnsZoneId = provisionPrivateDnsZone
  ? managedPrivateDnsZone!.id
  : existingPrivateDnsZone!.id
var effectivePrivateDnsZoneName = provisionPrivateDnsZone
  ? managedPrivateDnsZone!.name
  : existingPrivateDnsZone!.name

resource privateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (provisionPrivateDnsZone) {
  parent: managedPrivateDnsZone
  name: privateDnsLinkName
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResourceId
    }
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: 'pe-${keyVaultName}-vault'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'key-vault'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: effectivePrivateDnsZoneId
        }
      }
    ]
  }
}

output privateEndpointName string = privateEndpoint.name
output privateEndpointId string = privateEndpoint.id
output privateDnsZoneName string = effectivePrivateDnsZoneName
output privateDnsZoneId string = effectivePrivateDnsZoneId
output privateDnsZoneProvisioned bool = provisionPrivateDnsZone
output privateDnsLinkName string = provisionPrivateDnsZone ? privateDnsLink.name : ''
output privateDnsLinkId string = provisionPrivateDnsZone ? privateDnsLink.id : ''
output privateDnsLinkProvisioned bool = provisionPrivateDnsZone

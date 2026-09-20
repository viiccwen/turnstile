targetScope = 'resourceGroup'

param location string
param keyVaultName string
param keyVaultResourceGroupName string = resourceGroup().name
param virtualNetworkResourceId string
param privateEndpointSubnetResourceId string
param provisionPrivateDnsZone bool = true
@description('Exact existing DNS zone ID; takes precedence over legacy name/group inputs. No writes or VNet links are made to this zone.')
param existingPrivateDnsZoneResourceId string = ''
param existingPrivateDnsZoneName string = ''
param existingPrivateDnsZoneResourceGroupName string = ''
param privateDnsLinkName string = 'finops-vnet'
param privateLinkServiceConnectionName string = 'key-vault'

var privateDnsZoneName = 'privatelink.vaultcore.azure.net'
var reusePrivateDnsZone = !provisionPrivateDnsZone || !empty(existingPrivateDnsZoneResourceId)

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  scope: resourceGroup(keyVaultResourceGroupName)
  name: keyVaultName
}

resource managedPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = if (!reusePrivateDnsZone) {
  name: privateDnsZoneName
  location: 'global'
}

resource existingPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = if (reusePrivateDnsZone && empty(existingPrivateDnsZoneResourceId)) {
  scope: resourceGroup(existingPrivateDnsZoneResourceGroupName)
  name: existingPrivateDnsZoneName
}

var effectivePrivateDnsZoneId = !reusePrivateDnsZone
  ? managedPrivateDnsZone!.id
  : (!empty(existingPrivateDnsZoneResourceId) ? existingPrivateDnsZoneResourceId : existingPrivateDnsZone!.id)
var effectivePrivateDnsZoneName = last(split(effectivePrivateDnsZoneId, '/'))

resource privateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (!reusePrivateDnsZone) {
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
        name: privateLinkServiceConnectionName
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
output privateDnsZoneProvisioned bool = !reusePrivateDnsZone
output privateDnsLinkName string = !reusePrivateDnsZone ? privateDnsLink!.name : ''
output privateDnsLinkId string = !reusePrivateDnsZone ? privateDnsLink!.id : ''
output privateDnsLinkProvisioned bool = !reusePrivateDnsZone

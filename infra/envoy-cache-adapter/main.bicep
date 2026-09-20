targetScope = 'resourceGroup'

param apimResourceGroupName string = resourceGroup().name
param location string
param appServicePlanName string
@allowed([
  'P0v3'
  'P1v3'
  'P2v3'
  'P3v3'
])
param appServicePlanSkuName string = 'P0v3'
@minValue(1)
@maxValue(30)
param appServicePlanWorkerCount int = 1
param webAppName string
param acrName string
param provisionAcr bool = true
param acrResourceGroupName string = provisionAcr ? resourceGroup().name : apimResourceGroupName
param imageRepository string = 'turnstile/envoy-cache-adapter'
param imageTag string
param eventHubNamespaceName string
param eventHubName string = 'token-usage'
param manageEventHubRoleAssignment bool = true
param apimName string
param adapterKeyNamedValueName string = 'turnstile-envoy-adapter-key'

@secure()
param adapterSharedKey string

var acrLoginServer = '${acrName}.azurecr.io'
var image = '${acrLoginServer}/${imageRepository}:${imageTag}'

module registry 'br/public:avm/res/container-registry/registry:0.13.0' = if (provisionAcr) {
  name: 'observer-registry-${take(uniqueString(webAppName), 8)}'
  scope: resourceGroup(acrResourceGroupName)
  params: {
    name: acrName
    location: location
    acrSku: 'Basic'
    acrAdminUserEnabled: false
    azureADAuthenticationAsArmPolicyStatus: 'enabled'
    publicNetworkAccess: 'Enabled'
    networkRuleSetDefaultAction: 'Allow'
  }
}

module app 'app.bicep' = {
  name: 'observer-app-${take(uniqueString(webAppName), 8)}'
  params: {
    location: location
    appServicePlanName: appServicePlanName
    appServicePlanSkuName: appServicePlanSkuName
    appServicePlanWorkerCount: appServicePlanWorkerCount
    webAppName: webAppName
    image: image
    acrLoginServer: acrLoginServer
    eventHubNamespaceName: eventHubNamespaceName
    eventHubName: eventHubName
    manageEventHubRoleAssignment: manageEventHubRoleAssignment
    adapterSharedKey: adapterSharedKey
  }
}

module acrRole 'acr-role.bicep' = {
  scope: resourceGroup(acrResourceGroupName)
  name: 'observer-acr-role-${take(uniqueString(webAppName), 8)}'
  dependsOn: [
    registry
  ]
  params: {
    acrName: acrName
    principalId: app.outputs.principalId
  }
}

module apimIntegration 'apim.bicep' = {
  scope: resourceGroup(apimResourceGroupName)
  name: 'observer-apim-${take(uniqueString(webAppName, apimName), 8)}'
  params: {
    apimName: apimName
    adapterKeyNamedValueName: adapterKeyNamedValueName
    adapterSharedKey: adapterSharedKey
  }
}

output webAppUrl string = app.outputs.webAppUrl
output webAppName string = webAppName
output observerAppServicePlanName string = appServicePlanName
output observerAppServicePlanSkuName string = appServicePlanSkuName
output observerAppServicePlanWorkerCount int = appServicePlanWorkerCount
output webAppPrincipalId string = app.outputs.principalId
output adapterKeyNamedValueName string = apimIntegration.outputs.namedValueName
output acrName string = acrName
output acrResourceGroupName string = acrResourceGroupName
output image string = image

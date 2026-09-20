targetScope = 'resourceGroup'

type DisabledUsageObserver = {
  mode: 'disabled'
  url: ''
  keyNamedValue: ''
  legacyFoundryUpstreamHost: ''
  legacyFoundryUpstreamBasePath: ''
  legacyDatabricksUpstreamHost: ''
  legacyDatabricksUpstreamBasePath: ''
}

type EnabledUsageObserver = {
  mode: 'enabled'
  @minLength(1)
  url: string
  @minLength(1)
  keyNamedValue: string
  @minLength(1)
  legacyFoundryUpstreamHost: string
  @minLength(1)
  legacyFoundryUpstreamBasePath: string
  @minLength(1)
  legacyDatabricksUpstreamHost: string
  @minLength(1)
  legacyDatabricksUpstreamBasePath: string
}

@description('Short lowercase prefix used in globally unique resource names.')
@minLength(3)
@maxLength(12)
param resourcePrefix string = 'turnstile'

@description('Resource group containing the existing shared Storage Account used by Turnstile.')
param storageResourceGroupName string = resourceGroup().name

@description('Existing StorageV2 account with Blob, Queue, and Table endpoints.')
param storageAccountName string

@description('Existing blob container used for the telemetry Function deployment package.')
param telemetryDeploymentContainerName string = 'turnstile-telemetry-deploy'

@description('Existing blob container used for the control-plane Function deployment package.')
param controlPlaneDeploymentContainerName string = 'turnstile-control-deploy'

param location string
param postgresLocation string = location

@description('APIM publisher contact shown by Azure.')
param apimPublisherEmail string

@description('APIM publisher display name.')
param apimPublisherName string = 'Turnstile'

@allowed([
  'Developer'
  'BasicV2'
  'StandardV2'
])
param apimSkuName string = 'StandardV2'

@minValue(1)
param apimCapacity int = 1

@description('Create the APIM service. Set false only when adopting the deterministic APIM service in an existing Turnstile environment.')
param provisionApimService bool = true

@description('Create the PostgreSQL server, database, and Azure-services firewall rule. Set false only when adopting the deterministic database in an existing Turnstile environment.')
param provisionPostgres bool = true

@description('Existing PostgreSQL server resource ID when provisionPostgres is false for an adopted dependency.')
param postgresAdopted bool = false
param existingPostgresServerResourceId string = ''
param existingPostgresServerName string = ''
param existingPostgresDatabaseName string = ''
param useDatabaseUrlOverride bool = false
@secure()
param databaseUrlOverride string = ''

@description('Create the Event Hub namespace and token-usage hub.')
param provisionEventHub bool = true
param existingEventHubNamespaceResourceGroupName string = ''
param existingEventHubNamespaceName string = ''
param existingEventHubName string = ''
param existingEventHubNamespaceResourceId string = ''
param existingEventHubResourceId string = ''

@description('Create Log Analytics and workspace-based Application Insights.')
param provisionObservability bool = true
param existingLogAnalyticsWorkspaceResourceGroupName string = ''
param existingLogAnalyticsWorkspaceName string = ''
param existingApplicationInsightsResourceGroupName string = ''
param existingApplicationInsightsName string = ''

@description('Create the Turnstile Key Vault and its secrets.')
param provisionKeyVault bool = true
param existingKeyVaultResourceGroupName string = ''
param existingKeyVaultName string = ''
param existingKeyVaultResourceId string = ''
param existingDatabaseUrlSecretUri string = ''
param existingDatabaseUrlResourceId string = ''
param existingCredentialEncryptionKeySecretUri string = ''
param existingCredentialKeyResourceId string = ''
param existingManagementApiKeySecretUri string = ''
param existingManagementKeyResourceId string = ''
param existingApimSubscriptionKeySecretUri string = ''
param existingApimKeyResourceId string = ''
param existingApimProbeSubscriptionKeySecretUri string = ''
param existingApimProbeKeyResourceId string = ''

@description('Create the Turnstile VNet and four dedicated subnets.')
param provisionNetwork bool = true
param existingVirtualNetworkResourceId string = ''
param existingTelemetryFunctionSubnetResourceId string = ''
param existingControlFunctionSubnetResourceId string = ''
param existingPrivateEndpointSubnetResourceId string = ''
param existingApiSubnetResourceId string = ''
param provisionKeyVaultPrivateDnsZone bool = true
param keyVaultPrivateDnsLinkName string = 'finops-vnet'
param existingKeyVaultPrivateDnsZoneResourceId string = ''
param existingKeyVaultPrivateDnsZoneResourceGroupName string = ''
param existingKeyVaultPrivateDnsZoneName string = ''

@description('Deploy the bootstrap API, operations, and policies. Disable after the first model publication so infrastructure reruns cannot overwrite a live gateway revision.')
param deployApimBootstrap bool = true

@description('Name of an existing APIM service when provisionApimService is false.')
param existingApimName string = ''

@description('Resource group of an existing APIM service when provisionApimService is false.')
param existingApimResourceGroupName string = ''

@description('Principal ID of an existing APIM system-assigned identity when provisionApimService is false.')
param existingApimPrincipalId string = ''

@description('Gateway origin of an existing APIM service when provisionApimService is false.')
param existingApimGatewayUrl string = ''

@description('Environment-unique API identifier within the APIM service.')
param apimApiId string = 'turnstile-llm'

@description('Environment-unique API path within the APIM gateway.')
param gatewayApiRelativePath string = 'turnstile/llm'

@description('Environment-unique APIM product identifier.')
param apimProductId string = 'finops-ai-consumers'

@description('Environment-unique dashboard subscription identifier.')
param apimDashboardSubscriptionId string = 'turnstile-dashboard'

@description('Environment-unique publisher probe subscription identifier.')
param apimProbeSubscriptionId string = 'turnstile-publisher-probe'

@description('Environment-unique Application Insights logger identifier.')
param apimAppInsightsLoggerId string = 'finops-appinsights'

@description('Environment-unique Event Hub logger identifier.')
param apimEventHubLoggerId string = 'finops-token-usage-eventhub'

@description('Environment-unique APIM diagnostic setting name.')
param apimDiagnosticSettingName string = 'finops-llm-token-logs'

@description('Environment-unique Observer adapter key named value.')
param observerAdapterKeyNamedValueName string = 'turnstile-envoy-adapter-key'

@secure()
@minLength(16)
param postgresAdministratorPassword string

@secure()
param credentialEncryptionKey string

@secure()
param managementApiKey string

@secure()
param apimSubscriptionKey string

@secure()
param apimProbeSubscriptionKey string

@minValue(1)
param apimTokensPerMinute int = 100000

@description('Optional onboarded model alias used by publication probes. Leave empty on first deployment.')
param apimRegressionModelKey string = ''

@description('Temporary upgrade bridge for an existing gateway whose legacy Foundry/Databricks models have not yet been adopted into dynamic publication bindings. Fresh deployments must leave this false.')
param preserveLegacyProviderRouting bool = false

@description('Entra tenant that issues employee tokens for interactive clients such as Claude Desktop.')
param employeeTenantId string = subscription().tenantId

@description('Public client application ID used by employee desktop clients.')
param employeeClientId string = entraClientId

@description('Application ID of the model API that employee tokens are issued for.')
param employeeAudience string = entraClientId

@description('Per-minute burst ceiling for each validated employee. The monthly allowance is enforced from the Table Storage ledger, not from an APIM counter.')
@minValue(1)
param employeeTokensPerMinute int = 100000

@description('Budget ledger table name.')
param ledgerTableName string = 'TurnstileLedger'

@description('Organization ID attributed to employee desktop traffic. Must equal the enterprise catalog organization id, or employee usage rolls up to an organization that does not exist and the parent total comes out smaller than its own department.')
param employeeOrgId string = 'organization-default'

@description('Organization name attributed to employee desktop traffic. Must match the catalog organization name for the same reason.')
param employeeOrgName string = 'Default Organization'

@description('Maps FinOps department IDs, emitted as Entra app roles, to their display names.')
param employeeDepartmentMap object = {}

@description('Maps Entra client application IDs to the Agent name attributed to their traffic.')
param employeeClientMap object = {}

@description('Refines the Agent name from the User-Agent, most specific entry first. Every token must be present for an entry to match; no match keeps the client-map name.')
param employeeSurfaceMap array = []

@description('Maps trusted APIM subscription IDs to Agent identities for subscription-key callers.')
param subscriptionAgentMap object = {}

@description('Public client ID of the Microsoft Entra SPA used by the Turnstile web app.')
param entraClientId string = ''

@description('Exact email domains allowed to sign in through Microsoft Entra.')
param entraAllowedEmailDomains array = []

@description('Email address for the first password Owner created only when the user table is empty.')
param bootstrapOwnerEmail string

@description('Locally generated scrypt hash for the first Owner password. Plaintext is never deployed.')
@secure()
param bootstrapOwnerPasswordHash string

@description('Provision the isolated APIM publication Function with publishing disabled until explicitly enabled.')
param provisionControlPlane bool = false

@description('Allow the isolated control-plane Function to process queued gateway publications.')
param controlPlaneEnabled bool = false

@description('Allow the isolated control-plane Function to process queued Gateway Release operations.')
param gatewayReleaseWorkerEnabled bool = false

@description('Allow Owners to reveal and rotate governed APIM subscription keys through the Turnstile API.')
param gatewayApplicationKeyManagementEnabled bool = false

@description('Allow governed Application creation after ledger and APIM dependencies are ready.')
param gatewayApplicationProvisioningEnabled bool = false

@description('Enable Databricks OAuth M2M connection support and its scoped Publisher permissions.')
param databricksOAuthEnabled bool = false

@minValue(1)
param gatewayApplicationDefaultMonthlyTokenLimit int = 100000

@minValue(1)
param gatewayApplicationDefaultTokensPerMinute int = 100000

@description('All-or-nothing transparent usage observer configuration.')
@discriminator('mode')
param apimUsageObserver DisabledUsageObserver | EnabledUsageObserver = {
  mode: 'disabled'
  url: ''
  keyNamedValue: ''
  legacyFoundryUpstreamHost: ''
  legacyFoundryUpstreamBasePath: ''
  legacyDatabricksUpstreamHost: ''
  legacyDatabricksUpstreamBasePath: ''
}

@description('Activate historical fallback observer routes only after route reconciliation is active.')
param apimUsageObserverLegacyRoutingEnabled bool = false

param postgresAdministratorLogin string = 'turnstileadmin'
param postgresSkuName string = 'Standard_B1ms'
param postgresTier string = 'Burstable'
param suffix string = uniqueString(subscription().id, resourceGroup().name)

var effectiveApimResourceGroupName = provisionApimService ? resourceGroup().name : existingApimResourceGroupName

module apim 'modules/apim-service.bicep' = if (provisionApimService) {
  name: '${resourcePrefix}-apim-service'
  params: {
    name: 'apim-${resourcePrefix}-${suffix}'
    location: location
    publisherEmail: apimPublisherEmail
    publisherName: apimPublisherName
    skuName: apimSkuName
    capacity: apimCapacity
  }
}

var effectiveApimName = provisionApimService ? apim!.outputs.name : existingApimName
var effectiveApimPrincipalId = provisionApimService ? apim!.outputs.principalId : existingApimPrincipalId
var effectiveApimGatewayUrl = provisionApimService ? apim!.outputs.gatewayUrl : existingApimGatewayUrl
var effectiveGatewayApiPath = '${effectiveApimGatewayUrl}/${gatewayApiRelativePath}'

resource sharedStorage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  scope: resourceGroup(storageResourceGroupName)
  name: storageAccountName
}

module dataPlane 'modules/data-plane.bicep' = {
  name: '${resourcePrefix}-data-plane'
  params: {
    location: location
    postgresLocation: postgresLocation
    resourcePrefix: resourcePrefix
    suffix: suffix
    telemetryStorageName: sharedStorage.name
    telemetryBlobEndpoint: sharedStorage.properties.primaryEndpoints.blob
    telemetryQueueEndpoint: sharedStorage.properties.primaryEndpoints.queue
    telemetryTableEndpoint: sharedStorage.properties.primaryEndpoints.table
    telemetryDeploymentContainerName: telemetryDeploymentContainerName
    ledgerStorageName: sharedStorage.name
    ledgerTableEndpoint: sharedStorage.properties.primaryEndpoints.table
    postgresAdministratorLogin: postgresAdministratorLogin
    postgresAdministratorPassword: postgresAdministratorPassword
    postgresSkuName: postgresSkuName
    postgresTier: postgresTier
    provisionPostgres: provisionPostgres
    postgresAdopted: postgresAdopted
    existingPostgresServerResourceId: existingPostgresServerResourceId
    existingPostgresServerName: existingPostgresServerName
    existingPostgresDatabaseName: existingPostgresDatabaseName
    useDatabaseUrlOverride: useDatabaseUrlOverride
    databaseUrlOverride: databaseUrlOverride
    provisionEventHub: provisionEventHub
    existingEventHubNamespaceResourceGroupName: existingEventHubNamespaceResourceGroupName
    existingEventHubNamespaceName: existingEventHubNamespaceName
    existingEventHubName: existingEventHubName
    existingEventHubNamespaceResourceId: existingEventHubNamespaceResourceId
    existingEventHubResourceId: existingEventHubResourceId
    provisionObservability: provisionObservability
    existingLogAnalyticsWorkspaceResourceGroupName: existingLogAnalyticsWorkspaceResourceGroupName
    existingLogAnalyticsWorkspaceName: existingLogAnalyticsWorkspaceName
    existingApplicationInsightsResourceGroupName: existingApplicationInsightsResourceGroupName
    existingApplicationInsightsName: existingApplicationInsightsName
    provisionKeyVault: provisionKeyVault
    existingKeyVaultResourceGroupName: existingKeyVaultResourceGroupName
    existingKeyVaultName: existingKeyVaultName
    existingKeyVaultResourceId: existingKeyVaultResourceId
    existingDatabaseUrlSecretUri: existingDatabaseUrlSecretUri
    existingDatabaseUrlResourceId: existingDatabaseUrlResourceId
    existingCredentialEncryptionKeySecretUri: existingCredentialEncryptionKeySecretUri
    existingCredentialKeyResourceId: existingCredentialKeyResourceId
    existingManagementApiKeySecretUri: existingManagementApiKeySecretUri
    existingManagementKeyResourceId: existingManagementKeyResourceId
    existingApimSubscriptionKeySecretUri: existingApimSubscriptionKeySecretUri
    existingApimKeyResourceId: existingApimKeyResourceId
    existingApimProbeSubscriptionKeySecretUri: existingApimProbeSubscriptionKeySecretUri
    existingApimProbeKeyResourceId: existingApimProbeKeyResourceId
    provisionNetwork: provisionNetwork
    existingVirtualNetworkResourceId: existingVirtualNetworkResourceId
    existingTelemetryFunctionSubnetResourceId: existingTelemetryFunctionSubnetResourceId
    existingControlFunctionSubnetResourceId: existingControlFunctionSubnetResourceId
    existingPrivateEndpointSubnetResourceId: existingPrivateEndpointSubnetResourceId
    existingApiSubnetResourceId: existingApiSubnetResourceId
    provisionKeyVaultPrivateDnsZone: provisionKeyVaultPrivateDnsZone
    keyVaultPrivateDnsLinkName: keyVaultPrivateDnsLinkName
    existingKeyVaultPrivateDnsZoneResourceId: existingKeyVaultPrivateDnsZoneResourceId
    existingKeyVaultPrivateDnsZoneResourceGroupName: existingKeyVaultPrivateDnsZoneResourceGroupName
    existingKeyVaultPrivateDnsZoneName: existingKeyVaultPrivateDnsZoneName
    credentialEncryptionKey: credentialEncryptionKey
    managementApiKey: managementApiKey
    apimSubscriptionKey: apimSubscriptionKey
    apimProbeSubscriptionKey: apimProbeSubscriptionKey
    apimPrincipalId: effectiveApimPrincipalId
    apimResourceGroupName: effectiveApimResourceGroupName
    apimName: effectiveApimName
    apimApiId: apimApiId
    apimProductId: apimProductId
    apimGatewayUrl: effectiveGatewayApiPath
    ledgerTableName: ledgerTableName
    gatewayReleaseWorkerEnabled: provisionControlPlane && gatewayReleaseWorkerEnabled && apimUsageObserver.mode == 'enabled'
    gatewayApplicationKeyManagementEnabled: gatewayApplicationKeyManagementEnabled
    gatewayApplicationProvisioningEnabled: provisionControlPlane && gatewayApplicationProvisioningEnabled
    databricksOAuthEnabled: provisionControlPlane && databricksOAuthEnabled
    gatewayApplicationDefaultMonthlyTokenLimit: gatewayApplicationDefaultMonthlyTokenLimit
    gatewayApplicationDefaultTokensPerMinute: gatewayApplicationDefaultTokensPerMinute
    entraClientId: entraClientId
    entraAllowedEmailDomains: entraAllowedEmailDomains
    bootstrapOwnerEmail: bootstrapOwnerEmail
    bootstrapOwnerPasswordHash: bootstrapOwnerPasswordHash
  }
}

module apimIntegration 'modules/apim-integration.bicep' = if (deployApimBootstrap) {
  name: '${resourcePrefix}-apim-integration-${take(suffix, 8)}'
  scope: resourceGroup(effectiveApimResourceGroupName)
  params: {
    apimName: effectiveApimName
    apiId: apimApiId
    apiPath: gatewayApiRelativePath
    productId: apimProductId
    dashboardSubscriptionId: apimDashboardSubscriptionId
    probeSubscriptionId: apimProbeSubscriptionId
    appInsightsLoggerId: apimAppInsightsLoggerId
    eventHubLoggerId: apimEventHubLoggerId
    diagnosticSettingName: apimDiagnosticSettingName
    eventHubNamespaceResourceId: dataPlane.outputs.eventHubNamespaceResourceId
    eventHubNamespaceName: dataPlane.outputs.eventHubNamespaceName
    eventHubName: dataPlane.outputs.eventHubName
    apimSubscriptionKey: apimSubscriptionKey
    apimProbeSubscriptionKey: apimProbeSubscriptionKey
    tokensPerMinute: apimTokensPerMinute
    preserveLegacyProviderRouting: preserveLegacyProviderRouting
    usageObserver: apimUsageObserver
    legacyObserverRoutingEnabled: apimUsageObserverLegacyRoutingEnabled
    employeeTenantId: employeeTenantId
    employeeClientId: employeeClientId
    employeeAudience: employeeAudience
    employeeTokensPerMinute: employeeTokensPerMinute
    ledgerTableEndpoint: dataPlane.outputs.ledgerTableEndpoint
    ledgerTableName: ledgerTableName
    employeeOrgId: employeeOrgId
    employeeOrgName: employeeOrgName
    employeeDepartmentMap: employeeDepartmentMap
    employeeClientMap: employeeClientMap
    employeeSurfaceMap: employeeSurfaceMap
    subscriptionAgentMap: subscriptionAgentMap
    appInsightsName: dataPlane.outputs.applicationInsightsName
    appInsightsResourceGroupName: dataPlane.outputs.applicationInsightsResourceGroupName
  }
}

module controlPlane 'modules/control-plane-function.bicep' = if (provisionControlPlane) {
  name: '${resourcePrefix}-control-plane-function'
  params: {
    location: location
    resourcePrefix: resourcePrefix
    suffix: suffix
    storageName: sharedStorage.name
    storageBlobEndpoint: sharedStorage.properties.primaryEndpoints.blob
    storageQueueEndpoint: sharedStorage.properties.primaryEndpoints.queue
    storageTableEndpoint: sharedStorage.properties.primaryEndpoints.table
    deploymentContainerName: controlPlaneDeploymentContainerName
    functionSubnetResourceId: dataPlane.outputs.controlFunctionSubnetResourceId
    keyVaultName: dataPlane.outputs.keyVaultName
    manageKeyVaultRoleAssignments: dataPlane.outputs.keyVaultProvisioned
    databaseUrlSecretUri: dataPlane.outputs.databaseUrlSecretUri
    apimProbeSubscriptionKeySecretUri: dataPlane.outputs.apimProbeSubscriptionKeySecretUri
    credentialEncryptionKeySecretUri: dataPlane.outputs.credentialEncryptionKeySecretUri
    applicationInsightsConnectionString: dataPlane.outputs.applicationInsightsConnectionString
    apimResourceGroupName: effectiveApimResourceGroupName
    apimName: effectiveApimName
    apimApiId: apimApiId
    apimProductId: apimProductId
    probeSubscriptionId: apimProbeSubscriptionId
    apimGatewayUrl: effectiveGatewayApiPath
    regressionModelKey: apimRegressionModelKey
    usageObserverUrl: apimUsageObserver.url
    usageObserverKeyNamedValue: apimUsageObserver.keyNamedValue
    subscriptionAgentMap: subscriptionAgentMap
    publicationWorkerEnabled: controlPlaneEnabled
    releaseWorkerEnabled: gatewayReleaseWorkerEnabled
    applicationProvisioningEnabled: gatewayApplicationProvisioningEnabled
    databricksOAuthEnabled: databricksOAuthEnabled
    applicationDefaultMonthlyTokenLimit: gatewayApplicationDefaultMonthlyTokenLimit
    applicationDefaultTokensPerMinute: gatewayApplicationDefaultTokensPerMinute
    ledgerTableName: ledgerTableName
    ledgerTableEndpoint: dataPlane.outputs.ledgerTableEndpoint
  }
}

module controlPlaneApimRbac 'modules/control-plane-apim-rbac.bicep' = if (provisionControlPlane) {
  name: '${resourcePrefix}-control-plane-apim-rbac-${take(suffix, 8)}'
  scope: resourceGroup(effectiveApimResourceGroupName)
  params: {
    apimName: effectiveApimName
    controlPlanePrincipalId: controlPlane!.outputs.principalId
    databricksOAuthEnabled: databricksOAuthEnabled
  }
}

module applicationKeyManagementRbac 'modules/application-key-management-rbac.bicep' = if (gatewayApplicationKeyManagementEnabled) {
  name: '${resourcePrefix}-application-key-rbac-${take(suffix, 8)}'
  scope: resourceGroup(effectiveApimResourceGroupName)
  params: {
    apimName: effectiveApimName
    apiPrincipalIds: [
      dataPlane.outputs.apiPrincipalId
    ]
  }
}

output resourceGroupName string = resourceGroup().name
output storageResourceGroupName string = storageResourceGroupName
output storageAccountName string = sharedStorage.name
output storageAccountId string = sharedStorage.id
output ledgerTableId string = resourceId(
  storageResourceGroupName,
  'Microsoft.Storage/storageAccounts/tableServices/tables',
  sharedStorage.name,
  'default',
  ledgerTableName
)
output apimName string = effectiveApimName
output apimResourceGroupName string = effectiveApimResourceGroupName
output apimPrincipalId string = effectiveApimPrincipalId
output apimApiId string = apimApiId
output apimProbeSubscriptionId string = apimProbeSubscriptionId
output observerAdapterKeyNamedValueName string = observerAdapterKeyNamedValueName
output postgresServerName string = dataPlane.outputs.postgresServerName
output eventHubNamespaceName string = dataPlane.outputs.eventHubNamespaceName
output applicationInsightsName string = dataPlane.outputs.applicationInsightsName
output dependencyResources object = {
  postgres: {
    resourceId: dataPlane.outputs.postgresServerResourceId
    serverName: dataPlane.outputs.postgresServerName
    databaseName: dataPlane.outputs.databaseName
    provisioned: dataPlane.outputs.postgresProvisioned
  }
  eventHub: {
    namespaceResourceId: dataPlane.outputs.eventHubNamespaceResourceId
    resourceId: dataPlane.outputs.eventHubResourceId
    resourceGroupName: dataPlane.outputs.eventHubNamespaceResourceGroupName
    namespaceName: dataPlane.outputs.eventHubNamespaceName
    name: dataPlane.outputs.eventHubName
    provisioned: dataPlane.outputs.eventHubProvisioned
  }
  observability: {
    workspaceResourceId: dataPlane.outputs.logAnalyticsWorkspaceResourceId
    workspaceResourceGroupName: dataPlane.outputs.logAnalyticsWorkspaceResourceGroupName
    workspaceName: dataPlane.outputs.logAnalyticsWorkspaceName
    applicationInsightsResourceId: dataPlane.outputs.applicationInsightsResourceId
    applicationInsightsResourceGroupName: dataPlane.outputs.applicationInsightsResourceGroupName
    applicationInsightsName: dataPlane.outputs.applicationInsightsName
    provisioned: dataPlane.outputs.observabilityProvisioned
  }
  keyVault: {
    resourceId: dataPlane.outputs.keyVaultResourceId
    resourceGroupName: dataPlane.outputs.keyVaultResourceGroupName
    name: dataPlane.outputs.keyVaultName
    provisioned: dataPlane.outputs.keyVaultProvisioned
    databaseUrlSecretUri: dataPlane.outputs.databaseUrlSecretUri
    databaseUrlSecretResourceId: dataPlane.outputs.databaseUrlSecretResourceId
    credentialEncryptionKeySecretUri: dataPlane.outputs.credentialEncryptionKeySecretUri
    credentialEncryptionKeySecretResourceId: dataPlane.outputs.credentialEncryptionKeySecretResourceId
    managementApiKeySecretUri: dataPlane.outputs.managementApiKeySecretUri
    managementApiKeySecretResourceId: dataPlane.outputs.managementApiKeySecretResourceId
    apimSubscriptionKeySecretUri: dataPlane.outputs.apimSubscriptionKeySecretUri
    apimSubscriptionKeySecretResourceId: dataPlane.outputs.apimSubscriptionKeySecretResourceId
    apimProbeSubscriptionKeySecretUri: dataPlane.outputs.apimProbeSubscriptionKeySecretUri
    apimProbeSubscriptionKeySecretResourceId: dataPlane.outputs.apimProbeSubscriptionKeySecretResourceId
    privateEndpointId: dataPlane.outputs.keyVaultPrivateEndpointId
    privateDnsZoneId: dataPlane.outputs.keyVaultPrivateDnsZoneId
    privateDnsZoneName: dataPlane.outputs.keyVaultPrivateDnsZoneName
    privateDnsZoneProvisioned: dataPlane.outputs.keyVaultPrivateDnsZoneProvisioned
    privateDnsLinkName: dataPlane.outputs.keyVaultPrivateDnsLinkName
    privateDnsLinkId: dataPlane.outputs.keyVaultPrivateDnsLinkId
    privateDnsLinkProvisioned: dataPlane.outputs.keyVaultPrivateDnsLinkProvisioned
  }
  network: {
    virtualNetworkResourceId: dataPlane.outputs.virtualNetworkResourceId
    telemetryFunctionSubnetResourceId: dataPlane.outputs.telemetryFunctionSubnetResourceId
    controlFunctionSubnetResourceId: dataPlane.outputs.controlFunctionSubnetResourceId
    privateEndpointSubnetResourceId: dataPlane.outputs.privateEndpointSubnetResourceId
    apiSubnetResourceId: dataPlane.outputs.apiSubnetResourceId
    provisioned: dataPlane.outputs.networkProvisioned
  }
}
output appServicePlanName string = dataPlane.outputs.appServicePlanName
output telemetryFunctionPlanName string = dataPlane.outputs.telemetryFunctionPlanName
output telemetryDeploymentContainerName string = dataPlane.outputs.telemetryDeploymentContainerName
output telemetryStorageName string = sharedStorage.name
output ledgerStorageName string = sharedStorage.name
output ledgerTableName string = ledgerTableName
output apiName string = dataPlane.outputs.apiName
output apiUrl string = dataPlane.outputs.apiUrl
output apiPrincipalId string = dataPlane.outputs.apiPrincipalId
output telemetryFunctionName string = dataPlane.outputs.functionName
output telemetryPrincipalId string = dataPlane.outputs.telemetryPrincipalId
output apimGatewayUrl string = effectiveApimGatewayUrl
output gatewayApiPath string = effectiveGatewayApiPath
output controlPlaneFunctionName string = provisionControlPlane ? controlPlane!.outputs.functionName : ''
output controlPlanePrincipalId string = provisionControlPlane ? controlPlane!.outputs.principalId : ''
output controlPlaneFunctionPlanName string = provisionControlPlane ? controlPlane!.outputs.appServicePlanName : ''
output controlPlaneDeploymentContainerName string = provisionControlPlane ? controlPlane!.outputs.deploymentContainerName : ''
output controlPlaneStorageName string = sharedStorage.name

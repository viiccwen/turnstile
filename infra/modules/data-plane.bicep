targetScope = 'resourceGroup'

param location string
param postgresLocation string
@minLength(3)
@maxLength(12)
param resourcePrefix string
param suffix string
param telemetryStorageName string
param telemetryBlobEndpoint string
param telemetryQueueEndpoint string
param telemetryTableEndpoint string
param telemetryDeploymentContainerName string
param ledgerStorageName string
param ledgerTableEndpoint string
param postgresAdministratorLogin string
@secure()
param postgresAdministratorPassword string
param postgresSkuName string
param postgresTier string
param provisionPostgres bool = true
param postgresAdopted bool = false
param existingPostgresServerResourceId string = ''
param existingPostgresServerName string = ''
param existingPostgresDatabaseName string = ''
param useDatabaseUrlOverride bool = false
@secure()
param databaseUrlOverride string = ''
param provisionEventHub bool = true
param existingEventHubNamespaceResourceGroupName string = ''
param existingEventHubNamespaceName string = ''
param existingEventHubName string = ''
param existingEventHubNamespaceResourceId string = ''
param existingEventHubResourceId string = ''
param provisionObservability bool = true
param existingLogAnalyticsWorkspaceResourceGroupName string = ''
param existingLogAnalyticsWorkspaceName string = ''
param existingApplicationInsightsResourceGroupName string = ''
param existingApplicationInsightsName string = ''
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
@secure()
param credentialEncryptionKey string
@secure()
param managementApiKey string
@secure()
param apimSubscriptionKey string
@secure()
param apimProbeSubscriptionKey string
param apimPrincipalId string
param apimResourceGroupName string
param apimName string
param apimApiId string = 'turnstile-llm'
param apimProductId string = 'finops-ai-consumers'
param apimGatewayUrl string
param ledgerTableName string
param gatewayReleaseWorkerEnabled bool = false
param gatewayApplicationKeyManagementEnabled bool = false
param gatewayApplicationProvisioningEnabled bool = false
param databricksOAuthEnabled bool = false
@minValue(1)
param gatewayApplicationDefaultMonthlyTokenLimit int = 100000
@minValue(1)
param gatewayApplicationDefaultTokensPerMinute int = 100000
param entraClientId string = ''
param entraAllowedEmailDomains array = []
param bootstrapOwnerEmail string
@secure()
param bootstrapOwnerPasswordHash string

var managedPostgresServerName = 'pg-${resourcePrefix}-${suffix}'
var managedDatabaseName = 'turnstile'
var managedEventHubNamespaceName = 'eh-${resourcePrefix}-${suffix}'
var managedEventHubName = 'token-usage'
var managedWorkspaceName = 'log-${resourcePrefix}-${suffix}'
var managedAppInsightsName = 'appi-${resourcePrefix}-${suffix}'
var managedKeyVaultName = 'kv-${resourcePrefix}-${take(suffix, 8)}'
var planName = 'plan-${resourcePrefix}-${suffix}'
var telemetryPlanName = 'plan-${resourcePrefix}-telemetry-${suffix}'
var apiName = 'api-${resourcePrefix}-${suffix}'
var functionName = 'func-${resourcePrefix}-telemetry-${suffix}'
var managedVirtualNetworkName = 'vnet-${resourcePrefix}-${suffix}'
var telemetryFunctionSubnetName = 'snet-flex-telemetry'
var controlFunctionSubnetName = 'snet-flex-control'
var privateEndpointSubnetName = 'snet-private-endpoints'
var apiSubnetName = 'snet-api'
var effectivePostgresServerName = postgresAdopted ? existingPostgresServerName : managedPostgresServerName
var effectiveDatabaseName = postgresAdopted ? existingPostgresDatabaseName : managedDatabaseName
var generatedPostgresConnectionString = 'postgresql://${postgresAdministratorLogin}:${postgresAdministratorPassword}@${effectivePostgresServerName}.postgres.database.azure.com:5432/${effectiveDatabaseName}?sslmode=require'
var effectiveDatabaseUrl = useDatabaseUrlOverride ? databaseUrlOverride : generatedPostgresConnectionString
var effectiveEventHubNamespaceName = provisionEventHub ? managedEventHubNamespaceName : existingEventHubNamespaceName
var effectiveEventHubName = provisionEventHub ? managedEventHubName : existingEventHubName
var effectiveEventHubNamespaceResourceGroupName = provisionEventHub ? resourceGroup().name : existingEventHubNamespaceResourceGroupName
var effectiveWorkspaceResourceGroupName = provisionObservability ? resourceGroup().name : existingLogAnalyticsWorkspaceResourceGroupName
var effectiveAppInsightsResourceGroupName = provisionObservability ? resourceGroup().name : existingApplicationInsightsResourceGroupName
var effectiveKeyVaultResourceGroupName = provisionKeyVault ? resourceGroup().name : existingKeyVaultResourceGroupName
var effectiveKeyVaultName = provisionKeyVault ? managedKeyVaultName : existingKeyVaultName
var logAnalyticsReaderRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '73c42c96-874c-492b-b04d-ab87d138a893'
)

resource managedWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (provisionObservability) {
  name: managedWorkspaceName
  location: location
  properties: {
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource existingWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!provisionObservability) {
  scope: resourceGroup(existingLogAnalyticsWorkspaceResourceGroupName)
  name: existingLogAnalyticsWorkspaceName
}

var effectiveWorkspaceId = provisionObservability ? managedWorkspace!.id : existingWorkspace!.id
var effectiveWorkspaceCustomerId = provisionObservability
  ? managedWorkspace!.properties.customerId
  : existingWorkspace!.properties.customerId

resource managedAppInsights 'Microsoft.Insights/components@2020-02-02' = if (provisionObservability) {
  name: managedAppInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: managedWorkspace!.id
    RetentionInDays: 30
    DisableIpMasking: false
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource existingAppInsights 'Microsoft.Insights/components@2020-02-02' existing = if (!provisionObservability) {
  scope: resourceGroup(existingApplicationInsightsResourceGroupName)
  name: existingApplicationInsightsName
}

var effectiveAppInsightsName = provisionObservability ? managedAppInsights!.name : existingAppInsights!.name
var effectiveAppInsightsId = provisionObservability ? managedAppInsights!.id : existingAppInsights!.id
var effectiveAppInsightsConnectionString = provisionObservability
  ? managedAppInsights!.properties.ConnectionString
  : existingAppInsights!.properties.ConnectionString

resource managedKeyVault 'Microsoft.KeyVault/vaults@2023-07-01' = if (provisionKeyVault) {
  name: managedKeyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
      ipRules: []
      virtualNetworkRules: []
    }
    accessPolicies: []
  }
}

var effectiveKeyVaultId = provisionKeyVault ? managedKeyVault!.id : existingKeyVaultResourceId

resource managedPostgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = if (provisionPostgres) {
  name: managedPostgresServerName
  location: postgresLocation
  sku: {
    name: postgresSkuName
    tier: postgresTier
  }
  properties: {
    version: '16'
    administratorLogin: postgresAdministratorLogin
    administratorLoginPassword: postgresAdministratorPassword
    availabilityZone: '1'
    storage: {
      storageSizeGB: 32
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: {
      publicNetworkAccess: 'Enabled'
    }
    authConfig: {
      activeDirectoryAuth: 'Disabled'
      passwordAuth: 'Enabled'
    }
  }
}

resource managedDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = if (provisionPostgres) {
  parent: managedPostgres
  name: managedDatabaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource allowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = if (provisionPostgres) {
  parent: managedPostgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource databaseUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (provisionKeyVault) {
  parent: managedKeyVault
  name: 'database-url'
  properties: {
    value: effectiveDatabaseUrl
  }
}

resource credentialKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (provisionKeyVault) {
  parent: managedKeyVault
  name: 'credential-encryption-key'
  properties: {
    value: credentialEncryptionKey
  }
}

resource managementKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (provisionKeyVault) {
  parent: managedKeyVault
  name: 'management-api-key'
  properties: {
    value: managementApiKey
  }
}

resource apimKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (provisionKeyVault) {
  parent: managedKeyVault
  name: 'apim-subscription-key'
  properties: {
    value: apimSubscriptionKey
  }
}

resource apimProbeKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (provisionKeyVault) {
  parent: managedKeyVault
  name: 'apim-probe-subscription-key'
  properties: {
    value: apimProbeSubscriptionKey
  }
}

var effectiveDatabaseUrlSecretUri = provisionKeyVault
  ? databaseUrlSecret!.properties.secretUri
  : existingDatabaseUrlSecretUri
var effectiveCredentialEncryptionKeySecretUri = provisionKeyVault
  ? credentialKeySecret!.properties.secretUri
  : existingCredentialEncryptionKeySecretUri
var effectiveManagementApiKeySecretUri = provisionKeyVault
  ? managementKeySecret!.properties.secretUri
  : existingManagementApiKeySecretUri
var effectiveApimSubscriptionKeySecretUri = provisionKeyVault
  ? apimKeySecret!.properties.secretUri
  : existingApimSubscriptionKeySecretUri
var effectiveApimProbeSubscriptionKeySecretUri = provisionKeyVault
  ? apimProbeKeySecret!.properties.secretUri
  : existingApimProbeSubscriptionKeySecretUri

resource managedEventHubNamespace 'Microsoft.EventHub/namespaces@2024-01-01' = if (provisionEventHub) {
  name: managedEventHubNamespaceName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 1
  }
  properties: {
    isAutoInflateEnabled: true
    maximumThroughputUnits: 2
    publicNetworkAccess: 'Enabled'
  }
}

resource managedUsageEventHub 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = if (provisionEventHub) {
  parent: managedEventHubNamespace
  name: managedEventHubName
  properties: {
    messageRetentionInDays: 7
    partitionCount: 4
  }
}

var effectiveEventHubNamespaceResourceId = provisionEventHub
  ? managedEventHubNamespace!.id
  : existingEventHubNamespaceResourceId
var effectiveEventHubResourceId = provisionEventHub
  ? managedUsageEventHub!.id
  : existingEventHubResourceId

resource managedVirtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = if (provisionNetwork) {
  name: managedVirtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.42.0.0/16'
      ]
    }
  }
}

resource managedTelemetryFunctionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = if (provisionNetwork) {
  parent: managedVirtualNetwork
  name: telemetryFunctionSubnetName
  properties: {
    addressPrefix: '10.42.3.0/27'
    delegations: [
      {
        name: 'flex-consumption-delegation'
        properties: {
          serviceName: 'Microsoft.App/environments'
        }
      }
    ]
  }
}

resource managedControlFunctionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = if (provisionNetwork) {
  parent: managedVirtualNetwork
  name: controlFunctionSubnetName
  properties: {
    addressPrefix: '10.42.3.32/27'
    delegations: [
      {
        name: 'flex-consumption-delegation'
        properties: {
          serviceName: 'Microsoft.App/environments'
        }
      }
    ]
  }
  dependsOn: [
    managedTelemetryFunctionSubnet
  ]
}

resource managedPrivateEndpointSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = if (provisionNetwork) {
  parent: managedVirtualNetwork
  name: privateEndpointSubnetName
  properties: {
    addressPrefix: '10.42.2.0/24'
    privateEndpointNetworkPolicies: 'Disabled'
  }
  dependsOn: [
    managedControlFunctionSubnet
  ]
}

resource managedApiSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = if (provisionNetwork) {
  parent: managedVirtualNetwork
  name: apiSubnetName
  properties: {
    addressPrefix: '10.42.3.64/27'
    delegations: [
      {
        name: 'app-service-delegation'
        properties: {
          serviceName: 'Microsoft.Web/serverFarms'
        }
      }
    ]
  }
  dependsOn: [
    managedPrivateEndpointSubnet
  ]
}

var effectiveVirtualNetworkResourceId = provisionNetwork
  ? managedVirtualNetwork!.id
  : existingVirtualNetworkResourceId
var effectiveTelemetryFunctionSubnetResourceId = provisionNetwork
  ? managedTelemetryFunctionSubnet!.id
  : existingTelemetryFunctionSubnetResourceId
var effectiveControlFunctionSubnetResourceId = provisionNetwork
  ? managedControlFunctionSubnet!.id
  : existingControlFunctionSubnetResourceId
var effectivePrivateEndpointSubnetResourceId = provisionNetwork
  ? managedPrivateEndpointSubnet!.id
  : existingPrivateEndpointSubnetResourceId
var effectiveApiSubnetResourceId = provisionNetwork
  ? managedApiSubnet!.id
  : existingApiSubnetResourceId

module keyVaultPrivateEndpoint 'key-vault-private-endpoint.bicep' = if (provisionKeyVault) {
  name: '${resourcePrefix}-key-vault-private-endpoint'
  params: {
    location: location
    keyVaultName: managedKeyVault!.name
    keyVaultResourceGroupName: resourceGroup().name
    virtualNetworkResourceId: effectiveVirtualNetworkResourceId
    privateEndpointSubnetResourceId: effectivePrivateEndpointSubnetResourceId
    provisionPrivateDnsZone: provisionKeyVaultPrivateDnsZone
    privateDnsLinkName: keyVaultPrivateDnsLinkName
    existingPrivateDnsZoneResourceGroupName: existingKeyVaultPrivateDnsZoneResourceGroupName
    existingPrivateDnsZoneName: existingKeyVaultPrivateDnsZoneName
  }
}

resource apiPlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: planName
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
    capacity: 1
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

resource telemetryPlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: telemetryPlanName
  location: location
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

resource api 'Microsoft.Web/sites@2024-11-01' = {
  name: apiName
  location: location
  kind: 'app,linux'
  tags: {
    SecurityControl: 'Ignore'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: apiPlan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.11'
      alwaysOn: true
      healthCheckPath: '/health'
      appCommandLine: 'python -m backend.migrate && python -m backend.bootstrap && python -m uvicorn backend.api:app --host 0.0.0.0 --port 8000'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'false' }
        { name: 'ENABLE_ORYX_BUILD', value: 'false' }
        { name: 'WEBSITE_RUN_FROM_PACKAGE', value: '1' }
        { name: 'PYTHONPATH', value: '/home/site/wwwroot:/home/site/wwwroot/.python_packages/lib/site-packages' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'WEBSITES_CONTAINER_START_TIME_LIMIT', value: '1800' }
        { name: 'DATABASE_URL', value: effectiveDatabaseUrl }
        { name: 'DATA_BACKEND', value: 'postgresql' }
        { name: 'CREDENTIAL_ENCRYPTION_KEY', value: credentialEncryptionKey }
        { name: 'MANAGEMENT_API_KEY', value: managementApiKey }
        { name: 'APIM_PRINCIPAL_ID', value: apimPrincipalId }
        { name: 'DATABRICKS_OAUTH_ENABLED', value: string(databricksOAuthEnabled) }
        { name: 'AZURE_SUBSCRIPTION_ID', value: subscription().subscriptionId }
        { name: 'APIM_RESOURCE_GROUP', value: apimResourceGroupName }
        { name: 'APIM_SERVICE_NAME', value: apimName }
        { name: 'APIM_API_ID', value: apimApiId }
        { name: 'APIM_PRODUCT_ID', value: apimProductId }
        { name: 'APIM_GATEWAY_URL', value: apimGatewayUrl }
        { name: 'APIM_DASHBOARD_SUBSCRIPTION_KEY', value: apimSubscriptionKey }
        { name: 'GATEWAY_RELEASE_WORKER_ENABLED', value: string(gatewayReleaseWorkerEnabled) }
        { name: 'GATEWAY_APPLICATION_PROVISIONING_ENABLED', value: string(gatewayApplicationProvisioningEnabled) }
        { name: 'GATEWAY_APPLICATION_DEFAULT_MONTHLY_TOKEN_LIMIT', value: string(gatewayApplicationDefaultMonthlyTokenLimit) }
        { name: 'GATEWAY_APPLICATION_DEFAULT_TOKENS_PER_MINUTE', value: string(gatewayApplicationDefaultTokensPerMinute) }
        { name: 'LEDGER_SYNC_ENABLED', value: 'true' }
        { name: 'LEDGER_TABLE_ENDPOINT', value: ledgerTableEndpoint }
        { name: 'LEDGER_TABLE_NAME', value: ledgerTableName }
        { name: 'GATEWAY_APPLICATION_KEY_MANAGEMENT_ENABLED', value: string(gatewayApplicationKeyManagementEnabled) }
        { name: 'ENTRA_CLIENT_ID', value: entraClientId }
        { name: 'ENTRA_ALLOWED_EMAIL_DOMAINS', value: string(entraAllowedEmailDomains) }
        { name: 'BOOTSTRAP_OWNER_EMAIL', value: bootstrapOwnerEmail }
        { name: 'BOOTSTRAP_OWNER_PASSWORD_HASH', value: bootstrapOwnerPasswordHash }
        { name: 'PRODUCTION', value: 'true' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: effectiveAppInsightsConnectionString }
        { name: 'TRAFFIC_GENERATION_BUDGET_USD', value: '20' }
        { name: 'WEB_DIST_DIR', value: 'frontend/dist' }
        { name: 'MIGRATIONS_DIR', value: 'migrations' }
      ]
    }
  }
}

resource apiVnetIntegration 'Microsoft.Web/sites/networkConfig@2024-11-01' = {
  parent: api
  name: 'virtualNetwork'
  properties: {
    subnetResourceId: effectiveApiSubnetResourceId
    swiftSupported: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  tags: {
    SecurityControl: 'Ignore'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: telemetryPlan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${telemetryBlobEndpoint}${telemetryDeploymentContainerName}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 100
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.11'
      }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'AzureWebJobsFeatureFlags', value: 'EnableWorkerIndexing' }
        { name: 'AzureWebJobsStorage__accountName', value: telemetryStorageName }
        { name: 'AzureWebJobsStorage__blobServiceUri', value: telemetryBlobEndpoint }
        { name: 'AzureWebJobsStorage__queueServiceUri', value: telemetryQueueEndpoint }
        { name: 'AzureWebJobsStorage__tableServiceUri', value: telemetryTableEndpoint }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'EVENT_HUB_NAME', value: effectiveEventHubName }
        { name: 'EVENT_HUB_CONNECTION__fullyQualifiedNamespace', value: '${effectiveEventHubNamespaceName}.servicebus.windows.net' }
        { name: 'EVENT_HUB_CONNECTION__credential', value: 'managedidentity' }
        { name: 'DATABASE_URL', value: effectiveDatabaseUrl }
        { name: 'DATA_BACKEND', value: 'postgresql' }
        { name: 'PRODUCTION', value: 'true' }
        { name: 'LOG_ANALYTICS_WORKSPACE_ID', value: effectiveWorkspaceCustomerId }
        { name: 'APIM_API_ID', value: apimApiId }
        { name: 'CACHE_READ_BACKFILL_HOURS', value: '720' }
        { name: 'CACHE_READ_OVERLAP_HOURS', value: '24' }
        { name: 'LEDGER_SYNC_ENABLED', value: 'true' }
        { name: 'LEDGER_TABLE_ENDPOINT', value: ledgerTableEndpoint }
        { name: 'LEDGER_TABLE_NAME', value: ledgerTableName }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: effectiveAppInsightsConnectionString }
      ]
    }
  }
}

resource functionVnetIntegration 'Microsoft.Web/sites/networkConfig@2024-11-01' = {
  parent: functionApp
  name: 'virtualNetwork'
  properties: {
    subnetResourceId: effectiveTelemetryFunctionSubnetResourceId
    swiftSupported: true
  }
}

resource apiKeyVaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (provisionKeyVault) {
  name: guid(managedKeyVault!.id, api.id, 'key-vault-secrets-user')
  scope: managedKeyVault
  properties: {
    principalId: api.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

resource functionKeyVaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (provisionKeyVault) {
  name: guid(managedKeyVault!.id, functionApp.id, 'key-vault-secrets-user')
  scope: managedKeyVault
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

resource functionEventHubReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (provisionEventHub) {
  name: guid(managedUsageEventHub!.id, functionApp.id, 'event-hubs-data-receiver')
  scope: managedUsageEventHub
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde')
  }
}

resource functionLogAnalyticsReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (provisionObservability) {
  name: guid(managedWorkspace!.id, functionApp.id, 'log-analytics-reader')
  scope: managedWorkspace
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: logAnalyticsReaderRoleDefinitionId
  }
}

resource apimEventHubSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (provisionEventHub) {
  name: guid(managedUsageEventHub!.id, apimPrincipalId, 'event-hubs-data-sender')
  scope: managedUsageEventHub
  properties: {
    principalId: apimPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2b629674-e913-4c01-ae53-ef4638d8f975')
  }
}

output postgresServerName string = effectivePostgresServerName
output postgresServerResourceId string = postgresAdopted
  ? existingPostgresServerResourceId
  : resourceId('Microsoft.DBforPostgreSQL/flexibleServers', managedPostgresServerName)
output postgresFqdn string = '${effectivePostgresServerName}.postgres.database.azure.com'
output databaseName string = effectiveDatabaseName
output postgresProvisioned bool = !postgresAdopted
output eventHubNamespaceResourceId string = effectiveEventHubNamespaceResourceId
output eventHubResourceId string = effectiveEventHubResourceId
output eventHubNamespaceResourceGroupName string = effectiveEventHubNamespaceResourceGroupName
output eventHubNamespaceName string = effectiveEventHubNamespaceName
output eventHubName string = effectiveEventHubName
output eventHubProvisioned bool = provisionEventHub
output logAnalyticsWorkspaceResourceId string = effectiveWorkspaceId
output logAnalyticsWorkspaceResourceGroupName string = effectiveWorkspaceResourceGroupName
output logAnalyticsWorkspaceName string = provisionObservability ? managedWorkspace!.name : existingWorkspace!.name
output applicationInsightsResourceId string = effectiveAppInsightsId
output applicationInsightsResourceGroupName string = effectiveAppInsightsResourceGroupName
output applicationInsightsName string = effectiveAppInsightsName
output applicationInsightsConnectionString string = effectiveAppInsightsConnectionString
output observabilityProvisioned bool = provisionObservability
output telemetryStorageName string = telemetryStorageName
output ledgerStorageName string = ledgerStorageName
output ledgerTableEndpoint string = ledgerTableEndpoint
output keyVaultResourceId string = effectiveKeyVaultId
output keyVaultResourceGroupName string = effectiveKeyVaultResourceGroupName
output keyVaultName string = effectiveKeyVaultName
output keyVaultProvisioned bool = provisionKeyVault
output databaseUrlSecretUri string = effectiveDatabaseUrlSecretUri
output databaseUrlSecretResourceId string = provisionKeyVault ? databaseUrlSecret!.id : existingDatabaseUrlResourceId
output managementApiKeySecretUri string = effectiveManagementApiKeySecretUri
output managementApiKeySecretResourceId string = provisionKeyVault ? managementKeySecret!.id : existingManagementKeyResourceId
output apimSubscriptionKeySecretUri string = effectiveApimSubscriptionKeySecretUri
output apimSubscriptionKeySecretResourceId string = provisionKeyVault ? apimKeySecret!.id : existingApimKeyResourceId
output apimProbeSubscriptionKeySecretUri string = effectiveApimProbeSubscriptionKeySecretUri
output apimProbeSubscriptionKeySecretResourceId string = provisionKeyVault ? apimProbeKeySecret!.id : existingApimProbeKeyResourceId
output credentialEncryptionKeySecretUri string = effectiveCredentialEncryptionKeySecretUri
output credentialEncryptionKeySecretResourceId string = provisionKeyVault ? credentialKeySecret!.id : existingCredentialKeyResourceId
output virtualNetworkResourceId string = effectiveVirtualNetworkResourceId
output telemetryFunctionSubnetResourceId string = effectiveTelemetryFunctionSubnetResourceId
output controlFunctionSubnetResourceId string = effectiveControlFunctionSubnetResourceId
output privateEndpointSubnetResourceId string = effectivePrivateEndpointSubnetResourceId
output apiSubnetResourceId string = effectiveApiSubnetResourceId
output networkProvisioned bool = provisionNetwork
output keyVaultPrivateEndpointId string = provisionKeyVault ? keyVaultPrivateEndpoint!.outputs.privateEndpointId : ''
output keyVaultPrivateDnsZoneId string = provisionKeyVault
  ? keyVaultPrivateEndpoint!.outputs.privateDnsZoneId
  : existingKeyVaultPrivateDnsZoneResourceId
output keyVaultPrivateDnsZoneName string = provisionKeyVault
  ? keyVaultPrivateEndpoint!.outputs.privateDnsZoneName
  : existingKeyVaultPrivateDnsZoneName
output keyVaultPrivateDnsZoneProvisioned bool = provisionKeyVault && provisionKeyVaultPrivateDnsZone
output keyVaultPrivateDnsLinkName string = provisionKeyVault ? keyVaultPrivateEndpoint!.outputs.privateDnsLinkName : ''
output keyVaultPrivateDnsLinkId string = provisionKeyVault ? keyVaultPrivateEndpoint!.outputs.privateDnsLinkId : ''
output keyVaultPrivateDnsLinkProvisioned bool = provisionKeyVault && provisionKeyVaultPrivateDnsZone
output appServicePlanName string = apiPlan.name
output telemetryFunctionPlanName string = telemetryPlan.name
output telemetryDeploymentContainerName string = telemetryDeploymentContainerName
output apiName string = api.name
output apiUrl string = 'https://${api.properties.defaultHostName}'
output apiPrincipalId string = api.identity.principalId
output telemetryPrincipalId string = functionApp.identity.principalId
output functionName string = functionApp.name

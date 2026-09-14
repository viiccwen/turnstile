<#
.SYNOPSIS
Plans or executes removal of one Turnstile environment from shared Azure boundaries.

.DESCRIPTION
The default is a read-only dry run. The script never deletes the resource group, APIM
service, Foundry resources, the shared azuremonitor logger, or unrelated APIM objects.

.EXAMPLE
.\scripts\remove-turnstile.ps1 -Subscription <subscription-id>

.EXAMPLE
.\scripts\remove-turnstile.ps1 -Subscription <subscription-id> -Execute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Subscription,

    [string]$Parameters = (Join-Path $PSScriptRoot '..\.turnstile\main.parameters.json'),

    [string]$Outputs,

    [string]$Manifest,

    [switch]$CaptureManifest,

    [switch]$Execute,

    [switch]$Force,

    [switch]$RemoveLocalSecretState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $Name"
    }
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required JSON file does not exist: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-ParameterValue($Document, [string]$Name, $Default = $null) {
    $property = $Document.parameters.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }
    return $property.Value.value
}

function Invoke-AzJson([string[]]$Arguments, [switch]$AllowFailure) {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & az @Arguments 2>$null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        if ($AllowFailure) {
            return $null
        }
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }
    $text = ($output | Out-String).Trim()
    if (-not $text) {
        return $null
    }
    return $text | ConvertFrom-Json
}

$actions = [System.Collections.Generic.List[object]]::new()
function Add-AzAction([string]$Description, [string[]]$Arguments) {
    $actions.Add([pscustomobject]@{
        Description = $Description
        Arguments = $Arguments
    })
}

function Assert-ManifestAction(
    $Action,
    [string]$PlatformResourceGroup,
    [string]$StorageResourceGroup,
    [string]$ApimId,
    [string]$StorageAccountName,
    [string]$TelemetryContainerName,
    [string]$ControlContainerName,
    [string]$LedgerTableName
) {
    $arguments = @($Action.Arguments | ForEach-Object { [string]$_ })
    if ($arguments.Count -lt 2) {
        throw "Manifest action has no executable Azure CLI command: $($Action.Description)"
    }
    $signature = "$($arguments[0]) $($arguments[1])"
    $allowedSignatures = @(
        'functionapp stop',
        'webapp stop',
        'apim subscription',
        'apim api',
        'apim product',
        'monitor diagnostic-settings',
        'rest --method',
        'role assignment',
        'resource delete',
        'network private-dns',
        'storage container',
        'storage table'
    )
    if ($signature -notin $allowedSignatures) {
        throw "Manifest action uses an unsupported Azure CLI command: $signature"
    }

    $joined = $arguments -join ' '
    if ($joined -match '(?i)\bgroup\s+delete\b' -or $joined -match '(?i)\bapim\s+delete\b') {
        throw "Manifest action attempts to delete a protected boundary: $($Action.Description)"
    }
    if ($joined -match '(?i)Microsoft\.CognitiveServices') {
        throw "Manifest action attempts to delete a Foundry resource: $($Action.Description)"
    }

    if ($signature -in @('functionapp stop', 'webapp stop')) {
        $groupIndex = [Array]::IndexOf($arguments, '-g')
        if ($groupIndex -lt 0) { $groupIndex = [Array]::IndexOf($arguments, '--resource-group') }
        if ($groupIndex -lt 0 -or $arguments[$groupIndex + 1] -cne $PlatformResourceGroup) {
            throw "Manifest stop action is outside the platform resource group: $($Action.Description)"
        }
    }

    if ($signature -like 'apim *') {
        if ($arguments.Count -lt 3 -or $arguments[2] -cne 'delete') {
            throw "Manifest APIM action is not an explicit delete: $($Action.Description)"
        }
        $groupIndex = [Array]::IndexOf($arguments, '-g')
        $serviceIndex = [Array]::IndexOf($arguments, '-n')
        $expectedSegments = $ApimId.Split('/')
        $expectedGroup = $expectedSegments[[Array]::IndexOf($expectedSegments, 'resourceGroups') + 1]
        $expectedService = $expectedSegments[-1]
        if (
            $groupIndex -lt 0 -or $serviceIndex -lt 0 -or
            $arguments[$groupIndex + 1] -cne $expectedGroup -or
            $arguments[$serviceIndex + 1] -cne $expectedService
        ) {
            throw "Manifest APIM action targets another service: $($Action.Description)"
        }
        if ($signature -eq 'apim product') {
            $cascadeIndex = [Array]::IndexOf($arguments, '--delete-subscriptions')
            if ($cascadeIndex -lt 0 -or $arguments[$cascadeIndex + 1] -cne 'false') {
                throw 'Manifest product deletion must not use subscription cascade.'
            }
        }
    }

    if ($signature -eq 'resource delete') {
        $idIndex = [Array]::IndexOf($arguments, '--ids')
        if ($idIndex -lt 0 -or $idIndex + 1 -ge $arguments.Count) {
            throw "Manifest resource action has no resource ID: $($Action.Description)"
        }
        $resourceId = $arguments[$idIndex + 1]
        $platformPrefix = "/subscriptions/$Subscription/resourceGroups/$PlatformResourceGroup/providers/"
        $inPlatformGroup = $resourceId.StartsWith($platformPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $inPlatformGroup) {
            throw "Manifest resource is outside the platform resource group: $resourceId"
        }
        $allowedResourceSegments = @(
            '/providers/Microsoft.Web/sites/',
            '/providers/Microsoft.Web/serverFarms/',
            '/providers/Microsoft.ContainerRegistry/registries/',
            '/providers/Microsoft.DBforPostgreSQL/flexibleServers/',
            '/providers/Microsoft.EventHub/namespaces/',
            '/providers/Microsoft.KeyVault/vaults/',
            '/providers/Microsoft.Insights/components/',
            '/providers/Microsoft.OperationalInsights/workspaces/',
            '/providers/Microsoft.Network/virtualNetworks/',
            '/providers/Microsoft.Network/privateEndpoints/',
            '/providers/Microsoft.Network/networkSecurityGroups/'
        )
        if (-not @($allowedResourceSegments | Where-Object { $arguments[$idIndex + 1] -like "*$_*" }).Count) {
            throw "Manifest resource type is not approved for cleanup: $($arguments[$idIndex + 1])"
        }
    }

    if ($signature -in @('storage container', 'storage table')) {
        if ($arguments.Count -lt 3 -or $arguments[2] -cne 'delete') {
            throw "Manifest storage action is not an explicit delete: $($Action.Description)"
        }
        $accountIndex = [Array]::IndexOf($arguments, '--account-name')
        $nameIndex = [Array]::IndexOf($arguments, '--name')
        $authIndex = [Array]::IndexOf($arguments, '--auth-mode')
        if (
            $accountIndex -lt 0 -or $nameIndex -lt 0 -or $authIndex -lt 0 -or
            $arguments[$accountIndex + 1] -cne $StorageAccountName -or
            $arguments[$authIndex + 1] -cne 'login'
        ) {
            throw "Manifest storage action targets an unexpected account: $($Action.Description)"
        }
        $expectedNames = if ($signature -eq 'storage container') {
            @($TelemetryContainerName, $ControlContainerName)
        } else {
            @($LedgerTableName)
        }
        if ($arguments[$nameIndex + 1] -cnotin $expectedNames) {
            throw "Manifest storage action targets an unexpected child: $($Action.Description)"
        }
    }

    if ($signature -eq 'rest --method') {
        $urlIndex = [Array]::IndexOf($arguments, '--url')
        if ($urlIndex -lt 0 -or $urlIndex + 1 -ge $arguments.Count) {
            throw "Manifest REST action has no URL: $($Action.Description)"
        }
        $expectedPrefix = "https://management.azure.com$ApimId/"
        if (-not $arguments[$urlIndex + 1].StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Manifest REST action is outside the configured APIM service: $($arguments[$urlIndex + 1])"
        }
        if ($arguments[2] -cne 'delete' -or $arguments[$urlIndex + 1] -notmatch '(?i)/(subscriptions|backends|namedValues|loggers)/[^/?]+\?api-version=') {
            throw "Manifest REST action is not an approved APIM child deletion: $($Action.Description)"
        }
    }

    if ($signature -eq 'role assignment') {
        if ($arguments.Count -lt 3 -or $arguments[2] -cne 'delete') {
            throw "Manifest RBAC action is not an explicit delete: $($Action.Description)"
        }
        $idIndex = [Array]::IndexOf($arguments, '--ids')
        if (
            $idIndex -lt 0 -or
            -not $arguments[$idIndex + 1].StartsWith("$ApimId/providers/Microsoft.Authorization/roleAssignments/", [System.StringComparison]::OrdinalIgnoreCase)
        ) {
            throw "Manifest RBAC action is outside the configured APIM service: $($Action.Description)"
        }
    }

    if ($signature -eq 'monitor diagnostic-settings') {
        $resourceIndex = [Array]::IndexOf($arguments, '--resource')
        if ($arguments.Count -lt 3 -or $arguments[2] -cne 'delete' -or $resourceIndex -lt 0 -or $arguments[$resourceIndex + 1] -cne $ApimId) {
            throw "Manifest diagnostic action is outside the configured APIM service: $($Action.Description)"
        }
    }

    if ($signature -eq 'network private-dns') {
        if ($arguments -notcontains 'delete' -or $joined -notmatch '(?i)\blink\s+vnet\s+delete\b') {
            throw "Manifest DNS action is not a VNet-link deletion: $($Action.Description)"
        }
        if ($joined -match '(?i)\bzone\s+delete\b') {
            throw "Manifest must not delete a private DNS zone: $($Action.Description)"
        }
        $groupIndex = [Array]::IndexOf($arguments, '-g')
        $zoneIndex = [Array]::IndexOf($arguments, '-z')
        $nameIndex = [Array]::IndexOf($arguments, '-n')
        $allowedZones = @(
            'privatelink.blob.core.windows.net',
            'privatelink.queue.core.windows.net',
            'privatelink.table.core.windows.net',
            'privatelink.vaultcore.azure.net'
        )
        if (
            $groupIndex -lt 0 -or $zoneIndex -lt 0 -or $nameIndex -lt 0 -or
            $arguments[$groupIndex + 1] -cne $PlatformResourceGroup -or
            $arguments[$zoneIndex + 1] -notin $allowedZones -or
            $arguments[$nameIndex + 1] -cne 'finops-vnet'
        ) {
            throw "Manifest DNS action targets an unexpected link: $($Action.Description)"
        }
    }
}

function Invoke-RecordedCleanup(
    [string]$ManifestPath,
    [string]$OutputPath,
    [string]$ParameterSha256,
    [string]$OutputSha256,
    [string]$Prefix,
    [string]$PlatformResourceGroup,
    [string]$StorageResourceGroup,
    [string]$ApimResourceGroup,
    [string]$ApimName,
    [string]$ApiId,
    [string]$StorageAccountName,
    [string]$TelemetryContainerName,
    [string]$ControlContainerName,
    [string]$LedgerTableName,
    [bool]$ExecuteActions,
    [bool]$SkipConfirmation,
    [bool]$DeleteLocalSecretState
) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Resource manifest does not exist: $ManifestPath. Run this script once with -CaptureManifest."
    }
    $hashPath = "$ManifestPath.sha256"
    if (-not (Test-Path -LiteralPath $hashPath -PathType Leaf)) {
        throw "Resource manifest hash does not exist: $hashPath. Re-capture the manifest."
    }
    $manifestSha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $recordedSha256 = (Get-Content -LiteralPath $hashPath -Raw -Encoding ASCII).Trim().ToLowerInvariant()
    if ($manifestSha256 -cne $recordedSha256) {
        throw 'Resource manifest hash mismatch. Re-capture and review the manifest before cleanup.'
    }

    $manifestDocument = Read-JsonFile $ManifestPath
    if ([int]$manifestDocument.schemaVersion -ne 1) {
        throw "Unsupported resource manifest schema: $($manifestDocument.schemaVersion)"
    }
    if (-not [bool]$manifestDocument.options.coreEnvironmentOnly) {
        throw 'Resource manifest is not restricted to core environment cleanup.'
    }
    $apimId = "/subscriptions/$Subscription/resourceGroups/$ApimResourceGroup/providers/Microsoft.ApiManagement/service/$ApimName"
    $contextChecks = @{
        subscriptionId = $Subscription
        resourcePrefix = $Prefix
        platformResourceGroup = $PlatformResourceGroup
        storageResourceGroup = $StorageResourceGroup
        apimResourceGroup = $ApimResourceGroup
        apimName = $ApimName
        apimId = $apimId
        apiId = $ApiId
        storageAccountName = $StorageAccountName
        telemetryDeploymentContainerName = $TelemetryContainerName
        controlPlaneDeploymentContainerName = $ControlContainerName
        ledgerTableName = $LedgerTableName
        parametersSha256 = $ParameterSha256
        outputsSha256 = $OutputSha256
    }
    foreach ($entry in $contextChecks.GetEnumerator()) {
        if ([string]$manifestDocument.($entry.Key) -cne [string]$entry.Value) {
            throw "Resource manifest mismatch for $($entry.Key). Re-capture the manifest before cleanup."
        }
    }

    $recordedActions = [System.Collections.Generic.List[object]]::new()
    foreach ($action in @($manifestDocument.actions)) {
        Assert-ManifestAction `
            $action $PlatformResourceGroup $StorageResourceGroup $apimId `
            $StorageAccountName $TelemetryContainerName $ControlContainerName $LedgerTableName
        $recordedActions.Add([pscustomobject]@{
            Description = [string]$action.description
            Arguments = @($action.arguments | ForEach-Object { [string]$_ })
        })
    }

    Write-Host ''
    Write-Host "Removal manifest $ManifestPath contains $($recordedActions.Count) actions:" -ForegroundColor Cyan
    Write-Host "Manifest SHA256: $manifestSha256"
    for ($index = 0; $index -lt $recordedActions.Count; $index++) {
        Write-Host ("{0,3}. {1}" -f ($index + 1), $recordedActions[$index].Description)
    }
    Write-Host ''
    Write-Host "Never deleted: resource group $PlatformResourceGroup, storage account $StorageAccountName, APIM service $ApimResourceGroup/$ApimName, Foundry resources, and unrelated APIM objects." -ForegroundColor Green

    if (-not $ExecuteActions) {
        Write-Host 'Dry run only. Re-run with -Execute to perform this exact recorded cleanup.' -ForegroundColor Yellow
        return
    }
    if (-not $SkipConfirmation) {
        $confirmation = Read-Host "Type 'approve' to continue"
        if ($confirmation -cne 'approve') {
            throw 'Removal cancelled because the confirmation text did not match.'
        }
    }

    foreach ($action in $recordedActions) {
        Write-Host "Executing: $($action.Description)" -ForegroundColor Yellow
        & az @($action.Arguments)
        if ($LASTEXITCODE -ne 0) {
            throw "Removal stopped after failure: $($action.Description)"
        }
    }

    Remove-Item -LiteralPath $OutputPath -Force
    Write-Host "Deleted local outputs file: $OutputPath"
    if ($DeleteLocalSecretState) {
        $statePath = Join-Path (Split-Path $OutputPath -Parent) "$PlatformResourceGroup.json"
        if (Test-Path -LiteralPath $statePath) {
            Remove-Item -LiteralPath $statePath -Force
            Write-Host "Deleted local secret state: $statePath"
        }
    } else {
        Write-Host 'Private secret state was retained. Use -RemoveLocalSecretState only after backing it up or deciding not to reuse it.'
    }
    Write-Host 'Turnstile cleanup completed. The resource group, APIM service, and Foundry resources were preserved.' -ForegroundColor Green
}

function Get-AppPrincipal([string]$ResourceGroup, [string]$Name) {
    if (-not $Name) {
        return $null
    }
    $identity = Invoke-AzJson @(
        'webapp', 'identity', 'show',
        '--resource-group', $ResourceGroup,
        '--name', $Name,
        '--output', 'json'
    ) -AllowFailure
    if ($null -eq $identity) {
        return $null
    }
    return [string]$identity.principalId
}

function Test-AppExists([string]$ResourceGroup, [string]$Name) {
    if (-not $Name) {
        return $false
    }
    $app = Invoke-AzJson @(
        'webapp', 'show',
        '--resource-group', $ResourceGroup,
        '--name', $Name,
        '--output', 'json'
    ) -AllowFailure
    return $null -ne $app
}

function Get-ApimCollection([string]$ApimId, [string]$Collection) {
    $payload = Invoke-AzJson @(
        'rest', '--method', 'get',
        '--url', "https://management.azure.com$ApimId/${Collection}?api-version=2024-05-01",
        '--output', 'json'
    )
    return @($payload.value)
}

function Get-ApimPolicy([string]$ApimId, [string]$Path) {
    try {
        $token = & az account get-access-token `
            --resource 'https://management.azure.com/' `
            --query accessToken -o tsv
        if ($LASTEXITCODE -ne 0) {
            return ''
        }
        $response = Invoke-WebRequest `
            -UseBasicParsing `
            -Uri "https://management.azure.com$ApimId/$Path`?api-version=2024-05-01&format=rawxml" `
            -Headers @{
                Authorization = "Bearer $token"
                Accept = 'application/vnd.ms-azure-apim.policy.raw+xml'
            }
        return [string]$response.Content
    }
    catch {
        $statusCode = $null
        $responseProperty = $_.Exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
            $statusProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
            if ($null -ne $statusProperty) {
                $rawStatus = $statusProperty.Value
                $valueProperty = $rawStatus.PSObject.Properties['value__']
                $statusCode = if ($null -ne $valueProperty) {
                    [int]$valueProperty.Value
                } else {
                    [int]$rawStatus
                }
            }
        }
        if ($statusCode -eq 404 -or $_.Exception.Message -match '(?<!\d)404(?!\d)') {
            return ''
        }
        throw
    }
}

function Get-DeploymentResources(
    [string]$ResourceGroup,
    [string]$DeploymentName,
    [System.Collections.Generic.HashSet[string]]$Visited
) {
    $key = "$ResourceGroup/$DeploymentName"
    if (-not $Visited.Add($key)) {
        return @()
    }
    $operations = Invoke-AzJson @(
        'deployment', 'operation', 'group', 'list',
        '--resource-group', $ResourceGroup,
        '--name', $DeploymentName,
        '--output', 'json'
    ) -AllowFailure
    if ($null -eq $operations) {
        throw "Deployment record is unavailable: $key. A resource manifest cannot be captured safely."
    }

    $resources = [System.Collections.Generic.List[object]]::new()
    foreach ($operation in @($operations)) {
        $target = $operation.properties.targetResource
        if ($null -eq $target -or -not [string]$target.id) {
            continue
        }
        $targetId = [string]$target.id
        $targetType = [string]$target.resourceType
        if ($targetType -ieq 'Microsoft.Resources/deployments') {
            if ($targetId -notmatch '(?i)/resourceGroups/([^/]+)/providers/Microsoft\.Resources/deployments/([^/]+)$') {
                throw "Unexpected nested deployment resource ID: $targetId"
            }
            foreach ($resource in @(Get-DeploymentResources $Matches[1] $Matches[2] $Visited)) {
                $resources.Add($resource)
            }
            continue
        }
        $resources.Add([pscustomobject]@{
            id = $targetId
            name = [string]$target.resourceName
            type = $targetType
        })
    }
    return @($resources)
}

Require-Command 'az'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$parameterPath = (Resolve-Path $Parameters).Path
$parameterDocument = Read-JsonFile $parameterPath

$prefix = [string](Get-ParameterValue $parameterDocument 'resourcePrefix')
$platformResourceGroup = [string](Get-ParameterValue $parameterDocument 'resourceGroupName')
$storageResourceGroup = [string](Get-ParameterValue $parameterDocument 'storageResourceGroupName' $platformResourceGroup)
$storageAccountName = [string](Get-ParameterValue $parameterDocument 'storageAccountName')
$telemetryContainerName = [string](Get-ParameterValue $parameterDocument 'telemetryDeploymentContainerName' 'turnstile-telemetry-deploy')
$controlContainerName = [string](Get-ParameterValue $parameterDocument 'controlPlaneDeploymentContainerName' 'turnstile-control-deploy')
$ledgerTableName = [string](Get-ParameterValue $parameterDocument 'ledgerTableName' 'TurnstileLedger')
$apimName = [string](Get-ParameterValue $parameterDocument 'existingApimName')
$apimResourceGroup = [string](Get-ParameterValue $parameterDocument 'existingApimResourceGroupName')
$apiId = [string](Get-ParameterValue $parameterDocument 'apimApiId' "$prefix-llm")
$productId = [string](Get-ParameterValue $parameterDocument 'apimProductId' "$prefix-ai-consumers")
$dashboardSubscriptionId = [string](Get-ParameterValue $parameterDocument 'apimDashboardSubscriptionId' "$prefix-dashboard")
$probeSubscriptionId = [string](Get-ParameterValue $parameterDocument 'apimProbeSubscriptionId' "$prefix-publisher-probe")
$appInsightsLoggerId = [string](Get-ParameterValue $parameterDocument 'apimAppInsightsLoggerId' "$prefix-appinsights")
$eventHubLoggerId = [string](Get-ParameterValue $parameterDocument 'apimEventHubLoggerId' "$prefix-eventhub")
$diagnosticSettingName = [string](Get-ParameterValue $parameterDocument 'apimDiagnosticSettingName' "$prefix-gateway-logs")
$observerNamedValue = [string](Get-ParameterValue $parameterDocument 'observerAdapterKeyNamedValueName' "$prefix-observer-key")

if (-not $prefix -or -not $platformResourceGroup -or -not $storageAccountName -or -not $apimName -or -not $apimResourceGroup) {
    throw 'resourcePrefix, resourceGroupName, storageAccountName, existingApimName, and existingApimResourceGroupName are required.'
}

if (-not $Outputs) {
    $Outputs = Join-Path $repositoryRoot ".turnstile\deployments\$platformResourceGroup.outputs.json"
}
$outputPath = (Resolve-Path $Outputs).Path
$outputDocument = Read-JsonFile $outputPath
if (-not $Manifest) {
    $Manifest = $outputPath -replace '\.outputs\.json$', '.resources.json'
}
$manifestPath = [System.IO.Path]::GetFullPath($Manifest)
$parameterSha256 = (Get-FileHash -LiteralPath $parameterPath -Algorithm SHA256).Hash.ToLowerInvariant()
$outputSha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()

$outputContext = @{
    resourceGroupName = $platformResourceGroup
    storageResourceGroupName = $storageResourceGroup
    storageAccountName = $storageAccountName
    telemetryDeploymentContainerName = $telemetryContainerName
    controlPlaneDeploymentContainerName = $controlContainerName
    ledgerTableName = $ledgerTableName
    apimName = $apimName
    apimResourceGroupName = $apimResourceGroup
    apimApiId = $apiId
    apimProbeSubscriptionId = $probeSubscriptionId
    observerAdapterKeyNamedValueName = $observerNamedValue
}
foreach ($entry in $outputContext.GetEnumerator()) {
    $property = $outputDocument.PSObject.Properties[$entry.Key]
    if ($null -eq $property -or [string]$property.Value -cne [string]$entry.Value) {
        throw "Parameters and outputs identify different environments at $($entry.Key)."
    }
}

& az account show --only-show-errors --output none
if ($LASTEXITCODE -ne 0) {
    throw 'Azure CLI is not authenticated. Run az login first.'
}
& az account set --subscription $Subscription
if ($LASTEXITCODE -ne 0) {
    throw "Unable to select Azure subscription $Subscription"
}

$account = Invoke-AzJson @('account', 'show', '--query', '{subscription:id,tenant:tenantId,user:user.name}', '--output', 'json')
Write-Host "Azure account: $($account | ConvertTo-Json -Compress)"
Write-Host "Turnstile environment: prefix=$prefix platformRG=$platformResourceGroup sharedAPIM=$apimResourceGroup/$apimName"
Write-Host "Shared storage account: $storageResourceGroup/$storageAccountName"
Write-Host 'Protected boundaries: the resource group, shared storage account, APIM service, Foundry resources, shared azuremonitor logger, and unrelated APIM objects are never deleted.'

if (-not $CaptureManifest) {
    Invoke-RecordedCleanup `
        -ManifestPath $manifestPath `
        -OutputPath $outputPath `
        -ParameterSha256 $parameterSha256 `
        -OutputSha256 $outputSha256 `
        -Prefix $prefix `
        -PlatformResourceGroup $platformResourceGroup `
        -StorageResourceGroup $storageResourceGroup `
        -ApimResourceGroup $apimResourceGroup `
        -ApimName $apimName `
        -ApiId $apiId `
        -StorageAccountName $storageAccountName `
        -TelemetryContainerName $telemetryContainerName `
        -ControlContainerName $controlContainerName `
        -LedgerTableName $ledgerTableName `
        -ExecuteActions ([bool]$Execute) `
        -SkipConfirmation ([bool]$Force) `
        -DeleteLocalSecretState ([bool]$RemoveLocalSecretState)
    exit 0
}

if ($Execute) {
    throw '-CaptureManifest and -Execute cannot be used together.'
}

$apiName = [string]$outputDocument.apiName
$telemetryFunctionName = [string]$outputDocument.telemetryFunctionName
$controlPlaneFunctionName = [string]$outputDocument.controlPlaneFunctionName
$observerWebAppName = [string]$outputDocument.webAppName
$observerPlanName = [string]$outputDocument.observerAppServicePlanName
$observerAcrName = [string]$outputDocument.acrName
$observerToken = if ($observerWebAppName -like "obs-$prefix-*") {
    $observerWebAppName.Substring("obs-$prefix-".Length)
} else {
    ''
}

$apiPrincipal = Get-AppPrincipal $platformResourceGroup $apiName
$controlPrincipal = Get-AppPrincipal $platformResourceGroup $controlPlaneFunctionName

foreach ($appName in @($controlPlaneFunctionName, $telemetryFunctionName, $apiName, $observerWebAppName)) {
    if (Test-AppExists $platformResourceGroup $appName) {
        $kind = if ($appName -like 'func-*') { 'functionapp' } else { 'webapp' }
        Add-AzAction "Stop $kind $appName" @($kind, 'stop', '-g', $platformResourceGroup, '-n', $appName)
    }
}

$apim = Invoke-AzJson @('apim', 'show', '-g', $apimResourceGroup, '-n', $apimName, '--output', 'json')
$apimId = [string]$apim.id

$apimApis = @(Get-ApimCollection $apimId 'apis')
$apimProducts = @(Get-ApimCollection $apimId 'products')
$apimSubscriptions = @(Get-ApimCollection $apimId 'subscriptions')
$apimLoggers = @(Get-ApimCollection $apimId 'loggers')
$apimNamedValues = @(Get-ApimCollection $apimId 'namedValues')

foreach ($subscriptionId in @($dashboardSubscriptionId, $probeSubscriptionId)) {
    if ($apimSubscriptions.name -contains $subscriptionId) {
        Add-AzAction "Delete APIM subscription $subscriptionId" @(
            'rest', '--method', 'delete',
            '--url', "https://management.azure.com$apimId/subscriptions/$subscriptionId`?api-version=2024-05-01",
            '--headers', 'If-Match=*'
        )
    }
}

$productSubscriptionIds = @(
    & az rest --method get `
        --url "https://management.azure.com$apimId/products/$productId/subscriptions?api-version=2024-05-01" `
        --query 'value[].name' -o tsv
)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to list subscriptions for APIM product $productId"
}
foreach ($subscriptionId in $productSubscriptionIds) {
    $subscriptionId = [string]$subscriptionId
    if ($subscriptionId -in @($dashboardSubscriptionId, $probeSubscriptionId)) {
        continue
    }
    Add-AzAction "Delete APIM product subscription $subscriptionId" @(
        'rest', '--method', 'delete',
        '--url', "https://management.azure.com$apimId/subscriptions/$subscriptionId`?api-version=2024-05-01",
        '--headers', 'If-Match=*'
    )
}

$policyText = ''
$environmentApis = @(
    $apimApis | Where-Object {
        [string]$_.name -eq $apiId -or [string]$_.name -like "$apiId;rev=*"
    }
)
foreach ($environmentApi in $environmentApis) {
    $revisionApiId = [string]$environmentApi.name
    $policyText += "`n" + (Get-ApimPolicy $apimId "apis/$revisionApiId/policies/policy")
    $operationsPayload = Invoke-AzJson @(
        'rest', '--method', 'get',
        '--url', "https://management.azure.com$apimId/apis/$revisionApiId/operations?api-version=2024-05-01",
        '--output', 'json'
    ) -AllowFailure
    if ($null -ne $operationsPayload) {
        foreach ($operation in @($operationsPayload.value)) {
            $policyText += "`n" + (Get-ApimPolicy $apimId "apis/$revisionApiId/operations/$($operation.name)/policies/policy")
        }
    }
}

$referencedNamedValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($match in [regex]::Matches($policyText, '\{\{([^{}]+)\}\}')) {
    $null = $referencedNamedValues.Add($match.Groups[1].Value)
}
$null = $referencedNamedValues.Add($observerNamedValue)

$observerHost = if ($observerWebAppName) { "$observerWebAppName.azurewebsites.net" } else { '' }
$backendNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allBackends = @(Get-ApimCollection $apimId 'backends')
foreach ($match in [regex]::Matches($policyText, 'backend-id=(?:&quot;|")([^"&]+)')) {
    if ($allBackends.name -contains $match.Groups[1].Value) {
        $null = $backendNames.Add($match.Groups[1].Value)
    }
}
foreach ($backend in $allBackends) {
    $serialized = $backend | ConvertTo-Json -Depth 20 -Compress
    if (($observerHost -and $serialized -like "*$observerHost*") -or $serialized -like "*$prefix*") {
        $null = $backendNames.Add([string]$backend.name)
    }
}

$addedPoolMember = $true
while ($addedPoolMember) {
    $addedPoolMember = $false
    foreach ($backend in $allBackends | Where-Object { $backendNames.Contains([string]$_.name) }) {
        $poolProperty = $backend.properties.PSObject.Properties['pool']
        if ($null -eq $poolProperty) {
            continue
        }
        $servicesProperty = $poolProperty.Value.PSObject.Properties['services']
        if ($null -eq $servicesProperty) {
            continue
        }
        foreach ($service in @($servicesProperty.Value)) {
            $memberName = ([string]$service.id).Split('/')[-1]
            if ($memberName -and $allBackends.name -contains $memberName -and $backendNames.Add($memberName)) {
                $addedPoolMember = $true
            }
        }
    }
}
foreach ($backend in $allBackends | Where-Object { $backendNames.Contains([string]$_.name) }) {
    $serialized = $backend | ConvertTo-Json -Depth 20 -Compress
    foreach ($match in [regex]::Matches($serialized, '\{\{([^{}]+)\}\}')) {
        $null = $referencedNamedValues.Add($match.Groups[1].Value)
    }
}

$externalPolicyText = ''
foreach ($externalApi in @($apimApis | Where-Object { [string]$_.name -notlike "$apiId*" })) {
    $externalApiId = [string]$externalApi.name
    $externalPolicyText += "`n" + (Get-ApimPolicy $apimId "apis/$externalApiId/policies/policy")
    $externalOperations = Invoke-AzJson @(
        'rest', '--method', 'get',
        '--url', "https://management.azure.com$apimId/apis/$externalApiId/operations?api-version=2024-05-01",
        '--output', 'json'
    ) -AllowFailure
    if ($null -ne $externalOperations) {
        foreach ($operation in @($externalOperations.value)) {
            $externalPolicyText += "`n" + (Get-ApimPolicy $apimId "apis/$externalApiId/operations/$($operation.name)/policies/policy")
        }
    }
}
foreach ($backendName in $backendNames) {
    $backendPattern = 'backend-id=(?:&quot;|")({0})(?:&quot;|")' -f [regex]::Escape($backendName)
    if ($externalPolicyText -match $backendPattern) {
        throw "APIM backend $backendName is referenced by another API and cannot be recorded for cleanup."
    }
}
foreach ($namedValue in $referencedNamedValues) {
    $namedValuePattern = '\{\{' + [regex]::Escape($namedValue) + '\}\}'
    if ($externalPolicyText -match $namedValuePattern) {
        throw "APIM named value $namedValue is referenced by another API and cannot be recorded for cleanup."
    }
}

if ($apimApis.name -contains $apiId) {
    Add-AzAction "Delete APIM API $apiId and all revisions" @(
        'apim', 'api', 'delete', '-g', $apimResourceGroup, '-n', $apimName,
        '--api-id', $apiId, '--delete-revisions', 'true', '--if-match', '*', '-y'
    )
}
if ($apimProducts.name -contains $productId) {
    Add-AzAction "Delete APIM product $productId" @(
        'apim', 'product', 'delete', '-g', $apimResourceGroup, '-n', $apimName,
        '--product-id', $productId, '--delete-subscriptions', 'false', '-y'
    )
}
$diagnostics = Invoke-AzJson @(
    'monitor', 'diagnostic-settings', 'list', '--resource', $apimId, '--output', 'json'
)
if ($diagnostics.name -contains $diagnosticSettingName) {
    Add-AzAction "Delete APIM diagnostic setting $diagnosticSettingName" @(
        'monitor', 'diagnostic-settings', 'delete', '--resource', $apimId,
        '--name', $diagnosticSettingName
    )
}

foreach ($backendName in ($backendNames | Sort-Object)) {
    Add-AzAction "Delete APIM backend $backendName" @(
        'rest', '--method', 'delete',
        '--url', "https://management.azure.com$apimId/backends/$backendName`?api-version=2024-05-01",
        '--headers', 'If-Match=*'
    )
}
$ownedNamedValueNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($namedValue in ($referencedNamedValues | Sort-Object)) {
    $resource = $apimNamedValues | Where-Object { [string]$_.name -ieq $namedValue } | Select-Object -First 1
    $tags = @()
    if ($null -ne $resource) {
        $tagsProperty = $resource.properties.PSObject.Properties['tags']
        if ($null -ne $tagsProperty) {
            $tags = @($tagsProperty.Value)
        }
    }
    $ownedNamedValue = (
        $namedValue -ieq $observerNamedValue -or
        @($tags | Where-Object { [string]$_ -like 'turnstile_publication_*' }).Count -gt 0
    )
    if ($namedValue -eq 'azuremonitor' -or $null -eq $resource -or -not $ownedNamedValue) {
        continue
    }
    $null = $ownedNamedValueNames.Add($namedValue)
    Add-AzAction "Delete APIM named value $namedValue" @(
        'rest', '--method', 'delete',
        '--url', "https://management.azure.com$apimId/namedValues/$namedValue`?api-version=2024-05-01",
        '--headers', 'If-Match=*'
    )
}
foreach ($loggerName in @($appInsightsLoggerId, $eventHubLoggerId)) {
    if ($apimLoggers.name -notcontains $loggerName) {
        continue
    }
    Add-AzAction "Delete APIM logger $loggerName" @(
        'rest', '--method', 'delete',
        '--url', "https://management.azure.com$apimId/loggers/$loggerName`?api-version=2024-05-01",
        '--headers', 'If-Match=*'
    )
}

foreach ($principal in @($apiPrincipal, $controlPrincipal)) {
    if (-not $principal) {
        continue
    }
    $assignments = Invoke-AzJson @(
        'role', 'assignment', 'list', '--assignee-object-id', $principal, '--all', '--output', 'json'
    )
    foreach ($assignment in @($assignments)) {
        if ([string]$assignment.scope -ieq $apimId -and [string]$assignment.roleDefinitionName -like 'Turnstile APIM *') {
            Add-AzAction "Delete APIM role assignment $($assignment.roleDefinitionName) for $principal" @(
                'role', 'assignment', 'delete', '--ids', [string]$assignment.id
            )
        }
    }
}

$visitedDeployments = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$deploymentResources = @(
    Get-DeploymentResources $platformResourceGroup "$prefix-platform" $visitedDeployments
    Get-DeploymentResources $platformResourceGroup "$prefix-observer" $visitedDeployments
)
$platformIdPrefix = "/subscriptions/$Subscription/resourceGroups/$platformResourceGroup/providers/"
$deletableResourceTypes = @(
    'Microsoft.Web/sites',
    'Microsoft.Web/serverFarms',
    'Microsoft.ContainerRegistry/registries',
    'Microsoft.DBforPostgreSQL/flexibleServers',
    'Microsoft.EventHub/namespaces',
    'Microsoft.KeyVault/vaults',
    'Microsoft.Insights/components',
    'Microsoft.OperationalInsights/workspaces',
    'Microsoft.Network/virtualNetworks',
    'Microsoft.Network/privateEndpoints'
)
$ownedById = @{}
foreach ($resource in $deploymentResources) {
    $inPlatformGroup = [string]$resource.id -like "$platformIdPrefix*"
    if ($inPlatformGroup -and [string]$resource.type -in $deletableResourceTypes) {
        $ownedById[[string]$resource.id] = $resource
    }
}

$outputResourceSpecs = @(
    @{ output = 'postgresServerName'; type = 'Microsoft.DBforPostgreSQL/flexibleServers'; group = $platformResourceGroup },
    @{ output = 'eventHubNamespaceName'; type = 'Microsoft.EventHub/namespaces'; group = $platformResourceGroup },
    @{ output = 'applicationInsightsName'; type = 'Microsoft.Insights/components'; group = $platformResourceGroup },
    @{ output = 'appServicePlanName'; type = 'Microsoft.Web/serverFarms'; group = $platformResourceGroup },
    @{ output = 'telemetryFunctionPlanName'; type = 'Microsoft.Web/serverFarms'; group = $platformResourceGroup },
    @{ output = 'controlPlaneFunctionPlanName'; type = 'Microsoft.Web/serverFarms'; group = $platformResourceGroup },
    @{ output = 'apiName'; type = 'Microsoft.Web/sites'; group = $platformResourceGroup },
    @{ output = 'telemetryFunctionName'; type = 'Microsoft.Web/sites'; group = $platformResourceGroup },
    @{ output = 'controlPlaneFunctionName'; type = 'Microsoft.Web/sites'; group = $platformResourceGroup },
    @{ output = 'webAppName'; type = 'Microsoft.Web/sites'; group = $platformResourceGroup },
    @{ output = 'observerAppServicePlanName'; type = 'Microsoft.Web/serverFarms'; group = $platformResourceGroup },
    @{ output = 'acrName'; type = 'Microsoft.ContainerRegistry/registries'; group = $platformResourceGroup }
)
foreach ($spec in $outputResourceSpecs) {
    $property = $outputDocument.PSObject.Properties[[string]$spec.output]
    if ($null -eq $property -or -not [string]$property.Value) {
        continue
    }
    $resourceId = "/subscriptions/$Subscription/resourceGroups/$($spec.group)/providers/$($spec.type)/$($property.Value)"
    $resource = Invoke-AzJson @('resource', 'show', '--ids', $resourceId, '--output', 'json') -AllowFailure
    if ($null -eq $resource) {
        throw "Deployment output references a missing Azure resource: $resourceId"
    }
    $ownedById[$resourceId] = [pscustomobject]@{
        id = $resourceId
        name = [string]$property.Value
        type = [string]$spec.type
    }
}

$vnet = $ownedById.Values | Where-Object { [string]$_.type -ieq 'Microsoft.Network/virtualNetworks' } | Select-Object -First 1
if ($null -ne $vnet) {
    $vnetDetails = Invoke-AzJson @('resource', 'show', '--ids', [string]$vnet.id, '--output', 'json')
    foreach ($subnet in @($vnetDetails.properties.subnets)) {
        $nsgProperty = $subnet.properties.PSObject.Properties['networkSecurityGroup']
        if ($null -eq $nsgProperty -or -not [string]$nsgProperty.Value.id) {
            continue
        }
        $nsgId = [string]$nsgProperty.Value.id
        if ($nsgId -notlike "$platformIdPrefix*") {
            throw "Turnstile VNet references an NSG outside the platform resource group: $nsgId"
        }
        $nsg = Invoke-AzJson @('resource', 'show', '--ids', $nsgId, '--output', 'json')
        $ownedById[$nsgId] = [pscustomobject]@{
            id = $nsgId
            name = [string]$nsg.name
            type = 'Microsoft.Network/networkSecurityGroups'
        }
    }
}
$ownedResources = @($ownedById.Values)

$zones = @(
    'privatelink.blob.core.windows.net',
    'privatelink.queue.core.windows.net',
    'privatelink.table.core.windows.net',
    'privatelink.vaultcore.azure.net'
)
$dnsLinkIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($null -ne $vnet) {
    foreach ($zone in $zones) {
        $link = Invoke-AzJson @(
            'network', 'private-dns', 'link', 'vnet', 'show',
            '-g', $platformResourceGroup, '-z', $zone, '-n', 'finops-vnet', '--output', 'json'
        ) -AllowFailure
        if ($null -ne $link) {
            if ([string]$link.virtualNetwork.id -ine [string]$vnet.id) {
                throw "Private DNS link $zone/finops-vnet points to an unexpected VNet: $($link.virtualNetwork.id)"
            }
            $null = $dnsLinkIds.Add([string]$link.id)
            Add-AzAction "Delete private DNS link $zone/finops-vnet" @(
                'network', 'private-dns', 'link', 'vnet', 'delete',
                '-g', $platformResourceGroup, '-z', $zone, '-n', 'finops-vnet', '-y'
            )
        }
    }
}

$resourceDeletePriority = @{
    'Microsoft.Web/sites' = 10
    'Microsoft.Network/privateEndpoints' = 20
    'Microsoft.Web/serverFarms' = 30
    'Microsoft.ContainerRegistry/registries' = 40
    'Microsoft.DBforPostgreSQL/flexibleServers' = 50
    'Microsoft.EventHub/namespaces' = 50
    'Microsoft.KeyVault/vaults' = 50
    'Microsoft.Insights/components' = 50
    'Microsoft.OperationalInsights/workspaces' = 50
    'Microsoft.Network/virtualNetworks' = 60
    'Microsoft.Network/networkSecurityGroups' = 70
}
$ownedResources = $ownedResources | Sort-Object @{
    Expression = {
        $priority = $resourceDeletePriority[[string]$_.type]
        if ($null -eq $priority) { 55 } else { $priority }
    }
}, @{ Expression = { [string]$_.name } }

foreach ($resource in $ownedResources) {
    Add-AzAction "Delete Azure resource $($resource.type)/$($resource.name)" @(
        'resource', 'delete', '--ids', [string]$resource.id, '--only-show-errors'
    )
}

foreach ($containerName in @($telemetryContainerName, $controlContainerName)) {
    Add-AzAction "Delete shared storage container $containerName" @(
        'storage', 'container', 'delete',
        '--subscription', $Subscription,
        '--account-name', $storageAccountName,
        '--name', $containerName,
        '--auth-mode', 'login',
        '--only-show-errors'
    )
}
Add-AzAction "Delete shared storage table $ledgerTableName" @(
    'storage', 'table', 'delete',
    '--subscription', $Subscription,
    '--account-name', $storageAccountName,
    '--name', $ledgerTableName,
    '--auth-mode', 'login',
    '--only-show-errors'
)

$manifestOptions = [ordered]@{
    coreEnvironmentOnly = $true
}

if ($CaptureManifest) {
    $productApiLinks = @(Get-ApimCollection $apimId "products/$productId/apiLinks")
    $apimResourceIds = @(
        foreach ($environmentApi in $environmentApis) {
            [string]$environmentApi.id
        }
        if ($apimProducts.name -contains $productId) { "$apimId/products/$productId" }
        foreach ($apiLink in $productApiLinks) {
            [string]$apiLink.id
        }
        if ($diagnostics.name -contains $diagnosticSettingName) {
            "$apimId/providers/Microsoft.Insights/diagnosticSettings/$diagnosticSettingName"
        }
        foreach ($subscriptionId in $productSubscriptionIds) {
            "$apimId/subscriptions/$subscriptionId"
        }
        foreach ($backendName in $backendNames) {
            "$apimId/backends/$backendName"
        }
        foreach ($namedValue in $ownedNamedValueNames) {
            "$apimId/namedValues/$namedValue"
        }
        if ($apimLoggers.name -contains $appInsightsLoggerId) { "$apimId/loggers/$appInsightsLoggerId" }
        if ($apimLoggers.name -contains $eventHubLoggerId) { "$apimId/loggers/$eventHubLoggerId" }
    ) | Sort-Object -Unique
    $roleAssignmentIds = @(
        $actions |
            Where-Object { $_.Arguments[0] -eq 'role' -and $_.Arguments[1] -eq 'assignment' } |
            ForEach-Object {
                $idIndex = [Array]::IndexOf([string[]]$_.Arguments, '--ids')
                if ($idIndex -ge 0) { [string]$_.Arguments[$idIndex + 1] }
            }
    ) | Sort-Object -Unique
    $manifestDocument = [ordered]@{
        schemaVersion = 1
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        subscriptionId = $Subscription
        resourcePrefix = $prefix
        platformResourceGroup = $platformResourceGroup
        storageResourceGroup = $storageResourceGroup
        storageAccountName = $storageAccountName
        telemetryDeploymentContainerName = $telemetryContainerName
        controlPlaneDeploymentContainerName = $controlContainerName
        ledgerTableName = $ledgerTableName
        apimResourceGroup = $apimResourceGroup
        apimName = $apimName
        apimId = $apimId
        apiId = $apiId
        parametersSha256 = $parameterSha256
        outputsSha256 = $outputSha256
        protectedResources = @(
            "/subscriptions/$Subscription/resourceGroups/$platformResourceGroup",
            "/subscriptions/$Subscription/resourceGroups/$storageResourceGroup/providers/Microsoft.Storage/storageAccounts/$storageAccountName",
            $apimId,
            'Microsoft.CognitiveServices resources',
            "$apimId/loggers/azuremonitor"
        )
        resources = [ordered]@{
            azureResourceIds = @(
                @($ownedResources.id) + @($dnsLinkIds) | Sort-Object -Unique
            )
            apimResourceIds = $apimResourceIds
            roleAssignmentIds = $roleAssignmentIds
        }
        options = $manifestOptions
        actions = @(
            $actions | ForEach-Object {
                [ordered]@{
                    description = [string]$_.Description
                    arguments = @($_.Arguments | ForEach-Object { [string]$_ })
                }
            }
        )
    }
    $manifestDirectory = Split-Path $manifestPath -Parent
    New-Item -ItemType Directory -Path $manifestDirectory -Force | Out-Null
    $manifestDocument | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$manifestPath.sha256" -Value $manifestSha256 -Encoding ASCII
    Write-Host "Captured $($actions.Count) cleanup actions in $manifestPath"
    Write-Host "Manifest SHA256: $manifestSha256"
    Write-Host 'Review and retain this ignored file. Re-capture it after creating or publishing additional resources.' -ForegroundColor Yellow
    exit 0
}

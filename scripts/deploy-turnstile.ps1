<#
.SYNOPSIS
Plans or deploys a Turnstile environment through the supported Python orchestrator.

.EXAMPLE
.\scripts\deploy-turnstile.ps1 -Action plan -Subscription <subscription-id>

.EXAMPLE
.\scripts\deploy-turnstile.ps1 -Action deploy -Subscription <subscription-id>

.EXAMPLE
.\scripts\deploy-turnstile.ps1 -Action manifest -Subscription <subscription-id>
#>
[CmdletBinding()]
param(
    [ValidateSet('plan', 'deploy', 'manifest')]
    [string]$Action = 'plan',

    [Parameter(Mandatory)]
    [string]$Subscription,

    [string]$Parameters = (Join-Path $PSScriptRoot '..\.turnstile\main.parameters.json'),

    [string]$State,

    [string]$OwnerCredentials,

    [switch]$Yes,

    [switch]$AllowDirty,

    [switch]$SkipSync
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$adoptedSecretFields = @(
    'databaseUrl',
    'credentialEncryptionKey',
    'managementApiKey',
    'apimSubscriptionKey',
    'apimProbeSubscriptionKey'
)
$unsupportedAdoptedEnvironmentNames = @(
    'TURNSTILE_ADOPTED_DATABASE_URL',
    'TURNSTILE_ADOPTED_CREDENTIAL_ENCRYPTION_KEY',
    'TURNSTILE_ADOPTED_MANAGEMENT_API_KEY',
    'TURNSTILE_ADOPTED_APIM_SUBSCRIPTION_KEY',
    'TURNSTILE_ADOPTED_APIM_PROBE_SUBSCRIPTION_KEY'
)
$directSecretEnvironmentNames = [System.Collections.Generic.List[string]]::new()
foreach ($name in $unsupportedAdoptedEnvironmentNames) {
    $item = Get-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    if ($null -ne $item -and [string]$item.Value) {
        $directSecretEnvironmentNames.Add($name)
    }
}
if ($directSecretEnvironmentNames.Count) {
    throw 'Direct TURNSTILE_ADOPTED_* environment input is unsupported. Use the top-level adoptedSecrets object in the Parameters JSON.'
}

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $Name"
    }
}

function Protect-PrivateFile([string]$Path) {
    Require-Command 'icacls'
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls `
        $Path `
        '/inheritance:r' `
        '/grant:r' `
        "*$currentSid`:(F)" `
        '*S-1-5-18:(F)' `
        '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to secure private file ACL: $Path"
    }
}

Require-Command 'az'
if ($Action -ne 'manifest') {
    Require-Command 'uv'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$parameterPath = (Resolve-Path $Parameters).Path

$statePath = $null
if ($State) {
    $statePath = if ([System.IO.Path]::IsPathRooted($State)) {
        [System.IO.Path]::GetFullPath($State)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $State))
    }
}

$ownerCredentialPath = $null
if ($OwnerCredentials) {
    $ownerCredentialPath = (Resolve-Path $OwnerCredentials).Path
}

$parameterDocument = Get-Content -LiteralPath $parameterPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
$adoptedSecretsProperty = $parameterDocument.PSObject.Properties['adoptedSecrets']
if ($null -ne $adoptedSecretsProperty) {
    Protect-PrivateFile $parameterPath
    $adoptedSecretDocument = $adoptedSecretsProperty.Value
    if ($null -eq $adoptedSecretDocument -or $adoptedSecretDocument -isnot [pscustomobject]) {
        throw 'adoptedSecrets must contain one JSON object.'
    }
    $configuredNames = @($adoptedSecretDocument.PSObject.Properties.Name)
    $expectedNames = @($adoptedSecretFields)
    $missingNames = @($expectedNames | Where-Object { $_ -notin $configuredNames })
    $unexpectedNames = @($configuredNames | Where-Object { $_ -notin $expectedNames })
    if ($missingNames.Count -or $unexpectedNames.Count) {
        throw 'adoptedSecrets must contain exactly the five documented JSON keys.'
    }
    foreach ($field in $expectedNames) {
        $value = [string]$adoptedSecretDocument.PSObject.Properties[$field].Value
        if (-not $value) {
            throw "adoptedSecrets contains an empty value: $field"
        }
    }
}
$resourceGroup = [string]$parameterDocument.parameters.resourceGroupName.value
if (-not $resourceGroup) {
    throw 'resourceGroupName is required for deployment lifecycle operations.'
}
$existingKeyVault = $parameterDocument.parameters.PSObject.Properties['existingKeyVaultResourceId']
$existingKeyVaultResourceId = if ($null -eq $existingKeyVault) {
    ''
} else {
    [string]$existingKeyVault.Value.value
}
if ($null -ne $adoptedSecretsProperty -and -not $existingKeyVaultResourceId) {
    throw 'adoptedSecrets is valid only when adopting an existing Key Vault.'
}
if (
    $Action -ne 'manifest' -and
    $existingKeyVaultResourceId -and
    $null -eq $adoptedSecretsProperty
) {
    throw 'Adopted plan and deploy require the top-level adoptedSecrets object.'
}

Push-Location $repositoryRoot
try {
    & az account show --only-show-errors --output none
    if ($LASTEXITCODE -ne 0) {
        throw 'Azure CLI is not authenticated. Run az login first.'
    }

    & az account set --subscription $Subscription
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to select Azure subscription $Subscription"
    }

    $account = & az account show --query '{subscription:id,tenant:tenantId,user:user.name}' -o json
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read the selected Azure account.'
    }
    Write-Host "Azure target: $account"

    if ($Action -ne 'manifest' -and -not $SkipSync) {
        & uv sync --frozen
        if ($LASTEXITCODE -ne 0) {
            throw 'uv sync --frozen failed.'
        }
    }

    $outputsPath = if ($statePath) {
        Join-Path `
            (Split-Path $statePath -Parent) `
            "$([System.IO.Path]::GetFileNameWithoutExtension($statePath)).outputs.json"
    } else {
        Join-Path $repositoryRoot ".turnstile\deployments\$resourceGroup.outputs.json"
    }
    $captureScript = Join-Path $PSScriptRoot 'remove-turnstile.ps1'

    if ($Action -eq 'manifest') {
        & $captureScript `
            -Subscription $Subscription `
            -Parameters $parameterPath `
            -Outputs $outputsPath `
            -CaptureManifest
        if ($LASTEXITCODE -ne 0) {
            throw 'Resource manifest capture failed.'
        }
        return
    }

    $orchestratorArguments = @(
        '-m',
        'scripts.deploy',
        $Action,
        '--subscription',
        $Subscription,
        '--parameters',
        $parameterPath
    )

    if ($statePath) {
        $orchestratorArguments += @('--state', $statePath)
    }
    if ($ownerCredentialPath) {
        $orchestratorArguments += @('--owner-credentials', $ownerCredentialPath)
    }
    if ($Yes) {
        $orchestratorArguments += '--yes'
    }
    if ($AllowDirty) {
        $orchestratorArguments += '--allow-dirty'
    }

    Write-Host "Running Turnstile $Action from $repositoryRoot"
    & uv run python @orchestratorArguments
    $deployExitCode = $LASTEXITCODE
    if ($deployExitCode -ne 0) {
        throw "Turnstile $Action failed with exit code $deployExitCode"
    }

    if ($Action -eq 'deploy') {
        & $captureScript `
            -Subscription $Subscription `
            -Parameters $parameterPath `
            -Outputs $outputsPath `
            -CaptureManifest
        if ($LASTEXITCODE -ne 0) {
            throw 'Deployment succeeded, but resource manifest capture failed.'
        }
    }
}
finally {
    Pop-Location
}

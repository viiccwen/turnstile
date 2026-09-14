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

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $Name"
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
    $statePath = (Resolve-Path $State).Path
}

$ownerCredentialPath = $null
if ($OwnerCredentials) {
    $ownerCredentialPath = (Resolve-Path $OwnerCredentials).Path
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

    $parameterDocument = Get-Content -LiteralPath $parameterPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $resourceGroup = [string]$parameterDocument.parameters.resourceGroupName.value
    if (-not $resourceGroup) {
        throw 'resourceGroupName is required for deployment lifecycle operations.'
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

    $deployArguments = @(
        'run',
        'python',
        '-m',
        'scripts.deploy',
        $Action,
        '--subscription',
        $Subscription,
        '--parameters',
        $parameterPath
    )

    if ($statePath) {
        $deployArguments += @('--state', $statePath)
    }
    if ($ownerCredentialPath) {
        $deployArguments += @('--owner-credentials', $ownerCredentialPath)
    }
    if ($Yes) {
        $deployArguments += '--yes'
    }
    if ($AllowDirty) {
        $deployArguments += '--allow-dirty'
    }

    Write-Host "Running Turnstile $Action from $repositoryRoot"
    & uv @deployArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Turnstile $Action failed with exit code $LASTEXITCODE"
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

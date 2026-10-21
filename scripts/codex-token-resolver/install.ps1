[CmdletBinding()]
param(
    [string]$TenantId = 'b9bbf971-ad4d-4759-acf5-93dc3599c3f6',
    [string]$ClientId = '249631a0-836d-40a9-b32a-92c5240902c6',
    [string]$Audience = '7398a26d-832a-4a9d-889f-04b3c74218c4',
    [string]$Scope = '',
    [string]$GatewayBaseUrl = 'https://kurt-apim.azure-api.net/vicadopted/llm',
    [string]$Model = 'gpt-5.6-luna-foundry-6e35e30c',
    [string]$ProviderId = 'turnstile',
    [string]$ProviderName = 'Turnstile APIM',
    [string]$InstallRoot = (Join-Path $HOME '.codex\turnstile-auth'),
    [string]$ConfigPath = (Join-Path $HOME '.codex\config.toml'),
    [switch]$Login,
    [switch]$SkipDependencyInstall,
    [switch]$SkipPersistEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($value in @($TenantId, $ClientId, $Audience)) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($value, 'D', [ref]$parsed)) {
        throw "Expected a canonical UUID, received: $value"
    }
}
if ($ProviderId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
    throw 'ProviderId may contain only letters, numbers, underscores, and hyphens.'
}
$gatewayUri = $null
if (-not [uri]::TryCreate($GatewayBaseUrl, [UriKind]::Absolute, [ref]$gatewayUri) -or
    $gatewayUri.Scheme -ne 'https') {
    throw 'GatewayBaseUrl must be an absolute HTTPS URL.'
}
if (-not $Scope) {
    $Scope = "api://$Audience/Model.Invoke"
}

$node = Get-Command node -ErrorAction Stop
$npm = Get-Command npm -ErrorAction Stop
$sourceRoot = $PSScriptRoot
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
foreach ($name in @('token.cjs', 'run-resolver.ps1', 'package.json', 'package-lock.json')) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $InstallRoot $name) -Force
}
if (-not $SkipDependencyInstall) {
    & $npm.Source ci --omit=dev --no-audit --no-fund --prefix $InstallRoot
    if ($LASTEXITCODE -ne 0) { throw 'Token Resolver dependency installation failed.' }
}

$environment = [ordered]@{
    TURNSTILE_TENANT_ID = $TenantId
    TURNSTILE_CODEX_CLIENT_ID = $ClientId
    TURNSTILE_GATEWAY_AUDIENCE = $Audience
    TURNSTILE_GATEWAY_SCOPE = $Scope
}
foreach ($entry in $environment.GetEnumerator()) {
    Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
    if (-not $SkipPersistEnvironment) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'User')
    }
}

function ConvertTo-TomlString([string]$Value) {
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

$configDirectory = Split-Path -Parent $ConfigPath
New-Item -ItemType Directory -Force -Path $configDirectory | Out-Null
$config = if (Test-Path -LiteralPath $ConfigPath) {
    [IO.File]::ReadAllText($ConfigPath)
} else {
    ''
}
$firstTable = [regex]::Match($config, '(?m)^\[')
if ($firstTable.Success) {
    $topLevel = $config.Substring(0, $firstTable.Index)
    $tables = $config.Substring($firstTable.Index)
} else {
    $topLevel = $config
    $tables = ''
}
foreach ($setting in @(
    [pscustomobject]@{ Name = 'model'; Value = $Model },
    [pscustomobject]@{ Name = 'model_provider'; Value = $ProviderId }
)) {
    $line = "$($setting.Name) = $(ConvertTo-TomlString $setting.Value)"
    $pattern = "(?m)^$([regex]::Escape($setting.Name))\s*=.*$"
    if ([regex]::IsMatch($topLevel, $pattern)) {
        $topLevel = [regex]::Replace($topLevel, $pattern, $line, 1)
    } else {
        $topLevel = $line + [Environment]::NewLine + $topLevel
    }
}
$providerPattern = "(?ms)^\[model_providers\.$([regex]::Escape($ProviderId))\]\s*\r?\n.*?(?=^\[|\z)"
$authPattern = "(?ms)^\[model_providers\.$([regex]::Escape($ProviderId))\.auth\]\s*\r?\n.*?(?=^\[|\z)"
$tables = [regex]::Replace($tables, $authPattern, '')
$tables = [regex]::Replace($tables, $providerPattern, '')
$tokenPath = Join-Path $InstallRoot 'token.cjs'
$providerBlock = @"
[model_providers.$ProviderId]
name = $(ConvertTo-TomlString $ProviderName)
base_url = $(ConvertTo-TomlString $GatewayBaseUrl.TrimEnd('/'))
wire_api = "responses"

[model_providers.$ProviderId.auth]
command = $(ConvertTo-TomlString $node.Source)
args = [$(ConvertTo-TomlString $tokenPath)]
timeout_ms = 15000
refresh_interval_ms = 300000
"@
$newConfig = $topLevel.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine
if ($tables.Trim()) {
    $newConfig += $tables.Trim() + [Environment]::NewLine + [Environment]::NewLine
}
$newConfig += $providerBlock.Trim() + [Environment]::NewLine
[IO.File]::WriteAllText($ConfigPath, $newConfig, [Text.UTF8Encoding]::new($false))

Write-Output "Installed Token Resolver: $InstallRoot"
Write-Output "Updated Codex config: $ConfigPath"
Write-Output "Configured provider/model: $ProviderId / $Model"

if ($Login) {
    & $node.Source $tokenPath --login --check
    if ($LASTEXITCODE -ne 0) { throw 'Turnstile sign-in failed.' }
} else {
    Write-Output 'Next: run install.ps1 -Login, or run token.cjs --login --check.'
}

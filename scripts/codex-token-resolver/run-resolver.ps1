$ErrorActionPreference = 'Stop'
node (Join-Path $PSScriptRoot 'token.cjs') @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

ROOT = Path(__file__).parents[3]
DEPLOY = (ROOT / "scripts" / "deploy-turnstile.ps1").read_text(encoding="utf-8")
REMOVE = (ROOT / "scripts" / "remove-turnstile.ps1").read_text(encoding="utf-8")


def test_deploy_script_uses_supported_orchestrator() -> None:
    assert "'scripts.deploy'" in DEPLOY
    assert "'plan', 'deploy', 'manifest'" in DEPLOY
    assert "& uv sync --frozen" in DEPLOY
    assert "--allow-dirty" in DEPLOY
    assert "-CaptureManifest" in DEPLOY
    assert "if ($Action -eq 'manifest')" in DEPLOY
    assert "[System.IO.Path]::IsPathRooted($State)" in DEPLOY
    assert "[System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $State))" in DEPLOY
    for name in (
        "TURNSTILE_ADOPTED_DATABASE_URL",
        "TURNSTILE_ADOPTED_CREDENTIAL_ENCRYPTION_KEY",
        "TURNSTILE_ADOPTED_MANAGEMENT_API_KEY",
        "TURNSTILE_ADOPTED_APIM_SUBSCRIPTION_KEY",
        "TURNSTILE_ADOPTED_APIM_PROBE_SUBSCRIPTION_KEY",
    ):
        assert name in DEPLOY
    assert "Direct TURNSTILE_ADOPTED_* environment input is unsupported" in DEPLOY
    assert "adoptedSecrets is valid only when adopting" in DEPLOY
    assert "require the top-level adoptedSecrets object" in DEPLOY
    assert "Protect-PrivateFile $parameterPath" in DEPLOY
    assert "adoptedSecrets must contain one JSON object" in DEPLOY
    assert "adoptedSecrets must contain exactly the five documented JSON keys" in DEPLOY
    assert "adoptedSecrets contains an empty value" in DEPLOY
    for field in (
        "databaseUrl",
        "credentialEncryptionKey",
        "managementApiKey",
        "apimSubscriptionKey",
        "apimProbeSubscriptionKey",
    ):
        assert field in DEPLOY
    assert DEPLOY.index(
        "Direct TURNSTILE_ADOPTED_* environment input is unsupported"
    ) < DEPLOY.index("& az account show")
    assert DEPLOY.index("Protect-PrivateFile $parameterPath") < DEPLOY.index(
        "& az account show"
    )
    assert "& uv run python @orchestratorArguments" in DEPLOY


def test_remove_script_is_dry_run_by_default() -> None:
    assert "if (-not $ExecuteActions)" in REMOVE
    assert "Dry run only" in REMOVE
    assert 'Read-Host "Type \'approve\' to continue"' in REMOVE
    assert "if ($confirmation -cne 'approve')" in REMOVE
    assert "if (-not $SkipConfirmation)" in REMOVE
    assert "if (Test-AppExists $platformResourceGroup $appName)" in REMOVE
    assert "Resource manifest hash mismatch" in REMOVE
    assert '"$ManifestPath.sha256"' in REMOVE
    assert "parametersSha256" in REMOVE
    assert "outputsSha256" in REMOVE
    assert "Parameters and outputs identify different environments" in REMOVE
    assert "$ErrorActionPreference = 'Continue'" in REMOVE
    assert "$exitCode = $LASTEXITCODE" in REMOVE


def test_remove_script_preserves_shared_boundaries() -> None:
    lowered = REMOVE.lower()
    assert "az group delete" not in lowered
    assert "'group', 'delete'" not in lowered
    assert "'apim', 'delete'" not in lowered
    assert "microsoft.cognitiveservices" in lowered
    assert "azuremonitor" in lowered
    assert "protected boundaries" in lowered
    assert "removeentraapps" not in lowered
    assert "removesharedfoundryrole" not in lowered
    assert "removeprivatednszones" not in lowered


def test_remove_script_deletes_only_environment_apim_children() -> None:
    assert "--delete-revisions" in REMOVE
    assert "$dashboardSubscriptionId" in REMOVE
    assert "$probeSubscriptionId" in REMOVE
    assert "$productId" in REMOVE
    assert "$diagnosticSettingName" in REMOVE
    assert "$observerNamedValue" in REMOVE
    assert "Turnstile APIM *" in REMOVE
    assert "--delete-subscriptions', 'false'" in REMOVE
    assert "products/$productId/subscriptions" in REMOVE
    assert "Delete APIM product subscription" in REMOVE
    assert "'apim', 'subscription', 'delete'" not in REMOVE
    assert 'subscriptions/$subscriptionId`?api-version=2024-05-01' in REMOVE
    product_subscription_lookup = REMOVE.split(
        "$productSubscriptionIds = @()", 1
    )[1].split("foreach ($subscriptionId in $productSubscriptionIds)", 1)[0]
    assert "if ($apimProducts.name -contains $productId)" in product_subscription_lookup


def test_remove_script_records_exact_saved_output_resources() -> None:
    ownership = REMOVE.split("$platformIdPrefix", 1)[1].split("$vnet =", 1)[0]
    assert "Get-DeploymentResources" not in ownership
    assert "$outputResourceSpecs" in ownership
    assert "$dependencyResourceSpecs" in ownership
    for field in (
        "virtualNetworkResourceId",
        "workspaceResourceId",
        "privateEndpointId",
    ):
        assert field in ownership
    assert "Get-DependencyValue" in ownership
    assert '$name -like "*$prefix*"' not in REMOVE
    assert "Get-AppStorageAccountNames" not in REMOVE
    assert "Invoke-RecordedCleanup" in REMOVE
    assert "if (-not $CaptureManifest)" in REMOVE
    assert "azureResourceIds" in REMOVE
    assert "apimResourceIds" in REMOVE
    assert "roleAssignmentIds" in REMOVE
    assert "managedRoleAssignmentIds" in REMOVE
    assert "Delete deployment-managed role assignment" in REMOVE
    assert "Get-ManagedRoleAssignmentName" in REMOVE
    assert "Deployment output contains an unexpected managed role assignment" in REMOVE
    assert "$ApprovedAppServiceNames" in REMOVE
    assert "$arguments[$nameIndex + 1] -notin $ApprovedAppServiceNames" in REMOVE
    assert "'observerAppServicePlanName'" in REMOVE
    assert "Legacy outputs predate dependencyResources" in REMOVE
    assert "virtualNetworkSubnetId" in REMOVE
    assert "WorkspaceResourceId" in REMOVE
    assert "APIM_PROBE_SUBSCRIPTION_KEY" in REMOVE
    assert "privateEndpointConnections" in REMOVE
    assert "never infer ownership from a broad name search" in REMOVE
    app_service_guard = REMOVE.split(
        "if ($signature -in @('functionapp delete', 'webapp delete', 'appservice plan'))",
        1,
    )[1].split("if ($signature -like 'apim *')", 1)[0]
    assert '$arguments[$nameIndex + 1] -notlike "*$Prefix*"' not in app_service_guard


def test_remove_script_orders_dependent_resources() -> None:
    assert "'Microsoft.Web/sites' = 10" in REMOVE
    assert "'Microsoft.Network/privateEndpoints' = 20" in REMOVE
    assert "'Microsoft.Network/virtualNetworks' = 60" in REMOVE
    assert "'Microsoft.Network/networkSecurityGroups' = 70" in REMOVE
    assert "'network', 'private-endpoint', 'delete'" in REMOVE
    assert "'network', 'nsg', 'delete'" in REMOVE
    assert "$siteCommand, 'delete'" in REMOVE
    assert "'appservice', 'plan', 'delete'" in REMOVE


def test_remove_manifest_rejects_shared_and_unapproved_actions() -> None:
    assert "Manifest product deletion must not use subscription cascade" in REMOVE
    assert "Manifest resource type is not approved for cleanup" in REMOVE
    assert "Manifest REST action is not an approved APIM child deletion" in REMOVE
    assert "Manifest RBAC action is outside the approved resource scopes" in REMOVE
    assert "$assignmentId -in $ManagedRoleAssignmentIds" in REMOVE
    assert "$expectedManagedRoleAssignmentIds.Contains($assignmentId)" in REMOVE
    assert "eventHubReceiverRoleId" in REMOVE
    assert "logAnalyticsReaderRoleId" in REMOVE
    assert "keyVaultSecretsUserRoleId" in REMOVE
    assert "Manifest must not delete a private DNS zone" in REMOVE
    assert "is referenced by another API and cannot be recorded" in REMOVE
    assert "coreEnvironmentOnly" in REMOVE
    assert "RemoveEntraApps" not in REMOVE
    assert "RemoveSharedFoundryRole" not in REMOVE
    assert "adoptedResourceIds" in REMOVE
    assert "privateDnsLinkProvisioned" in REMOVE
    assert "Manifest network action targets an unexpected resource" in REMOVE
    assert "Manifest App Service action targets an unexpected resource" in REMOVE
    assert REMOVE.count(
        "$action $PlatformResourceGroup $Prefix $StorageResourceGroup $apimId"
    ) == 1
    assert REMOVE.count(
        "$action $platformResourceGroup $prefix $storageResourceGroup $apimId"
    ) == 1


def test_remove_script_retries_read_only_azure_queries() -> None:
    invoke = REMOVE.split("function Invoke-AzJson", 1)[1].split("$actions =", 1)[0]
    assert "foreach ($attempt in 1..3)" in invoke
    assert "if ($exitCode -eq 0)" in invoke


def test_remove_manifest_deletes_only_shared_storage_children() -> None:
    assert "storageResourceGroupName" in REMOVE
    assert "Manifest resource is outside the platform resource group" in REMOVE
    assert "'storage', 'container', 'delete'" in REMOVE
    assert "'storage', 'table', 'delete'" in REMOVE
    assert "Manifest storage action targets an unexpected account" in REMOVE
    assert "Manifest storage action targets an unexpected child" in REMOVE
    assert "providers/Microsoft.Storage/storageAccounts/$storageAccountName" in REMOVE
    assert "'Microsoft.Storage/storageAccounts' = 50" not in REMOVE


def _powershell_json(code: str):
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        pytest.skip("PowerShell is required for offline cleanup contract tests")
    path = str(ROOT / "scripts/remove-turnstile.ps1").replace("'", "''")
    # Load definitions through the parser, never the Azure-calling entry point.
    bootstrap = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) {{ throw ($parseErrors | Out-String) }}
foreach ($statement in $ast.EndBlock.Statements) {{
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {{
        Invoke-Expression $statement.Extent.Text
    }}
}}
function az {{ throw 'Offline test must never invoke Azure CLI' }}
$actions = [System.Collections.Generic.List[object]]::new()
"""
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", bootstrap + code],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def _ps_json(value: object) -> str:
    return "('" + json.dumps(value).replace("'", "''") + "' | ConvertFrom-Json)"


@pytest.mark.parametrize("arm_names", [False, True])
def test_remove_accepts_exact_legacy_and_arm_shared_dependency_grants(arm_names: bool) -> None:
    storage = "/subscriptions/sub/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/shared"
    ledger = storage + "/tableServices/default/tables/TurnstileLedger"
    route = storage + "/tableServices/default/tables/ModelRoutes"
    vault = "/subscriptions/sub/resourceGroups/platform/providers/Microsoft.KeyVault/vaults/credentials"
    site_prefix = "/subscriptions/sub/resourceGroups/platform/providers/Microsoft.Web/sites/"
    blob_owner = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
    contributor = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
    reader = "76199698-9eea-4c19-bc75-cec21354c6b6"
    rbac = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
    requirements = [
        (storage, "telemetry", blob_owner, "storage-blob-data-owner"),
        (storage, "control", blob_owner, "storage-blob-data-owner"),
        (ledger, "telemetry", contributor, "table-data-contributor"),
        (ledger, "api", contributor, "table-data-contributor"),
        (ledger, "control", contributor, "application-provisioning-table-contributor"),
        (ledger, "apim", contributor, "table-data-contributor"),
        (route, "api", reader, "route-table-reader"),
        (route, "apim", reader, "route-table-reader"),
        (route, "control", contributor, "route-table-contributor"),
        (vault, "apim", "4633458b-17de-408a-b874-0445c86b69e6", "route-credential-reader"),
        (vault, "control", "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", "route-credential-writer"),
    ]
    for principal, prefix in (("api", "apim"), ("control", "onboarding")):
        for scope, table in ((ledger, "ledger"), (route, "route")):
            requirements.append((scope, principal, rbac, f"{prefix}-{table}-rbac-delegator"))
    expected = []
    for scope, principal, role, label in requirements:
        if arm_names:
            identity = principal if principal == "apim" else site_prefix + principal
            name = str(uuid.uuid5(
                uuid.UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830"),
                "-".join((scope, identity, label)),
            ))
        else:
            digest = hashlib.sha256(f"turnstile|{scope.lower()}|{principal}|{role}".encode()).hexdigest()
            name = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        expected.append(f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}")
    foundry = (
        "/subscriptions/sub/resourceGroups/customer/providers/"
        "Microsoft.CognitiveServices/accounts/foundry"
    )
    for principal, role in (
        ("apim", "a97b65f3-24c7-4388-baec-2e87135dc908"),
        ("control", "b59867f0-fa02-499b-be73-45a86b5b3e1c"),
    ):
        digest = hashlib.sha256(
            f"turnstile|{foundry.lower()}|{principal}|{role}".encode()
        ).hexdigest()
        name = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        expected.append(f"{foundry}/providers/Microsoft.Authorization/roleAssignments/{name}")
    outputs = {
        "telemetryPrincipalId": "telemetry", "controlPlanePrincipalId": "control",
        "apiPrincipalId": "api", "apimPrincipalId": "apim",
        "telemetryFunctionName": "telemetry", "controlPlaneFunctionName": "control",
        "apiName": "api", "dependencyResources": {"credentialVault": {"resourceId": vault}},
    }
    block = REMOVE.split("if ($managedRoleAssignmentIds.Count -gt 0) {", 1)[1].split(
        "$adoptedResourceIds =", 1
    )[0]
    # Restore the opening condition removed by split; execute exactly the production block.
    setup = f"""
$Subscription = 'sub'; $platformResourceGroup = 'platform'; $storageResourceGroup = 'storage'
$storageAccountName = 'shared'; $ledgerTableName = 'TurnstileLedger'
$foundryResourceId = '{foundry}'
$outputDocument = {_ps_json(outputs)}
$managedRoleAssignmentIds = @({_ps_json(expected)})
"""
    result = _powershell_json(setup + "if ($managedRoleAssignmentIds.Count -gt 0) {" + block + """
$accepted = @($actions | ForEach-Object { $_.Arguments[-1] })
$managedRoleAssignmentIds = @('""" + route + """/providers/Microsoft.Authorization/roleAssignments/unrelated')
$rejected = $false
try {
""" + "if ($managedRoleAssignmentIds.Count -gt 0) {" + block + """
} catch { $rejected = $_.Exception.Message -like '*unexpected managed role assignment*' }
@{ accepted = $accepted; rejected = $rejected } | ConvertTo-Json -Depth 10 -Compress
""")
    assert set(result["accepted"]) == set(expected)
    assert result["rejected"] is True


@pytest.mark.parametrize("provisioned", [False, True])
def test_remove_credential_vault_inventory_respects_dependency_ownership(provisioned: bool) -> None:
    prefix = "/subscriptions/sub/resourceGroups/platform/providers/"
    config_vault = prefix + "Microsoft.KeyVault/vaults/adopted"
    vault = prefix + "Microsoft.KeyVault/vaults/credentials"
    endpoint = prefix + "Microsoft.Network/privateEndpoints/pe-credentials"
    outputs = {"dependencyResources": {
        "keyVault": {"resourceId": config_vault, "provisioned": False},
        "credentialVault": {"resourceId": vault, "privateEndpointId": endpoint, "provisioned": provisioned},
    }}
    block = "$adoptedResourceIds =" + REMOVE.split("$adoptedResourceIds =", 1)[1].split("$vnet =", 1)[0]
    result = _powershell_json(f"""
$Subscription = 'sub'; $platformResourceGroup = 'platform'
$outputDocument = {_ps_json(outputs)}
function Invoke-AzJson([string[]]$Arguments, [switch]$AllowFailure) {{
    [pscustomobject]@{{ name = $Arguments[3].Split('/')[-1] }}
}}
""" + block + """
@{ owned = @($ownedById.Keys); adopted = @($adoptedResourceIds) } | ConvertTo-Json -Compress
""")
    assert config_vault in result["adopted"]
    assert config_vault not in result["owned"]
    assert set(result["owned"]) == ({vault, endpoint} if provisioned else set())
    if not provisioned:
        assert {vault, endpoint} <= set(result["adopted"])


@pytest.mark.parametrize("owned", [False, True])
def test_remove_shared_children_require_creation_evidence_in_capture_and_replay(owned: bool) -> None:
    storage = "/subscriptions/sub/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/shared"
    children = [
        storage + "/blobServices/default/containers/telemetry",
        storage + "/blobServices/default/containers/control",
        storage + "/tableServices/default/tables/TurnstileLedger",
        storage + "/tableServices/default/tables/ModelRoutes",
    ]
    block = "foreach ($containerName in @($telemetryContainerName, $controlContainerName)) {" + REMOVE.split(
        "foreach ($containerName in @($telemetryContainerName, $controlContainerName)) {", 1
    )[1].split("$manifestOptions =", 1)[0]
    result = _powershell_json(f"""
$Subscription = 'sub'; $storageResourceGroup = 'storage'; $storageAccountName = 'shared'
$telemetryContainerName = 'telemetry'; $controlContainerName = 'control'; $ledgerTableName = 'TurnstileLedger'
$managedStorageChildResourceIds = @({_ps_json(children if owned else [])})
""" + block + """
foreach ($action in $actions) {
    Assert-ManifestAction $action 'platform' 'env' 'storage' '/apim' 'shared' 'telemetry' 'control' 'TurnstileLedger' @()
}
$rejected = $false
$managedStorageChildResourceIds = @()
try {
    Assert-ManifestAction ([pscustomobject]@{
        Description = 'old manifest'; Arguments = @('storage', 'table', 'delete', '--account-name', 'shared', '--name', 'ModelRoutes', '--auth-mode', 'login')
    }) 'platform' 'env' 'storage' '/apim' 'shared' 'telemetry' 'control' 'TurnstileLedger' @()
} catch { $rejected = $_.Exception.Message -like '*ownership evidence*' }
@{ names = @($actions | ForEach-Object {
    $index = [Array]::IndexOf([string[]]$_.Arguments, '--name'); $_.Arguments[$index + 1]
}); rejected = $rejected } | ConvertTo-Json -Compress
""")
    assert set(result["names"]) == ({"telemetry", "control", "TurnstileLedger", "ModelRoutes"} if owned else set())
    assert result["rejected"] is True


@pytest.mark.parametrize("config_owns_link", [False, True])
def test_remove_credential_dns_links_use_exact_ids_and_deduplicate(config_owns_link: bool) -> None:
    prefix = "/subscriptions/sub/resourceGroups/platform/providers/"
    vnet = prefix + "Microsoft.Network/virtualNetworks/adopted"
    link = prefix + "Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net/virtualNetworkLinks/env-vnet"
    outputs = {"dependencyResources": {
        "network": {"virtualNetworkResourceId": vnet, "provisioned": False},
        "keyVault": {"privateDnsLinkProvisioned": config_owns_link, "privateDnsLinkId": link},
        "credentialVault": {"privateDnsLinkProvisioned": True, "privateDnsLinkId": link},
    }}
    block = "$zones = @(" + REMOVE.split("$zones = @(", 1)[1].split("$resourceDeletePriority =", 1)[0]
    result = _powershell_json(f"""
$platformIdPrefix = '{prefix}'; $platformResourceGroup = 'platform'; $vnet = $null
$outputDocument = {_ps_json(outputs)}
function Invoke-AzJson([string[]]$Arguments, [switch]$AllowFailure) {{
    [pscustomobject]@{{ id = '{link}'; virtualNetwork = [pscustomobject]@{{ id = '{vnet}' }} }}
}}
""" + block + """
@{ count = $actions.Count; ids = @($dnsLinkIds); args = @($actions[0].Arguments) } | ConvertTo-Json -Compress
""")
    assert result["count"] == 1
    assert result["ids"] == [link]
    assert "env-vnet" in result["args"]


@pytest.mark.parametrize("command", ["webapp", "functionapp", "appservice"])
def test_remove_custom_app_service_names_require_exact_saved_outputs(command: str) -> None:
    outputs = {"apiName": "custom-api", "observerAppServicePlanName": "custom-plan"}
    block = "$approvedAppServiceNames = @(" + REMOVE.split(
        "$approvedAppServiceNames = @(", 1
    )[1].split("if (-not $Manifest)", 1)[0]
    name = "custom-plan" if command == "appservice" else "custom-api"
    arguments = [command, "plan", "delete"] if command == "appservice" else [command, "delete"]
    arguments += ["--resource-group", "platform", "--name", name, "--yes"]
    result = _powershell_json(f"""
$Subscription = 'sub'; $managedStorageChildResourceIds = @()
$outputDocument = {_ps_json(outputs)}
""" + block + f"""
$action = [pscustomobject]@{{ Description = 'custom deployment'; Arguments = @({_ps_json(arguments)}) }}
Assert-ManifestAction $action 'platform' 'env' 'storage' '/apim' 'shared' 'telemetry' 'control' 'Ledger' @() $approvedAppServiceNames
$action.Arguments[[Array]::IndexOf([string[]]$action.Arguments, '--name') + 1] = 'unrelated-env-app'
$rejected = $false
try {{
    Assert-ManifestAction $action 'platform' 'env' 'storage' '/apim' 'shared' 'telemetry' 'control' 'Ledger' @() $approvedAppServiceNames
}} catch {{ $rejected = $_.Exception.Message -like '*unexpected resource*' }}
@{{ approved = @($approvedAppServiceNames); rejected = $rejected }} | ConvertTo-Json -Compress
""")
    assert set(result["approved"]) == set(outputs.values())
    assert result["rejected"] is True


@pytest.mark.parametrize("provisioned,subscription,group,resource_type", [
    (False, "sub", "platform", "privateEndpoints"),
    (True, "sub", "platform", "privateEndpoints"),
    ("false", "sub", "platform", "privateEndpoints"),
    ([True], "sub", "platform", "privateEndpoints"),
    (None, "sub", "platform", "privateEndpoints"),
    (True, "other", "platform", "privateEndpoints"),
    (True, "sub", "other", "privateEndpoints"),
    (True, "sub", "platform", "networkSecurityGroups"),
])
def test_remove_shortened_vault_endpoint_requires_exact_managed_output(
    provisioned: object, subscription: str, group: str, resource_type: str,
) -> None:
    endpoint = (
        f"/subscriptions/{subscription}/resourceGroups/{group}/providers/"
        f"Microsoft.Network/{resource_type}/pe-kv-victurnstil-rt-abcdef-vault"
    )
    outputs = {"dependencyResources": {"credentialVault": {
        "provisioned": provisioned, "privateEndpointId": endpoint,
    }}}
    block = "$approvedPrivateEndpointIds = @(" + REMOVE.split(
        "$approvedPrivateEndpointIds = @(", 1
    )[1].split("$approvedAppServiceNames = @(", 1)[0]
    result = _powershell_json(f"""
$Subscription = 'sub'; $platformResourceGroup = 'platform'
$outputDocument = {_ps_json(outputs)}
""" + block + """
$accepted = @(); $rejected = @()
foreach ($name in @('pe-kv-victurnstil-rt-abcdef-vault', 'pe-unrelated')) {
    $action = [pscustomobject]@{
        Description = 'private endpoint'; Arguments = @(
            'network', 'private-endpoint', 'delete', '--resource-group', 'platform', '--name', $name
        )
    }
    try {
        Assert-ManifestAction `
            $action 'platform' 'victurnstile' 'storage' '/apim' `
            'shared' 'telemetry' 'control' 'Ledger' @() @() $approvedPrivateEndpointIds
        $accepted += $name
    } catch { $rejected += $name }
}
@{ accepted = @($accepted); rejected = @($rejected) } | ConvertTo-Json -Compress
""")
    name = endpoint.rsplit("/", 1)[-1]
    approved = (
        provisioned is True and subscription == "sub" and group == "platform"
        and resource_type == "privateEndpoints"
    )
    assert result["accepted"] == ([name] if approved else [])
    assert set(result["rejected"]) == ({"pe-unrelated"} if approved else {name, "pe-unrelated"})


@pytest.mark.parametrize("present", [False, True])
def test_remove_product_subscription_lookup_skips_absent_product(present: bool) -> None:
    block = "$productSubscriptionIds = @()" + REMOVE.split(
        "$productSubscriptionIds = @()", 1
    )[1].split("$policyText = ''", 1)[0]
    result = _powershell_json(f"""
$apimProducts = @([pscustomobject]@{{ name = '{"custom-product" if present else "other"}' }})
$productId = 'custom-product'; $apimId = '/apim'
$dashboardSubscriptionId = 'dashboard'; $probeSubscriptionId = 'probe'
$script:queries = 0
function az {{ $script:queries++; $global:LASTEXITCODE = 0; 'consumer' }}
""" + block + """
@{ queries = $script:queries; actions = $actions.Count } | ConvertTo-Json -Compress
""")
    assert result == {"queries": int(present), "actions": int(present)}
    api_links = REMOVE.split("$productApiLinks = @()", 1)[1].split("$apimResourceIds =", 1)[0]
    assert "if ($apimProducts.name -contains $productId)" in api_links


@pytest.mark.parametrize("outside", [None, "vnet", "workspace", "endpoint"])
def test_remove_legacy_dependency_discovery_uses_exact_linked_resources(outside: str | None) -> None:
    prefix = "/subscriptions/sub/resourceGroups/platform/providers/"
    other = "/subscriptions/sub/resourceGroups/unrelated/providers/"
    vnet = (other if outside == "vnet" else prefix) + "Microsoft.Network/virtualNetworks/custom"
    workspace = (other if outside == "workspace" else prefix) + "Microsoft.OperationalInsights/workspaces/custom"
    endpoint = (other if outside == "endpoint" else prefix) + "Microsoft.Network/privateEndpoints/custom"
    vault = prefix + "Microsoft.KeyVault/vaults/custom-vault"
    api = prefix + "Microsoft.Web/sites/custom-api"
    insights = prefix + "Microsoft.Insights/components/custom-insights"
    resources = {
        api: {"properties": {"virtualNetworkSubnetId": vnet + "/subnets/api"}},
        insights: {"properties": {"WorkspaceResourceId": workspace}},
        vault: {"properties": {"privateEndpointConnections": [
            {"properties": {"privateEndpoint": {"id": endpoint}}},
        ]}},
        vnet: {"name": "custom"}, workspace: {"name": "custom"}, endpoint: {"name": "custom"},
    }
    outputs = {"apiName": "custom-api", "applicationInsightsName": "custom-insights", "controlPlaneFunctionName": "custom-control"}
    block = "$dependencyMetadata = Get-ObjectValue" + REMOVE.split(
        "$dependencyMetadata = Get-ObjectValue", 1
    )[1].split("$dependencyResourceSpecs =", 1)[0]
    result = _powershell_json(f"""
$Subscription = 'sub'; $platformResourceGroup = 'platform'; $platformIdPrefix = '{prefix}'
$outputDocument = {_ps_json(outputs)}; $resources = {_ps_json(resources)}; $ownedById = @{{}}
function Invoke-AzJson([string[]]$Arguments, [switch]$AllowFailure) {{
    if ($Arguments[0] -eq 'rest') {{
        return [pscustomobject]@{{ probe = '@Microsoft.KeyVault(SecretUri=https://custom-vault.vault.azure.net/secrets/probe)' }}
    }}
    $id = $Arguments[[Array]::IndexOf($Arguments, '--ids') + 1]
    $resource = Get-ObjectValue $resources $id
    if ($null -eq $resource) {{ throw "Unexpected lookup: $id" }}
    return $resource
}}
$rejected = $false
try {{
""" + block + """
} catch { $rejected = $_.Exception.Message -like '*outside the platform resource group*' }
@{ owned = @($ownedById.Keys); rejected = $rejected } | ConvertTo-Json -Compress
""")
    assert result["rejected"] is (outside is not None)
    if outside is None:
        assert set(result["owned"]) == {vnet, workspace, vault, endpoint}
    else:
        assert not any(resource.startswith(other) for resource in result["owned"])


def test_remove_legacy_discovery_handles_missing_optional_properties() -> None:
    block = "$dependencyMetadata = Get-ObjectValue" + REMOVE.split(
        "$dependencyMetadata = Get-ObjectValue", 1
    )[1].split("$dependencyResourceSpecs =", 1)[0]
    result = _powershell_json("""
$Subscription = 'sub'; $platformResourceGroup = 'platform'
$platformIdPrefix = '/subscriptions/sub/resourceGroups/platform/providers/'
$outputDocument = [pscustomobject]@{ apiName = 'api'; applicationInsightsName = 'insights'; controlPlaneFunctionName = 'control' }
$ownedById = @{}
function Invoke-AzJson([string[]]$Arguments, [switch]$AllowFailure) {
    if ($Arguments[0] -eq 'rest') {
        return [pscustomobject]@{ probe = '@Microsoft.KeyVault(SecretUri=https://custom-vault.vault.azure.net/secrets/probe)' }
    }
    return [pscustomobject]@{ properties = [pscustomobject]@{} }
}
""" + block + """
@{ owned = @($ownedById.Keys) } | ConvertTo-Json -Compress
""")
    assert result["owned"] == [
        "/subscriptions/sub/resourceGroups/platform/providers/Microsoft.KeyVault/vaults/custom-vault"
    ]

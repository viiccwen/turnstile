from __future__ import annotations

from pathlib import Path

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


def test_remove_script_records_exact_arm_deployment_resources() -> None:
    assert "Get-DeploymentResources" in REMOVE
    assert '"$prefix-platform"' in REMOVE
    assert '"$prefix-observer"' in REMOVE
    assert '$name -like "*$prefix*"' not in REMOVE
    assert "Get-AppStorageAccountNames" not in REMOVE
    assert "Get-DeploymentResources" in REMOVE
    assert "Invoke-RecordedCleanup" in REMOVE
    assert "if (-not $CaptureManifest)" in REMOVE
    assert "azureResourceIds" in REMOVE
    assert "apimResourceIds" in REMOVE
    assert "roleAssignmentIds" in REMOVE


def test_remove_script_orders_dependent_resources() -> None:
    assert "'Microsoft.Web/sites' = 10" in REMOVE
    assert "'Microsoft.Network/privateEndpoints' = 20" in REMOVE
    assert "'Microsoft.Network/virtualNetworks' = 60" in REMOVE
    assert "'Microsoft.Network/networkSecurityGroups' = 70" in REMOVE


def test_remove_manifest_rejects_shared_and_unapproved_actions() -> None:
    assert "Manifest product deletion must not use subscription cascade" in REMOVE
    assert "Manifest resource type is not approved for cleanup" in REMOVE
    assert "Manifest REST action is not an approved APIM child deletion" in REMOVE
    assert "Manifest RBAC action is outside the configured APIM service" in REMOVE
    assert "Manifest must not delete a private DNS zone" in REMOVE
    assert "is referenced by another API and cannot be recorded" in REMOVE
    assert "coreEnvironmentOnly" in REMOVE
    assert "RemoveEntraApps" not in REMOVE
    assert "RemoveSharedFoundryRole" not in REMOVE


def test_remove_manifest_deletes_only_shared_storage_children() -> None:
    assert "storageResourceGroupName" in REMOVE
    assert "Manifest resource is outside the platform resource group" in REMOVE
    assert "'storage', 'container', 'delete'" in REMOVE
    assert "'storage', 'table', 'delete'" in REMOVE
    assert "Manifest storage action targets an unexpected account" in REMOVE
    assert "Manifest storage action targets an unexpected child" in REMOVE
    assert "providers/Microsoft.Storage/storageAccounts/$storageAccountName" in REMOVE
    assert "'Microsoft.Storage/storageAccounts' = 50" not in REMOVE

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
import urllib.error
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock
from typing import cast
from unittest.mock import MagicMock

import httpx
import pytest
from packaging.tags import cpython_tags
from packaging.utils import parse_wheel_filename

from scripts.deploy import (
    OBSERVER_RUNTIME_FILES,
    OBSERVER_SHARED_PATHS,
    EXISTING_RESOURCE_API_VERSIONS,
    CommandRunner,
    DeploymentError,
    DeploymentInputs,
    ExistingCore,
    SecretMaterial,
    _arm_role_assignment_name,
    _delegation_condition,
    _install_linux_dependencies,
    _managed_role_assignment_name,
    _resource_group_deployment_command,
    _upgrade_lock,
    _write_private_json,
    build_and_start_observer,
    build_parser,
    deploy_function_package,
    deploy_packages,
    deploy_webapp_package,
    deployment_parameters,
    deterministic_zip,
    ensure_adopted_apim_prerequisite_role,
    ensure_adopted_dependency_roles,
    ensure_foundry_role,
    ensure_observer_event_hub_role,
    ensure_role_assignments,
    ensure_shared_storage_resources,
    ensure_shared_storage_roles,
    execute,
    frontend_asset,
    initialize_fixed_program,
    linux_dependency_command,
    load_existing_core,
    load_or_create_secret_material,
    observer_build_context,
    observer_names,
    observer_outputs_complete,
    observer_parameters,
    observer_plan_name,
    observer_source_version,
    owner_credentials_password,
    pip_linux_dependency_command,
    resolve_adopted_secret_material,
    restart_runtime_apps,
    runtime_release_parameters,
    temporary_parameter_file,
    validate_adoption_context,
    validate_existing_dependencies,
    validate_existing_network,
    validate_flex_consumption_capabilities,
    validate_packaged_dependencies,
    validate_postgres_capabilities,
    verify_initial_fixed_program,
    validate_shared_storage_account,
    verify_owner_login,
    wait_for_health,
    wait_for_observer_health,
    what_if,
)
from scripts.stage_deployment import REPOSITORY_ROOT


def _parameters(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "parameters": {
                    "resourcePrefix": {"value": "turnstile"},
                    "resourceGroupName": {"value": "turnstile-test"},
                    "location": {"value": "eastus2"},
                    "apimPublisherEmail": {"value": "admin@example.com"},
                    "bootstrapOwnerEmail": {"value": "owner@example.com"},
                    "storageResourceGroupName": {"value": "storage"},
                    "storageAccountName": {"value": "geoliangdatalake"},
                    "telemetryDeploymentContainerName": {
                        "value": "victurnstile-telemetry-deploy"
                    },
                    "controlPlaneDeploymentContainerName": {
                        "value": "victurnstile-control-deploy"
                    },
                    "ledgerTableName": {"value": "VicturnstileLedger"},
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _set_parameters(path: Path, values: Mapping[str, object]) -> Path:
    document = json.loads(path.read_text(encoding="utf-8"))
    document["parameters"].update(
        {name: {"value": value} for name, value in values.items()}
    )
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _set_adopted_secrets(path: Path, values: Mapping[str, object]) -> Path:
    document = json.loads(path.read_text(encoding="utf-8"))
    document["adoptedSecrets"] = dict(values)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _adopted_dependency_values(subscription: str) -> dict[str, str]:
    network = (
        f"/subscriptions/{subscription}/resourceGroups/network/providers/"
        "Microsoft.Network/virtualNetworks/shared-vnet"
    )
    vault_id = (
        f"/subscriptions/{subscription}/resourceGroups/security/providers/"
        "Microsoft.KeyVault/vaults/shared-vault"
    )
    secret_root = "https://shared-vault.vault.azure.net/secrets"
    return {
        "existingVirtualNetworkResourceId": network,
        "existingTelemetryFunctionSubnetResourceId": f"{network}/subnets/telemetry",
        "existingControlPlaneFunctionSubnetResourceId": f"{network}/subnets/control",
        "existingPrivateEndpointSubnetResourceId": f"{network}/subnets/private",
        "existingApiSubnetResourceId": f"{network}/subnets/api",
        "existingKeyVaultPrivateDnsZoneResourceId": (
            f"/subscriptions/{subscription}/resourceGroups/dns/providers/"
            "Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
        ),
        "existingPostgresServerResourceId": (
            f"/subscriptions/{subscription}/resourceGroups/data/providers/"
            "Microsoft.DBforPostgreSQL/flexibleServers/shared-postgres"
        ),
        "existingPostgresDatabaseName": "turnstile-existing",
        "existingEventHubResourceId": (
            f"/subscriptions/{subscription}/resourceGroups/data/providers/"
            "Microsoft.EventHub/namespaces/shared-events/eventhubs/usage"
        ),
        "existingLogAnalyticsWorkspaceResourceId": (
            f"/subscriptions/{subscription}/resourceGroups/monitor/providers/"
            "Microsoft.OperationalInsights/workspaces/shared-logs"
        ),
        "existingApplicationInsightsResourceId": (
            f"/subscriptions/{subscription}/resourceGroups/monitor/providers/"
            "Microsoft.Insights/components/shared-appinsights"
        ),
        "existingKeyVaultResourceId": vault_id,
        "existingDatabaseUrlSecretUri": f"{secret_root}/database-url",
        "existingCredentialEncryptionKeySecretUri": (
            f"{secret_root}/credential-encryption-key"
        ),
        "existingManagementApiKeySecretUri": f"{secret_root}/management-api-key",
        "existingApimSubscriptionKeySecretUri": (
            f"{secret_root}/apim-subscription-key"
        ),
        "existingApimProbeSubscriptionKeySecretUri": (
            f"{secret_root}/apim-probe-subscription-key"
        ),
    }


def test_secret_state_is_private_stable_and_excludes_plaintext(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "00000000-0000-0000-0000-000000000001",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    prompts: list[str] = []
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))

    def read_password(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    first = load_or_create_secret_material(
        inputs,
        read_password=read_password,
        require_owner_password=True,
    )
    second = load_or_create_secret_material(
        inputs,
        read_password=lambda _: "a-secure-owner-password",
        require_owner_password=True,
    )

    assert first.values == second.values
    assert first.owner_password == "a-secure-owner-password"
    assert prompts == [
        "Initial Owner password (minimum 12 characters): ",
        "Repeat Initial Owner password (minimum 12 characters): ",
    ]
    assert first.values["observerAdapterSharedKey"] != first.values["managementApiKey"]
    assert "a-secure-owner-password" not in inputs.state_path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert stat.S_IMODE(inputs.state_path.stat().st_mode) == 0o600


def test_resume_rejects_short_owner_password_before_deployment(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "00000000-0000-0000-0000-000000000001",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=True,
    )
    prompts: list[str] = []

    def read_short_password(prompt: str) -> str:
        prompts.append(prompt)
        return "too-short"

    with pytest.raises(DeploymentError, match="at least 12 characters"):
        load_or_create_secret_material(
            inputs,
            read_password=read_short_password,
            require_owner_password=True,
        )

    assert prompts == [
        "Initial Owner password for verification (minimum 12 characters): "
    ]


def test_public_parameter_file_rejects_secure_values(tmp_path: Path) -> None:
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["parameters"]["managementApiKey"] = {"value": "do-not-store-here"}
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DeploymentError, match="Keep secure parameters out"):
        DeploymentInputs.load("subscription", path)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    (
        ("observerPlanSkuName", "B1", "must be one of"),
        ("observerPlanWorkerCount", 0, "must be between 1 and 30"),
        ("observerPlanWorkerCount", 31, "must be between 1 and 30"),
        ("observerPlanWorkerCount", "2", "must be an integer"),
    ),
)
def test_observer_plan_parameters_are_validated_before_deployment(
    tmp_path: Path, name: str, value: object, message: str
) -> None:
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["parameters"][name] = {"value": value}
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DeploymentError, match=message):
        DeploymentInputs.load("subscription", path)


def test_skip_what_if_is_explicit_and_defaults_off(tmp_path: Path) -> None:
    base = [
        "plan",
        "--subscription",
        "subscription",
        "--parameters",
        str(_parameters(tmp_path / "parameters.json")),
    ]

    assert build_parser().parse_args(base).skip_what_if is False
    assert build_parser().parse_args(base).skip_platform_deployment is False
    recovery = build_parser().parse_args(
        [*base, "--skip-what-if", "--skip-platform-deployment"]
    )
    assert recovery.skip_what_if is True
    assert recovery.skip_platform_deployment is True


def test_foundry_parameter_can_be_omitted_without_azure_role_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()

    def unexpected_command(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Omitting Foundry must not perform Azure role operations")

    monkeypatch.setattr(runner, "run", unexpected_command)
    monkeypatch.setattr(runner, "run_json", unexpected_command)

    assert inputs.foundry_resource_id is None
    assert ensure_foundry_role(runner, inputs, {}) == set()


def test_foundry_resource_id_is_validated_and_not_forwarded_to_bicep(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    foundry_id = (
        f"/subscriptions/{subscription}/resourceGroups/foundry/providers/"
        "Microsoft.CognitiveServices/accounts/customer-foundry"
    )
    document["parameters"]["foundryCognitiveServicesAccountResourceId"] = {
        "value": foundry_id
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    inputs = DeploymentInputs.load(subscription, path, tmp_path / "state.json")
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )

    assert inputs.foundry_resource_id == foundry_id
    assert "foundryCognitiveServicesAccountResourceId" not in deployment_parameters(
        inputs, material
    )["parameters"]


@pytest.mark.parametrize(
    "value",
    (
        "foundry",
        "/subscriptions/other/resourceGroups/foundry/providers/"
        "Microsoft.CognitiveServices/accounts/customer-foundry",
        "/subscriptions/subscription/resourceGroups/foundry/providers/"
        "Microsoft.CognitiveServices/accounts/customer-foundry/projects/project",
    ),
)
def test_foundry_resource_id_rejects_invalid_or_cross_subscription_scope(
    tmp_path: Path, value: str
) -> None:
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["parameters"]["foundryCognitiveServicesAccountResourceId"] = {
        "value": value
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DeploymentError, match="foundryCognitiveServicesAccountResourceId"):
        DeploymentInputs.load("subscription", path)


def test_existing_dependencies_map_to_non_provisioning_bicep_parameters(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    path = _set_parameters(
        _parameters(tmp_path / "parameters.json"),
        _adopted_dependency_values(subscription),
    )
    inputs = DeploymentInputs.load(subscription, path, tmp_path / "state.json")
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    generated = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    material = SecretMaterial(
        generated.values,
        None,
        "postgresql://user:password@shared-postgres/turnstile-existing",
    )

    parameters = deployment_parameters(inputs, material)["parameters"]

    assert parameters["provisionNetwork"]["value"] is False
    assert parameters["provisionEventHub"]["value"] is False
    assert parameters["provisionObservability"]["value"] is False
    assert parameters["provisionKeyVault"]["value"] is False
    assert parameters["provisionPostgres"]["value"] is False
    assert parameters["postgresAdopted"]["value"] is True
    assert parameters["useDatabaseUrlOverride"]["value"] is True
    assert parameters["databaseUrlOverride"]["value"].startswith("postgresql://")
    assert parameters["existingEventHubNamespaceName"]["value"] == "shared-events"
    assert parameters["existingEventHubName"]["value"] == "usage"
    assert parameters["existingLogAnalyticsWorkspaceName"]["value"] == "shared-logs"
    assert parameters["existingApplicationInsightsName"]["value"] == (
        "shared-appinsights"
    )
    assert parameters["existingKeyVaultName"]["value"] == "shared-vault"
    assert parameters["provisionKeyVaultPrivateDnsZone"]["value"] is False
    assert parameters["existingKeyVaultPrivateDnsZoneName"]["value"] == (
        "privatelink.vaultcore.azure.net"
    )


def test_existing_network_rejects_partial_or_mixed_vnet_configuration(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    network_values = {
        name: value
        for name, value in values.items()
        if "Subnet" in name or "VirtualNetwork" in name
    }
    network_values.pop("existingApiSubnetResourceId")
    path = _set_parameters(
        _parameters(tmp_path / "partial.json"), network_values
    )
    with pytest.raises(DeploymentError, match="Existing network adoption requires"):
        DeploymentInputs.load(subscription, path)

    complete = {
        name: value
        for name, value in values.items()
        if "Subnet" in name or "VirtualNetwork" in name
    }
    complete["existingApiSubnetResourceId"] = complete[
        "existingApiSubnetResourceId"
    ].replace("shared-vnet", "other-vnet")
    path = _set_parameters(_parameters(tmp_path / "mixed.json"), complete)
    with pytest.raises(DeploymentError, match="must belong to the configured VNet"):
        DeploymentInputs.load(subscription, path)


def test_existing_postgres_and_key_vault_must_be_adopted_together(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    postgres_only = {
        "existingPostgresServerResourceId": values[
            "existingPostgresServerResourceId"
        ],
        "existingPostgresDatabaseName": values["existingPostgresDatabaseName"],
    }
    path = _set_parameters(
        _parameters(tmp_path / "postgres.json"), postgres_only
    )
    with pytest.raises(DeploymentError, match="must be adopted together"):
        DeploymentInputs.load(subscription, path)


def test_existing_key_vault_secret_uri_must_use_the_configured_vault(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    selected = {
        name: value
        for name, value in values.items()
        if name.startswith("existingPostgres")
        or name == "existingKeyVaultResourceId"
        or "SecretUri" in name
    }
    selected["existingManagementApiKeySecretUri"] = (
        "https://shared-vault.vault.evil.example/secrets/management-api-key"
    )
    path = _set_parameters(_parameters(tmp_path / "parameters.json"), selected)

    with pytest.raises(DeploymentError, match="Key Vault secret URI"):
        DeploymentInputs.load(subscription, path)


def test_adopted_secrets_are_resolved_from_private_parameters_without_rewriting_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    selected = {
        name: value
        for name, value in values.items()
        if name.startswith("existingPostgres")
        or name == "existingKeyVaultResourceId"
        or "SecretUri" in name
    }
    path = _set_parameters(_parameters(tmp_path / "parameters.json"), selected)
    initial_inputs = DeploymentInputs.load(subscription, path, tmp_path / "state.json")
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        initial_inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    original_state = initial_inputs.state_path.read_text(encoding="utf-8")
    fernet_key = material.values["credentialEncryptionKey"]
    adopted_secrets = {
        "databaseUrl": "postgresql://user:secret@postgres/db",
        "credentialEncryptionKey": fernet_key,
        "managementApiKey": "management-secret",
        "apimSubscriptionKey": "dashboard-secret",
        "apimProbeSubscriptionKey": "probe-secret",
    }
    _set_adopted_secrets(path, adopted_secrets)
    inputs = DeploymentInputs.load(subscription, path, initial_inputs.state_path)
    runner = CommandRunner()
    monkeypatch.setattr(
        runner,
        "run",
        lambda *_args, **_kwargs: pytest.fail("Adopted secrets need no Azure data-plane read"),
    )
    resolved = resolve_adopted_secret_material(runner, inputs, material)

    assert resolved.database_url_override == adopted_secrets["databaseUrl"]
    assert resolved.values["credentialEncryptionKey"] == fernet_key
    assert resolved.values["managementApiKey"] == "management-secret"
    assert inputs.state_path.read_text(encoding="utf-8") == original_state
    assert "management-secret" not in original_state
    assert "adoptedSecrets" not in inputs.parameters


def test_adopted_dependencies_require_top_level_secrets_when_resolving(
    tmp_path: Path,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    selected = {
        name: value
        for name, value in values.items()
        if name.startswith("existingPostgres")
        or name == "existingKeyVaultResourceId"
        or "SecretUri" in name
    }
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(_parameters(tmp_path / "parameters.json"), selected),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    with pytest.raises(DeploymentError, match="top-level adoptedSecrets"):
        resolve_adopted_secret_material(CommandRunner(), inputs, material)


@pytest.mark.parametrize(
    "adopted_secrets, message",
    [
        ({"databaseUrl": "postgresql://user:secret@host/db"}, "exactly"),
        (
            {
                "databaseUrl": "",
                "credentialEncryptionKey": "key",
                "managementApiKey": "management",
                "apimSubscriptionKey": "dashboard",
                "apimProbeSubscriptionKey": "probe",
            },
            "non-empty",
        ),
    ],
)
def test_malformed_adopted_secrets_are_rejected(
    tmp_path: Path,
    adopted_secrets: dict[str, str],
    message: str,
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    selected = {
        name: value
        for name, value in values.items()
        if name.startswith("existingPostgres")
        or name == "existingKeyVaultResourceId"
        or "SecretUri" in name
    }
    path = _set_parameters(_parameters(tmp_path / "parameters.json"), selected)
    _set_adopted_secrets(path, adopted_secrets)

    with pytest.raises(DeploymentError, match=message):
        DeploymentInputs.load(subscription, path, tmp_path / "state.json")


def test_existing_network_preflight_validates_delegations_capacity_and_dns_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    network_values = {
        name: value
        for name, value in values.items()
        if "Subnet" in name
        or "VirtualNetwork" in name
        or "PrivateDnsZone" in name
    }
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(_parameters(tmp_path / "parameters.json"), network_values),
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []
    existing_network = inputs.existing_network
    assert existing_network is not None

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        if command[1:3] == ["resource", "show"]:
            resource_id = command[command.index("--ids") + 1]
            if "privateDnsZones" in resource_id:
                resource_type = "Microsoft.Network/privateDnsZones"
            else:
                resource_type = "Microsoft.Network/virtualNetworks"
            return {
                "id": resource_id,
                "type": resource_type,
                "location": "eastus2",
            }
        resource_id = command[command.index("--ids") + 1]
        if resource_id.endswith("/private"):
            return {
                "addressPrefix": "10.50.3.96/27",
                "privateEndpointNetworkPolicies": "Disabled",
                "ipConfigurations": [],
            }
        service = (
            "Microsoft.Web/serverFarms"
            if resource_id.endswith("/api")
            else "Microsoft.App/environments"
        )
        return {
            "addressPrefix": "10.50.3.0/27",
            "delegations": [{"serviceName": service}],
            "ipConfigurations": [],
        }

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                [
                    {
                        "virtualNetwork": {
                            "id": existing_network.virtual_network_resource_id
                        }
                    }
                ]
            ),
        )

    monkeypatch.setattr(runner, "run_json", run_json)
    monkeypatch.setattr(runner, "run", run)

    validate_existing_network(runner, inputs)
    resource_commands = [
        command for command in commands if command[1:3] == ["resource", "show"]
    ]
    assert [
        command[command.index("--api-version") + 1]
        for command in resource_commands
    ] == [
        EXISTING_RESOURCE_API_VERSIONS["microsoft.network/virtualnetworks"],
        EXISTING_RESOURCE_API_VERSIONS["microsoft.network/privatednszones"],
    ]


def test_existing_network_preflight_rejects_wrong_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    network_values = {
        name: value
        for name, value in values.items()
        if "Subnet" in name or "VirtualNetwork" in name
    }
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(_parameters(tmp_path / "parameters.json"), network_values),
    )
    runner = CommandRunner()

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        resource_id = command[command.index("--ids") + 1]
        if command[1:3] == ["resource", "show"]:
            return {
                "id": resource_id,
                "type": "Microsoft.Network/virtualNetworks",
                "location": "eastus2",
            }
        return {
            "addressPrefix": "10.50.3.0/27",
            "delegations": [{"serviceName": "Microsoft.Web/serverFarms"}],
            "privateEndpointNetworkPolicies": "Disabled",
            "ipConfigurations": [],
        }

    monkeypatch.setattr(runner, "run_json", run_json)

    with pytest.raises(DeploymentError, match="Telemetry Function subnet must be delegated"):
        validate_existing_network(runner, inputs)


def test_saved_dependency_ownership_cannot_switch_on_rerun(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json")
    )
    outputs = {
        "dependencyResources": {
            name: {"provisioned": True}
            for name in ("postgres", "eventHub", "observability", "keyVault", "network")
        }
    }
    validate_adoption_context(inputs, outputs)
    outputs["dependencyResources"]["network"]["provisioned"] = False
    with pytest.raises(DeploymentError, match="network ownership"):
        validate_adoption_context(inputs, outputs)


def test_existing_event_hub_and_observability_preflight_checks_linkage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    all_values = _adopted_dependency_values(subscription)
    selected = {
        name: all_values[name]
        for name in (
            "existingEventHubResourceId",
            "existingLogAnalyticsWorkspaceResourceId",
            "existingApplicationInsightsResourceId",
        )
    }
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(_parameters(tmp_path / "parameters.json"), selected),
    )
    runner = CommandRunner()

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        resource_id = command[command.index("--ids") + 1]
        if "/eventhubs/" in resource_id:
            resource_type = "Microsoft.EventHub/namespaces/eventhubs"
            properties: dict[str, object] = {}
        elif "/namespaces/" in resource_id:
            resource_type = "Microsoft.EventHub/namespaces"
            properties = {}
        elif "OperationalInsights" in resource_id:
            resource_type = "Microsoft.OperationalInsights/workspaces"
            properties = {}
        else:
            resource_type = "Microsoft.Insights/components"
            properties = {
                "WorkspaceResourceId": selected[
                    "existingLogAnalyticsWorkspaceResourceId"
                ]
            }
        return {"id": resource_id, "type": resource_type, "properties": properties}

    monkeypatch.setattr(runner, "run_json", run_json)
    validate_existing_dependencies(runner, inputs)


def test_adopted_dependency_roles_use_exact_external_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(
            _parameters(tmp_path / "parameters.json"),
            _adopted_dependency_values(subscription),
        ),
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []
    monkeypatch.setattr(
        runner,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="[]"
        ),
    )

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        scope = command[command.index("--scope") + 1]
        name = command[command.index("--name") + 1]
        return {
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}"
        }

    monkeypatch.setattr(runner, "run_json", run_json)
    outputs = {
        "telemetryPrincipalId": "telemetry-principal",
        "controlPlanePrincipalId": "control-principal",
        "apimPrincipalId": "apim-principal",
    }

    managed = ensure_adopted_dependency_roles(runner, inputs, outputs)
    managed.update(
        ensure_observer_event_hub_role(
            runner, inputs, {"webAppPrincipalId": "observer-principal"}
        )
    )

    assert len(managed) == 7
    roles = [command[command.index("--role") + 1] for command in commands]
    assert roles.count("2b629674-e913-4c01-ae53-ef4638d8f975") == 2
    assert roles.count("a638d3c7-ab3a-418d-83e6-5f17a39d4fde") == 1
    assert roles.count("73c42c96-874c-492b-b04d-ab87d138a893") == 1
    assert roles.count("4633458b-17de-408a-b874-0445c86b69e6") == 3
    assert inputs.existing_event_hub is not None
    event_hub_id = inputs.existing_event_hub.resource_id
    assert sum(command[command.index("--scope") + 1] == event_hub_id for command in commands) == 3


def test_existing_apim_event_hub_role_is_ready_before_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    values = _adopted_dependency_values(subscription)
    inputs = DeploymentInputs.load(
        subscription,
        _set_parameters(
            _parameters(tmp_path / "parameters.json"),
            {"existingEventHubResourceId": values["existingEventHubResourceId"]},
        ),
    )
    core = ExistingCore(
        apim_name="shared-apim",
        apim_resource_group_name="apim",
        apim_principal_id="apim-principal",
        apim_gateway_url="https://shared-apim.azure-api.net",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []
    monkeypatch.setattr(
        runner,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="[]"),
    )

    def create(command: Sequence[str], **_kwargs: object) -> dict[str, str]:
        commands.append(command)
        scope = command[command.index("--scope") + 1]
        name = command[command.index("--name") + 1]
        return {
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}"
        }

    monkeypatch.setattr(runner, "run_json", create)

    managed = ensure_adopted_apim_prerequisite_role(runner, inputs, core)

    assert len(managed) == 1
    assert commands[0][commands[0].index("--assignee-object-id") + 1] == (
        "apim-principal"
    )
    assert commands[0][commands[0].index("--scope") + 1] == (
        values["existingEventHubResourceId"]
    )


def test_postgres_preflight_rejects_restricted_region(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    monkeypatch.setattr(
        runner,
        "run_json",
        lambda *_args, **_kwargs: {
            "reason": "Subscriptions are restricted from provisioning in this region.",
            "versions": [],
            "editions": [],
        },
    )

    with pytest.raises(DeploymentError, match="PostgreSQL 16 is unavailable in eastus2"):
        validate_postgres_capabilities(runner, inputs)


def test_flex_preflight_accepts_registered_supported_region(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    responses = iter(("Registered\n", "eastus2\nwestus3\n"))

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout=next(responses))

    monkeypatch.setattr(runner, "run", run)

    validate_flex_consumption_capabilities(runner, inputs)


def test_flex_preflight_rejects_unsupported_region(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    responses = iter(("Registered\n", "westus3\n"))

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout=next(responses))

    monkeypatch.setattr(runner, "run", run)

    with pytest.raises(DeploymentError, match="Flex Consumption is unavailable"):
        validate_flex_consumption_capabilities(runner, inputs)


def test_postgres_preflight_accepts_requested_sku_and_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        return {
            "reason": None,
            "versions": ["16"],
            "editions": [
                {
                    "name": "Burstable",
                    "skus": [
                        {"name": "Standard_B1ms", "zones": ["1", "2", "3"]}
                    ],
                }
            ],
        }

    monkeypatch.setattr(runner, "run_json", run_json)

    validate_postgres_capabilities(runner, inputs)

    assert commands[0][:4] == ["az", "postgres", "flexible-server", "list-skus"]
    assert commands[0][commands[0].index("--location") + 1] == "eastus2"


def test_shared_storage_bootstrap_requires_distinct_ledger_and_route_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _set_parameters(_parameters(tmp_path / "parameters.json"), {"ledgerTableName": "ModelRoutes"})
    inputs = DeploymentInputs.load("subscription", path, tmp_path / "state.json")
    runner = CommandRunner()
    monkeypatch.setattr(runner, "run", lambda *_args, **_kwargs: pytest.fail("No resources should be created"))
    with pytest.raises(DeploymentError, match="distinct tables"):
        ensure_shared_storage_resources(runner, inputs)


def test_shared_storage_preflight_requires_function_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    monkeypatch.setattr(
        runner,
        "run_json",
        lambda *_args, **_kwargs: {
            "kind": "StorageV2",
            "publicNetworkAccess": "Enabled",
            "blob": "https://geoliangdatalake.blob.core.windows.net/",
            "queue": "https://geoliangdatalake.queue.core.windows.net/",
            "table": "https://geoliangdatalake.table.core.windows.net/",
        },
    )

    validate_shared_storage_account(runner, inputs)


def test_shared_storage_bootstrap_creates_only_owned_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(runner, "run", run)

    ensure_shared_storage_resources(runner, inputs)

    assert [command[1:4] for command in commands] == [
        ["storage", "container", "create"],
        ["storage", "container", "create"],
        ["storage", "table", "create"],
        ["storage", "table", "create"],
    ]
    assert [command[command.index("--name") + 1] for command in commands] == [
        "victurnstile-telemetry-deploy", "victurnstile-control-deploy",
        "VicturnstileLedger", "ModelRoutes",
    ]
    assert all(command[command.index("--account-name") + 1] == "geoliangdatalake" for command in commands)
    assert all("--auth-mode" in command and "login" in command for command in commands)
    assert all("queue" not in command for command in commands)


@pytest.mark.parametrize(
    ("responses", "owned_indexes"),
    [
        (["false", "false", "false", "false"], []),
        (["true", "false", "true", "false"], [0, 2]),
        (["true", "true", "true", "true"], [0, 1, 2, 3]),
        (["", "null", "{}", '"true"'], []),
    ],
)
def test_storage_child_ownership_requires_explicit_creation_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    responses: list[str], owned_indexes: list[int],
) -> None:
    from scripts import deploy

    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    account_id = _shared_storage_outputs()["storageAccountId"]
    children = [
        f"{account_id}/blobServices/default/containers/victurnstile-telemetry-deploy",
        f"{account_id}/blobServices/default/containers/victurnstile-control-deploy",
        f"{account_id}/tableServices/default/tables/VicturnstileLedger",
        f"{account_id}/tableServices/default/tables/ModelRoutes",
    ]
    runner = CommandRunner()
    results = iter(responses)

    def run(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["capture"] is True
        assert command[command.index("--query") + 1] == "created"
        assert command[command.index("--output") + 1] == "json"
        return subprocess.CompletedProcess(command, 0, stdout=next(results))

    monkeypatch.setattr(runner, "run", run)
    ensure_shared_storage_resources(runner, inputs)
    checkpoint = inputs.state_path.with_suffix(".storage-children.json")
    expected = sorted(children[index] for index in owned_indexes)
    assert checkpoint.exists() is bool(expected)
    if expected:
        assert json.loads(checkpoint.read_text(encoding="utf-8")) == {
            "managedStorageChildResourceIds": expected,
        }
    # ARM outputs and later observer/runtime output rewrites must retain evidence.
    deploy._write_outputs(inputs, {"resourceGroupName": "turnstile-test"})
    deploy._write_outputs(inputs, {"resourceGroupName": "turnstile-test", "apiName": "api"})
    saved = deploy.load_saved_outputs(inputs)
    assert saved is not None
    assert saved.get("managedStorageChildResourceIds", []) == expected


def test_storage_child_ownership_resumes_partial_bootstrap_without_claiming_existing_route_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import deploy

    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    runner = CommandRunner()
    calls = 0

    def interrupted(command: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise DeploymentError("bootstrap interrupted")
        return subprocess.CompletedProcess(command, 0, stdout="true\n")

    monkeypatch.setattr(runner, "run", interrupted)
    with pytest.raises(DeploymentError, match="bootstrap interrupted"):
        ensure_shared_storage_resources(runner, inputs)
    assert deploy.load_saved_outputs(inputs) is None  # ARM has not returned outputs yet.
    checkpoint = inputs.state_path.with_suffix(".storage-children.json")
    first = json.loads(checkpoint.read_text(encoding="utf-8"))["managedStorageChildResourceIds"]
    assert len(first) == 1

    results = iter(("false", "true", "false", "false"))
    monkeypatch.setattr(
        runner, "run", lambda command, **_: subprocess.CompletedProcess(
            command, 0, stdout=next(results)
        ),
    )
    ensure_shared_storage_resources(runner, inputs)
    deploy._write_outputs(inputs, {"resourceGroupName": "turnstile-test"})
    saved = deploy.load_saved_outputs(inputs)
    assert saved is not None
    owned = saved["managedStorageChildResourceIds"]
    assert len(owned) == 2
    assert set(first) <= set(owned)
    assert all("/containers/" in resource_id for resource_id in owned)

    # A later resume can recover from outputs alone, without inferring ownership
    # from resource names or successfully re-running idempotent create commands.
    checkpoint.unlink()
    monkeypatch.setattr(
        runner, "run", lambda command, **_: subprocess.CompletedProcess(command, 0, stdout="false"),
    )
    ensure_shared_storage_resources(runner, inputs)
    deploy._write_outputs(inputs, {"apiName": "api"})
    assert deploy.load_saved_outputs(inputs)["managedStorageChildResourceIds"] == owned


def test_storage_child_creation_merges_prior_outputs_before_later_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import deploy

    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    account_id = _shared_storage_outputs()["storageAccountId"]
    ledger_id = _shared_storage_outputs()["ledgerTableId"]
    unrelated = f"{account_id}/tableServices/default/tables/Unrelated"
    dependencies = {"postgres": {"provisioned": False, "resourceId": "adopted-postgres"}}
    outputs_path = inputs.state_path.with_suffix(".outputs.json")
    outputs_path.write_text(json.dumps({
        "managedStorageChildResourceIds": [ledger_id, unrelated],
        "dependencyResources": dependencies,
        "managedRoleAssignmentIds": ["prior-role"],
    }), encoding="utf-8")
    runner = CommandRunner()

    def run(command: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[command.index("--name") + 1] == "victurnstile-control-deploy":
            raise DeploymentError("later creation failed")
        return subprocess.CompletedProcess(command, 0, stdout="true")

    monkeypatch.setattr(runner, "run", run)
    with pytest.raises(DeploymentError, match="later creation failed"):
        ensure_shared_storage_resources(runner, inputs)
    saved = deploy.load_saved_outputs(inputs)
    assert saved is not None
    assert saved["managedStorageChildResourceIds"] == sorted([
        ledger_id, f"{account_id}/blobServices/default/containers/victurnstile-telemetry-deploy",
    ])
    assert saved["dependencyResources"] == dependencies
    assert saved["managedRoleAssignmentIds"] == ["prior-role"]
    assert _shared_storage_outputs()["routeTableId"] not in saved["managedStorageChildResourceIds"]


def _shared_storage_outputs() -> dict[str, str]:
    account_id = (
        "/subscriptions/subscription/resourceGroups/storage/providers/"
        "Microsoft.Storage/storageAccounts/geoliangdatalake"
    )
    return {
        "storageAccountId": account_id,
        "ledgerTableId": f"{account_id}/tableServices/default/tables/VicturnstileLedger",
        "routeTableId": f"{account_id}/tableServices/default/tables/ModelRoutes",
        "routeTableName": "ModelRoutes",
        "credentialVaultName": "route-credentials",
        "credentialVaultResourceId": (
            "/subscriptions/subscription/resourceGroups/turnstile-test/providers/"
            "Microsoft.KeyVault/vaults/route-credentials"
        ),
        "apiName": "turnstile-api",
        "telemetryFunctionName": "turnstile-telemetry",
        "controlPlaneFunctionName": "turnstile-control",
        "telemetryPrincipalId": "telemetry-principal",
        "apiPrincipalId": "api-principal",
        "controlPlanePrincipalId": "control-principal",
        "apimPrincipalId": "apim-principal",
    }


def test_shared_storage_roles_are_granted_automatically_without_queue_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()

    commands: list[Sequence[str]] = []

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="[]")

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        scope = command[command.index("--scope") + 1]
        name = command[command.index("--name") + 1]
        return {
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "scope": scope,
            "roleDefinitionId": command[command.index("--role") + 1],
        }

    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(runner, "run_json", run_json)
    outputs = _shared_storage_outputs()

    managed = ensure_shared_storage_roles(runner, inputs, outputs)

    assert len(managed) == 15
    assert len(commands) == 15
    roles = {command[command.index("--role") + 1] for command in commands}
    assert roles == {
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
        "76199698-9eea-4c19-bc75-cec21354c6b6",
        "4633458b-17de-408a-b874-0445c86b69e6",
        "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
    }
    assert all("--assignee-principal-type" in command for command in commands)
    assert all("--name" in command for command in commands)
    assert all("queue" not in " ".join(command).casefold() for command in commands)
    route_grants = {
        (command[command.index("--assignee-object-id") + 1], command[command.index("--role") + 1])
        for command in commands
        if command[command.index("--scope") + 1] == outputs["routeTableId"]
        and "--condition" not in command
    }
    assert route_grants == {
        ("api-principal", "76199698-9eea-4c19-bc75-cec21354c6b6"),
        ("apim-principal", "76199698-9eea-4c19-bc75-cec21354c6b6"),
        ("control-principal", "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"),
    }
    delegations = [command for command in commands if "--condition" in command]
    assert len(delegations) == 4
    for command in delegations:
        scope = command[command.index("--scope") + 1]
        principal = command[command.index("--assignee-object-id") + 1]
        is_route = scope == outputs["routeTableId"]
        assert scope in {outputs["ledgerTableId"], outputs["routeTableId"]}
        assert principal in {"api-principal", "control-principal"}
        assert command[command.index("--condition-version") + 1] == "2.0"
        delegated_role = (
            "76199698-9eea-4c19-bc75-cec21354c6b6" if is_route
            else "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
        )
        assert command[command.index("--condition") + 1] == (
            "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR "
            "(@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] "
            f"ForAnyOfAnyValues:GuidEquals {{{delegated_role}}} AND "
            "@Request[Microsoft.Authorization/roleAssignments:PrincipalType] "
            "ForAnyOfAnyValues:StringEqualsIgnoreCase {'ServicePrincipal'})) AND "
            "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})))"
        )
        site = "turnstile-api" if principal == "api-principal" else "turnstile-control"
        prefix = "apim" if principal == "api-principal" else "onboarding"
        label = f"{prefix}-{'route' if is_route else 'ledger'}-rbac-delegator"
        assert command[command.index("--name") + 1] == _arm_role_assignment_name(
            scope,
            "/subscriptions/subscription/resourceGroups/turnstile-test/providers/"
            f"Microsoft.Web/sites/{site}",
            label,
        )


def test_shared_route_roles_resume_and_reuse_arm_credentials_without_claiming_external_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    outputs = _shared_storage_outputs()
    runner = CommandRunner()
    assignments: dict[str, list[dict[str, object]]] = {}
    commands: list[Sequence[str]] = []
    for principal, role, label, identity in (
        ("apim-principal", "4633458b-17de-408a-b874-0445c86b69e6", "route-credential-reader", "apim-principal"),
        ("control-principal", "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", "route-credential-writer",
         "/subscriptions/subscription/resourceGroups/turnstile-test/providers/Microsoft.Web/sites/turnstile-control"),
    ):
        scope = outputs["credentialVaultResourceId"]
        name = _arm_role_assignment_name(scope, identity, label)
        assignments[principal] = [{
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "scope": scope, "roleDefinitionId": role,
        }]
    # This unrelated route reader is sufficient, but must not become cleanup-owned.
    assignments["api-principal"] = [{
        "id": f"{outputs['routeTableId']}/providers/Microsoft.Authorization/roleAssignments/external",
        "scope": outputs["routeTableId"],
        "roleDefinitionId": "76199698-9eea-4c19-bc75-cec21354c6b6",
    }]

    def run(command: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        principal = command[command.index("--assignee-object-id") + 1]
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(assignments.get(principal, [])))

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        principal = command[command.index("--assignee-object-id") + 1]
        scope = command[command.index("--scope") + 1]
        name = command[command.index("--name") + 1]
        assignment: dict[str, object] = {
            "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "scope": scope,
            "roleDefinitionId": command[command.index("--role") + 1],
        }
        if "--condition" in command:
            assignment.update(
                condition=command[command.index("--condition") + 1], conditionVersion="2.0"
            )
        assignments.setdefault(principal, []).append(assignment)
        return assignment

    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(runner, "run_json", run_json)
    first = ensure_shared_storage_roles(runner, inputs, outputs)
    assert len(commands) == 12  # Two ARM credentials and one external reader reused.
    assert len(first) == 14
    assert all(not item.endswith("/external") for item in first)
    assert all(command[command.index("--scope") + 1] != outputs["credentialVaultResourceId"] for command in commands)
    commands.clear()
    assert ensure_shared_storage_roles(runner, inputs, outputs) == first
    assert commands == []


@pytest.mark.parametrize("field,value", [
    ("routeTableId", "/subscriptions/subscription/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/other/tableServices/default/tables/ModelRoutes"),
    ("ledgerTableId", "/subscriptions/subscription/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/geoliangdatalake/tableServices/default/tables/OtherLedger"),
    ("routeTableName", "OtherRoutes"),
    ("credentialVaultName", "wrong-vault"),
    ("credentialVaultResourceId", "/subscriptions/other/resourceGroups/security/providers/Microsoft.KeyVault/vaults/route-credentials"),
])
def test_shared_route_roles_reject_unrelated_output_scopes_before_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    outputs = {**_shared_storage_outputs(), field: value}
    runner = CommandRunner()
    monkeypatch.setattr(runner, "run", lambda *_args, **_kwargs: pytest.fail("No Azure calls for invalid outputs"))
    with pytest.raises(DeploymentError):
        ensure_shared_storage_roles(runner, inputs, outputs)


def test_shared_route_roles_reject_adopted_configuration_vault_as_credential_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _parameters(tmp_path / "parameters.json")
    adopted = _adopted_dependency_values("subscription")
    _set_parameters(path, adopted)
    inputs = DeploymentInputs.load("subscription", path, tmp_path / "state.json")
    outputs = {
        **_shared_storage_outputs(),
        "credentialVaultName": "shared-vault",
        "credentialVaultResourceId": adopted["existingKeyVaultResourceId"],
    }
    runner = CommandRunner()
    monkeypatch.setattr(runner, "run", lambda *_args, **_kwargs: pytest.fail("No Azure calls for configuration vault"))
    with pytest.raises(DeploymentError, match="dedicated vault"):
        ensure_shared_storage_roles(runner, inputs, outputs)


@pytest.mark.parametrize("condition,version", [(None, None), ("incorrect", "2.0"), ("expected", "1.0")])
def test_managed_delegator_with_changed_condition_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, condition: str | None, version: str | None
) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    scope = _shared_storage_outputs()["routeTableId"]
    role = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
    expected = _delegation_condition("76199698-9eea-4c19-bc75-cec21354c6b6")
    name = _arm_role_assignment_name(scope, "api-resource-id", "apim-route-rbac-delegator")
    assignment = {
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
        "scope": scope, "roleDefinitionId": role,
        "condition": expected if condition == "expected" else condition,
        "conditionVersion": version,
    }
    runner = CommandRunner()
    monkeypatch.setattr(runner, "run", lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=json.dumps([assignment])))
    monkeypatch.setattr(runner, "run_json", lambda *_args, **_kwargs: pytest.fail("Do not overwrite mismatched permissions"))
    with pytest.raises(DeploymentError, match="unexpected condition"):
        ensure_role_assignments(
            runner, inputs, (("api", "Role Based Access Control Administrator", role, scope),),
            assignment_names={("api", role, scope): name}, condition=expected,
        )


@pytest.mark.parametrize("existing_condition", [None, "matching-parent-condition"])
def test_parent_rbac_admin_does_not_replace_exact_constrained_table_delegation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_condition: str | None
) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    outputs = _shared_storage_outputs()
    scope = outputs["routeTableId"]
    role = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
    condition = _delegation_condition("76199698-9eea-4c19-bc75-cec21354c6b6")
    existing = {
        "id": f"{outputs['storageAccountId']}/providers/Microsoft.Authorization/roleAssignments/external",
        "scope": outputs["storageAccountId"], "roleDefinitionId": role,
        "condition": condition if existing_condition else None, "conditionVersion": "2.0",
    }
    runner = CommandRunner()
    commands: list[Sequence[str]] = []
    monkeypatch.setattr(runner, "run", lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=json.dumps([existing])))

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        name = command[command.index("--name") + 1]
        return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}"}

    monkeypatch.setattr(runner, "run_json", run_json)
    managed = ensure_role_assignments(
        runner, inputs, (("api", "Role Based Access Control Administrator", role, scope),),
        condition=condition,
    )
    assert len(commands) == 1
    assert commands[0][commands[0].index("--scope") + 1] == scope
    assert commands[0][commands[0].index("--condition") + 1] == condition
    assert str(existing["id"]) not in managed


def test_legacy_cli_assignment_remains_owned_during_arm_name_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription", _parameters(tmp_path / "parameters.json"), tmp_path / "state.json"
    )
    scope = _shared_storage_outputs()["routeTableId"]
    role = "76199698-9eea-4c19-bc75-cec21354c6b6"
    legacy_name = _managed_role_assignment_name(scope, "api", role)
    legacy_id = f"{scope}/providers/Microsoft.Authorization/roleAssignments/{legacy_name}"
    runner = CommandRunner()
    monkeypatch.setattr(runner, "run", lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 0, stdout=json.dumps([{"id": legacy_id, "scope": scope, "roleDefinitionId": role}])
    ))
    monkeypatch.setattr(runner, "run_json", lambda *_args, **_kwargs: pytest.fail("Reuse legacy assignment"))
    assert ensure_role_assignments(
        runner, inputs, (("api", "Storage Table Data Reader", role, scope),),
        assignment_names={("api", role, scope): _arm_role_assignment_name(scope, "api-resource", "route-table-reader")},
    ) == {legacy_id}


def test_existing_parent_scope_role_is_reused_without_becoming_cleanup_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    parent_scope = "/subscriptions/subscription/resourceGroups/storage"
    assignment = {
        "id": f"{parent_scope}/providers/Microsoft.Authorization/roleAssignments/existing",
        "scope": parent_scope,
        "roleDefinitionName": "Storage Table Data Contributor",
    }
    monkeypatch.setattr(
        runner,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps([assignment])
        ),
    )
    monkeypatch.setattr(
        runner,
        "run_json",
        lambda *_args, **_kwargs: pytest.fail("A covering assignment must be reused"),
    )

    managed = ensure_role_assignments(
        runner,
        inputs,
        (
            (
                "principal",
                "Storage Table Data Contributor",
                "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
                f"{parent_scope}/providers/Microsoft.Storage/storageAccounts/shared/"
                "tableServices/default/tables/ledger",
            ),
        ),
    )

    assert managed == set()


def test_arm_route_delegation_name_matches_fixed_uuid5_vector() -> None:
    assert _arm_role_assignment_name(
        _shared_storage_outputs()["routeTableId"],
        "/subscriptions/subscription/resourceGroups/turnstile-test/providers/"
        "Microsoft.Web/sites/turnstile-api",
        "apim-route-rbac-delegator",
    ) == "f5d4231a-b392-51f9-a2ac-5d7346f0e501"


def test_managed_role_assignment_name_is_stable() -> None:
    assert _managed_role_assignment_name(
        "/subscriptions/sub/resourceGroups/storage/providers/"
        "Microsoft.Storage/storageAccounts/shared",
        "00000000-0000-4000-8000-000000000001",
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
    ) == "d5ee4e88-fb8e-26a0-77e6-c0fa4d79a75c"


def test_foundry_role_is_granted_to_apim_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subscription = "00000000-0000-0000-0000-000000000001"
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    foundry_id = (
        f"/subscriptions/{subscription}/resourceGroups/foundry/providers/"
        "Microsoft.CognitiveServices/accounts/customer-foundry"
    )
    document["parameters"]["foundryCognitiveServicesAccountResourceId"] = {
        "value": foundry_id
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    inputs = DeploymentInputs.load(subscription, path, tmp_path / "state.json")
    runner = CommandRunner()
    commands: list[Sequence[str]] = []
    monkeypatch.setattr(
        runner,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="[]"),
    )

    def run_json(command: Sequence[str], **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        name = command[command.index("--name") + 1]
        return {
            "id": f"{foundry_id}/providers/Microsoft.Authorization/roleAssignments/{name}"
        }

    monkeypatch.setattr(runner, "run_json", run_json)

    managed = ensure_foundry_role(
        runner, inputs, {"apimPrincipalId": "apim-principal"}
    )

    assert len(managed) == 1
    assert commands[0][commands[0].index("--role") + 1] == (
        "a97b65f3-24c7-4388-baec-2e87135dc908"
    )
    assert commands[0][commands[0].index("--scope") + 1] == foundry_id


def test_owner_credentials_are_private_and_match_public_email(tmp_path: Path) -> None:
    path = tmp_path / "owner.credentials.json"
    path.write_text(
        json.dumps(
            {
                "email": "owner@example.com",
                "password": "a-secure-owner-password",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    assert (
        owner_credentials_password(path, "owner@example.com")
        == "a-secure-owner-password"
    )
    with pytest.raises(DeploymentError, match="does not match"):
        owner_credentials_password(path, "other@example.com")


@pytest.mark.skipif(os.name == "nt", reason="Windows credentials use ACL protection")
def test_owner_credentials_reject_group_or_world_access(tmp_path: Path) -> None:
    path = tmp_path / "owner.credentials.json"
    path.write_text(
        json.dumps(
            {
                "email": "owner@example.com",
                "password": "a-secure-owner-password",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o644)

    with pytest.raises(DeploymentError, match="permissions must be 0600"):
        owner_credentials_password(path, "owner@example.com")


def test_base_parameters_disable_workers_until_observer_exists(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )

    parameters = deployment_parameters(inputs, material)["parameters"]

    assert parameters["provisionControlPlane"]["value"] is True
    assert parameters["controlPlaneEnabled"]["value"] is False
    assert parameters["gatewayReleaseWorkerEnabled"]["value"] is False
    assert parameters["keyVaultPrivateDnsLinkName"]["value"] == "turnstile-vnet"
    assert parameters["apimUsageObserver"]["value"]["mode"] == "disabled"
    assert "observerAdapterSharedKey" not in parameters


def test_external_apim_still_provisions_a_clean_platform(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    core = ExistingCore(
        apim_name="apim-existing",
        apim_resource_group_name="apim-shared",
        apim_principal_id="00000000-0000-4000-8000-000000000010",
        apim_gateway_url="https://apim-existing.azure-api.net",
    )

    parameters = deployment_parameters(
        inputs, material, existing_core=core
    )["parameters"]

    assert parameters["provisionApimService"]["value"] is False
    assert parameters["provisionPostgres"]["value"] is True
    assert parameters["deployApimBootstrap"]["value"] is True
    assert parameters["existingApimName"]["value"] == core.apim_name
    assert (
        parameters["existingApimResourceGroupName"]["value"]
        == core.apim_resource_group_name
    )
    assert parameters["existingApimPrincipalId"]["value"] == core.apim_principal_id
    assert parameters["existingApimGatewayUrl"]["value"] == core.apim_gateway_url
    assert parameters["apimApiId"]["value"] == "turnstile-llm"
    assert parameters["gatewayApiRelativePath"]["value"] == "turnstile/llm"
    assert parameters["observerAdapterKeyNamedValueName"]["value"] == (
        "turnstile-observer-key"
    )


def test_external_apim_adoption_rejects_partial_configuration(tmp_path: Path) -> None:
    path = _parameters(tmp_path / "parameters.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["parameters"]["existingApimName"] = {"value": "apim-existing"}
    path.write_text(json.dumps(document), encoding="utf-8")
    inputs = DeploymentInputs.load("subscription", path, tmp_path / "state.json")

    with pytest.raises(
        DeploymentError,
        match="Existing APIM adoption requires:.*existingApimResourceGroupName",
    ):
        ExistingCore.from_parameters(inputs.parameters)


def test_resume_skips_existing_platform_and_gateway_bootstrap(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    core = ExistingCore(
        apim_name="apim-existing",
        apim_resource_group_name="turnstile-test",
        apim_principal_id="00000000-0000-4000-8000-000000000010",
        apim_gateway_url="https://apim-existing.azure-api.net",
    )

    parameters = deployment_parameters(
        inputs,
        material,
        existing_core=core,
        resume_existing_environment=True,
    )["parameters"]

    assert parameters["provisionApimService"]["value"] is False
    assert parameters["provisionPostgres"]["value"] is False
    assert parameters["deployApimBootstrap"]["value"] is False
    assert parameters["keyVaultPrivateDnsLinkName"]["value"] == "finops-vnet"


def test_resume_reuses_saved_private_dns_link_name(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    core = ExistingCore(
        apim_name="apim-existing",
        apim_resource_group_name="turnstile-test",
        apim_principal_id="00000000-0000-4000-8000-000000000010",
        apim_gateway_url="https://apim-existing.azure-api.net",
    )

    parameters = deployment_parameters(
        inputs,
        material,
        existing_core=core,
        resume_existing_environment=True,
        saved_outputs={
            "dependencyResources": {
                "keyVault": {"privateDnsLinkName": "turnstile-vnet"}
            }
        },
    )["parameters"]

    assert parameters["keyVaultPrivateDnsLinkName"]["value"] == "turnstile-vnet"


@pytest.mark.parametrize(
    ("existing", "complete_installation", "failure_stage"),
    [
        (existing, complete, failure)
        for existing, complete in [
            (False, False), (True, False), ("pending", False), (True, True), ("pending", True),
            ("platform", False), ("platform", True), ("observer", False), ("observer", True),
            ("platform-with-observer", False), ("platform-with-observer", True),
        ]
        for failure in (None, "readiness")
    ] + [
        (False, False, "packages"), (False, False, "observer"),
        (False, False, "plan"), ("platform", False, "plan"), ("observer", False, "plan"),
    ],
)
def test_deployment_initializes_fixed_program_only_for_a_new_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool | str,
    complete_installation: bool, failure_stage: str | None, capsys: pytest.CaptureFixture[str],
) -> None:
    program_ready = failure_stage != "readiness"
    outputs: dict[str, object] = {
        "resourceGroupName": "turnstile-test",
        "apiName": "api-test",
        "apiUrl": "https://api-test.example.test",
        "controlPlaneFunctionName": "control-test",
        "telemetryFunctionName": "telemetry-test",
        "webAppUrl": "https://observer-test.example.test",
        "apimPrincipalId": "00000000-0000-0000-0000-000000000002",
        "acrName": "retained-registry",
    }
    deployed_outputs = dict(outputs)
    if existing == "pending":
        outputs["pendingFixedBootstrap"] = {}
    elif existing in {"platform", "observer", "platform-with-observer"}:
        outputs["pendingInstallation"] = "observer" if existing == "observer" else "platform"
        if existing == "platform":
            outputs.pop("webAppUrl")
            outputs.pop("acrName")
    arguments = build_parser().parse_args([
        "plan" if failure_stage == "plan" else "deploy",
        "--subscription", "00000000-0000-0000-0000-000000000001",
        "--parameters", str(_parameters(tmp_path / "parameters.json")),
        "--state", str(tmp_path / "state.json"), "--yes",
        *(["--complete-installation"] if complete_installation else []),
    ])
    for name in (
        "require_prerequisites", "validate_source_snapshot", "gateway_upgrade",
        "deployment_budget_delegation",
        "validate_flex_consumption_capabilities", "validate_postgres_capabilities",
        "_confirm_deployment", "what_if", "what_if_resource_group", "wait_for_health",
        "wait_for_observer_health", "verify_frontend_asset", "verify_owner_login",
        "verify_function_indexing", "verify_telemetry_function_health", "restart_runtime_apps",
    ):
        monkeypatch.setattr(f"scripts.deploy.{name}", Mock())
    monkeypatch.setattr("scripts.deploy.gateway_upgrade", Mock(return_value=None))
    monkeypatch.setattr("scripts.deploy.load_saved_outputs", Mock(
        return_value=outputs if existing else None,
    ))
    monkeypatch.setattr("scripts.deploy.ExistingCore.from_outputs", Mock(return_value=None))
    monkeypatch.setattr("scripts.deploy.load_or_create_secret_material", Mock(
        return_value=Mock(owner_password="offline-owner-password"),
    ))
    for name in (
        "deployment_parameters", "runtime_release_parameters", "observer_parameters",
        "deploy_template", "build_packages", "current_app_settings",
    ):
        monkeypatch.setattr(f"scripts.deploy.{name}", Mock(return_value={}))
    monkeypatch.setattr("scripts.deploy.deployment_outputs", Mock(return_value={
        **{key: value for key, value in deployed_outputs.items()
              if not complete_installation or existing is not True or key != "acrName"},
        **({"controlPlanePrincipalId": "00000000-0000-4000-8000-000000000011"}
              if complete_installation and existing is True else {}),
    }))
    for name in ("source_version", "observer_source_version", "frontend_asset"):
        monkeypatch.setattr(f"scripts.deploy.{name}", Mock(return_value="offline-candidate"))
    events: list[str] = []

    def record_event(*args: object, event: str) -> None:
        events.append(event)
        if (failure_stage == "packages" and event == "deploy_packages") or (
            failure_stage == "observer" and event == "build_and_start_observer"
        ):
            raise DeploymentError("Checkpoint interruption")

    for name in (
        "deploy_packages", "build_and_start_observer",
        "deploy_resource_group_template",
    ):
        monkeypatch.setattr(
            f"scripts.deploy.{name}",
            Mock(side_effect=lambda *args, event=name, **kwargs: record_event(*args, event=event)),
            raising=False,
        )

    checkpoints: list[dict[str, object]] = []
    write_outputs = execute.__globals__["_write_outputs"]

    def save_checkpoint(inputs: DeploymentInputs, values: dict[str, object]) -> None:
        events.append("_write_outputs")
        checkpoints.append(dict(values))
        write_outputs(inputs, values)

    monkeypatch.setattr("scripts.deploy._write_outputs", Mock(side_effect=save_checkpoint))
    descriptor = {
        "registration": {"gateway_profile_id": "unit-target"},
        "binding": {"program_sha256": "a" * 64},
    }

    def initialize_program(*args: object) -> dict[str, dict[str, str]]:
        events.append("initialize_fixed_program")
        return descriptor

    monkeypatch.setattr("scripts.deploy.initialize_fixed_program", Mock(
        side_effect=initialize_program,
    ))

    def verify_program(*args: object) -> None:
        events.append("verify_initial_fixed_program")
        if not program_ready:
            raise DeploymentError("Initial fixed program is not ready for model publication")

    program_readiness = Mock(side_effect=verify_program)
    monkeypatch.setattr("scripts.deploy.verify_initial_fixed_program", program_readiness)
    readiness = Mock()
    isolated_frontend_read = Mock(side_effect=AssertionError(
        "Frontend must share startup deadline",
    ))
    monkeypatch.setattr("scripts.deploy.wait_for_health", readiness)
    monkeypatch.setattr("scripts.deploy.verify_frontend_asset", isolated_frontend_read)
    initializes_program = existing is not True or complete_installation
    if failure_stage in {"packages", "observer"} or (initializes_program and not program_ready):
        with pytest.raises(DeploymentError):
            execute(arguments, CommandRunner())
    else:
        execute(arguments, CommandRunner())

    if failure_stage == "plan":
        assert events == []
        assert checkpoints == []
        assert not (tmp_path / "state.outputs.json").exists()
        return
    if checkpoints:
        outputs_path = tmp_path / "state.outputs.json"
        assert json.loads(outputs_path.read_text()) == checkpoints[-1]
        assert stat.S_IMODE(outputs_path.stat().st_mode) == 0o600
    if failure_stage in {"packages", "observer"}:
        expected = ["_write_outputs", "deploy_packages"]
        if failure_stage == "observer":
            expected.extend(("_write_outputs", "build_and_start_observer"))
        assert events == expected
        assert checkpoints[-1]["pendingInstallation"] == (
            "platform" if failure_stage == "packages" else "observer"
        )
        readiness.assert_not_called()
        program_readiness.assert_not_called()
        assert "Turnstile deployment completed." not in capsys.readouterr().out
        return

    readiness.assert_called_once_with(
        "https://api-test.example.test", timeout_seconds=1800, expected_asset="offline-candidate",
    )
    isolated_frontend_read.assert_not_called()
    expected = []
    platform_deployed = not existing or (complete_installation and existing is True)
    if platform_deployed:
        expected.append("_write_outputs")
    expected.append("deploy_packages")
    if initializes_program:
        expected.append("_write_outputs")
    expected.append("build_and_start_observer")
    if initializes_program:
        expected.append("initialize_fixed_program")
    expected.append("deploy_resource_group_template")
    if initializes_program:
        expected.append("verify_initial_fixed_program")
        owner_email = json.loads(arguments.parameters.read_text())["parameters"][
            "bootstrapOwnerEmail"
        ]["value"]
        program_readiness.assert_called_once_with(
            "https://api-test.example.test", owner_email, "offline-owner-password", descriptor,
        )
    else:
        program_readiness.assert_not_called()
    if not initializes_program or program_ready:
        expected.append("_write_outputs")
    assert events == expected
    assert ("Turnstile deployment completed." in capsys.readouterr().out) == (
        not initializes_program or program_ready
    )
    if initializes_program:
        phases = [values["pendingInstallation"] for values in checkpoints
                  if "pendingInstallation" in values]
        assert phases == (["platform", "observer"] if platform_deployed else ["observer"])
        assert checkpoints[-1].get("pendingInstallation") == (
            None if program_ready else "observer"
        )
    if complete_installation and program_ready:
        observer = execute.__globals__["observer_parameters"].call_args.kwargs["existing_observer"]
        if existing == "platform":
            assert observer is None
        else:
            assert observer["acrName"] == "retained-registry"
        assert execute.__globals__["_write_outputs"].call_args.args[1] == deployed_outputs


def test_invalid_installation_checkpoint_is_rejected_before_cloud_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = build_parser().parse_args([
        "deploy", "--subscription", "unit",
        "--parameters", str(_parameters(tmp_path / "parameters.json")),
        "--state", str(tmp_path / "state.json"),
    ])
    outputs_path = tmp_path / "state.outputs.json"
    original = json.dumps({"pendingInstallation": "unknown-stage"})
    outputs_path.write_text(original)
    monkeypatch.setattr("scripts.deploy.require_prerequisites", Mock())
    monkeypatch.setattr("scripts.deploy.validate_source_snapshot", Mock())
    runner = Mock(spec=CommandRunner)

    with pytest.raises(DeploymentError, match="invalid installation stage"):
        execute(arguments, runner)

    runner.run.assert_not_called()
    runner.run_json.assert_not_called()
    assert outputs_path.read_text() == original


def test_saved_outputs_enable_existing_core_on_rerun(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    outputs_path = tmp_path / "state.outputs.json"
    outputs_path.write_text(
        json.dumps(
            {
                    "resourceGroupName": "turnstile-test",
                "apimName": "apim-existing",
                "apimPrincipalId": "00000000-0000-4000-8000-000000000010",
                "apimGatewayUrl": "https://apim-existing.azure-api.net",
            }
        ),
        encoding="utf-8",
    )

    core = load_existing_core(inputs)

    assert core is not None
    assert core.apim_name == "apim-existing"
    assert core.apim_resource_group_name == "turnstile-test"


@pytest.mark.parametrize("installation_fails", [False, True])
def test_initial_fixed_program_binds_compiled_policies_before_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installation_fails: bool,
) -> None:
    from uuid import UUID

    from backend.bootstrap_storage_route import FixedInstallationDescriptor
    from scripts.apim_upgrade import GatewaySnapshot
    from tests.backend.model_platform.test_apim_onboarding import (
        onboarding_configuration,
        onboarding_plan,
    )
    from turnstile_core.domain.budget_delegation import BudgetDelegationTrust
    from turnstile_core.integrations.apim_onboarding_policy import _render_onboarding_parent
    from turnstile_core.integrations.apim_policy_components import parse_policy
    from turnstile_core.integrations.apim_storage_routes import fixed_policy_digest

    configuration = onboarding_configuration()
    request = onboarding_plan().request
    inputs = DeploymentInputs.load(
        str(request.subscription_id),
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    outputs = {
        "resourceGroupName": inputs.resource_group_name,
        "apiName": "api-test",
        "apiPrincipalId": "00000000-0000-4000-8000-000000000091",
        "controlPlaneFunctionName": "control-test",
        "telemetryFunctionName": "telemetry-test",
        "apimName": request.service_name,
        "apimResourceGroupName": request.resource_group,
        "apimPrincipalId": "00000000-0000-4000-8000-000000000003",
        "apimGatewayUrl": f"https://{request.service_name}.azure-api.net",
        "apimApiId": request.api_id,
        "apimProbeSubscriptionId": request.probe_subscription_id,
        "gatewayApiPath": f"https://{request.service_name}.azure-api.net/{request.api_path}",
        "observerAdapterKeyNamedValueName": "turnstile-observer-key",
    }
    settings = {
        "DATABASE_URL": "postgresql://unit@unit-server.postgres.database.azure.com/turnstile",
        "APIM_GATEWAY_PROFILE_ID": str(request.gateway_profile_id),
        "APIM_DASHBOARD_SUBSCRIPTION_ID": request.dashboard_subscription_id,
    }
    canonical = (REPOSITORY_ROOT / "infra/policies/foundry-finops-policy.xml").read_text()
    snapshot = GatewaySnapshot(
        "1",
        {"path": request.api_path, "subscriptionRequired": False},
        _render_onboarding_parent(request, configuration, canonical),
        {},
        {},
    )
    client_factory = httpx.Client

    def read_arm(arm_request: httpx.Request) -> httpx.Response:
        if arm_request.url.path.endswith("/namedValues/turnstile-platform-governance"):
            return httpx.Response(
                200,
                json={
                    "properties": {
                        "value": configuration.model_dump_json(),
                    }
                },
            )
        return httpx.Response(200, json={"sku": {"name": "StandardV2"}})

    monkeypatch.setattr(
        "scripts.deploy.httpx.Client",
        lambda **kwargs: client_factory(
            **kwargs,
            transport=httpx.MockTransport(read_arm),
        ),
    )
    monkeypatch.setattr("scripts.deploy.AzureUpgradeBackend.read", Mock(return_value=snapshot))
    preview = Mock()
    apply = Mock(
        side_effect=DeploymentError("ARM installation failed") if installation_fails else None
    )
    monkeypatch.setattr("scripts.deploy.what_if", preview)
    monkeypatch.setattr("scripts.deploy.deploy_template", apply)
    runner = Mock(spec=CommandRunner)
    runner.run_json.side_effect = lambda command: (
        {"properties": {"clientId": "00000000-0000-4000-8000-000000000092",
         "principalId": outputs["apiPrincipalId"],
         "tenantId": str(configuration.management_tenant_id)}}
        if "rest" in command else {"accessToken": "offline-token"}
    )

    if installation_fails:
        with pytest.raises(DeploymentError, match="ARM installation failed"):
            initialize_fixed_program(runner, inputs, outputs, settings)
        return
    descriptor = FixedInstallationDescriptor.model_validate_json(
        json.dumps(
            initialize_fixed_program(runner, inputs, outputs, settings),
        )
    )

    preview.assert_called_once()
    apply.assert_called_once_with(*preview.call_args.args)
    parameters = apply.call_args.args[3]["parameters"]
    operations = parameters["fixedOperations"]["value"]
    assert operations[0]["name"] == "anthropic-models"
    assert operations[0]["method"] == "POST"
    assert {item["name"]: fixed_policy_digest(item["policy"]) for item in operations} == (
        descriptor.operation_policies_sha256
    )
    assert (
        fixed_policy_digest(parameters["parentPolicy"]["value"]) == descriptor.parent_policy_sha256
    )
    assert descriptor.binding.model_additions_enabled
    assert descriptor.binding.models_path == "/v1/models"
    assert descriptor.registration.gateway_profile_id == request.gateway_profile_id
    assert descriptor.registration.probe_subscription_id == request.probe_subscription_id
    assert descriptor.api_name == "control-test"
    assert descriptor.expected_server == "unit-server.postgres.database.azure.com"
    parent = parse_policy(parameters["parentPolicy"]["value"])
    delegation = parent.find(
        ".//validate-azure-ad-token[@header-name='x-turnstile-delegation-token']",
    )
    assert delegation is not None
    assert delegation.attrib["tenant-id"] == str(configuration.management_tenant_id)
    assert delegation.findtext("client-application-ids/application-id") == (
        "00000000-0000-4000-8000-000000000092"
    )
    assert delegation.findtext("required-claims/claim[@name='oid']/value") == (
        outputs["apiPrincipalId"]
    )
    trust = BudgetDelegationTrust(
        tenant_id=configuration.management_tenant_id,
        audience="https://management.azure.com/",
        client_ids=(UUID("00000000-0000-4000-8000-000000000092"),),
        object_ids=(UUID(outputs["apiPrincipalId"]),),
    )

    runtime = runtime_release_parameters(
        SecretMaterial(
            {"apimSubscriptionKey": "dashboard-key", "apimProbeSubscriptionKey": "probe-key"}, None
        ),
        outputs,
        {
            "webAppUrl": "https://observer.example.test",
            "adapterKeyNamedValueName": "turnstile-observer-key",
        },
        {"keep": "api"},
        {"keep": "publisher"},
        descriptor.model_dump(mode="json"),
        {"keep": "telemetry"},
        trust,
    )["parameters"]
    assert "TURNSTILE_FIXED_BOOTSTRAP_DESCRIPTOR" not in runtime["currentApiSettings"]["value"]
    publisher = runtime["currentControlPlaneSettings"]["value"]
    assert json.loads(publisher["TURNSTILE_FIXED_BOOTSTRAP_DESCRIPTOR"]) == (
        descriptor.model_dump(mode="json")
    )
    assert publisher["keep"] == "publisher"
    api = runtime["currentApiSettings"]["value"]
    target_id = str(request.gateway_profile_id)
    assert json.loads(api["BUDGET_DELEGATION_TARGETS"])[target_id] == {
        "audience": trust.audience,
        "allowed_origins": [f"https://{request.service_name}.azure-api.net/"],
    }
    for current in (api, publisher):
        assert json.loads(current["BUDGET_EXECUTION_TARGET_IDS"]) == [target_id]
        assert json.loads(current["BUDGET_DELEGATION_TRUST"]) == {
            target_id: trust.model_dump(mode="json"),
        }
    assert runtime["currentTelemetrySettings"]["value"] == {
        "keep": "telemetry",
        "BUDGET_EXECUTION_ENABLED": "true",
        "BUDGET_SETTLEMENT_ENABLED": "true",
    }
    saved = json.loads(inputs.state_path.with_suffix(".outputs.json").read_text())
    assert saved["pendingFixedBootstrap"] == descriptor.model_dump(mode="json")


@pytest.mark.parametrize("fault", [
    None, "parent", "operation", "contract", "missing_policy", "target", "digest",
    "missing_operation",
])
def test_new_fixed_program_can_be_redeployed_without_policy_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None,
) -> None:
    from typing import cast

    from scripts import deploy
    from scripts.apim_upgrade import ApimUpgradeError, AzureUpgradeBackend, GatewaySnapshot
    from turnstile_core.integrations.apim_policy_components import parse_policy, serialize_policy

    runtime = Mock(wraps=runtime_release_parameters)
    monkeypatch.setattr(sys.modules[__name__], "runtime_release_parameters", runtime)
    with monkeypatch.context() as initialization:
        test_initial_fixed_program_binds_compiled_policies_before_registration(
            tmp_path, initialization, False,
        )
        applied = cast(Mock, deploy.deploy_template)
        inputs = applied.call_args.args[1]
        outputs = runtime.call_args.args[1]
        parameters = applied.call_args.args[3]["parameters"]
        descriptor = runtime.call_args.args[5]
    values = {name: entry["value"] for name, entry in parameters.items()}
    operations = values["fixedOperations"]
    current = GatewaySnapshot(
        values["revision"], values["apiProperties"], values["parentPolicy"],
        {operation["name"]: {
            "displayName": operation["name"], "method": operation["method"],
            "urlTemplate": operation["path"], "templateParameters": [], "responses": [],
        } for operation in operations},
        {operation["name"]: operation["policy"] for operation in operations},
    )
    if fault == "parent":
        from dataclasses import replace

        root = parse_policy(current.parent_policy)
        trust = root.find(".//set-variable[@name='routeTrust']")
        assert trust is not None
        trust.set("value", "f" * 64)
        current = replace(current, parent_policy=serialize_policy(root))
    elif fault == "operation":
        current.operation_policies["chat-completions"] = (
            "<policies><inbound><return-response /></inbound></policies>"
        )
    elif fault == "contract":
        current.operations["chat-completions"]["method"] = "GET"
    elif fault == "missing_policy":
        current.operation_policies["chat-completions"] = None
    elif fault == "target":
        descriptor["registration"]["resource_group"] = "other-resource-group"
    elif fault == "digest":
        descriptor["binding"]["program_sha256"] = "f" * 64
    elif fault == "missing_operation":
        del current.operations["chat-completions"]
    runner = Mock(spec=CommandRunner)
    runner.run_json.return_value = {"accessToken": "offline-token"}
    monkeypatch.setattr(AzureUpgradeBackend, "read", Mock(return_value=current))
    monkeypatch.setattr(deploy, "current_app_settings", Mock(return_value={
        "TURNSTILE_FIXED_BOOTSTRAP_DESCRIPTOR": json.dumps(descriptor),
    }))
    writes = Mock(side_effect=AssertionError("Redeployment must not rewrite fixed policies"))
    monkeypatch.setattr(deploy, "deploy_template", writes)
    monkeypatch.setattr(deploy, "_write_private_json", writes)

    if fault:
        with pytest.raises((DeploymentError, ApimUpgradeError)):
            deploy.gateway_upgrade(runner, inputs, outputs, "check")
    else:
        deploy.gateway_upgrade(runner, inputs, outputs, "check")
    writes.assert_not_called()
    assert runner.run_json.call_count == 1


@pytest.mark.parametrize("phase", ["complete", "missing", "changed_target", "checkpoint_conflict"])
def test_existing_program_delegation_uses_guarded_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    from contextlib import nullcontext
    from types import SimpleNamespace
    from typing import Any, cast

    from fastapi import Response

    from backend import bootstrap_storage_route as bootstrap
    from backend.http.model_platform import preview_gateway_program_upgrade
    from scripts import deploy
    from scripts.apim_upgrade import GatewaySnapshot
    from turnstile_core.config import Settings
    from turnstile_core.integrations.apim_budget_execution import bind_budget_delegation
    from turnstile_core.integrations.apim_policy_components import parse_policy, serialize_policy
    from turnstile_core.integrations.apim_storage_routes import (
        compact_fixed_policy,
        fixed_policy_digest,
        fixed_program_digest,
    )
    from turnstile_core.services.storage_route_publisher import _validate_program_cutover

    runtime = Mock(wraps=runtime_release_parameters)
    monkeypatch.setattr(sys.modules[__name__], "runtime_release_parameters", runtime)
    with monkeypatch.context() as initialization:
        test_initial_fixed_program_binds_compiled_policies_before_registration(
            tmp_path, initialization, False,
        )
        descriptor = bootstrap.FixedInstallationDescriptor.model_validate_json(
            json.dumps(runtime.call_args.args[5]),
        )
        inputs = cast(Mock, deploy.deploy_template).call_args.args[1]
        parameters = cast(Mock, deploy.deploy_template).call_args.args[3]["parameters"]
        outputs = runtime.call_args.args[1]
        parent = parameters["parentPolicy"]["value"]
        trust = runtime.call_args.args[7]
    policies = {item["name"]: item["policy"]
                for item in parameters["fixedOperations"]["value"]}
    installed = bootstrap.installation_record(descriptor, "a" * 64)
    if phase != "complete":
        parent = compact_fixed_policy(bind_budget_delegation(
            parent, None, gateway_profile_id=descriptor.registration.gateway_profile_id,
        ))
        contracts = tuple(
            (name, *contract) for name, contract in installed.operation_contracts.items()
        )
        digest = fixed_program_digest(parent, policies, contracts)
        root = parse_policy(parent)
        marker = root.find(".//set-variable[@name='routeProgram']")
        assert marker is not None
        marker.set("value", digest)
        parent = serialize_policy(root)
        installed = installed.model_copy(update={
            "program": installed.program.model_copy(update={"program_sha256": digest}),
            "parent_policy_sha256": fixed_policy_digest(parent),
        })
    if phase == "changed_target":
        parent = parent.replace('name="routeTrust"', 'name="changedTrust"')
    repository = Mock()
    target_id = descriptor.registration.gateway_profile_id
    publication_id = "00000000-0000-4000-8000-000000000093"
    repository.effective_gateway_publication.return_value = {
        "id": publication_id, "resource_manifest": {"fixed_route_program": installed.model_dump()},
    }
    repository.get_gateway_profiles.return_value = [{"id": target_id, "config": {}}]
    connection = Mock()
    connection.transaction.side_effect = lambda: nullcontext()
    repository._connection.side_effect = lambda: nullcontext(connection)
    def save_checkpoint(statement: str, parameters: Any) -> Mock:
        assert "AND config = %s RETURNING id" in statement
        if phase == "checkpoint_conflict":
            return Mock(fetchone=Mock(return_value=None))
        repository.get_gateway_profiles.return_value[0]["config"] = parameters[0].obj
        return Mock(fetchone=Mock(return_value={"id": target_id}))
    connection.execute.side_effect = save_checkpoint
    management = Mock()
    management._read_policy.return_value = (
        httpx.Response(200, headers={"ETag": '"unit-etag"'}), parent,
    )
    management.route_program_operations.return_value = {
        name: (*contract, policies[name])
        for name, contract in installed.operation_contracts.items()
    }
    monkeypatch.setattr(bootstrap, "AzureApimPublisherClient", Mock(return_value=management))
    register = Mock()
    monkeypatch.setattr(bootstrap, "register_verified_program_upgrade", register)
    settings = Settings.model_construct(budget_delegation_trust={target_id: trust})
    if phase in {"changed_target", "checkpoint_conflict"}:
        message = ("Gateway configuration changed" if phase == "checkpoint_conflict"
                   else "approved parent changed")
        with pytest.raises(RuntimeError, match=message):
            bootstrap.configure_budget_delegation(repository, settings, target_id)
        register.assert_not_called()
        management._request.assert_not_called()
    else:
        bootstrap.configure_budget_delegation(repository, settings, target_id)
        if phase == "complete":
            register.assert_not_called()
        else:
            upgrade = register.call_args.args[2]
            upgrade.require_previous(publication_id, installed)
            assert upgrade.installation.program.scope == installed.program.scope
            assert upgrade.installation.operation_policies_sha256 == (
                installed.operation_policies_sha256
            )
            assert register.call_args.kwargs["expected_parent_etag"] == '"unit-etag"'
            policy = parse_policy(register.call_args.kwargs["parent_policy"])
            assert policy.find(
                ".//validate-azure-ad-token[@header-name='x-turnstile-delegation-token']",
            ) is not None
            legacy = policy.find(".//set-variable[@name='routeLegacyProgram']")
            assert legacy is not None
            assert legacy.get("value") == installed.program.program_sha256
            _validate_program_cutover(
                register.call_args.kwargs["parent_policy"], installed, upgrade.installation,
                cast(Any, SimpleNamespace(gateway_profile_id=target_id, settings=SimpleNamespace(
                    ledger_table_endpoint=descriptor.binding.ledger_table_endpoint,
                    ledger_table_name=descriptor.binding.ledger_table_name,
                ))), management,
            )
            original = descriptor.model_copy(update={
                "binding": descriptor.binding.model_copy(update={
                    "program_sha256": installed.program.program_sha256,
                }),
                "parent_policy_sha256": installed.parent_policy_sha256,
            })
            repository.get_gateway_profiles.return_value = [{
                "id": target_id, "config": {
                    "fixed_route_program_upgrade": upgrade.model_dump(mode="json"),
                },
            }]
            registration = preview_gateway_program_upgrade(
                target_id, repository, "unit-owner", Response(),
            )
            for tampered in (
                None, "behavior", "legacy", "predecessor", "unregistered", "approval_history",
                "unbound_current",
            ):
                candidate = parse_policy(register.call_args.kwargs["parent_policy"])
                approval = json.loads(json.dumps(registration))
                if tampered == "behavior":
                    granted = candidate.find(
                        ".//set-variable[@name='budgetDelegatedPerson'][@value='@(true)']",
                    )
                    assert granted is not None
                    granted.set("value", "@(false)")
                elif tampered in {"legacy", "predecessor"}:
                    name = (
                        "routeLegacyProgram" if tampered == "legacy" else "routePredecessorPrograms"
                    )
                    history = candidate.find(f".//set-variable[@name='{name}']")
                    assert history is not None
                    history.set("value", "f" * 64 if tampered == "legacy"
                                else json.dumps(["f" * 64]))
                elif tampered == "unregistered":
                    approval = None
                elif tampered == "approval_history":
                    approval["registration"]["installation"]["legacy_program_sha256"] = "f" * 64
                elif tampered == "unbound_current":
                    approval["current_installation"]["legacy_program_sha256"] = "f" * 64
                program_marker = candidate.find(".//set-variable[@name='routeProgram']")
                assert program_marker is not None
                program_marker.set("value", fixed_program_digest(
                    serialize_policy(candidate), policies, contracts,
                ))
                snapshot = GatewaySnapshot(
                    descriptor.binding.api_revision, parameters["apiProperties"]["value"],
                    serialize_policy(candidate),
                    {item["name"]: {"method": item["method"], "urlTemplate": item["path"]}
                     for item in parameters["fixedOperations"]["value"]}, policies,
                )
                if tampered:
                    with pytest.raises(DeploymentError):
                        deploy._validate_installed_fixed_program(
                            snapshot, original, inputs, outputs, trust, approval,
                        )
                else:
                    deploy._validate_installed_fixed_program(
                        snapshot, original, inputs, outputs, trust, approval,
                    )


@pytest.mark.parametrize("native_state", [
    "old", "candidate", "normalized", "foreign", "interrupted", "proof_written", "proof_expired",
    "entry_interrupted", "entry_normalized", "entry_proof_written", "entry_proof_expired",
    "entry_missing_checkpoint", "entry_changed_trust", "entry_changed_publication",
    "entry_changed_target", "entry_changed_revision", "entry_changed_source",
    "entry_changed_candidate", "entry_foreign",
    "deployment_normalized", "deployment_candidate", "deployment_foreign", "deployment_source",
    "deployment_source_target", "deployment_revision", "deployment_operation",
    "deployment_contract", "deployment_approval", "deployment_etag", "deployment_write_failure",
    "deployment_missing_source", "deployment_unreadable_source", "deployment_redacted_source",
    "deployment_source_descriptor", "deployment_path", "deployment_unknown", "deployment_mismatch",
    "deployment_healthy", "deployment_incomplete_target",
])
def test_real_delegation_cutover_xml_roundtrip_and_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_state: str,
) -> None:
    from contextlib import nullcontext
    from types import SimpleNamespace
    from typing import Any, cast
    from uuid import UUID
    from xml.etree import ElementTree as ET

    from pydantic import SecretStr

    from backend import bootstrap_storage_route as bootstrap
    from scripts import deploy
    from tests.backend.model_platform.control_plane_support import (
        GatewayControlPlaneService,
        bedrock_publication,
    )
    from turnstile_core.config import Settings
    from turnstile_core.domain.control_plane import (
        GatewayReleaseSpec,
        PublicationKind,
        PublicationStatus,
    )
    from turnstile_core.domain.storage_routes import (
        ActiveRouteHead,
        ConfigurationApproval,
        ProgramCapabilityProof,
        RouteSnapshot,
        catalog_digest,
        configuration_manifests,
        document_digest,
    )
    from turnstile_core.integrations.apim_storage_routes import fixed_policy_digest
    from turnstile_core.integrations.storage_route_projection import RouteProjectionConflict
    from turnstile_core.persistence.in_memory import InMemoryRepository
    from turnstile_core.services import storage_route_publisher as routes

    runtime = Mock(wraps=runtime_release_parameters)
    monkeypatch.setattr(sys.modules[__name__], "runtime_release_parameters", runtime)
    with monkeypatch.context() as setup:
        test_initial_fixed_program_binds_compiled_policies_before_registration(
            tmp_path, setup, False,
        )
        parameters = cast(Mock, deploy.deploy_template).call_args.args[3]["parameters"]
        deployment_inputs = cast(Mock, deploy.deploy_template).call_args.args[1]
        deployment_outputs = {**runtime.call_args.args[1], "apiUrl": "https://api-test.example.test"}
        descriptor = bootstrap.FixedInstallationDescriptor.model_validate_json(
            json.dumps(runtime.call_args.args[5]),
        )
        old_parent = parameters["parentPolicy"]["value"]
        trust = runtime.call_args.args[7]
    target = descriptor.registration.gateway_profile_id
    deployment = native_state.startswith("deployment_")
    arm_parameters = json.loads(json.dumps(parameters))
    if native_state == "deployment_source":
        arm_parameters["parentPolicy"]["value"] = old_parent.replace(
            'name="routeTrust"', 'name="drift"',
        )
    elif native_state == "deployment_source_target":
        arm_parameters["apimName"]["value"] = "other-apim"
    previous = bootstrap.installation_record(descriptor, "b" * 64)
    operations = {item["name"]: (item["method"], item["path"], item["policy"])
                  for item in parameters["fixedOperations"]["value"]}
    repository, management = Mock(), Mock()
    registration = Mock()
    repository.get_gateway_profiles.return_value = [{"id": target, "config": {}}]
    connection = Mock()
    connection.transaction.side_effect = lambda: nullcontext()
    repository._connection.side_effect = lambda: nullcontext(connection)
    def save_checkpoint(statement: str, parameters: Any) -> Mock:
        repository.get_gateway_profiles.return_value[0]["config"] = parameters[0].obj
        return Mock(fetchone=Mock(return_value={"id": target}))
    connection.execute.side_effect = save_checkpoint
    repository.effective_gateway_publication.return_value = {
        "id": str(UUID(int=75)),
        "resource_manifest": {"fixed_route_program": previous.model_dump()},
    }
    management._read_policy.return_value = (
        httpx.Response(200, headers={"ETag": '"old"'}), old_parent,
    )
    management.route_program_operations.return_value = operations
    settings = Settings.model_construct(budget_delegation_trust={target: trust.model_copy(
        update={"client_ids": (UUID(int=94),)},
    )})
    with monkeypatch.context() as capture:
        capture.setattr(bootstrap, "AzureApimPublisherClient", Mock(return_value=management))
        capture.setattr(bootstrap, "register_verified_program_upgrade", registration)
        capture.setattr(bootstrap, "apim_target_client_config_resolver", Mock())
        bootstrap.configure_budget_delegation(repository, settings, target)
    upgrade = registration.call_args.args[2]
    candidate = registration.call_args.kwargs["parent_policy"]
    repository.get_gateway_profiles.return_value = [{"id": target, "config": {}}]
    version = str(UUID(int=76))
    _, manifest, dependencies = configuration_manifests(
        previous.program.scope, version, (), {}, 1100,
    )
    approval = ConfigurationApproval(
        approval_id=str(UUID(int=77)), scope=previous.program.scope, route_version=version,
        generation=1, manifest_sha256=manifest, dependency_manifest_sha256=dependencies,
        catalog_sha256=catalog_digest(()), entry_count=0,
        required_program_sha256=previous.program.program_sha256, required_profiles=(),
        budget_epoch=str(descriptor.epoch), issued_epoch=1100, activate_before_epoch=1700,
    )
    snapshot = RouteSnapshot.prepare(approval, (), {}, 1100)
    head = ActiveRouteHead(approval=approval, activated_epoch=1100)
    source = GatewayControlPlaneService(InMemoryRepository()).publish(bedrock_publication(), "unit")
    source = source.model_copy(update={
        "id": UUID(int=75), "gateway_profile_id": target, "status": PublicationStatus.ACTIVE,
        "publication_kind": PublicationKind.ROUTE_RECONCILE, "generation": 1,
        "base_release_id": None, "apim_revision": previous.program.api_revision,
        "policy_sha256": previous.program.program_sha256,
        "desired_spec": GatewayReleaseSpec(
            gateway_profile_id=target, bindings=[], discovery_models=[],
        ),
        "resource_manifest": {"fixed_route_program": previous.model_dump(mode="json"),
                              "fixed_route_snapshot": snapshot.model_dump(mode="json"),
                              "fixed_route_head": head.model_dump(mode="json")},
    })
    repository.effective_gateway_publication.return_value = source.model_dump(mode="python")
    original_publication = source.model_dump(mode="python")
    repository.model_availability_proof_guard.side_effect = lambda *_, **__: nullcontext()
    proof = ProgramCapabilityProof(
        proof_id=str(UUID(int=78)), identity=previous.program,
        supported_profiles=previous.supported_profiles, issued_epoch=1050, expires_epoch=1170,
    )
    already_written = native_state in {
        "candidate", "proof_written", "proof_expired", "deployment_candidate",
    }
    current: dict[str, Any] = {"parent": candidate if already_written else
               ET.tostring(ET.fromstring(candidate), encoding="unicode")
               if native_state == "normalized" or deployment else
               '<policies><inbound><return-response /></inbound></policies>'
               if native_state == "foreign" else old_parent,
               "etag": '"old"', "proof": proof}
    if native_state == "deployment_healthy":
        current["parent"] = old_parent
    if native_state in {"proof_written", "proof_expired"}:
        current["proof"] = proof.model_copy(update={
            "identity": upgrade.installation.program,
                **({"issued_epoch": 900, "expires_epoch": 1020}
                    if native_state == "proof_expired" else {}),
        })
    writes: list[str] = []
    deployment_events: list[str] = []
    cutover_inputs: list[Any] = []
    arm_history_reads: list[str] = []
    def request(method: str, path: str, **kwargs: Any) -> httpx.Response:
        if method == "PUT":
            assert kwargs["extra_headers"] == {"If-Match": current["etag"]}
            current["parent"] = ET.tostring(ET.fromstring(
                kwargs["json_body"]["properties"]["value"],
            ), encoding="unicode")
            current["etag"] = '"new"'
            writes.append(path)
        return httpx.Response(200, headers={"ETag": current["etag"]})
    management._request.side_effect = request
    management._read_policy.side_effect = lambda *_: (
        httpx.Response(200, headers={"ETag": current["etag"]}), current["parent"],
    )
    management.current_revision.return_value = previous.program.api_revision
    management.revision_api_policy.side_effect = lambda *_: current["parent"]
    entry = native_state.startswith("entry_")
    registration_failure = [native_state in {"entry_proof_written", "entry_proof_expired"}]
    reject = [native_state in {"interrupted", "deployment_write_failure"}
              or entry and not registration_failure[0]]
    def probe(request: httpx.Request) -> httpx.Response:
        if request.url.host == "management.azure.com":
            if request.method == "GET":
                arm_history_reads.append(str(request.url))
            return httpx.Response(200, headers={"ETag": current["etag"]}, json={"properties": {
                "provisioningState": "Succeeded", "parameters": {
                    name: {} if name in {"parentPolicy", "apiProperties", "fixedOperations"}
                    else value for name, value in arm_parameters.items()
                },
            }})
        if request.url.host == "control-test.azurewebsites.net":
            import azure.functions as func

            from functions.control_plane import function_app as control_plane

            assert deployment_events[-1] == "indexing"
            assert "packages" in deployment_events and "started" in deployment_events
            assert request.headers["x-functions-key"] == "offline-function-key"
            cutover_inputs.append(json.loads(request.content))
            result = control_plane.cutover_gateway_program(func.HttpRequest(
                method="POST", url=str(request.url), headers=dict(request.headers),
                body=request.content, route_params={"target_id": str(target)},
            ))
            deployment_events.append("cutover")
            if native_state == "deployment_unknown":
                raise httpx.ReadTimeout("Injected unknown cutover result", request=request)
            if native_state == "deployment_mismatch":
                return httpx.Response(200, json={"unconfirmed": True})
            return httpx.Response(result.status_code, content=result.get_body())
        is_new = fixed_policy_digest(current["parent"]) == upgrade.installation.parent_policy_sha256
        if reject[0] and is_new:
            reject[0] = False
            return httpx.Response(503)
        program = upgrade.installation.program if is_new else previous.program
        headers = {"abi": "2", "nonce": request.headers["x-turnstile-route-probe"],
                   "target": program.scope.target_id, "api": program.scope.api_id,
                   "revision": program.api_revision, "gateway": program.scope.gateway_id,
                   "instance": program.instance_id, "program": program.program_sha256,
                   "trust": program.trust_binding_sha256}
        if request.url.path.endswith("/configuration"):
            headers.update(version=version, generation="1", epoch=str(descriptor.epoch))
        return httpx.Response(204, headers={"x-turnstile-route-" + name: value
                                          for name, value in headers.items()})
    projection = Mock()
    def read_proof(identity: Any) -> Any:
        if current["proof"].identity != identity:
            raise RouteProjectionConflict("ROUTE_PROGRAM_PROOF_IDENTITY_CHANGED")
        return current["proof"], 'W/"proof"'
    projection.read_program_proof.side_effect = read_proof
    projection.read_active.return_value = (head, 'W/"head"')
    projection.publish_upgraded_program_proof.side_effect = lambda *args: current.update(
        proof=args[2],
    )
    projection.publish_program_proof.side_effect = lambda *args: current.update(proof=args[0])
    configurations = Mock()
    configurations.resolve.return_value = SimpleNamespace(
        gateway_profile_id=target, route_target_identity_sha256=previous.target_identity_sha256,
        settings=SimpleNamespace(apim_api_id=previous.program.scope.api_id,
            apim_gateway_url=previous.gateway_endpoint,
            apim_probe_subscription_id=previous.publisher_subscription_id,
            apim_probe_subscription_key=SecretStr("unit-key"),
            ledger_table_endpoint=descriptor.binding.ledger_table_endpoint,
            ledger_table_name=descriptor.binding.ledger_table_name),
    )
    recorded: list[Any] = []
    def record(value: Any, digest: str, **options: Any) -> None:
        options["before_record"]()
        if registration_failure[0]:
            registration_failure[0] = False
            raise ValueError("Injected registration failure")
        recorded.append(value)
    repository.record_fixed_program_upgrade.side_effect = record
    real_client = httpx.Client
    monkeypatch.setattr(routes, "AzureApimPublisherClient", Mock(return_value=management))
    monkeypatch.setattr(routes, "TableRouteProjection", Mock(return_value=projection))
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        **kwargs, transport=httpx.MockTransport(probe),
    ))
    entry_registration = Mock(side_effect=lambda *args, **kwargs: (
        routes.register_verified_program_upgrade(*args, **kwargs, clock=lambda: 1100)
    ))
    monkeypatch.setattr(bootstrap, "AzureApimPublisherClient", Mock(return_value=management))
    monkeypatch.setattr(bootstrap, "register_verified_program_upgrade", entry_registration)
    monkeypatch.setattr(bootstrap, "apim_target_client_config_resolver", lambda *_: configurations)
    def cutover() -> None:
        if entry:
            bootstrap.configure_budget_delegation(repository, settings, target)
            return
        routes.register_verified_program_upgrade(
            repository, configurations, upgrade, document_digest({}), clock=lambda: 1100,
            parent_policy=candidate, expected_parent_etag=current["etag"],
        )
    if deployment:
        import getpass

        from fastapi import Response

        from backend.http.model_platform import preview_gateway_program_upgrade
        from functions.control_plane import function_app as control_plane
        from scripts.apim_upgrade import AzureUpgradeBackend, GatewaySnapshot

        source_path = tmp_path / "original-fixed-program.outputs.json"
        deploy._write_private_json(source_path, {
            "pendingFixedBootstrap": descriptor.model_dump(mode="json"),
            "pendingFixedProgramParameters": {"parameters": arm_parameters},
        })
        if native_state in {
            "deployment_redacted_source", "deployment_source_descriptor",
            "deployment_incomplete_target",
        }:
            retained = json.loads(source_path.read_text())
            if native_state == "deployment_redacted_source":
                del retained["pendingFixedProgramParameters"]["parameters"]["parentPolicy"]["value"]
            elif native_state == "deployment_incomplete_target":
                del retained["pendingFixedProgramParameters"]["parameters"]["apimName"]
            else:
                retained["pendingFixedBootstrap"]["registration"]["api_id"] = "other"
            deploy._write_private_json(source_path, retained)
        elif native_state in {"deployment_unreadable_source", "deployment_healthy"}:
            source_path = tmp_path / "absent-original.outputs.json"
        runner = Mock(spec=CommandRunner)
        runner.run_json.side_effect = lambda command: (
            {"default": "offline-function-key"} if "keys" in command
            else {"accessToken": "offline-token"}
        )
        if native_state == "deployment_foreign":
            current["parent"] = candidate.replace('name="routeTrust"', 'name="drift"')
        elif native_state == "deployment_operation":
            operation = operations["chat-completions"]
            operations["chat-completions"] = (
                operation[0], operation[1], "<policies><inbound /></policies>",
            )
        elif native_state == "deployment_contract":
            operation = operations["chat-completions"]
            operations["chat-completions"] = ("GET", operation[1], operation[2])
        monkeypatch.setattr(AzureUpgradeBackend, "read", lambda *_: GatewaySnapshot(
            "other" if native_state == "deployment_revision" else previous.program.api_revision,
            {**parameters["apiProperties"]["value"],
             **({"path": "other"} if native_state == "deployment_path" else {})}, current["parent"],
            {name: {"method": method, "urlTemplate": path}
             for name, (method, path, _) in operations.items()},
            {name: policy for name, (_, _, policy) in operations.items()},
        ))
        monkeypatch.setattr(deploy, "current_app_settings", lambda *_: {
            "TURNSTILE_FIXED_BOOTSTRAP_DESCRIPTOR": descriptor.model_dump_json(),
        })
        monkeypatch.setattr(deploy, "deployment_budget_delegation", lambda *_: (
            settings.budget_delegation_trust[target]
        ))
        monkeypatch.setattr(getpass, "getpass", lambda *_: "offline-owner-password")
        def approved_preview(*args: Any) -> Any:
            result = preview_gateway_program_upgrade(target, repository, "unit-owner", Response())
            if native_state == "deployment_approval":
                result["current_installation"]["parent_policy_sha256"] = "f" * 64
            return result
        monkeypatch.setattr(deploy, "verify_initial_fixed_program", approved_preview)
        def deployment_args(action: str) -> Any:
            return deploy.build_parser().parse_args([
                action, "--subscription", deployment_inputs.subscription,
                "--parameters", str(deployment_inputs.parameters_path),
                "--state", str(deployment_inputs.state_path), "--yes",
                *([] if native_state == "deployment_missing_source"
                  else ["--fixed-program-source", str(source_path)]),
            ])
        if native_state in {
            "deployment_foreign", "deployment_source", "deployment_source_target",
            "deployment_revision", "deployment_operation", "deployment_contract",
            "deployment_approval",
            "deployment_missing_source", "deployment_unreadable_source",
            "deployment_redacted_source",
            "deployment_source_descriptor", "deployment_path",
            "deployment_incomplete_target",
        }:
            monkeypatch.setattr(deploy, "require_prerequisites", lambda *_: None)
            monkeypatch.setattr(deploy, "validate_source_snapshot", lambda *_: None)
            monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: deployment_outputs)
            unavailable = "requires --fixed-program-source" if (
                native_state == "deployment_missing_source"
            ) else "recovery source" if native_state in {
                "deployment_unreadable_source", "deployment_redacted_source",
                "deployment_source_descriptor", "deployment_incomplete_target",
            } else None
            with pytest.raises(DeploymentError, match=unavailable):
                deploy.execute(deployment_args("plan"), runner)
            assert not writes and not recorded and not deployment_events
            assert not arm_history_reads
            return
        recovery = deploy.gateway_upgrade(
            runner, deployment_inputs, deployment_outputs, "check",
            fixed_program_source=source_path,
        )
        assert not writes and not recorded
        if native_state == "deployment_healthy":
            assert recovery is None
        else:
            assert recovery is not None
            assert recovery[0].upgrade == upgrade
            assert recovery[0].parent_policy == candidate
        monkeypatch.setattr(control_plane, "get_settings", lambda: Settings.model_construct(
            control_plane_enabled=True,
        ))
        monkeypatch.setattr(control_plane, "create_repository", lambda *_: repository)
        monkeypatch.setattr(control_plane, "apim_target_client_config_resolver", lambda *_: (
            configurations
        ))
        monkeypatch.setattr(
            control_plane, "register_verified_program_upgrade", lambda *args, **kwargs: (
                routes.register_verified_program_upgrade(*args, **kwargs, clock=lambda: 1100)
            ),
        )
        def finish_registration(value: Any, digest: str, **options: Any) -> None:
            record(value, digest, **options)
            repository.get_gateway_profiles.return_value[0]["config"] = {
                "fixed_route_program_upgrade": value,
            }
        repository.record_fixed_program_upgrade.side_effect = finish_registration
        monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: deployment_outputs)
        monkeypatch.setattr(deploy, "load_or_create_secret_material", lambda *_, **kwargs: (
            Mock(owner_password="offline-owner-password")
        ))
        for name in (
            "require_prerequisites", "validate_source_snapshot", "what_if_resource_group",
            "deploy_resource_group_template", "what_if", "build_and_start_observer",
            "wait_for_observer_health", "verify_owner_login", "verify_telemetry_function_health",
            "_confirm_deployment", "_write_outputs",
        ):
            monkeypatch.setattr(deploy, name, Mock())
        completion = Mock()
        monkeypatch.setattr(deploy, "_write_outputs", completion)
        printed = Mock()
        monkeypatch.setattr(deploy, "print", printed, raising=False)
        for name in (
            "deployment_parameters", "runtime_release_parameters", "observer_parameters",
            "build_packages", "deploy_template",
        ):
            monkeypatch.setattr(deploy, name, Mock(return_value={}))
        for name in ("source_version", "observer_source_version", "frontend_asset"):
            monkeypatch.setattr(deploy, name, lambda *_: "offline-fixed-runtime")
        monkeypatch.setattr(deploy, "deployment_outputs", lambda *_: {
            "webAppUrl": "https://observer.example.test",
        })
        def uploaded(*args: Any) -> None:
            assert not writes and not recorded
            deployment_events.append("packages")
            if native_state == "deployment_etag":
                current["etag"] = '"changed"'
        monkeypatch.setattr(deploy, "deploy_packages", uploaded)
        monkeypatch.setattr(deploy, "restart_runtime_apps", lambda *_: (
            deployment_events.append("started")
        ))
        monkeypatch.setattr(deploy, "verify_function_indexing", lambda *_: (
            deployment_events.append("indexing")
        ))
        def healthy(*args: Any, **kwargs: Any) -> None:
            assert len(recorded) == (native_state != "deployment_healthy")
            deployment_events.append("healthy")
        monkeypatch.setattr(deploy, "wait_for_health", healthy)
        for action in ("plan", "deploy"):
            arguments = deployment_args(action)
            if action == "deploy" and native_state in {
                "deployment_etag", "deployment_write_failure", "deployment_unknown",
                "deployment_mismatch",
            }:
                expected_error = (httpx.ReadTimeout if native_state == "deployment_unknown"
                                  else DeploymentError if native_state == "deployment_mismatch"
                                  else httpx.HTTPStatusError)
                with pytest.raises(expected_error):
                    deploy.execute(arguments, runner)
                assert deployment_events == ["packages", "started", "indexing", "cutover"]
                assert len(cutover_inputs) == 1
                assert len(recorded) == (
                    native_state in {"deployment_unknown", "deployment_mismatch"}
                )
                assert len(writes) == (native_state != "deployment_etag")
                completion.assert_not_called()
                assert all(call.args != ("Turnstile deployment completed.",)
                           for call in printed.call_args_list)
                assert repository.effective_gateway_publication.return_value == original_publication
                assert not arm_history_reads
                return
            deploy.execute(arguments, runner)
            if action == "plan":
                assert not writes and not recorded and not deployment_events
                completion.assert_not_called()
        if native_state == "deployment_healthy":
            assert deployment_events == ["packages", "started", "healthy", "indexing"]
            assert not writes and not recorded and not cutover_inputs
            assert not arm_history_reads
            return
        assert deployment_events == ["packages", "started", "indexing", "cutover", "healthy"]
        assert len(recorded) == len(cutover_inputs) == 1
        assert len(writes) == (native_state != "deployment_candidate")
        assert recovery is not None
        assert cutover_inputs[0] == recovery[0].model_dump(mode="json")
        assert fixed_policy_digest(current["parent"]) == upgrade.installation.parent_policy_sha256
        assert repository.effective_gateway_publication.return_value == original_publication
        assert "recorded_usage" not in str(repository.mock_calls)
        assert not arm_history_reads
        return
    if native_state == "foreign":
        with pytest.raises(ValueError):
            cutover()
        assert not writes and not recorded
        return
    if native_state == "interrupted" or entry:
        message = "registration failure" if registration_failure[0] else "authenticated probe"
        with pytest.raises(ValueError, match=message):
            cutover()
        assert not recorded and len(writes) == 1
    if entry:
        checkpoint = repository.get_gateway_profiles.return_value[0]["config"][
            "budget_delegation_cutover"
        ]
        assert checkpoint["parent_policy"] == old_parent
        assert checkpoint["candidate_parent_policy_sha256"] == (
            upgrade.installation.parent_policy_sha256
        )
        if native_state == "entry_normalized":
            current["parent"] = ET.tostring(ET.fromstring(candidate), encoding="unicode")
            current["etag"] = '"normalized"'
        elif native_state == "entry_proof_expired":
            current["proof"] = current["proof"].model_copy(update={
                "issued_epoch": 900, "expires_epoch": 1020,
            })
        elif native_state == "entry_missing_checkpoint":
            del repository.get_gateway_profiles.return_value[0]["config"][
                "budget_delegation_cutover"
            ]
        elif native_state == "entry_changed_trust":
            settings = settings.model_copy(update={"budget_delegation_trust": {
                target: trust.model_copy(update={"client_ids": (UUID(int=95),)}),
            }})
        elif native_state == "entry_changed_publication":
            repository.effective_gateway_publication.return_value["id"] = str(UUID(int=95))
        elif native_state in {"entry_changed_target", "entry_changed_revision"}:
            identity = repository.effective_gateway_publication.return_value[
                "resource_manifest"
            ]["fixed_route_program"]["program"]
            if native_state == "entry_changed_target":
                identity["scope"]["target_id"] = str(UUID(int=95))
            else:
                identity["api_revision"] = "other"
        elif native_state == "entry_changed_source":
            checkpoint["parent_policy"] = old_parent.replace('name="routeTrust"', 'name="drift"')
        elif native_state == "entry_changed_candidate":
            checkpoint["candidate_parent_policy_sha256"] = "f" * 64
        elif native_state == "entry_foreign":
            current["parent"] = candidate.replace('name="routeTrust"', 'name="drift"')
        if native_state in {
            "entry_missing_checkpoint", "entry_changed_trust", "entry_changed_publication",
            "entry_changed_target", "entry_changed_revision", "entry_changed_source",
            "entry_changed_candidate", "entry_foreign",
        }:
            with pytest.raises(RuntimeError, match="approved parent changed"):
                cutover()
            assert entry_registration.call_count == 1
            assert not recorded and len(writes) == 1
            return
    recovery_etag = current["etag"]
    cutover()
    assert len(recorded) == 1
    assert fixed_policy_digest(current["parent"]) == upgrade.installation.parent_policy_sha256
    assert len(writes) == (0 if already_written else 2 if native_state == "entry_normalized" else 1)
    if entry:
        assert entry_registration.call_count == 2
        first, second = entry_registration.call_args_list
        assert first.args[2] == second.args[2] == upgrade
        assert first.kwargs["parent_policy"] == second.kwargs["parent_policy"] == candidate
        assert first.args[3] == second.args[3]
        assert second.kwargs["expected_parent_etag"] == recovery_etag


@pytest.mark.parametrize("phase", ["complete", "failed", "running", "changed_target"])
def test_partial_fixed_installation_reuses_bound_checkpoint_without_policy_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    from scripts import deploy
    from scripts.apim_upgrade import AzureUpgradeBackend, GatewaySnapshot

    runtime = Mock(wraps=runtime_release_parameters)
    monkeypatch.setattr(sys.modules[__name__], "runtime_release_parameters", runtime)
    with monkeypatch.context() as initialization:
        test_initial_fixed_program_binds_compiled_policies_before_registration(
            tmp_path, initialization, False,
        )
        from typing import cast

        applied = cast(Mock, deploy.deploy_template)
        inputs = applied.call_args.args[1]
        parameters = applied.call_args.args[3]["parameters"]
        descriptor = runtime.call_args.args[5]
        initial_snapshot = cast(Mock, AzureUpgradeBackend.read).return_value
    saved = json.loads(inputs.state_path.with_suffix(".outputs.json").read_text())
    values = {name: entry["value"] for name, entry in parameters.items()}
    current = GatewaySnapshot(
        values["revision"], values["apiProperties"], values["parentPolicy"],
        {item["name"]: {"method": item["method"], "urlTemplate": item["path"],
                        "templateParameters": []} for item in values["fixedOperations"]},
        {item["name"]: item["policy"] for item in values["fixedOperations"]},
    )
    if phase != "complete":
        current = initial_snapshot
    if phase == "changed_target":
        saved["pendingFixedProgramParameters"]["parameters"]["apimName"]["value"] = "other-apim"
    monkeypatch.setattr(AzureUpgradeBackend, "read", Mock(return_value=current))
    writes = Mock()
    monkeypatch.setattr(deploy, "what_if", writes)
    monkeypatch.setattr(deploy, "deploy_template", writes)
    runner = Mock(spec=CommandRunner)
    runner.run_json.return_value = {"accessToken": "offline-token"}
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        **kwargs, transport=httpx.MockTransport(lambda _: httpx.Response(
            200, json={"sku": {"name": "StandardV2"}, "properties": {
                "provisioningState": "Running" if phase == "running" else "Failed",
            }},
        )),
    ))

    if phase in {"running", "changed_target"}:
        with pytest.raises(DeploymentError):
            initialize_fixed_program(runner, inputs, saved, {})
    else:
        assert initialize_fixed_program(runner, inputs, saved, {}) == descriptor
    assert writes.call_count == (2 if phase == "failed" else 0)


@pytest.mark.parametrize("wrong_binding", [False, True])
def test_initial_fixed_program_readiness_requires_verified_binding_and_logout(
    monkeypatch: pytest.MonkeyPatch,
    wrong_binding: bool,
) -> None:
    calls: list[str] = []
    client_factory = httpx.Client

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.method == "POST":
            return httpx.Response(200, json={})
        return httpx.Response(
            200,
            json={
                "current_installation": {
                    "program": {
                        "program_sha256": "b" * 64 if wrong_binding else "a" * 64,
                        "scope": {"target_id": "unit-target"},
                    },
                    "model_additions_enabled": True,
                }
            },
        )

    monkeypatch.setattr(
        "scripts.deploy.httpx.Client",
        lambda **kwargs: client_factory(
            **kwargs,
            transport=httpx.MockTransport(respond),
        ),
    )
    descriptor = {
        "registration": {"gateway_profile_id": "unit-target"},
        "binding": {"program_sha256": "a" * 64},
    }
    arguments = ("https://api.example.test", "owner@example.test", "offline", descriptor)
    if wrong_binding:
        with pytest.raises(DeploymentError, match="binding differs"):
            verify_initial_fixed_program(*arguments)
    else:
        verify_initial_fixed_program(*arguments)
    assert calls == [
        "/api/v1/auth/login",
        "/api/v1/model-management/gateways/unit-target/program-upgrades/preview",
        "/api/v1/auth/logout",
    ]


@pytest.mark.parametrize("failure", ["once", "always", "401", "403", "preview-pending"])
def test_initial_fixed_program_login_retries_within_shared_deadline(
    monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    elapsed = [0.0]
    calls = {"login": 0, "preview": 0, "logout": 0}
    client_factory = httpx.Client

    def advance(seconds: float) -> None:
        elapsed[0] += seconds

    def respond(request: httpx.Request) -> httpx.Response:
        timeout = request.extensions["timeout"]["read"]
        assert 0 < timeout <= 15
        if request.url.path.endswith("/auth/login"):
            calls["login"] += 1
            if failure == "always" or (
                failure in {"once", "preview-pending"} and calls["login"] == 1
            ):
                advance(timeout)
                raise httpx.ReadTimeout("Offline transient login timeout", request=request)
            if failure in {"401", "403"}:
                return httpx.Response(int(failure), json={"detail": "Rejected"})
            return httpx.Response(
                200, json={}, headers={"Set-Cookie": "offline-owner=verified; Path=/"},
            )
        if request.url.path.endswith("/auth/logout"):
            calls["logout"] += 1
            return httpx.Response(204)
        calls["preview"] += 1
        assert request.headers["Cookie"] == "offline-owner=verified"
        if failure == "preview-pending":
            advance(timeout)
            return httpx.Response(409, json={"detail": "A current fixed program is required"})
        return httpx.Response(200, json={"current_installation": {
            "program": {"program_sha256": "a" * 64, "scope": {"target_id": "unit-target"}},
            "model_additions_enabled": True,
        }})

    monkeypatch.setattr("scripts.deploy.time.monotonic", lambda: elapsed[0])
    monkeypatch.setattr("scripts.deploy.time.sleep", advance)
    monkeypatch.setattr("scripts.deploy.httpx.Client", lambda **kwargs: client_factory(
        **kwargs, transport=httpx.MockTransport(respond),
    ))
    descriptor = {
        "registration": {"gateway_profile_id": "unit-target"},
        "binding": {"program_sha256": "a" * 64},
    }
    arguments = ("https://offline.example.test", "owner@example.test", "offline", descriptor)
    if failure in {"401", "403"}:
        with pytest.raises(httpx.HTTPStatusError) as rejected:
            verify_initial_fixed_program(*arguments)
        assert rejected.value.response.status_code == int(failure)
        assert calls == {"login": 1, "preview": 0, "logout": 0}
    elif failure in {"always", "preview-pending"}:
        with pytest.raises(DeploymentError):
            verify_initial_fixed_program(*arguments)
        assert elapsed[0] == 180
        assert calls["logout"] == (1 if failure == "preview-pending" else 0)
    else:
        verify_initial_fixed_program(*arguments)
        assert calls == {"login": 2, "preview": 1, "logout": 1}
        assert elapsed[0] < 180


def test_platform_only_outputs_do_not_resume_runtime_release() -> None:
    platform_outputs = {
        "apiName": "api-turnstile-test",
        "controlPlaneFunctionName": "func-turnstile-control-test",
    }
    completed_outputs = {
        **platform_outputs,
        "acrName": "crturnstiletest",
        "webAppName": "obs-turnstile-test",
        "webAppUrl": "https://obs-turnstile-test.azurewebsites.net",
        "adapterKeyNamedValueName": "turnstile-observer-key",
    }

    assert observer_outputs_complete(platform_outputs) is False
    assert observer_outputs_complete(completed_outputs) is True


@pytest.mark.parametrize("action", ["plan", "deploy"])
@pytest.mark.parametrize("observer_complete", [False, True])
def test_resume_previews_only_available_runtime_and_preserves_release_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    observer_complete: bool,
) -> None:
    from scripts import deploy

    arguments = build_parser().parse_args([
        action, "--subscription", "subscription", "--parameters",
        str(_parameters(tmp_path / "parameters.json")), "--state",
        str(tmp_path / "state.json"), "--yes",
    ])
    platform_outputs = {
        "resourceGroupName": "turnstile-test",
        "apiName": "api-turnstile-test",
        "apiUrl": "https://api.example.test",
        "controlPlaneFunctionName": "func-turnstile-control-test",
        "apimName": "shared-apim",
        "apimPrincipalId": "apim-principal",
        "apimGatewayUrl": "https://apim.example.test",
        "gatewayApiPath": "https://apim.example.test/turnstile/llm",
        "eventHubNamespaceName": "events-turnstile-test",
        "apimDashboardSubscriptionId": "saved-dashboard",
        "apimProbeSubscriptionId": "saved-probe",
    }
    observer_outputs = {
        "acrName": "crturnstiletest",
        "webAppName": "obs-turnstile-test",
        "webAppUrl": "https://observer.example.test",
        "adapterKeyNamedValueName": "turnstile-observer-key",
    }
    saved_outputs = {
        **platform_outputs,
        **(observer_outputs if observer_complete else {}),
    }
    material = deploy.SecretMaterial(
        {name: f"test-{name}" for name in deploy.STATE_SECRET_NAMES},
        "a-secure-owner-password",
    )
    previews: list[tuple[str, dict[str, object]]] = []
    writes: list[dict[str, object]] = []
    settings_reads: list[str] = []
    events: list[str] = []
    role_calls: list[str] = []

    def ensure_roles(name: str):
        def ensure(*_args: object, **_kwargs: object) -> set[str]:
            role_calls.append(name)
            events.append(name)
            return {f"role-assignment-{name}"}

        return ensure

    def current_settings(
        _runner: object, _inputs: object, app_name: str
    ) -> dict[str, str]:
        settings_reads.append(app_name)
        return {"EXISTING_SETTING": app_name}

    def preview(
        _runner: object, _inputs: object, template: Path,
        document: dict[str, object], _name: str,
    ) -> None:
        previews.append((template.name, document["parameters"]))

    def apply_template(
        _runner: object, _inputs: object, template: Path,
        _document: object, _name: str,
    ) -> dict[str, str]:
        events.append(template.parent.name + "/" + template.name)
        if template.parent.name == "envoy-cache-adapter":
            return observer_outputs
        # ARM may not repeat saved runtime identifiers on a platform-only rerun.
        return {"resourceGroupName": "turnstile-test"}

    def checkpoint(_inputs: object, outputs: Mapping[str, object]) -> None:
        writes.append(dict(outputs))
        events.append("checkpoint")

    def packages(*_args: object) -> dict[str, Path]:
        events.append("packages")
        return {}

    monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: saved_outputs)
    monkeypatch.setattr(deploy, "load_or_create_secret_material", lambda *_, **__: material)
    monkeypatch.setattr(deploy, "current_app_settings", current_settings)
    monkeypatch.setattr(deploy, "what_if_resource_group", preview)
    monkeypatch.setattr(deploy, "deploy_resource_group_template", apply_template)
    monkeypatch.setattr(deploy, "deployment_outputs", lambda result: result)
    monkeypatch.setattr(deploy, "_write_outputs", checkpoint)
    monkeypatch.setattr(deploy, "build_packages", packages)
    monkeypatch.setattr(deploy, "source_version", lambda *_: "source-version")
    monkeypatch.setattr(deploy, "observer_source_version", lambda *_: "observer-version")
    monkeypatch.setattr(deploy, "frontend_asset", lambda: "assets/index-test.js")
    for name in (
        "require_prerequisites", "validate_source_snapshot", "gateway_upgrade",
        "validate_shared_storage_account", "ensure_shared_storage_resources",
        "validate_existing_dependencies", "deploy_packages", "build_and_start_observer",
        "wait_for_observer_health", "restart_runtime_apps", "wait_for_health",
        "verify_frontend_asset", "verify_owner_login", "verify_function_indexing",
        "verify_telemetry_function_health",
    ):
        monkeypatch.setattr(deploy, name, lambda *_, **__: None)
    role_helpers = (
        "ensure_shared_storage_roles", "ensure_foundry_role",
        "ensure_adopted_dependency_roles", "ensure_observer_event_hub_role",
    )
    for name in role_helpers:
        monkeypatch.setattr(deploy, name, ensure_roles(name))

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Resume must not repeat fresh-platform capability checks")

    monkeypatch.setattr(deploy, "validate_flex_consumption_capabilities", forbidden)
    monkeypatch.setattr(deploy, "validate_postgres_capabilities", forbidden)
    monkeypatch.setattr(deploy, "ensure_adopted_apim_prerequisite_role", forbidden)

    execute(arguments, CommandRunner())

    assert [name for name, _ in previews[:2]] == [
        "main.bicep", "runtime-release.bicep" if observer_complete else "main.bicep",
    ]
    base_parameters = previews[0][1]
    for name in ("provisionPostgres", "provisionApimService", "deployApimBootstrap"):
        assert base_parameters[name]["value"] is False
    releases = [parameters for name, parameters in previews if name == "runtime-release.bicep"]
    assert len(releases) == int(observer_complete) + int(action == "deploy")
    for parameters in releases:
        assert parameters["dashboardSubscriptionId"]["value"] == "saved-dashboard"
        assert parameters["probeSubscriptionId"]["value"] == "saved-probe"
        assert parameters["currentApiSettings"]["value"] == {
            "EXISTING_SETTING": platform_outputs["apiName"],
        }
        assert parameters["currentControlPlaneSettings"]["value"] == {
            "EXISTING_SETTING": platform_outputs["controlPlaneFunctionName"],
        }
    assert settings_reads == [
        platform_outputs["apiName"], platform_outputs["controlPlaneFunctionName"],
    ] * len(releases)
    if action == "plan":
        assert events == []
        assert writes == []
        assert role_calls == []
    else:
        assert events.index("checkpoint") < events.index("packages")
        assert writes[0] == saved_outputs
        assert role_calls == list(role_helpers)
        for name in role_helpers[:3]:
            assert events.index("checkpoint") < events.index(name) < events.index("packages")
        assert writes[1] == {
            **saved_outputs,
            "managedRoleAssignmentIds": sorted(
                f"role-assignment-{name}" for name in role_helpers[:3]
            ),
        }
        assert events.index("envoy-cache-adapter/main.bicep") < events.index(
            "ensure_observer_event_hub_role"
        ) < events.index("infra/runtime-release.bicep")
        assert writes[-1] == {
            **saved_outputs,
            **observer_outputs,
            "managedRoleAssignmentIds": sorted(
                f"role-assignment-{name}" for name in role_helpers
            ),
        }


def test_temporary_parameter_file_is_private_and_deleted(tmp_path: Path) -> None:
    with temporary_parameter_file({"parameters": {}}, tmp_path) as path:
        assert path.is_file()
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not path.exists()


def test_observer_names_are_stable_and_azure_safe(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "00000000-0000-0000-0000-000000000001",
        _parameters(tmp_path / "parameters.json"),
    )

    acr_name, web_app_name = observer_names(inputs)

    assert acr_name == observer_names(inputs)[0]
    assert acr_name.isalnum() and acr_name.islower() and len(acr_name) <= 50
    assert web_app_name.startswith("obs-turnstile-") and len(web_app_name) <= 60
    assert observer_plan_name(inputs).startswith("plan-obs-")
    assert "turnstile" in observer_plan_name(inputs)
    assert len(observer_plan_name(inputs)) <= 40


def test_observer_parameters_reuse_apps_but_isolate_the_observer_plan(
    tmp_path: Path,
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    document = observer_parameters(
        inputs,
        {
            "resourceGroupName": "turnstile-test",
            "apimResourceGroupName": "shared-apim",
            "appServicePlanName": "plan-turnstile-test",
            "eventHubNamespaceName": "eh-turnstile-test",
            "apimName": "apim-turnstile-test",
            "observerAdapterKeyNamedValueName": "turnstile-test-observer-key",
        },
        material,
        "abc123",
        existing_observer={
            "acrName": "acrexisting",
            "webAppName": "observer-existing",
            "observerAppServicePlanName": "plan-observer-existing",
        },
    )

    assert document["parameters"]["acrName"]["value"] == "acrexisting"
    assert document["parameters"]["webAppName"]["value"] == "observer-existing"
    assert document["parameters"]["apimResourceGroupName"]["value"] == "shared-apim"
    assert document["parameters"]["adapterKeyNamedValueName"]["value"] == (
        "turnstile-test-observer-key"
    )
    assert (
        document["parameters"]["appServicePlanName"]["value"]
        == observer_plan_name(inputs)
    )
    assert document["parameters"]["appServicePlanName"]["value"] != "plan-turnstile-test"
    assert document["parameters"]["appServicePlanSkuName"]["value"] == "P0v3"
    assert document["parameters"]["appServicePlanWorkerCount"]["value"] == 1
    assert document["parameters"]["provisionAcr"]["value"] is False
    assert document["parameters"]["manageEventHubRoleAssignment"]["value"] is True


def test_observer_parameters_use_adopted_event_hub_without_bicep_rbac(
    tmp_path: Path,
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    document = observer_parameters(
        inputs,
        {
            "resourceGroupName": "turnstile-test",
            "apimName": "shared-apim",
            "eventHubNamespaceName": "legacy-fallback",
            "dependencyResources": {
                "eventHub": {
                    "namespaceName": "shared-events",
                    "name": "shared-usage",
                    "provisioned": False,
                }
            },
        },
        material,
        "abc123",
    )

    assert document["parameters"]["eventHubNamespaceName"]["value"] == (
        "shared-events"
    )
    assert document["parameters"]["eventHubName"]["value"] == "shared-usage"
    assert document["parameters"]["manageEventHubRoleAssignment"]["value"] is False


@pytest.mark.parametrize(
    ("existing_observer", "expected_acr_group"),
    (
        (None, "turnstile-test"),
        ({"acrName": "acrexisting", "webAppName": "observer-existing"}, "turnstile-test"),
        (
            {
                "acrName": "acrexisting",
                "webAppName": "observer-existing",
                "acrResourceGroupName": "turnstile-test",
            },
            "turnstile-test",
        ),
    ),
)
def test_observer_registry_scope_is_independent_of_reused_apim(
    tmp_path: Path,
    existing_observer: dict[str, str] | None,
    expected_acr_group: str,
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    document = observer_parameters(
        inputs,
        {
            "resourceGroupName": "turnstile-test",
            "apimResourceGroupName": "shared-apim",
            "eventHubNamespaceName": "eh-turnstile-test",
            "apimName": "apim-shared",
        },
        material,
        "abc123",
        existing_observer=existing_observer,
    )

    assert document["parameters"]["acrResourceGroupName"]["value"] == expected_acr_group
    assert document["parameters"]["apimResourceGroupName"]["value"] == "shared-apim"


def test_deterministic_zip_has_stable_bytes_and_order(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "b.txt").write_text("b", encoding="utf-8")
    (source / "a.txt").write_text("a", encoding="utf-8")
    (source / "b.txt").chmod(0o600)
    (source / "a.txt").chmod(0o700)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    deterministic_zip(source, first)
    deterministic_zip(source, second)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["a.txt", "b.txt"]
        expected_executable_mode = 0o644 if os.name == "nt" else 0o755
        assert (
            stat.S_IMODE(archive.getinfo("a.txt").external_attr >> 16)
            == expected_executable_mode
        )
        assert stat.S_IMODE(archive.getinfo("b.txt").external_attr >> 16) == 0o644


def test_observer_version_is_scoped_to_its_source_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="ee355910a942\n")

    monkeypatch.setattr(runner, "run", run)

    assert observer_source_version(runner) == hashlib.sha256(b"ee355910a942").hexdigest()[:12]
    assert commands == [
        ["git", "rev-parse", "HEAD:infra/envoy-cache-adapter",
         *(f"HEAD:{path}" for path in OBSERVER_SHARED_PATHS)]
    ]


def test_observer_context_contains_only_runtime_and_shared_stdlib_modules() -> None:
    with observer_build_context() as context:
        files = {
            path.relative_to(context).as_posix() for path in context.rglob("*") if path.is_file()
        }
        assert files == {*OBSERVER_RUNTIME_FILES, *OBSERVER_SHARED_PATHS}
        for path in context.rglob("*.py"):
            ast.parse(path.read_text(), feature_version=(3, 10))
        subprocess.run([
            sys.executable, "-I", "-S", "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); import shipper; "
            "from turnstile_core.integrations.budget_completion import BudgetCompletionClient; "
            "BudgetCompletionClient('https://ledger.example.test', 'TurnstileLedger', lambda: '')",
            str(context),
        ], check=True, capture_output=True, text=True, timeout=10)
    assert not context.exists()


def test_existing_observer_image_skips_rebuild_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner, "run", run)

    build_and_start_observer(
        runner,
        inputs,
        {
            "acrName": "acrexisting",
            "image": (
                "acrexisting.azurecr.io/turnstile/"
                "envoy-cache-adapter:ee355910a942"
            ),
            "webAppName": "observer-existing",
        },
        "ee355910a942",
    )

    assert len(commands) == 1
    assert commands[0][:4] == ["az", "acr", "repository", "show"]


def test_missing_observer_image_is_built_and_restarted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:4] == ["az", "acr", "repository", "show"]:
            raise DeploymentError("Error: the specified tag does not exist")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner, "run", run)

    build_and_start_observer(
        runner,
        inputs,
        {
            "acrName": "acrexisting",
            "image": "acrexisting.azurecr.io/turnstile/observer:new-tag",
            "webAppName": "observer-existing",
        },
        "new-tag",
    )

    assert [command[:3] for command in commands] == [
        ["az", "acr", "repository"],
        ["az", "acr", "build"],
        ["az", "webapp", "restart"],
    ]


def test_deploy_packages_uses_webapp_and_function_cli_with_health_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    api_deployments: list[tuple[str, str, Path]] = []
    health_calls: list[tuple[str, int]] = []

    class Runner:
        def run(self, command: Sequence[str], **_: object) -> None:
            commands.append(list(command))

        def run_json(
            self, command: Sequence[str], **_: object
        ) -> dict[str, str]:
            commands.append(list(command))
            return {"status": "Deployment was successful."}

    monkeypatch.setattr(
        "scripts.deploy.wait_for_health",
        lambda url, timeout_seconds=180: health_calls.append((url, timeout_seconds)),
    )
    monkeypatch.setattr(
        "scripts.deploy.deploy_webapp_package",
        lambda _runner, _inputs, app_name, app_url, package: api_deployments.append(
            (app_name, app_url, package)
        ),
    )
    deploy_packages(
        Runner(),  # type: ignore[arg-type]
        type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
        {
            "resourceGroupName": "rg",
            "apiName": "api",
            "apiUrl": "https://api.example.test",
            "telemetryFunctionName": "telemetry",
            "controlPlaneFunctionName": "control",
        },
        {
            "api": Path("api.zip"),
            "telemetry": Path("telemetry.zip"),
            "control-plane": Path("control-plane.zip"),
        },
    )

    assert api_deployments == [
        ("api", "https://api.example.test", Path("api.zip"))
    ]
    assert [
        command[command.index("--name") + 1]
        for command in commands
        if command[1:5] == ["functionapp", "deployment", "source", "config-zip"]
    ] == ["telemetry", "control"]
    assert health_calls == [("https://api.example.test", 1800)]


def test_webapp_package_deployment_uses_async_zip_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    package = tmp_path / "api.zip"
    package.write_bytes(b"package-bytes")

    class Runner:
        def run_json(self, command: Sequence[str], **_: object) -> dict[str, object]:
            commands.append(list(command))
            return {"properties": {"status": "RuntimeSuccessful"}}

    deploy_webapp_package(
        Runner(),  # type: ignore[arg-type]
        cast(
            DeploymentInputs,
            type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
        ),
        "api",
        "https://api.example.test",
        package,
    )

    assert commands == [
        [
            "az",
            "webapp",
            "deploy",
            "--subscription",
            "sub",
            "--resource-group",
            "rg",
            "--name",
            "api",
            "--src-path",
            str(package),
            "--type",
            "zip",
            "--async",
            "true",
            "--restart",
            "true",
            "--clean",
            "true",
            "--output",
            "json",
        ]
    ]


def test_webapp_package_rejects_failed_cli_deployment(tmp_path: Path) -> None:
    package = tmp_path / "api.zip"
    package.write_bytes(b"package-bytes")

    class Runner:
        def run_json(self, _command: Sequence[str], **_: object) -> dict[str, object]:
            return {"properties": {"status": "RuntimeFailed"}}

    with pytest.raises(DeploymentError, match="RuntimeFailed"):
        deploy_webapp_package(
            Runner(),  # type: ignore[arg-type]
            cast(
                DeploymentInputs,
                type(
                    "Inputs", (), {"subscription": "sub", "resource_group_name": "rg"}
                )(),
            ),
            "api",
            "https://api.example.test",
            package,
        )


def test_webapp_package_accepts_recent_success_after_cli_startup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "api.zip"
    package.write_bytes(b"package-bytes")
    commands: list[list[str]] = []

    class Runner:
        def run_json(self, command: Sequence[str], **_: object) -> dict[str, object]:
            commands.append(list(command))
            if command[1:4] == ["webapp", "deploy", "--subscription"]:
                raise subprocess.CalledProcessError(1, command)
            assert command[1:5] == ["webapp", "log", "deployment", "list"]
            return {
                "status": 4,
                "complete": True,
                "receivedTime": datetime.now(UTC).isoformat(),
            }

    health_calls: list[tuple[str, int]] = []

    def healthy(url: str, timeout_seconds: int) -> str:
        health_calls.append((url, timeout_seconds))
        return "ok"

    monkeypatch.setattr(
        "scripts.deploy.wait_for_health",
        healthy,
    )

    deploy_webapp_package(
        Runner(),  # type: ignore[arg-type]
        cast(
            DeploymentInputs,
            type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
        ),
        "api",
        "https://api.example.test",
        package,
    )

    assert len(commands) == 2
    assert health_calls == [("https://api.example.test", 180)]


def test_function_package_deployment_restarts_and_retries_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    deployments: list[list[str]] = []

    class Runner:
        def run(self, command: Sequence[str], **_: object) -> None:
            if command[1:5] == ["functionapp", "deployment", "source", "config-zip"]:
                deployments.append(list(command))
                if len(deployments) == 1:
                    raise subprocess.CalledProcessError(1, command)
            else:
                commands.append(list(command))

    def deploy_api(
        _runner: object,
        _inputs: object,
        _app_name: str,
        _app_url: str,
        _package: Path,
    ) -> None:
        return

    monkeypatch.setattr("scripts.deploy.wait_for_health", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("scripts.deploy.deploy_webapp_package", deploy_api)
    monkeypatch.setattr("scripts.deploy.time.sleep", lambda _: None)
    deploy_packages(
        Runner(),  # type: ignore[arg-type]
        type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
        {
            "resourceGroupName": "rg",
            "apiName": "api",
            "apiUrl": "https://api.example.test",
            "telemetryFunctionName": "telemetry",
            "controlPlaneFunctionName": "control",
        },
        {
            "api": Path("api.zip"),
            "telemetry": Path("telemetry.zip"),
            "control-plane": Path("control-plane.zip"),
        },
    )

    assert [item[item.index("--name") + 1] for item in deployments] == [
        "telemetry",
        "telemetry",
        "control",
    ]
    assert all(
        item[1:5] == ["functionapp", "deployment", "source", "config-zip"]
        for item in deployments
    )
    assert all(item[item.index("--build-remote") + 1] == "false" for item in deployments)
    assert len(commands) == 1
    assert commands[0][:3] == ["az", "functionapp", "restart"]
    assert commands[0][commands[0].index("--name") + 1] == "telemetry"


@pytest.mark.parametrize("scenario", [
    "frontend_recovers", "frontend_unreachable", "frontend_wrong_version", "health_recovers",
])
def test_runtime_readiness_requires_the_expected_frontend_within_one_deadline(
    monkeypatch: pytest.MonkeyPatch, scenario: str,
) -> None:
    from scripts import deploy

    expected = "assets/index-new-build.js"
    elapsed = [0.0]
    attempts: dict[str, int] = {}
    timeouts: list[float] = []

    def request_page(request: urllib.request.Request, timeout: float) -> bytes:
        path = request.full_url.removeprefix("https://api.example.test")
        attempts[path] = attempts.get(path, 0) + 1
        timeouts.append(timeout)
        unavailable = "/health" if scenario == "health_recovers" else "/"
        if scenario != "frontend_wrong_version" and path == unavailable and (
            attempts[path] == 1 or scenario == "frontend_unreachable"
        ):
            elapsed[0] += 1
            raise TimeoutError("read timed out")
        if path == "/health":
            return b'{"status":"ok"}'
        asset = "assets/index-old-build.js" if scenario == "frontend_wrong_version" else expected
        return f'<script type="module" src="/{asset}"></script>'.encode()

    def advance(seconds: float) -> None:
        elapsed[0] += seconds

    monkeypatch.setattr(deploy, "_open_without_proxy", request_page)
    monkeypatch.setattr("scripts.deploy.time.monotonic", lambda: elapsed[0])
    monkeypatch.setattr("scripts.deploy.time.sleep", advance)
    if scenario in {"frontend_unreachable", "frontend_wrong_version"}:
        with pytest.raises(DeploymentError) as failure:
            wait_for_health("https://api.example.test", timeout_seconds=6, expected_asset=expected)
        message = str(failure.value)
        assert "Frontend" in message and expected in message
        if scenario == "frontend_wrong_version":
            assert "assets/index-old-build.js" in message
            assert attempts["/"] == 1 and elapsed[0] == 0
        else:
            assert "read timed out" in message and "6" in message
    else:
        assert wait_for_health(
            "https://api.example.test", timeout_seconds=6, expected_asset=expected,
        ) == '{"status":"ok"}'
        assert attempts["/"] >= 1
    assert elapsed[0] <= 6
    assert all(0 < timeout <= 6 for timeout in timeouts)


def test_function_package_retry_continues_when_restart_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployments = 0
    sleeps: list[int] = []

    class Runner:
        def run(self, command: Sequence[str], **_: object) -> None:
            nonlocal deployments
            if command[1:5] == ["functionapp", "deployment", "source", "config-zip"]:
                deployments += 1
                if deployments == 1:
                    raise subprocess.CalledProcessError(1, command)
                return
            assert command[1:3] == ["functionapp", "restart"]
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr("scripts.deploy.time.sleep", sleeps.append)

    deploy_function_package(
        Runner(),  # type: ignore[arg-type]
        cast(
            DeploymentInputs,
            type("Inputs", (), {"subscription": "sub"})(),
        ),
        "rg",
        "function",
        Path("function.zip"),
    )

    assert deployments == 2
    assert sleeps == [15]


def test_health_gate_accepts_successful_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.deploy._open_without_proxy", lambda *_: b"")

    assert wait_for_health("https://observer.example.test") == ""


def test_observer_health_gate_allows_slow_container_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    def wait_for_health(url: str, timeout_seconds: int = 180) -> str:
        calls.append((url, timeout_seconds))
        return "ok"

    monkeypatch.setattr("scripts.deploy.wait_for_health", wait_for_health)

    assert wait_for_observer_health("https://observer.example.test") == "ok"
    assert calls == [("https://observer.example.test", 1800)]


def test_owner_login_retries_transient_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses: list[object] = [
        urllib.error.URLError("app restarting"),
        json.dumps(
            {
                "email": "owner@example.com",
                "role": "owner",
                "method": "password",
            }
        ).encode(),
    ]

    def open_request(*_: object) -> bytes:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, bytes)
        return response

    monkeypatch.setattr("scripts.deploy._open_without_proxy", open_request)
    monkeypatch.setattr("scripts.deploy.time.sleep", lambda _: None)

    verify_owner_login(
        "https://api.example.test", "owner@example.com", "secret", timeout_seconds=10
    )

    assert responses == []


def test_linux_dependency_command_uses_pinned_target_platform(tmp_path: Path) -> None:
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "requirements.txt").write_text("fastapi==0.139.2\n", encoding="utf-8")

    command = linux_dependency_command(staged)

    assert command[:3] == ["uv", "pip", "install"]
    assert "x86_64-manylinux_2_28" in command
    assert "3.11" in command
    assert "--compile-bytecode" not in command
    assert "--no-compile" not in command
    assert "--requirements" in command
    assert command[command.index("--constraint") + 1] == str(staged / "constraints.txt")


def test_pip_fallback_uses_pinned_target_platform(tmp_path: Path) -> None:
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "requirements.txt").write_text("fastapi==0.139.2\n", encoding="utf-8")

    command = pip_linux_dependency_command(staged, "/usr/bin/pip3")

    assert command[:2] == ["/usr/bin/pip3", "install"]
    assert "manylinux_2_28_x86_64" in command
    assert "manylinux_2_17_x86_64" in command
    assert "manylinux2014_x86_64" in command
    assert "3.11" in command
    assert "--only-binary=:all:" in command
    assert "--requirement" in command
    assert command[command.index("--constraint") + 1] == str(staged / "constraints.txt")


@pytest.mark.parametrize("fallback", [False, True])
def test_linux_install_locks_primary_and_fallback_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    staged = tmp_path / "staged"
    staged.mkdir()
    commands: list[list[str]] = []
    runner = CommandRunner()

    def run(command: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        if list(command[:2]) == ["uv", "export"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if fallback and list(command[:3]) == ["uv", "pip", "install"]:
            raise subprocess.CalledProcessError(1, command)
        metadata = staged / ".python_packages/lib/site-packages/fastapi-0.139.2.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text("Name: fastapi\nVersion: 0.139.2\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr("scripts.deploy.shutil.which", lambda _: "/usr/bin/pip3")
    _install_linux_dependencies(runner, staged)
    assert commands[0][:3] == ["uv", "export", "--locked"]
    assert "--no-dev" in commands[0] and "--no-emit-project" in commands[0]
    assert commands[0][-1] == str(staged / "constraints.txt")
    for command in commands[1:]:
        assert command[command.index("--constraint") + 1] == str(staged / "constraints.txt")
    manifest = json.loads((staged / "dependency-manifest.json").read_text())
    assert manifest["packages"] == {"fastapi": "0.139.2"}
    assert len(manifest["lock_sha256"]) == 64


@pytest.mark.parametrize("name,version", [("fastapi", "0.1.0"), ("unexpected-package", "1.0")])
def test_packaged_dependencies_reject_versions_outside_the_lock(
    tmp_path: Path, name: str, version: str
) -> None:
    metadata = tmp_path / ".python_packages/lib/site-packages/unit.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    with pytest.raises(DeploymentError, match="does not match uv.lock"):
        validate_packaged_dependencies(tmp_path)


def test_linux_fallback_accepts_locked_pillow_and_older_binary_wheels(tmp_path: Path) -> None:
    command = pip_linux_dependency_command(tmp_path / "staged", "/usr/bin/pip3")
    platforms = [command[index + 1] for index, value in enumerate(command) if value == "--platform"]
    compatible = set(cpython_tags(python_version=(3, 11), abis=["cp311"], platforms=platforms))
    lock = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package_name in ("pillow", "cryptography", "psycopg-binary"):
        package = next(item for item in lock["package"] if item["name"] == package_name)
        available = set().union(*(
            parse_wheel_filename(wheel["url"].rsplit("/", 1)[-1])[3]
            for wheel in package["wheels"]
        ))
        assert compatible.intersection(available), f"No compatible locked wheel for {package_name}"


def test_frontend_asset_reads_the_hashed_entrypoint(tmp_path: Path) -> None:
    index = tmp_path / "index.html"
    index.write_text(
        '<script type="module" src="/assets/index-Ab_12-c.js"></script>',
        encoding="utf-8",
    )

    assert frontend_asset(index) == "assets/index-Ab_12-c.js"


def test_runtime_release_recycles_updated_apps_without_stale_api_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = CommandRunner()
    commands: list[Sequence[str]] = []

    def run(command: Sequence[str], **_kwargs: object) -> None:
        commands.append(command)

    monkeypatch.setattr(runner, "run", run)

    restart_runtime_apps(
        runner,
        inputs,
        {
            "resourceGroupName": "turnstile-test",
            "apiName": "api-turnstile-test",
            "controlPlaneFunctionName": "func-turnstile-control-test",
        },
    )

    assert [command[:3] for command in commands] == [
        ["az", "webapp", "stop"],
        ["az", "webapp", "start"],
        ["az", "functionapp", "restart"],
    ]
    assert [command[command.index("--name") + 1] for command in commands] == [
        "api-turnstile-test",
        "api-turnstile-test",
        "func-turnstile-control-test",
    ]


def test_upgrade_files_are_private_and_concurrent_execution_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "upgrade"
    path = directory / "journal.json"
    _write_private_json(path, {"status": "preparing"})
    _write_private_json(path, {"status": "passed"})
    assert json.loads(path.read_text()) == {"status": "passed"}
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    with (
        _upgrade_lock(directory), pytest.raises(DeploymentError, match="Another process"),
        _upgrade_lock(directory),
    ):
        pass
    with _upgrade_lock(directory):
        pass


@pytest.mark.parametrize("values,expected_client", [
    ({
        "employeeClientId": " be989933-a2eb-42ef-9ae6-72024b01a997 ",
        "employeeAudience": "model-api",
    }, "be989933-a2eb-42ef-9ae6-72024b01a997"),
    ({
        "entraClientId": "be989933-a2eb-42ef-9ae6-72024b01a997",
    }, "be989933-a2eb-42ef-9ae6-72024b01a997"),
    ({
        "employeeClientId": "",
        "employeeAudience": "model-api",
    }, "00000000-0000-0000-0000-000000000000"),
    ({
        "employeeClientId": "be989933-a2eb-42ef-9ae6-72024b01a997",
        "employeeAudience": " ",
    }, "00000000-0000-0000-0000-000000000000"),
    ({}, "00000000-0000-0000-0000-000000000000"),
])
def test_gateway_upgrade_uses_only_the_shared_employee_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    values: dict[str, str], expected_client: str,
) -> None:
    from xml.etree import ElementTree

    from scripts import deploy

    inputs = DeploymentInputs.load(
        "subscription",
        _set_parameters(_parameters(tmp_path / "parameters.json"), values),
        tmp_path / "state.json",
    )
    runner = MagicMock(spec=CommandRunner)
    runner.run_json.return_value = {"accessToken": "unit-test-token"}
    backend = MagicMock()
    monkeypatch.setattr(deploy, "AzureUpgradeBackend", lambda *_: backend)
    plan = MagicMock(return_value=MagicMock(required=False))
    monkeypatch.setattr(deploy, "plan_image_upgrade", plan)

    deploy.gateway_upgrade(runner, inputs, {
        "resourceGroupName": "turnstile-test",
        "apimName": "test-apim",
        "apimPrincipalId": "test-principal",
        "apimGatewayUrl": "https://test-apim.azure-api.net",
        "apimApiId": "test-api",
        "apiName": "test-web",
        "controlPlaneFunctionName": "test-control",
    }, "check")

    plan.assert_called_once()
    canonical = ElementTree.fromstring(plan.call_args.args[2])
    assert [node.text for node in canonical.iter("application-id")] == [expected_client]


@pytest.mark.parametrize("action", ["plan-upgrade", "upgrade", "rollback-upgrade"])
def test_incremental_commands_do_not_recreate_secrets_or_deploy_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    from scripts import deploy

    arguments = build_parser().parse_args([
        action, "--subscription", "subscription", "--parameters",
        str(_parameters(tmp_path / "parameters.json")), "--state", str(tmp_path / "state.json"),
    ])
    outputs = {"resourceGroupName": "turnstile-test"}
    monkeypatch.setattr(deploy, "require_prerequisites", lambda *_: None)
    monkeypatch.setattr(deploy, "validate_source_snapshot", lambda *_: None)
    monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: outputs)
    calls: list[str] = []

    def upgrade(*args: object, **kwargs: object) -> None:
        assert args[2] is outputs
        calls.append(str(args[3]))

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("An upgrade must not touch platform secrets, packages or bootstrap")

    monkeypatch.setattr(deploy, "gateway_upgrade", upgrade)
    monkeypatch.setattr(deploy, "load_or_create_secret_material", forbidden)
    monkeypatch.setattr(deploy, "build_packages", forbidden)
    monkeypatch.setattr(deploy, "deploy_template", forbidden)
    execute(arguments, CommandRunner())
    assert calls == [action]


def test_rerun_checks_apim_upgrade_before_secrets_or_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import deploy

    arguments = build_parser().parse_args([
        "deploy", "--subscription", "subscription", "--parameters",
        str(_parameters(tmp_path / "parameters.json")),
    ])
    monkeypatch.setattr(deploy, "require_prerequisites", lambda *_: None)
    monkeypatch.setattr(deploy, "validate_source_snapshot", lambda *_: None)
    monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: {
        "existing": True, "resourceGroupName": "turnstile-test",
    })

    def blocked(*args: object, **kwargs: object) -> None:
        assert args[3] == "check"
        raise DeploymentError("APIM upgrade required")

    monkeypatch.setattr(deploy, "gateway_upgrade", blocked)
    with pytest.raises(DeploymentError, match="APIM upgrade required"):
        execute(arguments, CommandRunner())


def test_repository_parameter_example_and_generated_documents_match_bicep(
    tmp_path: Path,
) -> None:
    inputs = DeploymentInputs.load(
        "00000000-0000-0000-0000-000000000001",
        REPOSITORY_ROOT / "infra" / "main.parameters.example.json",
        tmp_path / "state.json",
    )
    assert inputs.foundry_resource_id is None
    answers = iter(("a-secure-owner-password", "a-secure-owner-password"))
    material = load_or_create_secret_material(
        inputs,
        read_password=lambda _: next(answers),
        require_owner_password=False,
    )
    platform_outputs = {
        "resourceGroupName": inputs.resource_group_name,
        "appServicePlanName": "plan-turnstile-test",
        "eventHubNamespaceName": "eh-turnstile-test",
        "apimName": "apim-turnstile-test",
    }
    root_document = deployment_parameters(inputs, material)
    observer_document = observer_parameters(inputs, platform_outputs, material, "abc123")
    release_document = runtime_release_parameters(
        inputs,
        material,
        {
            "apiName": "api-turnstile-test",
            "controlPlaneFunctionName": "func-turnstile-control-test",
            "gatewayApiPath": "https://apim.test/turnstile/llm",
        },
        {
            "webAppUrl": "https://observer.test",
            "adapterKeyNamedValueName": "turnstile-observer-key",
        },
        {"EXISTING_API_SETTING": "preserved"},
        {"EXISTING_CONTROL_SETTING": "preserved"},
    )

    root_declared = set(
        re.findall(
            r"(?m)^param\s+(\w+)",
            (REPOSITORY_ROOT / "infra" / "main.bicep").read_text(encoding="utf-8"),
        )
    )
    observer_declared = set(
        re.findall(
            r"(?m)^param\s+(\w+)",
            (REPOSITORY_ROOT / "infra" / "envoy-cache-adapter" / "main.bicep").read_text(
                encoding="utf-8"
            ),
        )
    )
    release_declared = set(
        re.findall(
            r"(?m)^param\s+(\w+)",
            (REPOSITORY_ROOT / "infra" / "runtime-release.bicep").read_text(
                encoding="utf-8"
            ),
        )
    )

    assert set(root_document["parameters"]) <= root_declared
    assert set(observer_document["parameters"]) <= observer_declared
    assert set(release_document["parameters"]) <= release_declared
    assert (
        release_document["parameters"]["currentApiSettings"]["value"]
        == {"EXISTING_API_SETTING": "preserved"}
    )


def test_repository_parameter_examples_expose_the_same_supported_fields() -> None:
    tracked_example = REPOSITORY_ROOT / "infra" / "main.parameters.example.json"
    expected = set(json.loads(tracked_example.read_text(encoding="utf-8"))["parameters"])
    assert {
        "employeeClientId", "employeeAudience",
        "keyVaultPrivateDnsLinkName",
        *_adopted_dependency_values("subscription"),
    } <= expected
    assert {
        name for name in expected if name.startswith("employee") and "ClientId" in name
    } == {"employeeClientId"}
    assert not any("foundry" in name.casefold() for name in expected)
    for path in (
        REPOSITORY_ROOT / ".turnstile" / "handoff" / "managed.parameters.example.json",
        REPOSITORY_ROOT / ".turnstile" / "handoff" / "adopted.parameters.example.json",
    ):
        if path.exists():
            assert set(json.loads(path.read_text(encoding="utf-8"))["parameters"]) == expected


class WhatIfRunner(CommandRunner):
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result

    def run_json(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> dict[str, object]:
        del command, cwd, env
        return self.result


def test_platform_deployment_targets_the_existing_resource_group(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )

    command = _resource_group_deployment_command(
        "what-if",
        inputs,
        Path("infra/main.bicep"),
        tmp_path / "parameters.generated.json",
        "turnstile-platform",
    )

    assert command[:4] == ["az", "deployment", "group", "what-if"]
    assert command[command.index("--resource-group") + 1] == "turnstile-test"
    assert "sub" not in command


def test_command_runner_resolves_windows_command_shims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []
    monkeypatch.setattr(
        "scripts.deploy.shutil.which",
        lambda name: f"C:/resolved/{name}.CMD",
    )

    def run(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        assert kwargs["encoding"] == ("mbcs" if os.name == "nt" else "utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr("scripts.deploy.subprocess.run", run)

    CommandRunner().run(["az", "account", "show"])

    assert captured == ["C:/resolved/az.CMD", "account", "show"]


def test_what_if_reads_root_level_changes_and_rejects_delete(tmp_path: Path) -> None:
    inputs = DeploymentInputs.load(
        "subscription",
        _parameters(tmp_path / "parameters.json"),
        tmp_path / "state.json",
    )
    runner = WhatIfRunner(
        {
            "status": "Succeeded",
            "changes": [
                {"changeType": "Deploy", "resourceId": "/safe"},
                {"changeType": "Delete", "resourceId": "/unsafe"},
            ],
        }
    )

    with pytest.raises(DeploymentError, match="contains Delete changes"):
        what_if(
            runner,
            inputs,
            Path("infra/main.bicep"),
            {"parameters": {}},
            "test-deployment",
        )

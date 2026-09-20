from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tomllib
import urllib.error
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from packaging.tags import cpython_tags
from packaging.utils import parse_wheel_filename

from scripts.deploy import (
    EXISTING_RESOURCE_API_VERSIONS,
    CommandRunner,
    DeploymentError,
    DeploymentInputs,
    ExistingCore,
    SecretMaterial,
    _install_linux_dependencies,
    _managed_role_assignment_name,
    _resource_group_deployment_command,
    _upgrade_lock,
    _write_private_json,
    build_and_start_observer,
    build_parser,
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
    linux_dependency_command,
    load_existing_core,
    load_or_create_secret_material,
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
    ]
    assert all("--auth-mode" in command and "login" in command for command in commands)
    assert all("queue" not in command for command in commands)


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
    outputs = {
        "storageAccountId": (
            "/subscriptions/subscription/resourceGroups/storage/providers/"
            "Microsoft.Storage/storageAccounts/geoliangdatalake"
        ),
        "ledgerTableId": (
            "/subscriptions/subscription/resourceGroups/storage/providers/"
            "Microsoft.Storage/storageAccounts/geoliangdatalake/tableServices/"
            "default/tables/VicturnstileLedger"
        ),
        "telemetryPrincipalId": "telemetry-principal",
        "apiPrincipalId": "api-principal",
        "controlPlanePrincipalId": "control-principal",
        "apimPrincipalId": "apim-principal",
    }

    managed = ensure_shared_storage_roles(runner, inputs, outputs)

    assert len(managed) == 6
    assert len(commands) == 6
    roles = {command[command.index("--role") + 1] for command in commands}
    assert roles == {
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
    }
    assert all("--assignee-principal-type" in command for command in commands)
    assert all("--name" in command for command in commands)
    assert all("queue" not in " ".join(command).casefold() for command in commands)


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

    assert observer_source_version(runner) == "ee355910a942"
    assert commands == [
        ["git", "rev-parse", "--short=12", "HEAD:infra/envoy-cache-adapter"]
    ]


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
    api_deployments: list[tuple[str, Path]] = []
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
        lambda _runner, _inputs, app_name, package: api_deployments.append(
            (app_name, package)
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

    assert api_deployments == [("api", Path("api.zip"))]
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
        type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
        "api",
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
            type("Inputs", (), {"subscription": "sub", "resource_group_name": "rg"})(),
            "api",
            package,
        )


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
        _runner: object, _inputs: object, _app_name: str, _package: Path
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
    monkeypatch.setattr(deploy, "load_saved_outputs", lambda *_: {"existing": True})

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

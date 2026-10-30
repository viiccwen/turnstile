from __future__ import annotations

import ast
import json
import re
from xml.etree import ElementTree

from tests.support.paths import REPOSITORY_ROOT

ROOT = REPOSITORY_ROOT
MAIN = (ROOT / "infra/main.bicep").read_text(encoding="utf-8")
DATA_PLANE = (ROOT / "infra/modules/data-plane.bicep").read_text(encoding="utf-8")
DEPLOY_SCRIPT = (ROOT / "scripts/deploy.py").read_text(encoding="utf-8")
APIM_SERVICE = (ROOT / "infra/modules/apim-service.bicep").read_text(encoding="utf-8")
APIM_INTEGRATION = (ROOT / "infra/modules/apim-integration.bicep").read_text(
    encoding="utf-8"
)
CONTROL_PLANE = (ROOT / "infra/modules/control-plane-function.bicep").read_text(
    encoding="utf-8"
)
OBSERVER_APP = (ROOT / "infra/envoy-cache-adapter/app.bicep").read_text(
    encoding="utf-8"
)
OBSERVER_MAIN = (ROOT / "infra/envoy-cache-adapter/main.bicep").read_text(
    encoding="utf-8"
)
CONTROL_PLANE_APIM_RBAC = (
    ROOT / "infra/modules/control-plane-apim-rbac.bicep"
).read_text(encoding="utf-8")
APPLICATION_KEY_MANAGEMENT_RBAC = (
    ROOT / "infra/modules/application-key-management-rbac.bicep"
).read_text(encoding="utf-8")
INITIAL_SCHEMA = (ROOT / "migrations/001_initial_schema.up.sql").read_text(
    encoding="utf-8"
)
PARAMETERS = json.loads(
    (ROOT / "infra/main.parameters.example.json").read_text(encoding="utf-8")
)["parameters"]


def test_self_hosted_access_is_opt_in_and_separates_creation_from_tokens() -> None:
    wrapper = (ROOT / "infra/self-hosted-gateway-access.bicep").read_text()
    access = (ROOT / "infra/modules/self-hosted-gateway-rbac.bicep").read_text()
    assert "targetScope = 'subscription'" in wrapper
    assert "scope: apimResourceGroup" in wrapper
    assert "self-hosted-gateway-rbac" not in MAIN
    assert access.count("scope: apim\n") == 2
    for action in ("gateways/write", "gateways/apis/write", "gateways/generateToken/action"):
        assert f"Microsoft.ApiManagement/service/{action}" in access
        assert f"Microsoft.ApiManagement/service/{action}" not in CONTROL_PLANE_APIM_RBAC
    provisioner, bootstrap = access.split("resource bootstrapRole", 1)
    assert "generateToken" not in provisioner
    assert "Microsoft.Authorization/permissions/read" in bootstrap
    assert "gateways/write" not in bootstrap and "gateways/apis/write" not in bootstrap
    assert all(value not in access for value in ("listSecrets", "listKeys", "/delete", "'*'"))


def test_main_deploys_into_an_existing_platform_resource_group() -> None:
    assert "targetScope = 'resourceGroup'" in MAIN
    assert "resource platformResourceGroup" not in MAIN
    assert "module apim 'modules/apim-service.bicep'" in MAIN
    assert "scope: platformResourceGroup" not in MAIN
    assert "output resourceGroupName string = resourceGroup().name" in MAIN
    assert "targetScope = 'resourceGroup'" in OBSERVER_MAIN
    assert "type: 'SystemAssigned'" in APIM_SERVICE
    assert "publisherEmail: publisherEmail" in APIM_SERVICE
    assert PARAMETERS["storageResourceGroupName"]["value"] == (
        "shared-storage-resource-group"
    )
    assert PARAMETERS["storageAccountName"]["value"] == "existingsharedstorage"


def test_new_apim_defaults_to_standard_v2() -> None:
    assert "param apimSkuName string = 'StandardV2'" in MAIN
    assert PARAMETERS["apimSkuName"]["value"] == "StandardV2"


def test_data_plane_outputs_stay_within_the_arm_limit() -> None:
    outputs = re.findall(r"^output\s+(\w+)\s", DATA_PLANE, re.MULTILINE)
    assert len(outputs) <= 64
    assert len(outputs) == len(set(outputs))
    assert "apimOutboundSubnetId" in outputs
    assert "output routeTableId string = dataPlane.outputs.routeTableResourceId" in MAIN


def test_fresh_standard_v2_private_egress_is_bound_after_the_data_plane() -> None:
    assert (
        "var provisionApimOutboundNetwork = provisionApimService && provisionNetwork && apimSkuName == 'StandardV2'"
        in MAIN
    )
    initial = MAIN.split("module apim 'modules/apim-service.bicep'", 1)[1].split(
        "var effectiveApimName", 1,
    )[0]
    assert "if (provisionApimService)" in initial
    assert "dataPlane.outputs" not in initial
    binding = MAIN.split("module apimOutboundNetwork ", 1)[1].split(
        "module apimIntegration ", 1,
    )[0]
    assert "if (provisionApimOutboundNetwork)" in binding
    assert "name: effectiveApimName" in binding
    assert "outboundSubnetResourceId: dataPlane.outputs.apimOutboundSubnetId" in binding
    integration = MAIN.split("module apimIntegration ", 1)[1].split("module controlPlane ", 1)[0]
    assert "apimOutboundNetwork" in integration.split("dependsOn: [", 1)[1].split("]", 1)[0]
    assert "virtualNetworkType: 'External'" in APIM_SERVICE
    assert "subnetResourceId: outboundSubnetResourceId" in APIM_SERVICE
    assert "empty(outboundSubnetResourceId) ? {}" in APIM_SERVICE


def test_apim_outbound_subnet_preserves_adopted_network_and_storage_ownership() -> None:
    import re
    from ipaddress import ip_network

    subnet = DATA_PLANE.split("resource apimOutboundSubnet ", 1)[1].split(
        "var effectiveVirtualNetworkResourceId ", 1,
    )[0]
    assert "if (provisionApimOutboundNetwork)" in subnet
    assert "parent: managedVirtualNetwork" in subnet
    assert "serviceName: 'Microsoft.Web/serverFarms'" in subnet
    assert "id: apimOutboundSecurityGroup!.id" in subnet
    assert "managedApiSubnet" in subnet.split("dependsOn: [", 1)[1].split("]", 1)[0]
    network = ip_network("10.42.3.96/27")
    for prefix in re.findall(r"addressPrefix: '([^']+)'", DATA_PLANE):
        if prefix != str(network):
            assert not network.overlaps(ip_network(prefix))
    nsg = DATA_PLANE.split("resource apimOutboundSecurityGroup ", 1)[1].split(
        "resource apimOutboundSubnet ", 1,
    )[0]
    assert "destinationAddressPrefix: 'AzureKeyVault'" in nsg
    assert "destinationPortRange: '443'" in nsg
    assert "virtualNetworkResourceId: effectiveVirtualNetworkResourceId" in DATA_PLANE
    assert "privateEndpointSubnetResourceId: effectivePrivateEndpointSubnetResourceId" in DATA_PLANE
    assert "resource ledgerStorage " not in DATA_PLANE
    assert "var ledgerTableResourceId = resourceId(ledgerStorageResourceGroupName," in DATA_PLANE
    assert "provisionApimService && provisionNetwork" in MAIN


def test_credential_vault_name_fits_the_maximum_resource_prefix() -> None:
    assert (
        "var credentialVaultName = 'kv-${take(resourcePrefix, 11)}-rt-${take(suffix, 6)}'"
        in DATA_PLANE
    )
    suffix = "fv2a6jyqwtz52"
    for prefix in ("abc", "turnstile", "vicadopted", "a" * 11, "victurnstile", "a" * 12):
        name = f"kv-{prefix[:11]}-rt-{suffix[:6]}"
        assert 3 <= len(name) <= 24
        assert re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", name)
        if len(prefix) <= 11:
            assert name == f"kv-{prefix}-rt-{suffix[:6]}"


def test_postgres_availability_zone_is_configurable_with_the_existing_default() -> None:
    for template in (MAIN, DATA_PLANE):
        assert "param postgresAvailabilityZone string = '1'" in template
    assert "postgresAvailabilityZone: postgresAvailabilityZone" in MAIN
    assert "availabilityZone: postgresAvailabilityZone" in DATA_PLANE
    assert "availabilityZone: '1'" not in DATA_PLANE


def test_managed_postgres_name_can_change_without_renaming_other_resources() -> None:
    for template in (MAIN, DATA_PLANE):
        assert (
            "param managedPostgresServerName string = 'pg-${resourcePrefix}-${suffix}'"
            in template
        )
    assert "managedPostgresServerName: managedPostgresServerName" in MAIN
    assert "var managedPostgresServerName =" not in DATA_PLANE
    assert (
        "var effectivePostgresServerName = postgresAdopted ? existingPostgresServerName "
        ": managedPostgresServerName"
    ) in DATA_PLANE
    postgres = DATA_PLANE.split("resource managedPostgres ", 1)[1].split(
        "\nresource ", 1
    )[0]
    assert "name: managedPostgresServerName" in postgres
    assert "location: postgresLocation" in postgres
    assert (
        "resourceId('Microsoft.DBforPostgreSQL/flexibleServers', managedPostgresServerName)"
        in DATA_PLANE
    )
    assert "${effectivePostgresServerName}.postgres.database.azure.com" in DATA_PLANE
    assert "var apiName = 'api-${resourcePrefix}-${suffix}'" in DATA_PLANE
    assert "var managedVirtualNetworkName = 'vnet-${resourcePrefix}-${suffix}'" in DATA_PLANE


def test_observer_compute_region_does_not_move_the_registry() -> None:
    assert "param registryLocation string = location" in OBSERVER_MAIN
    registry = OBSERVER_MAIN.split("module registry ", 1)[1].split("module app ", 1)[0]
    assert "location: registryLocation" in registry
    assert "output observerLocation string = location" in OBSERVER_MAIN


def test_apim_exposes_the_turnstile_gateway_path() -> None:
    assert "param apimApiId string = 'turnstile-llm'" in MAIN
    assert "param gatewayApiRelativePath string = 'turnstile/llm'" in MAIN
    assert "name: apiId" in APIM_INTEGRATION
    assert "displayName: '${apiId} | Turnstile AI Gateway'" in APIM_INTEGRATION
    assert "param apiPath string" in APIM_INTEGRATION
    assert "path: apiPath" in APIM_INTEGRATION
    assert "path: 'finops/llm'" not in APIM_INTEGRATION


def test_fresh_apim_precreates_a_fail_closed_image_operation() -> None:
    operation = APIM_INTEGRATION.split("resource imagesGenerationsOperation ", 1)[1].split(
        "\nresource ", 1
    )[0]
    for declaration in (
        "parent: api", "name: 'images-generations'", "method: 'POST'",
        "urlTemplate: '/images/generations'", "templateParameters: []",
    ):
        assert declaration in operation
    policy_resource = APIM_INTEGRATION.split(
        "resource imagesGenerationsOperationPolicy ", 1
    )[1].split("\nresource ", 1)[0]
    assert "parent: imagesGenerationsOperation" in policy_resource
    assert "loadTextContent('../policies/provider-neutral-images-policy.xml')" in policy_resource
    policy = ElementTree.parse(ROOT / "infra/policies/provider-neutral-images-policy.xml")
    assert policy.find("./inbound/base") is not None
    selected_model = policy.find("./inbound/set-variable")
    assert selected_model is not None
    assert selected_model.attrib == {
        "name": "selectedModelKnown", "value": "@(false)",
    }
    denial = policy.find("./inbound/return-response")
    assert denial is not None
    response_status = denial.find("set-status")
    assert response_status is not None and response_status.get("code") == "400"
    body = json.loads(denial.findtext("set-body", ""))
    assert body["error"]["code"] == "image_model_not_published"
    assert policy.find(".//send-request") is None
    assert policy.find(".//forward-request") is None
    assert "Microsoft.ApiManagement/service/apis/operations/write" in CONTROL_PLANE_APIM_RBAC


def test_incremental_apim_template_only_prepares_and_promotes_existing_api_revisions() -> None:
    root = (ROOT / "infra/apim-upgrade.bicep").read_text()
    module = (ROOT / "infra/modules/apim-upgrade.bicep").read_text()
    assert "targetScope = 'resourceGroup'" in root
    assert "name: 'apim-image-upgrade-${uniqueString(apimName, apiId, revision, stage)}'" in root
    assert "scope: resourceGroup(apimResourceGroupName)" not in root
    assert "sourceApiId: '${api.id};rev=${sourceRevision}'" in module
    assert "stage == 'prepare' && initializeImagePolicy" in module
    assert "stage == 'promote'" in module
    assert "loadTextContent('../policies/provider-neutral-images-policy.xml')" in module
    assert "apiId: '${api.id};rev=${revision}'" in module
    for resource in ("Microsoft.Authorization", "resourceGroups@", "namedValues@", "products@"):
        assert resource not in root + module
    assert "Microsoft.ApiManagement/service@2024-05-01' existing" in module
    assert "Microsoft.ApiManagement/service/apis@2024-05-01' existing" in module


def test_fixed_program_uses_xml_format_for_serialized_policies() -> None:
    module = (ROOT / "infra/modules/apim-upgrade.bicep").read_text()
    operation = module.split("resource fixedOperationPolicy", 1)[1].split("resource parent", 1)[0]
    parent = module.split("resource parent", 1)[1].split("resource promotion", 1)[0]
    assert "format: 'xml'" in operation
    assert "format: empty(fixedOperations) ? 'rawxml' : 'xml'" in parent


def test_shared_apim_resources_are_environment_isolated() -> None:
    for parameter, resource_name in (
        ("apiId", "apiId"),
        ("productId", "productId"),
        ("dashboardSubscriptionId", "dashboardSubscriptionId"),
        ("probeSubscriptionId", "probeSubscriptionId"),
        ("appInsightsLoggerId", "appInsightsLoggerId"),
        ("eventHubLoggerId", "eventHubLoggerId"),
        ("diagnosticSettingName", "diagnosticSettingName"),
    ):
        assert f"param {parameter} string" in APIM_INTEGRATION
        assert f"name: {resource_name}" in APIM_INTEGRATION

    assert "displayName: '${apiId} | Turnstile AI Gateway'" in APIM_INTEGRATION
    assert "displayName: '${productId} | Turnstile AI'" in APIM_INTEGRATION
    assert "param existingApimResourceGroupName string = ''" in MAIN
    assert "resource effectiveApimResourceGroup" not in MAIN
    assert MAIN.count("scope: resourceGroup(effectiveApimResourceGroupName)") == 5


def test_fresh_apim_creates_its_azure_monitor_logger() -> None:
    assert (
        "resource azureMonitorLogger 'Microsoft.ApiManagement/service/loggers@"
        in APIM_INTEGRATION
    )
    assert "name: 'azuremonitor'" in APIM_INTEGRATION
    assert "loggerType: 'azureMonitor'" in APIM_INTEGRATION
    assert "loggerId: azureMonitorLogger.id" in APIM_INTEGRATION
    logger = APIM_INTEGRATION.split("resource azureMonitorLogger", 1)[1].split(
        "resource llmDiagnostics", 1
    )[0]
    assert "credentials:" not in logger


def test_employee_token_policy_defaults_to_the_login_tenant_and_client() -> None:
    assert "param employeeTenantId string = subscription().tenantId" in MAIN
    assert "param employeeClientId string = entraClientId" in MAIN
    assert "param employeeAudience string = entraClientId" in MAIN


def test_employee_token_policy_is_disabled_without_entra_configuration() -> None:
    assert PARAMETERS["entraClientId"]["value"] == ""
    assert (
        "var employeeTokenEnabled = !empty(trim(employeeClientId)) "
        "&& !empty(trim(employeeAudience))"
    ) in APIM_INTEGRATION
    assert "employeeTokenEnabled ? 'true' : 'false'" in APIM_INTEGRATION
    assert "employeeTokenEnabled ? trim(employeeClientId)" in APIM_INTEGRATION
    assert "employeeTokenEnabled ? trim(employeeAudience)" in APIM_INTEGRATION
    assert "@(__EMPLOYEE_TOKEN_ENABLED__ &amp;&amp;" in (
        ROOT / "infra/policies/foundry-finops-policy.xml"
    ).read_text(encoding="utf-8")


def test_employee_clients_share_one_registration_across_gateway_and_control_plane() -> None:
    for names in (
        PARAMETERS,
        re.findall(r"(?m)^param\s+(\w+)", MAIN),
        re.findall(r"(?m)^param\s+(\w+)", APIM_INTEGRATION),
    ):
        assert {
            name for name in names if name.startswith("employee") and "ClientId" in name
        } == {"employeeClientId"}
    assert (
        "var approvedEmployeeClientIds = !empty(trim(employeeClientId)) "
        "&& !empty(trim(employeeAudience))\n"
        "  ? [trim(employeeClientId)]\n"
        "  : ['00000000-0000-0000-0000-000000000000']"
    ) in MAIN
    assert "employeeClientId: employeeClientId" in MAIN
    assert "employeeClientIds: approvedEmployeeClientIds" in MAIN


def test_templates_create_platform_resources_without_foundry_projects_or_models() -> None:
    for resource in (
        "Microsoft.DBforPostgreSQL/flexibleServers@",
        "Microsoft.EventHub/namespaces@",
        "Microsoft.KeyVault/vaults@",
        "Microsoft.Insights/components@",
        "Microsoft.Web/sites@",
    ):
        assert resource in DATA_PLANE
    assert "resource sharedStorage 'Microsoft.Storage/storageAccounts@" in MAIN
    assert "existing = {" in MAIN.split("resource sharedStorage", 1)[1].split(
        "module dataPlane", 1
    )[0]
    combined = MAIN + DATA_PLANE + APIM_SERVICE + CONTROL_PLANE
    assert combined.count("Microsoft.Storage/storageAccounts@") == 1
    assert "Microsoft.CognitiveServices/accounts/projects" not in combined
    assert "Microsoft.CognitiveServices/accounts/deployments" not in combined


def test_api_python_path_contains_package_root_and_prebuilt_dependencies() -> None:
    assert (
        "{ name: 'PYTHONPATH', value: "
        "'/home/site/wwwroot:/home/site/wwwroot/.python_packages/lib/site-packages' }"
        in DATA_PLANE
    )


def test_functions_use_separate_flex_consumption_plans() -> None:
    telemetry = DATA_PLANE.split("resource functionApp", 1)[1].split(
        "resource functionStorageBlobOwner", 1
    )[0]
    control = CONTROL_PLANE.split("resource functionApp", 1)[1].split(
        "resource keyVault", 1
    )[0]

    assert "serverFarmId: apiPlan.id" in DATA_PLANE
    assert "serverFarmId: telemetryPlan.id" in telemetry
    assert "serverFarmId: plan.id" in control
    assert DATA_PLANE.count("tier: 'FlexConsumption'") == 1
    assert CONTROL_PLANE.count("tier: 'FlexConsumption'") == 1
    assert "name: 'FC1'" in DATA_PLANE
    assert "name: 'FC1'" in CONTROL_PLANE
    for template in (telemetry, control):
        assert "functionAppConfig:" in template
        assert "instanceMemoryMB: 2048" in template
        assert "maximumInstanceCount: 100" in template
        assert "name: 'python'" in template
        assert "version: '3.11'" in template
        assert "type: 'SystemAssignedIdentity'" in template
        for incompatible in (
            "alwaysOn:",
            "linuxFxVersion:",
            "vnetRouteAllEnabled:",
            "WEBSITE_RUN_FROM_PACKAGE",
            "WEBSITES_CONTAINER_START_TIME_LIMIT",
            "SCM_DO_BUILD_DURING_DEPLOYMENT",
            "FUNCTIONS_WORKER_RUNTIME",
        ):
            assert incompatible not in template


def test_observer_uses_a_configurable_premium_v3_plan() -> None:
    assert "param appServicePlanSkuName string = 'P0v3'" in OBSERVER_APP
    assert "param appServicePlanWorkerCount int = 1" in OBSERVER_APP
    assert "name: appServicePlanSkuName" in OBSERVER_APP
    assert "tier: 'PremiumV3'" in OBSERVER_APP
    assert "capacity: appServicePlanWorkerCount" in OBSERVER_APP
    assert "appServicePlanSkuName: appServicePlanSkuName" in OBSERVER_MAIN
    assert "appServicePlanWorkerCount: appServicePlanWorkerCount" in OBSERVER_MAIN


def test_basic_observer_registry_does_not_emit_network_rules() -> None:
    assert "acrSku: 'Basic'" in OBSERVER_MAIN
    assert "publicNetworkAccess: 'Enabled'" in OBSERVER_MAIN
    assert "networkRuleSetDefaultAction: 'Allow'" in OBSERVER_MAIN


def test_flex_functions_have_isolated_network_and_deployment_storage() -> None:
    assert "addressPrefix: '10.42.3.0/27'" in DATA_PLANE
    assert "addressPrefix: '10.42.3.32/27'" in DATA_PLANE
    assert DATA_PLANE.count("serviceName: 'Microsoft.App/environments'") == 2
    assert "param telemetryDeploymentContainerName string" in MAIN
    assert "param controlPlaneDeploymentContainerName string" in MAIN
    assert "telemetryDeploymentContainerName: telemetryDeploymentContainerName" in MAIN
    assert "deploymentContainerName: controlPlaneDeploymentContainerName" in MAIN
    assert "resource functionVnetIntegration 'Microsoft.Web/sites/networkConfig@" in (
        DATA_PLANE
    )
    assert "resource functionVnetIntegration 'Microsoft.Web/sites/networkConfig@" in (
        CONTROL_PLANE
    )


def test_public_runtime_resources_are_exempt_from_network_modify_policy() -> None:
    for template, resource_name in (
        (DATA_PLANE, "api"),
        (DATA_PLANE, "functionApp"),
        (CONTROL_PLANE, "functionApp"),
        (OBSERVER_APP, "webApp"),
    ):
        resource = template.split(f"resource {resource_name} ", 1)[1].split(
            "\nresource ", 1
        )[0]
        assert "SecurityControl: 'Ignore'" in resource
        assert "publicNetworkAccess: 'Enabled'" in resource


def test_vnet_subnets_are_created_serially() -> None:
    telemetry_subnet = DATA_PLANE.split("resource managedTelemetryFunctionSubnet", 1)[1].split(
        "resource managedControlFunctionSubnet", 1
    )[0]
    control_subnet = DATA_PLANE.split("resource managedControlFunctionSubnet", 1)[1].split(
        "resource managedPrivateEndpointSubnet", 1
    )[0]
    private_endpoint_subnet = DATA_PLANE.split("resource managedPrivateEndpointSubnet", 1)[
        1
    ].split("module keyVaultPrivateEndpoint", 1)[0]
    assert "parent: managedVirtualNetwork" in telemetry_subnet
    assert "managedTelemetryFunctionSubnet" in control_subnet.split("dependsOn:", 1)[1]
    assert "managedControlFunctionSubnet" in private_endpoint_subnet.split("dependsOn:", 1)[1]


def test_functions_use_shared_storage_service_endpoints_without_private_links() -> None:
    for setting in (
        "AzureWebJobsStorage__blobServiceUri",
        "AzureWebJobsStorage__queueServiceUri",
        "AzureWebJobsStorage__tableServiceUri",
    ):
        assert setting in DATA_PLANE
        assert setting in CONTROL_PLANE
    assert "privatelink.blob.core.windows.net" not in DATA_PLANE
    assert "privatelink.queue.core.windows.net" not in DATA_PLANE
    assert "privatelink.table.core.windows.net" not in DATA_PLANE
    assert "Storage Queue Data Contributor" not in DEPLOY_SCRIPT


def test_control_plane_host_storage_reuses_shared_endpoints_without_recreating_storage() -> None:
    assert "storageName: sharedStorage.name" in MAIN
    for service in ("blob", "queue", "table"):
        assert (
            f"storage{service.title()}Endpoint: sharedStorage.properties.primaryEndpoints.{service}"
            in MAIN
        )
    assert "Microsoft.Storage/storageAccounts@" not in CONTROL_PLANE
    assert "module storagePrivateNetwork" not in CONTROL_PLANE
    function_app = CONTROL_PLANE.split("resource functionApp ", 1)[1].split(
        "resource functionVnetIntegration", 1
    )[0]
    assert "storagePrivateNetwork" not in function_app
    assert "value: '${storageBlobEndpoint}${deploymentContainerName}'" in function_app
    assert "type: 'SystemAssignedIdentity'" in function_app


def test_legacy_control_plane_storage_private_link_upgrade_remains_standalone() -> None:
    network = (ROOT / "infra/modules/storage-private-endpoints.bicep").read_text()
    upgrade = (ROOT / "infra/control-plane-storage-network-upgrade.bicep").read_text()
    for service in ("blob", "queue", "table"):
        assert f"'{service}'" in network
    assert "privateLinkServiceId: storage.id" in network
    assert "privateDnsZoneId: privateDnsZones[index].id" in network
    assert "name: 'privatelink.${service}.${environment().suffixes.storage}'" in network
    assert "parent: privateEndpoints[index]" in network
    assert "name: 'pe-${storageAccountName}-${service}'" in network
    assert "storageAccounts@2023-05-01' existing" in network
    assert "virtualNetworks@2024-05-01' existing" in network
    assert "subnets@2024-05-01' existing" in network
    assert "privateDnsZones@2024-06-01' existing" in network
    assert "targetScope = 'subscription'" in upgrade
    assert "'modules/storage-private-endpoints.bicep'" in upgrade
    assert "scope: resourceGroup(resourceGroupName)" in upgrade
    for forbidden in ("Microsoft.Web/sites", "Microsoft.Authorization", "listKeys("):
        assert forbidden not in network + upgrade


def test_api_and_apim_share_the_same_gateway_path() -> None:
    assert "param gatewayApiRelativePath string = 'turnstile/llm'" in MAIN
    assert (
        "var effectiveGatewayApiPath = "
        "'${effectiveApimGatewayUrl}/${gatewayApiRelativePath}'"
        in MAIN
    )
    assert "apimGatewayUrl: effectiveGatewayApiPath" in MAIN
    assert "apimApiId: apimApiId" in MAIN
    assert "apiPath: gatewayApiRelativePath" in MAIN
    assert "{ name: 'APIM_GATEWAY_URL', value: apimGatewayUrl }" in DATA_PLANE
    assert (
        "{ name: 'APIM_DASHBOARD_SUBSCRIPTION_KEY', value: apimSubscriptionKey }"
        in DATA_PLANE
    )
    assert "path: apiPath" in APIM_INTEGRATION


def test_api_bootstraps_initial_owner_between_migration_and_startup() -> None:
    assert (
        "appCommandLine: 'python -m backend.migrate && python -m backend.bootstrap "
        "&& python -m uvicorn backend.api:app"
        in DATA_PLANE
    )
    assert "{ name: 'BOOTSTRAP_OWNER_EMAIL', value: bootstrapOwnerEmail }" in DATA_PLANE
    assert (
        "{ name: 'BOOTSTRAP_OWNER_PASSWORD_HASH', value: bootstrapOwnerPasswordHash }"
        in DATA_PLANE
    )


def test_collapsed_migration_restores_search_path_after_pg_dump() -> None:
    dump_end, historical_migrations = INITIAL_SCHEMA.split(
        "-- Integrated from historical migration 041_pinned_report_layout.up.sql.", 1
    )
    assert "SELECT pg_catalog.set_config('search_path', '', false);" in dump_end
    assert dump_end.rstrip().endswith("SET search_path = public, pg_catalog;")
    assert "CREATE TABLE pinned_report_layout" in historical_migrations


def test_ledger_and_model_routes_use_exact_shared_storage_children() -> None:
    assert "param ledgerStorageResourceGroupName string" in DATA_PLANE
    assert "ledgerStorageResourceGroupName: storageResourceGroupName" in MAIN
    assert "ledgerStorageName: sharedStorage.name" in MAIN
    assert "ledgerTableEndpoint: sharedStorage.properties.primaryEndpoints.table" in MAIN
    for variable, table_name in (
        ("ledgerTableResourceId", "ledgerTableName"),
        ("routeTableResourceId", "'ModelRoutes'"),
    ):
        assert (
            f"var {variable} = resourceId(ledgerStorageResourceGroupName, "
            "'Microsoft.Storage/storageAccounts/tableServices/tables', "
            f"ledgerStorageName, 'default', {table_name})"
        ) in DATA_PLANE
        assert f"output {variable} string = {variable}" in DATA_PLANE
        assert f"{variable}: dataPlane.outputs.{variable}" in MAIN
    assert "Microsoft.Storage/storageAccounts@" not in DATA_PLANE
    assert "resource ledgerTable " not in DATA_PLANE
    assert "resource routeTable " not in DATA_PLANE
    assert "output ledgerTableEndpoint string = ledgerTableEndpoint" in DATA_PLANE


def test_deployment_bootstraps_only_owned_shared_storage_children() -> None:
    module = ast.parse(DEPLOY_SCRIPT)
    bootstrap = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "ensure_shared_storage_resources"
    )
    commands = [
        [ast.unparse(item) for item in node.elts[:4]]
        for node in ast.walk(bootstrap)
        if isinstance(node, ast.List) and len(node.elts) >= 4
        and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "az"
    ]
    assert commands == [
        ["'az'", "'storage'", "kind", "'create'"],
    ]
    source = ast.unparse(bootstrap)
    for child in (
        "('container', 'blobServices/default/containers', telemetry_container)",
        "('container', 'blobServices/default/containers', control_container)",
        "('table', 'tableServices/default/tables', ledger_table)",
        "('table', 'tableServices/default/tables', DEFAULT_ROUTE_TABLE_NAME)",
    ):
        assert child in source
    assert "for kind, child_path, name in children:" in source
    assert "'--auth-mode', 'login'" in source
    assert "result.stdout.strip() == 'true'" in source
    assert re.search(r'^DEFAULT_ROUTE_TABLE_NAME\s*=\s*[\'"]ModelRoutes[\'"]', DEPLOY_SCRIPT, re.M)
    assert "param ledgerTableName string = 'TurnstileLedger'" in MAIN
    assert "resource sharedStorage 'Microsoft.Storage/storageAccounts@" in MAIN
    assert "output storageAccountId string = sharedStorage.id" in MAIN
    assert "output ledgerTableId string = resourceId(" in MAIN


def test_shared_storage_roles_are_granted_outside_arm_deployment() -> None:
    assert "Storage Blob Data Owner" in DEPLOY_SCRIPT
    assert "Storage Table Data Contributor" in DEPLOY_SCRIPT
    assert "Storage Queue Data Contributor" not in DEPLOY_SCRIPT
    assert '_output_string(outputs, "apiPrincipalId")' in DEPLOY_SCRIPT
    assert '_output_string(outputs, "controlPlanePrincipalId")' in DEPLOY_SCRIPT
    assert "module storageRbac" not in MAIN
    assert (
        "name: guid(managedWorkspace!.id, functionApp.id, 'log-analytics-reader')"
        in DATA_PLANE
    )
    assert "if (provisionObservability)" in DATA_PLANE


def test_api_projects_model_access_using_its_exact_ledger_and_identity() -> None:
    api = DATA_PLANE.split("resource api 'Microsoft.Web/sites", 1)[1].split(
        "resource functionApp ", 1
    )[0]
    for setting in (
        "{ name: 'LEDGER_SYNC_ENABLED', value: 'true' }",
        "{ name: 'LEDGER_TABLE_ENDPOINT', value: ledgerTableEndpoint }",
        "{ name: 'LEDGER_TABLE_NAME', value: ledgerTableName }",
    ):
        assert api.count(setting) == 1
    assert "output apiPrincipalId string = dataPlane.outputs.apiPrincipalId" in MAIN
    assert "resource apiLedgerContributor" not in DATA_PLANE


def test_existing_api_model_access_upgrade_reuses_ledger_and_preserves_settings() -> None:
    upgrade = (ROOT / "infra/model-access-upgrade.bicep").read_text(encoding="utf-8")
    roles = (ROOT / "infra/modules/model-access-ledger-rbac.bicep").read_text(encoding="utf-8")
    assert "targetScope = 'resourceGroup'" in upgrade
    assert "param apiNames string[]" in upgrade
    assert "for (apiName, index) in apiNames" in upgrade
    assert "scope: resourceGroup(ledgerResourceGroupName)" in upgrade
    assert "apiPrincipalId: apis[index].identity.principalId" in upgrade
    assert "apiResourceId: apis[index].id" in upgrade
    assert "@secure()\nparam currentApiSettings object" in upgrade
    assert "union(currentApiSettings[apiName], {" in upgrade
    assert "list(" not in upgrade
    assert "LEDGER_SYNC_ENABLED: 'true'" in upgrade
    assert "LEDGER_TABLE_ENDPOINT: ledgerStorage.properties.primaryEndpoints.table" in upgrade
    assert "LEDGER_TABLE_NAME: ledgerTableName" in upgrade
    assert "dependsOn: [\n    ledgerAccess[index]" in upgrade
    assert roles.count(" existing = {") == 3
    assert "guid(ledgerTable.id, apiResourceId, 'table-data-contributor')" in roles
    assert "scope: ledgerTable" in roles and "scope: ledgerStorage" not in roles
    assert "principalId: apiPrincipalId" in roles
    assert "'0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'" in roles
    assert "Microsoft.Network/" not in upgrade + roles
    assert "listKeys(" not in upgrade + roles
    assert "output " not in upgrade + roles


def test_api_ledger_network_supports_shared_public_storage() -> None:
    upgrade = (ROOT / "infra/model-access-network-upgrade.bicep").read_text(encoding="utf-8")
    subnet = DATA_PLANE.split("resource managedApiSubnet ", 1)[1].split(
        "\n  dependsOn:", 1
    )[0]
    assert "parent: managedVirtualNetwork" in subnet
    assert "serviceName: 'Microsoft.Web/serverFarms'" in subnet
    integration = DATA_PLANE.split("resource apiVnetIntegration ", 1)[1].split(
        "\nresource ", 1,
    )[0]
    assert "parent: api" in integration
    assert "name: 'virtualNetwork'" in integration
    assert "subnetResourceId: effectiveApiSubnetResourceId" in integration
    assert "swiftSupported: true" in integration
    upgrade_subnet = upgrade.split("resource apiSubnet ", 1)[1].split(
        "\nresource ", 1
    )[0]
    assert "parent: virtualNetwork" in upgrade_subnet
    assert "serviceName: 'Microsoft.Web/serverFarms'" in upgrade_subnet
    upgrade_integration = upgrade.split("resource apiVnetIntegration ", 1)[1].split(
        "\nresource ", 1,
    )[0]
    assert "subnetResourceId: apiSubnet.id" in upgrade_integration
    assert "addressPrefix: '10.42.3.64/27'" in DATA_PLANE
    assert "dependsOn: [\n    managedPrivateEndpointSubnet\n  ]" in DATA_PLANE
    assert "resource ledgerTablePrivateEndpoint" not in DATA_PLANE
    assert "resource storageBlobPrivateEndpoint" not in DATA_PLANE
    assert "Microsoft.Storage/" not in upgrade
    assert "Microsoft.Authorization/" not in upgrade
    assert "appsettings" not in upgrade
    assert "param apiSubnetAddressPrefix string = '10.42.3.64/27'" in upgrade


def test_databricks_oauth_is_opt_in_for_api_publisher_and_scoped_permissions() -> None:
    for template in (MAIN, DATA_PLANE, CONTROL_PLANE, CONTROL_PLANE_APIM_RBAC):
        assert "param databricksOAuthEnabled bool = false" in template
    assert "databricksOAuthEnabled: provisionControlPlane && databricksOAuthEnabled" in MAIN
    assert MAIN.count("databricksOAuthEnabled: databricksOAuthEnabled") == 2
    for template in (DATA_PLANE, CONTROL_PLANE):
        assert (
            "{ name: 'DATABRICKS_OAUTH_ENABLED', value: string(databricksOAuthEnabled) }"
            in template
        )
    oauth = CONTROL_PLANE_APIM_RBAC.split("var oauthActions = ", 1)[1].split(
        "resource apim ", 1
    )[0]
    assert oauth.startswith("databricksOAuthEnabled ? [")
    assert "] : []" in oauth
    assert "*" not in oauth and "/delete'" not in oauth
    for suffix in ("", "/authorizations", "/authorizations/accessPolicies"):
        for operation in ("read", "write"):
            action = f"Microsoft.ApiManagement/service/authorizationProviders{suffix}/{operation}"
            assert action in oauth
    assert "], oauthActions)" in CONTROL_PLANE_APIM_RBAC
    assert "Microsoft.ApiManagement/service/apis/operations/write" in CONTROL_PLANE_APIM_RBAC
    contract = json.loads(
        (ROOT / "turnstile_core/domain/apim_publication_permissions.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(re.findall(r"'([^']+)'", oauth)) == set(contract["oauth"])


def test_control_plane_features_default_to_disabled() -> None:
    for declaration in (
        "param provisionControlPlane bool = false",
        "param controlPlaneEnabled bool = false",
        "param gatewayReleaseWorkerEnabled bool = false",
        "param gatewayApplicationKeyManagementEnabled bool = false",
    ):
        assert declaration in MAIN
    assert "effectivePublicationWorkerEnabled = publicationWorkerEnabled" in CONTROL_PLANE
    assert "effectiveReleaseWorkerEnabled = releaseWorkerEnabled" in CONTROL_PLANE


def test_application_creation_is_gated_and_uses_the_exact_platform_ledger() -> None:
    assert "param gatewayApplicationProvisioningEnabled bool = false" in MAIN
    assert (
        "gatewayApplicationProvisioningEnabled: provisionControlPlane "
        "&& gatewayApplicationProvisioningEnabled" in MAIN
    )
    assert "ledgerTableEndpoint: dataPlane.outputs.ledgerTableEndpoint" in MAIN
    assert MAIN.count("apimProductId: apimProductId") == 2
    assert "value: string(applicationProvisioningEnabled)" in CONTROL_PLANE
    release = (ROOT / "infra/runtime-release.bicep").read_text(encoding="utf-8")
    assert "union(currentApiSettings" in release
    assert "union(currentControlPlaneSettings" in release
    assert release.count("GATEWAY_RELEASE_WORKER_ENABLED: string(releaseWorkerEnabled)") == 2
    assert release.count("APIM_USAGE_OBSERVER_URL: usageObserverUrl") == 2
    assert release.count("APIM_USAGE_OBSERVER_KEY_NAMED_VALUE: usageObserverKeyNamedValue") == 2
    assert "resource applicationProduct " in APIM_INTEGRATION
    assert "name: 'turnstile-ai-consumers'" in APIM_INTEGRATION
    for parameter, setting in (
        ("apimTargetRegistryEnabled", "APIM_TARGET_REGISTRY_ENABLED"),
        ("selfHostedGatewayEnabled", "SELF_HOSTED_GATEWAY_ENABLED"),
        ("selfHostedGatewayProvisioningEnabled", "SELF_HOSTED_GATEWAY_PROVISIONING_ENABLED"),
        ("multiApimTargetRolloutEnabled", "MULTI_APIM_TARGET_ROLLOUT_ENABLED"),
    ):
        assert f"param {parameter} bool = true" in release
        assert release.count(f"{setting}: string({parameter})") == 2
    assert "resource applicationLedgerContributor" not in CONTROL_PLANE
    assert '_output_string(outputs, "controlPlanePrincipalId")' in DEPLOY_SCRIPT
    for template in (DATA_PLANE, CONTROL_PLANE):
        for setting in (
            "APIM_PRODUCT_ID", "LEDGER_TABLE_ENDPOINT", "LEDGER_TABLE_NAME",
            "GATEWAY_APPLICATION_PROVISIONING_ENABLED",
            "GATEWAY_APPLICATION_DEFAULT_MONTHLY_TOKEN_LIMIT",
            "GATEWAY_APPLICATION_DEFAULT_TOKENS_PER_MINUTE",
        ):
            assert f"name: '{setting}'" in template
    for action in (
        "Microsoft.Authorization/permissions/read",
        "Microsoft.ApiManagement/service/subscriptions/read",
        "Microsoft.ApiManagement/service/subscriptions/write",
        "Microsoft.ApiManagement/service/products/apis/read",
        "Microsoft.ApiManagement/service/apis/policies/read",
        "Microsoft.ApiManagement/service/gateways/read",
    ):
        assert action in CONTROL_PLANE_APIM_RBAC
    # Initialization reads existing subscription keys; rotation remains a separate role.
    assert "Microsoft.ApiManagement/service/subscriptions/listSecrets/action" in CONTROL_PLANE_APIM_RBAC
    assert "regenerate" not in CONTROL_PLANE_APIM_RBAC


def test_control_plane_initialization_roles_do_not_depend_on_worker_activation() -> None:
    for name in (
        "routeCredentialWriter", "onboardingCredentialVaultRoleDelegator",
    ):
        declaration = CONTROL_PLANE.split(f"resource {name} ", 1)[1].splitlines()[0]
        assert " = {" in declaration
        assert "if (" not in declaration
    # Exact-scope grants on adopted shared tables are established by the lifecycle
    # before fixed-program initialization, not by the resource-group compute module.
    for name in (
        "routeContributor", "applicationLedgerContributor",
        "onboardingLedgerRoleDelegator", "onboardingRouteRoleDelegator",
    ):
        assert f"resource {name} " not in CONTROL_PLANE
    lifecycle = DEPLOY_SCRIPT.split("def execute(", 1)[1]
    assert lifecycle.index("ensure_shared_storage_roles(") < lifecycle.index("initialize_fixed_program(")
    grants = DEPLOY_SCRIPT.split("def ensure_shared_storage_roles(", 1)[1].split(
        "def ensure_foundry_role(", 1,
    )[0]
    assert '"Storage Table Data Contributor",' in grants
    assert '"Role Based Access Control Administrator"' in grants
    assert "condition=_delegation_condition(delegated_role)" in grants
    event_hub = CONTROL_PLANE.split("resource onboardingEventHubRoleDelegator ", 1)[1]
    assert "if (manageEventHubRoleAssignments && !empty(eventHubNamespaceName))" in event_hub.splitlines()[0]
    assert "var effectiveEnabled =" in CONTROL_PLANE
    assert "value: string(effectiveEnabled)" in CONTROL_PLANE
    assert (
        "module controlPlane 'modules/control-plane-function.bicep' = if (provisionControlPlane)"
        in MAIN
    )


def test_observer_stage_prepares_publisher_key_access_after_named_value_creation() -> None:
    observer = (ROOT / "infra/envoy-cache-adapter/main.bicep").read_text(encoding="utf-8")
    access = observer.split("module publisherObserverKeyAccess ", 1)[1].split("output ", 1)[0]
    assert "if (!empty(publisherPrincipalId))" in access
    assert "scope: resourceGroup(apimResourceGroupName)" in access
    assert "uniqueString(resourceGroup().name)" in access
    assert "apimIntegration.outputs.namedValueName" in access
    assert "publisherPrincipalId: publisherPrincipalId" in access
    assert "output controlPlanePrincipalId string = provisionControlPlane ?" in MAIN


def test_control_plane_uses_its_own_flex_plan_and_the_platform_vnet() -> None:
    assert "appServicePlanName:" not in MAIN.split("module controlPlane", 1)[1].split(
        "module controlPlaneApimRbac", 1
    )[0]
    assert "resourcePrefix: resourcePrefix" in MAIN
    assert "functionSubnetResourceId: dataPlane.outputs.controlFunctionSubnetResourceId" in MAIN
    assert "param functionSubnetResourceId string" in CONTROL_PLANE
    assert "subnetResourceId: functionSubnetResourceId" in CONTROL_PLANE
    assert "apimGatewayUrl: effectiveGatewayApiPath" in MAIN
    assert (
        "var storageName = 'st${take(compactResourcePrefix, 12)}cp${take(suffix, 8)}'"
        not in CONTROL_PLANE
    )
    assert "param storageName string" in CONTROL_PLANE
    assert "var functionName = 'func-${resourcePrefix}-control-${suffix}'" in CONTROL_PLANE
    assert "var planName = 'plan-${resourcePrefix}-control-${suffix}'" in CONTROL_PLANE
    assert "plan-finops" not in CONTROL_PLANE
    assert "vnet-finops" not in CONTROL_PLANE


def test_foundry_managed_identity_access_matches_account_role_contract() -> None:
    from turnstile_core.domain.runtime_models import FOUNDRY_INFERENCE_ROLE_ID

    role = (ROOT / "infra/modules/foundry-managed-identity-rbac.bicep").read_text()
    entry = (ROOT / "infra/foundry-managed-identity-access.bicep").read_text()
    assert FOUNDRY_INFERENCE_ROLE_ID in role
    assert "accounts@2025-06-01' existing" in role
    assert "scope: account" in role
    assert "name: guid(account.id, apimPrincipalId, inferenceRoleId)" in role
    assert "principalId: apimPrincipalId" in role
    assert "principalType: 'ServicePrincipal'" in role
    assert "roleDefinitionId: inferenceRoleId" in role
    assert "includes account key access" in role
    assert "targetScope = 'subscription'" in entry
    assert "'modules/foundry-managed-identity-rbac.bicep'" in entry
    assert "publicNetworkAccess" not in role + entry
    assert "foundry-managed-identity" not in MAIN
    documentation = (ROOT / "docs/deployment.md").read_text()
    assert "foundry-managed-identity-access.bicep" in documentation
    assert FOUNDRY_INFERENCE_ROLE_ID in documentation
    assert "Cognitive Services OpenAI User" in documentation
    assert "does not read or output keys" in documentation


def test_existing_dependency_contracts_are_conditional_and_output_ownership() -> None:
    for name in (
        "existingVirtualNetworkResourceId",
        "existingTelemetryFunctionSubnetResourceId",
        "existingControlPlaneFunctionSubnetResourceId",
        "existingPrivateEndpointSubnetResourceId",
        "existingApiSubnetResourceId",
        "existingPostgresServerResourceId",
        "existingEventHubResourceId",
        "existingLogAnalyticsWorkspaceResourceId",
        "existingApplicationInsightsResourceId",
        "existingKeyVaultResourceId",
    ):
        assert name in MAIN or name in DEPLOY_SCRIPT
        assert name in PARAMETERS
    for switch in (
        "provisionNetwork",
        "provisionEventHub",
        "provisionObservability",
        "provisionKeyVault",
    ):
        assert f"param {switch} bool = true" in MAIN
        assert f"param {switch} bool = true" in DATA_PLANE
    assert "output dependencyResources object" in MAIN
    assert "param keyVaultPrivateDnsLinkName string = 'finops-vnet'" in MAIN
    assert "privateDnsLinkName: keyVaultPrivateDnsLinkName" in DATA_PLANE
    for resource in ("postgres", "eventHub", "observability", "keyVault", "network"):
        assert f"  {resource}: {{" in MAIN
        assert "provisioned:" in MAIN.split(f"  {resource}: {{", 1)[1].split("  }", 1)[0]
    assert "if (provisionNetwork)" in DATA_PLANE
    assert "if (provisionEventHub)" in DATA_PLANE
    assert "if (provisionObservability)" in DATA_PLANE
    assert "if (provisionKeyVault)" in DATA_PLANE
    assert "manageEventHubRoleAssignment" in OBSERVER_APP
    assert "manageKeyVaultRoleAssignments" in CONTROL_PLANE


def test_only_existing_storage_reference_targets_the_storage_resource_group() -> None:
    assert "param storageResourceGroupName string = resourceGroup().name" in MAIN
    assert MAIN.count("scope: resourceGroup(storageResourceGroupName)") == 1
    shared_storage = MAIN.split("resource sharedStorage", 1)[1].split(
        "module dataPlane", 1
    )[0]
    assert "scope: resourceGroup(storageResourceGroupName)" in shared_storage
    assert "existing = {" in shared_storage


def test_observability_public_endpoints_are_explicit() -> None:
    assert DATA_PLANE.count("publicNetworkAccessForIngestion: 'Enabled'") == 2
    assert DATA_PLANE.count("publicNetworkAccessForQuery: 'Enabled'") == 2


def test_application_key_management_role_is_least_privilege() -> None:
    actions = {
        line.strip().strip("'")
        for line in APPLICATION_KEY_MANAGEMENT_RBAC.split("actions: [", 1)[1]
        .split("]", 1)[0]
        .splitlines()
        if line.strip().startswith("'")
    }
    assert actions == {
        "Microsoft.ApiManagement/service/subscriptions/read",
        "Microsoft.ApiManagement/service/subscriptions/listSecrets/action",
        "Microsoft.ApiManagement/service/subscriptions/regeneratePrimaryKey/action",
        "Microsoft.ApiManagement/service/subscriptions/regenerateSecondaryKey/action",
    }
    assert "scope: apim" in APPLICATION_KEY_MANAGEMENT_RBAC


def test_apim_inventory_role_is_read_only_and_resource_scoped() -> None:
    inventory_role = APPLICATION_KEY_MANAGEMENT_RBAC.split("resource inventoryReaderRole ", 1)[1]
    actions = {
        line.strip().strip("'")
        for line in inventory_role.split("actions: [", 1)[1].split("]", 1)[0].splitlines()
        if line.strip().startswith("'")
    }
    assert actions == {
        "Microsoft.Authorization/permissions/read",
        "Microsoft.ApiManagement/service/read",
        "Microsoft.ApiManagement/service/apis/read",
        "Microsoft.ApiManagement/service/apis/operations/read",
        "Microsoft.ApiManagement/service/apis/policies/read",
        "Microsoft.ApiManagement/service/apis/operations/policies/read",
        "Microsoft.ApiManagement/service/gateways/read",
        "Microsoft.ApiManagement/service/gateways/apis/read",
        "Microsoft.ApiManagement/service/gateways/hostnameConfigurations/read",
        "Microsoft.ApiManagement/service/gateways/certificateAuthorities/read",
        "Microsoft.ApiManagement/service/namedValues/read",
    }
    assignment = inventory_role.split("resource apiInventoryReaders ", 1)[1]
    assert "scope: apim" in assignment
    assert "principalId: apiPrincipalId" in assignment
    assert "roleDefinitionId: inventoryReaderRole.id" in assignment
    assert "dataActions: []" in inventory_role


def test_control_plane_role_has_no_subscription_or_resource_group_scope() -> None:
    assert "scope: apim" in CONTROL_PLANE_APIM_RBAC
    assert "assignableScopes: [" in CONTROL_PLANE_APIM_RBAC
    assert "resourceGroup().id" in CONTROL_PLANE_APIM_RBAC


def test_publisher_observer_key_read_is_scoped_to_one_named_value() -> None:
    source = (ROOT / "infra/modules/observer-named-value-rbac.bicep").read_text(
        encoding="utf-8"
    )
    assert "param apimName string" in source
    assert "param observerKeyNamedValue string" in source
    assert "param publisherPrincipalId string" in source
    assert "parent: apim" in source
    assert "name: observerKeyNamedValue" in source
    actions = source.split("actions: [", 1)[1].split("]", 1)[0]
    assert actions.strip() == "'Microsoft.ApiManagement/service/namedValues/listValue/action'"
    assert "scope: observerKey" in source
    assert "scope: apim" not in source
    assert "principalId: publisherPrincipalId" in source
    assert "principalType: 'ServicePrincipal'" in source
    assert "dataActions: []" in source
    assert "module publisherObserverKeyAccess 'modules/observer-named-value-rbac.bicep'" in MAIN
    assert "if (provisionControlPlane && !empty(apimUsageObserver.keyNamedValue))" in MAIN
    assert "observerKeyNamedValue: apimUsageObserver.keyNamedValue" in MAIN
    assert "publisherPrincipalId: controlPlane!.outputs.principalId" in MAIN
    assert all(value not in source for value in ("xle-", "finops-", "75038ef6", "*/"))


def test_publisher_actions_match_the_exact_approved_contract() -> None:
    contract = json.loads(
        (ROOT / "turnstile_core/domain/apim_publication_permissions.json").read_text(
            encoding="utf-8"
        )
    )
    base = CONTROL_PLANE_APIM_RBAC.split("actions: concat([", 1)[1].split(
        "], oauthActions)", 1
    )[0]
    actions = re.findall(r"'([^']+)'", base)
    expected = set(contract["publication"]) | {
        "Microsoft.ApiManagement/service/apis/products/read",
        "Microsoft.ApiManagement/service/apis/revisions/read",
        "Microsoft.ApiManagement/service/gateways/apis/read",
        "Microsoft.ApiManagement/service/gateways/certificateAuthorities/read",
        "Microsoft.ApiManagement/service/gateways/hostnameConfigurations/read",
        "Microsoft.ApiManagement/service/gateways/read",
        "Microsoft.ApiManagement/service/loggers/read",
        "Microsoft.ApiManagement/service/loggers/write",
        "Microsoft.ApiManagement/service/policies/read",
        "Microsoft.ApiManagement/service/policyFragments/read",
        "Microsoft.ApiManagement/service/products/apiLinks/read",
        "Microsoft.ApiManagement/service/products/apis/read",
        "Microsoft.ApiManagement/service/products/policies/read",
        "Microsoft.ApiManagement/service/products/policy/read",
        "Microsoft.ApiManagement/service/products/read",
        "Microsoft.ApiManagement/service/subscriptions/read",
        "Microsoft.ApiManagement/service/subscriptions/listSecrets/action",
        "Microsoft.ApiManagement/service/subscriptions/write",
    }
    assert set(actions) == expected
    assert len(actions) == len(expected)
    assert all("*" not in action and "/delete" not in action for action in actions)
    assert "notActions: []" in CONTROL_PLANE_APIM_RBAC
    assert "dataActions: []" in CONTROL_PLANE_APIM_RBAC


def test_custom_roles_use_installation_specific_names() -> None:
    for template in (CONTROL_PLANE_APIM_RBAC, APPLICATION_KEY_MANAGEMENT_RBAC):
        assert "var roleNameSuffix = uniqueString(resourceGroup().id)" in template
        assert "${roleNameSuffix}'" in template
    assert "roleName: 'Turnstile APIM Publisher ${roleNameSuffix}'" in CONTROL_PLANE_APIM_RBAC
    assert (
        "roleName: 'Turnstile APIM Subscription Key Operator ${roleNameSuffix}'"
        in APPLICATION_KEY_MANAGEMENT_RBAC
    )
    assert "roleName: 'FinOps" not in CONTROL_PLANE_APIM_RBAC
    assert "roleName: 'FinOps" not in APPLICATION_KEY_MANAGEMENT_RBAC


def test_example_parameters_are_non_secret_and_environment_neutral() -> None:
    assert PARAMETERS["resourcePrefix"]["value"] == "turnstile"
    assert PARAMETERS["entraClientId"]["value"] == ""
    assert PARAMETERS["entraAllowedEmailDomains"]["value"] == []
    for secret in (
        "postgresAdministratorPassword",
        "credentialEncryptionKey",
        "managementApiKey",
        "apimSubscriptionKey",
        "apimProbeSubscriptionKey",
    ):
        assert secret not in PARAMETERS
    serialized = json.dumps(PARAMETERS)
    for forbidden in ("xle-", "sebpvmm", "2b04b108", "azurewebsites.net"):
        assert forbidden not in serialized


def test_platform_identities_can_delegate_scoped_apim_dependency_roles() -> None:
    for template, event_hub in (
        (DATA_PLANE, "managedUsageEventHub"),
        (CONTROL_PLANE, "usageEventHub"),
    ):
        assert "f58310d9-a9f6-439a-9e8d-f62e7b41a168" in template
        assert "312a565d-c81f-4fd8-895a-4e21e48d571c" in template
        assert "conditionVersion: '2.0'" in template
        for scope_name, role_id in (
            (event_hub, "2b629674-e913-4c01-ae53-ef4638d8f975"),
            ("credentialVault", "4633458b-17de-408a-b874-0445c86b69e6"),
        ):
            assert f"scope: {scope_name}" in template
            assert f"GuidEquals {{{role_id}}}" in template
    assert "resource apiSubscriptionApimContributor" not in MAIN
    assert "resource controlPlaneSubscriptionApimContributor" not in MAIN
    assert "eventHubNamespaceName: dataPlane.outputs.eventHubNamespaceName" in MAIN
    assert "eventHubName: dataPlane.outputs.eventHubName" in MAIN


def test_adopted_event_hub_grants_are_not_applied_at_a_managed_or_wrong_group_scope() -> None:
    assert "manageEventHubRoleAssignments: dataPlane.outputs.eventHubProvisioned" in MAIN
    for name in (
        "functionEventHubReceiver", "apimEventHubSender", "apiEventHubRoleDelegator",
    ):
        resource = DATA_PLANE.split(f"resource {name} ", 1)[1].split("\nresource ", 1)[0]
        assert "= if (provisionEventHub)" in resource
        assert "scope: managedUsageEventHub" in resource
    delegator = CONTROL_PLANE.split("resource onboardingEventHubRoleDelegator ", 1)[1].split(
        "\nresource ", 1
    )[0]
    assert "if (manageEventHubRoleAssignments && !empty(eventHubNamespaceName))" in delegator
    assert "scope: usageEventHub" in delegator
    for template, resource_name, switch in (
        (CONTROL_PLANE, "eventHubNamespace", "manageEventHubRoleAssignments"),
        (CONTROL_PLANE, "usageEventHub", "manageEventHubRoleAssignments"),
        (OBSERVER_APP, "eventHubNamespace", "manageEventHubRoleAssignment"),
        (OBSERVER_APP, "usageEventHub", "manageEventHubRoleAssignment"),
        (OBSERVER_APP, "eventHubSender", "manageEventHubRoleAssignment"),
    ):
        resource = template.split(f"resource {resource_name} ", 1)[1].split("\nresource ", 1)[0]
        assert f"if ({switch}" in resource
    assert "manageEventHubRoleAssignment: manageEventHubRoleAssignment" in OBSERVER_MAIN


def test_credential_vault_is_separate_and_uses_the_effective_private_network() -> None:
    credential_vault = DATA_PLANE.split("resource credentialVault ", 1)[1].split(
        "\nvar ", 1
    )[0]
    assert "= if (provisionKeyVault)" not in credential_vault
    assert "name: credentialVaultName" in credential_vault
    assert "defaultAction: 'Deny'" in credential_vault
    assert "credentialVaultName: dataPlane.outputs.credentialVaultName" in MAIN
    assert "manageKeyVaultRoleAssignments: dataPlane.outputs.keyVaultProvisioned" in MAIN
    for name in (
        "functionDatabaseSecretReader", "functionCredentialSecretReader", "functionProbeSecretReader",
    ):
        resource = CONTROL_PLANE.split(f"resource {name} ", 1)[1].split("\nresource ", 1)[0]
        assert "= if (manageKeyVaultRoleAssignments)" in resource
    endpoint = DATA_PLANE.split("module credentialVaultPrivateEndpoint ", 1)[1].split(
        "\nresource ", 1
    )[0]
    for required in (
        "'key-vault-private-endpoint.bicep'", "keyVaultName: credentialVault.name",
        "privateEndpointSubnetResourceId: effectivePrivateEndpointSubnetResourceId",
        "virtualNetworkResourceId: effectiveVirtualNetworkResourceId",
        "provisionPrivateDnsZone: !provisionKeyVault && provisionKeyVaultPrivateDnsZone",
        "existingPrivateDnsZoneResourceId: provisionKeyVault",
        "? keyVaultPrivateEndpoint!.outputs.privateDnsZoneId",
        ": existingKeyVaultPrivateDnsZoneResourceId",
        "privateLinkServiceConnectionName: 'route-credentials'",
    ):
        assert required in endpoint
    assert "resource vaultPrivateDnsZone " not in DATA_PLANE
    assert "id: privateEndpointSubnet.id" not in DATA_PLANE
    assert "output credentialVaultPrivateEndpointId string" in MAIN
    assert "  credentialVault: {" in MAIN
    assert "output routeTableName string = 'ModelRoutes'" in MAIN
    assert "output routeTableName string = 'ModelRoutes'" in DATA_PLANE
    assert "output routeTableId string = dataPlane.outputs.routeTableResourceId" in MAIN
    assert "output credentialVaultResourceGroupName string = resourceGroup().name" in DATA_PLANE


def test_vault_dns_reuses_exact_external_ids_without_duplicate_zones_or_links() -> None:
    endpoint = (ROOT / "infra/modules/key-vault-private-endpoint.bicep").read_text(
        encoding="utf-8"
    )
    assert "param existingPrivateDnsZoneResourceId string = ''" in endpoint
    assert (
        "var reusePrivateDnsZone = !provisionPrivateDnsZone "
        "|| !empty(existingPrivateDnsZoneResourceId)"
    ) in endpoint
    for name in ("managedPrivateDnsZone", "privateDnsLink"):
        resource = endpoint.split(f"resource {name} ", 1)[1].split("\nresource ", 1)[0]
        assert "= if (!reusePrivateDnsZone)" in resource
    assert "? existingPrivateDnsZoneResourceId : existingPrivateDnsZone!.id" in endpoint
    assert "privateDnsZoneId: effectivePrivateDnsZoneId" in endpoint
    assert "output privateDnsZoneProvisioned bool = !reusePrivateDnsZone" in endpoint
    assert "output privateDnsLinkProvisioned bool = !reusePrivateDnsZone" in endpoint
    assert DATA_PLANE.count("module credentialVaultPrivateEndpoint ") == 1
    assert "resource credentialVaultPrivateDnsZoneGroup " not in DATA_PLANE
    for output in ("privateDnsZoneProvisioned", "privateDnsLinkProvisioned"):
        assert f"credentialVaultPrivateEndpoint.outputs.{output}" in DATA_PLANE


def test_shared_table_permissions_have_an_explicit_external_installation_contract() -> None:
    documentation = (ROOT / "docs/deployment.md").read_text(encoding="utf-8")
    for template in (DATA_PLANE, CONTROL_PLANE):
        assert "scope: ledgerTable" not in template
        assert "scope: routeTable" not in template
    for required in (
        "ModelRoutes", "routeTableResourceId", "ledgerTableResourceId",
        "Storage Table Data Reader", "Storage Table Data Contributor",
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
        "76199698-9eea-4c19-bc75-cec21354c6b6",
        "conditionVersion=2.0", "ServicePrincipal", "roleAssignments/delete",
    ):
        assert required in documentation
    for output in (
        "routeTableId", "routeTableResourceId", "ledgerTableResourceId",
        "ledgerTableEndpoint", "routeTableEndpoint", "credentialVaultResourceId",
    ):
        assert f"output {output} string = dataPlane.outputs." in MAIN


def test_deployment_installs_model_routes_and_constrained_shared_table_permissions() -> None:
    # These permissions moved out of ARM, not out of the installation contract.
    # Keep this regression guard even while the deployment script is merged separately.
    assert "ModelRoutes" in DEPLOY_SCRIPT
    assert "routeTableResourceId" in DEPLOY_SCRIPT or "routeTableId" in DEPLOY_SCRIPT
    assert (
        "Storage Table Data Reader" in DEPLOY_SCRIPT
        or "76199698-9eea-4c19-bc75-cec21354c6b6" in DEPLOY_SCRIPT
    )
    assert (
        "Role Based Access Control Administrator" in DEPLOY_SCRIPT
        or "f58310d9-a9f6-439a-9e8d-f62e7b41a168" in DEPLOY_SCRIPT
    )
    for condition_fragment in (
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
        "76199698-9eea-4c19-bc75-cec21354c6b6",
        "GuidEquals", "PrincipalType", "ServicePrincipal",
        "Microsoft.Authorization/roleAssignments/delete",
    ):
        assert condition_fragment in DEPLOY_SCRIPT
    assert "conditionVersion" in DEPLOY_SCRIPT or "--condition-version" in DEPLOY_SCRIPT


def test_governance_and_route_credentials_retain_scoped_access() -> None:
    for name in (
        "ledgerTableResourceId", "routeTableResourceId", "credentialVaultResourceId",
    ):
        assert f"param {name} string" in APIM_INTEGRATION
        assert f"{name}: dataPlane.outputs.{name}" in MAIN
    assert "resource platformGovernance " in APIM_INTEGRATION
    assert "scope: platformGovernance" in APIM_INTEGRATION
    assert "credential_vault_resource_id: credentialVaultResourceId" in APIM_INTEGRATION
    assert "route_table_resource_id: routeTableResourceId" in APIM_INTEGRATION
    assert "normalizedLedgerTableEndpoint" in APIM_INTEGRATION
    assert "endsWith(trimmedLedgerTableEndpoint, '/')" in APIM_INTEGRATION
    reader = DATA_PLANE.split("resource apimRouteCredentialReader ", 1)[1].split(
        "\nresource ", 1
    )[0]
    assert "scope: credentialVault" in reader
    assert "principalId: apimPrincipalId" in reader
    assert "4633458b-17de-408a-b874-0445c86b69e6" in reader
    writer = CONTROL_PLANE.split("resource routeCredentialWriter ", 1)[1].split(
        "\nresource ", 1
    )[0]
    assert "if (effectiveEnabled)" not in writer
    assert "scope: credentialVault" in writer
    assert "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" in writer


def test_runtime_diagnostic_access_is_generic_probe_scoped_and_not_key_management() -> None:
    from turnstile_core.domain.runtime_models import RuntimeDiagnosticAccess

    template_rel_path = RuntimeDiagnosticAccess.model_fields["template_path"].default
    assert template_rel_path == "infra/modules/runtime-diagnostic-rbac.bicep"
    source = (ROOT / template_rel_path).read_text(encoding="utf-8")
    integration = (ROOT / "infra/modules/apim-integration.bicep").read_text(encoding="utf-8")
    contract = json.loads(
        (ROOT / "turnstile_core/domain/apim_publication_permissions.json").read_text(
            encoding="utf-8"
        )
    )
    assert "output probeSubscriptionId string = probeSubscription.name" in integration
    assert (
        "loadJsonContent('../../turnstile_core/domain/apim_publication_permissions.json').probe"
        in source
    )
    assert "actions: probePermissions" in source
    assert set(contract["probe"]) == {
        "Microsoft.Authorization/permissions/read",
        "Microsoft.ApiManagement/service/subscriptions/read",
        "Microsoft.ApiManagement/service/subscriptions/listSecrets/action",
    }
    assert "param apimName string\n" in source
    assert "param probeSubscriptionId string\n" in source
    assert "param apiPrincipalIds string[]" in source
    assert "scope: probe" in source
    assert "scope: apim" not in source
    assert "principalType: 'ServicePrincipal'" in source
    assert "union(apiPrincipalIds, [])" in source
    assert "guid(probe.id, principalId, diagnosticReader.id)" in source
    assert "resourceGroup().id" in source
    assert "existing = {" in source
    assert all(value not in source for value in ("xle-", "contoso", "regenerate", "Contributor"))
    assert "module publisherProbeAccess 'runtime-diagnostic-rbac.bicep'" in CONTROL_PLANE_APIM_RBAC
    assert "module runtimeDiagnosticRbac 'modules/runtime-diagnostic-rbac.bicep'" in MAIN
    runtime_rbac = MAIN.split("module runtimeDiagnosticRbac ", 1)[1].split(
        "\noutput ", 1
    )[0]
    assert "probeSubscriptionId: apimProbeSubscriptionId" in runtime_rbac
    assert "apimIntegration.outputs" not in runtime_rbac
    assert "dependsOn: [\n    apimIntegration\n  ]" in runtime_rbac
    assert "output runtimeDiagnosticScope string = runtimeDiagnosticRbac.outputs.probeScope" in MAIN
    assert (
        "output publisherProbeScope string = provisionControlPlane ? runtimeDiagnosticRbac"
        in MAIN
    )


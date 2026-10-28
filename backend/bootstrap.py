"""Create the first password Owner and bootstrap the initial APIM target."""

from __future__ import annotations

import os
import sys
from typing import Protocol
from uuid import UUID

from backend.services.gateway_targets import (
    DEFAULT_SEEDED_APIM_GATEWAY_ID,
    register_existing_apim_target,
)
from turnstile_core.config import Settings, get_settings
from turnstile_core.domain.gateway_targets import ApimTargetWrite
from turnstile_core.persistence.auth_store import AuthStore
from turnstile_core.persistence.repository import PostgreSqlOpsDbProxy
from turnstile_core.persistence.repository_contract import QueryRepository


class InitialOwnerStore(Protocol):
    def create_initial_owner(self, email: str, password_hash: str) -> dict[str, object] | None: ...


def bootstrap_initial_owner(store: InitialOwnerStore, settings: Settings) -> bool:
    email = settings.bootstrap_owner_email.strip().lower()
    configured_hash = settings.bootstrap_owner_password_hash
    if not email or configured_hash is None:
        return False
    return store.create_initial_owner(email, configured_hash.get_secret_value()) is not None


def bootstrap_initial_apim_target(
    repository: QueryRepository,
    settings: Settings,
    *,
    tenant_id: str | None = None,
) -> bool:
    targets = repository.list_apim_targets()
    if targets:
        if not any((settings.apim_gateway_profile_id, settings.apim_resource_group,
                settings.apim_service_name, settings.apim_gateway_url)):
            return False
        identity = settings.legacy_apim_identity
        matches = [row for row in targets if (
            settings.apim_gateway_profile_id is None
            or str(row["gateway_profile_id"]) == str(settings.apim_gateway_profile_id)
        ) and (
            identity is not None and (
                str(row.get("subscription_id")), str(row.get("resource_group")).casefold(),
                str(row.get("service_name")).casefold(), str(row.get("api_id")).casefold(),
            ) == identity
            or identity is None and settings.apim_gateway_profile_id is not None
        )]
        if len(matches) == 1:
            return False
        raise ValueError(
            "Initial APIM identity does not match exactly one of the other APIM targets",
        )
    identity = settings.legacy_apim_identity
    gateway_url = (settings.apim_gateway_url or "").strip()
    resolved_tenant = (tenant_id or os.environ.get("AZURE_TENANT_ID") or "").strip()
    required = {
        "AZURE_SUBSCRIPTION_ID": settings.azure_subscription_id,
        "APIM_RESOURCE_GROUP": settings.apim_resource_group,
        "APIM_SERVICE_NAME": settings.apim_service_name,
        "APIM_API_ID": settings.apim_api_id,
        "APIM_GATEWAY_URL": gateway_url,
        "AZURE_TENANT_ID": resolved_tenant,
    }
    missing = [name for name, value in required.items() if not (value or "").strip()]
    if missing:
        raise ValueError("Missing initial APIM configuration: " + ", ".join(missing))
    if identity is None:
        raise ValueError("AZURE_SUBSCRIPTION_ID must be a valid UUID")
    try:
        parsed_tenant = UUID(resolved_tenant)
    except ValueError as error:
        raise ValueError("AZURE_TENANT_ID must be a valid UUID") from error
    subscription_id = UUID(identity[0])
    resource_group = (settings.apim_resource_group or "").strip()
    service_name = (settings.apim_service_name or "").strip()
    api_id = (settings.apim_api_id or "").strip()
    arm_resource_id = (
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.ApiManagement/service/{service_name}"
    )
    registration = ApimTargetWrite.model_validate(
        {
            "gateway_profile_id": DEFAULT_SEEDED_APIM_GATEWAY_ID,
            "name": service_name,
            "tenant_id": parsed_tenant,
            "subscription_id": subscription_id,
            "resource_group": resource_group,
            "service_name": service_name,
            "api_id": api_id,
            "management_endpoint": f"https://management.azure.com{arm_resource_id}",
            "gateway_endpoint": gateway_url,
            "probe_subscription_id": settings.apim_probe_subscription_id,
        }
    )
    register_existing_apim_target(
        registration,
        settings=settings,
        repository=repository,
    )
    return True


def main() -> int:
    settings = get_settings()
    if settings.bootstrap_owner_email:
        if not settings.database_url:
            print("DATABASE_URL is required to bootstrap the initial Owner.", file=sys.stderr)
            return 2
        store = AuthStore(settings.database_url)
        try:
            created = bootstrap_initial_owner(store, settings)
        finally:
            store.close()
        print("Initial Owner created." if created else "Initial Owner bootstrap skipped.")
    registration_required = settings.apim_target_registry_enabled or any((
        settings.apim_resource_group, settings.apim_service_name, settings.apim_gateway_url,
    ))
    if registration_required:
        if not settings.database_url:
            print(
                "Initial APIM target bootstrap failed: DATABASE_URL is required.", file=sys.stderr,
            )
            return 2
        repository = PostgreSqlOpsDbProxy(settings.database_url, apim_api_id=settings.apim_api_id)
        try:
            if bootstrap_initial_apim_target(repository, settings):
                print("Initial APIM target registered.")
            else:
                print("Initial APIM target bootstrap skipped: APIM targets are already registered.")
        except Exception as error:
            print(f"Initial APIM target bootstrap failed: {error}", file=sys.stderr)
            return 2
        finally:
            repository.close()
    else:
        print(
            "Initial APIM target bootstrap skipped: automatic APIM registration is not configured.",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
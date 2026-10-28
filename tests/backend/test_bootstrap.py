from __future__ import annotations

from unittest.mock import Mock, patch
from uuid import UUID

import pytest
from pydantic import SecretStr

from backend import bootstrap
from backend.bootstrap import bootstrap_initial_apim_target, bootstrap_initial_owner
from backend.services.auth_service import hash_password, verify_password
from backend.services.gateway_targets import DEFAULT_SEEDED_APIM_GATEWAY_ID
from turnstile_core.config import Settings
from turnstile_core.persistence.in_memory import InMemoryRepository


class CapturingInitialOwnerStore:
    def __init__(self, *, created: bool = True) -> None:
        self.created = created
        self.calls: list[tuple[str, str]] = []

    def create_initial_owner(self, email: str, password_hash: str) -> dict[str, object] | None:
        self.calls.append((email, password_hash))
        return {"role": "owner"} if self.created else None


def test_bootstrap_creates_owner_with_configured_hash() -> None:
    password_hash = hash_password("a-long-bootstrap-password")
    settings = Settings(
        bootstrap_owner_email=" Owner@Contoso.com ",
        bootstrap_owner_password_hash=SecretStr(password_hash),
    )
    store = CapturingInitialOwnerStore()

    assert bootstrap_initial_owner(store, settings)
    assert store.calls[0][0] == "owner@contoso.com"
    assert verify_password("a-long-bootstrap-password", store.calls[0][1])


def test_bootstrap_is_a_noop_when_users_already_exist() -> None:
    settings = Settings(
        bootstrap_owner_email="owner@contoso.com",
        bootstrap_owner_password_hash=SecretStr(hash_password("a-long-bootstrap-password")),
    )

    assert not bootstrap_initial_owner(CapturingInitialOwnerStore(created=False), settings)


def test_bootstrap_configuration_must_be_paired() -> None:
    try:
        Settings(bootstrap_owner_email="owner@contoso.com")
    except ValueError as error:
        assert "must be configured together" in str(error)
    else:
        raise AssertionError("one-sided bootstrap configuration was accepted")


def test_bootstrap_initial_apim_target_registers_seeded_profile_when_empty() -> None:
    repository = InMemoryRepository()
    settings = Settings(
        azure_subscription_id="00000000-0000-4000-8000-000000000010",
        apim_resource_group="unit-group",
        apim_service_name="unit-apim",
        apim_api_id="turnstile-llm",
        apim_gateway_url="https://unit-apim.azure-api.net/turnstile/llm",
    )
    with patch("backend.bootstrap.register_existing_apim_target") as register:
        created = bootstrap_initial_apim_target(
            repository,
            settings,
            tenant_id="00000000-0000-4000-8000-000000000020",
        )
    assert created is True
    register.assert_called_once()
    registration = register.call_args.args[0]
    assert registration.gateway_profile_id == DEFAULT_SEEDED_APIM_GATEWAY_ID
    assert registration.name == "unit-apim"
    assert registration.tenant_id == UUID("00000000-0000-4000-8000-000000000020")
    assert str(registration.gateway_endpoint) == "https://unit-apim.azure-api.net/turnstile/llm"


@pytest.mark.parametrize("case", [
    "missing_tenant", "invalid_tenant", "azure_subscription_id", "apim_resource_group",
    "apim_service_name", "apim_api_id", "apim_gateway_url", "registration_failed",
    "registered", "other_target", "success",
])
def test_required_initial_apim_bootstrap_has_explicit_outcome(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], case: str,
) -> None:
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    settings = Settings(
        apim_target_registry_enabled=True,
        database_url="postgresql://offline.invalid/turnstile",
        azure_subscription_id="00000000-0000-4000-8000-000000000010",
        apim_resource_group="unit-group", apim_service_name="unit-apim",
        apim_api_id="turnstile-llm", apim_gateway_url="https://unit-apim.azure-api.net/turnstile/llm",
    )
    if case in {"azure_subscription_id", "apim_resource_group", "apim_service_name",
                "apim_api_id", "apim_gateway_url"}:
        settings = settings.model_copy(update={case: ""})
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    if case != "missing_tenant":
        monkeypatch.setenv(
            "AZURE_TENANT_ID", "not-a-uuid" if case == "invalid_tenant"
            else "00000000-0000-4000-8000-000000000020",
        )
    repository = Mock()
    repository.list_apim_targets.return_value = [{
        "gateway_profile_id": DEFAULT_SEEDED_APIM_GATEWAY_ID,
        "subscription_id": settings.azure_subscription_id,
        "resource_group": settings.apim_resource_group, "service_name": settings.apim_service_name,
        "api_id": settings.apim_api_id,
    }] if case == "registered" else [{"gateway_profile_id": UUID(int=999)}] if (
        case == "other_target"
    ) else []
    monkeypatch.setattr(bootstrap, "get_settings", lambda: settings)
    monkeypatch.setattr(bootstrap, "PostgreSqlOpsDbProxy", Mock(return_value=repository))
    register = Mock(side_effect=RuntimeError("ARM inventory denied")
                    if case == "registration_failed" else None)
    monkeypatch.setattr(bootstrap, "register_existing_apim_target", register)
    code = bootstrap.main()
    output = capsys.readouterr()
    if case == "success":
        assert code == 0
        assert "Initial APIM target registered." in output.out
        register.assert_called_once()
    elif case == "registered":
        assert code == 0
        assert "already registered" in output.out.lower()
        register.assert_not_called()
    else:
        assert code != 0
        assert "failed" in output.err.lower()
        if case in {"missing_tenant", "invalid_tenant"}:
            assert "AZURE_TENANT_ID" in output.err
        elif case == "registration_failed":
            assert "ARM inventory denied" in output.err
        elif case == "other_target":
            assert "other APIM targets" in output.err
        else:
            assert case.upper() in output.err
        if case != "registration_failed":
            register.assert_not_called()
    repository.close.assert_called_once()


def test_bootstrap_restart_preserves_existing_owner_and_registers_only_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    settings = Settings(
        database_url="postgresql://offline.invalid/turnstile",
        bootstrap_owner_email="owner@example.test",
        bootstrap_owner_password_hash=SecretStr(hash_password("unit-existing-owner-password")),
        azure_subscription_id="00000000-0000-4000-8000-000000000010",
        apim_resource_group="unit-group", apim_service_name="unit-apim",
        apim_api_id="turnstile-llm", apim_gateway_url="https://unit-apim.azure-api.net/turnstile/llm",
    )
    monkeypatch.setenv("AZURE_TENANT_ID", "00000000-0000-4000-8000-000000000020")
    monkeypatch.setattr(bootstrap, "get_settings", lambda: settings)
    owner = Mock()
    owner.create_initial_owner.return_value = None
    monkeypatch.setattr(bootstrap, "AuthStore", Mock(return_value=owner))
    repository = Mock()
    repository.list_apim_targets.side_effect = [[], [{
        "gateway_profile_id": DEFAULT_SEEDED_APIM_GATEWAY_ID,
        "subscription_id": settings.azure_subscription_id,
        "resource_group": settings.apim_resource_group, "service_name": settings.apim_service_name,
        "api_id": settings.apim_api_id,
    }]]
    monkeypatch.setattr(bootstrap, "PostgreSqlOpsDbProxy", Mock(return_value=repository))
    register = Mock()
    monkeypatch.setattr(bootstrap, "register_existing_apim_target", register)
    assert bootstrap.main() == bootstrap.main() == 0
    register.assert_called_once()
    assert owner.create_initial_owner.call_count == owner.close.call_count == 2
    assert repository.close.call_count == 2
    output = capsys.readouterr()
    assert output.out.count("Initial Owner bootstrap skipped.") == 2
    assert output.out.count("Initial APIM target registered.") == 1
    assert "already registered" in output.out


@pytest.mark.parametrize("required", [False, True])
def test_initial_registration_without_database_is_explicit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], required: bool,
) -> None:
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    settings = Settings(apim_target_registry_enabled=required)
    monkeypatch.setattr(bootstrap, "get_settings", lambda: settings)
    repository = Mock()
    monkeypatch.setattr(bootstrap, "PostgreSqlOpsDbProxy", repository)
    code = bootstrap.main()
    output = capsys.readouterr()
    repository.assert_not_called()
    if required:
        assert code != 0 and "DATABASE_URL" in output.err
    else:
        assert code == 0 and "not configured" in output.out


@pytest.mark.parametrize("explicit", [None, "matching", "different", "registry_only"])
def test_existing_nondefault_apim_is_identified_without_default_uuid(
    monkeypatch: pytest.MonkeyPatch, explicit: str | None,
) -> None:
    from tests.backend.model_platform.test_gateway_targets import target

    identity = UUID("20000000-0000-4000-8000-000000000001")
    row = target(gateway_profile_id=identity)
    settings = Settings.model_construct(
        database_url="postgresql://offline.invalid/turnstile", apim_target_registry_enabled=True,
        azure_subscription_id=str(row.subscription_id), apim_resource_group=row.resource_group,
        apim_service_name=row.service_name, apim_api_id=row.api_id,
        apim_gateway_url=f"https://{row.service_name}.azure-api.net/{row.api_path}",
        apim_gateway_profile_id=None if explicit is None else identity
        if explicit == "matching" else UUID(int=999),
    )
    if explicit == "registry_only":
        settings = settings.model_copy(update={
            "azure_subscription_id": None, "apim_resource_group": None,
            "apim_service_name": None, "apim_gateway_url": None,
            "apim_gateway_profile_id": None,
        })
    repository = Mock()
    repository.list_apim_targets.return_value = [row.model_dump(mode="python")]
    monkeypatch.setattr(bootstrap, "get_settings", lambda: settings)
    monkeypatch.setattr(bootstrap, "PostgreSqlOpsDbProxy", Mock(return_value=repository))
    register = Mock()
    monkeypatch.setattr(bootstrap, "register_existing_apim_target", register)
    assert bootstrap.main() == (2 if explicit == "different" else 0)
    register.assert_not_called()
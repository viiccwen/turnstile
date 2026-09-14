from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).parents[3]
ADAPTER = ROOT / "infra" / "envoy-cache-adapter"


def load_shipper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("envoy_cache_shipper", ADAPTER / "shipper.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def access_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "timestamp": "2026-08-15T01:02:03.000Z",
        "request_id": "request-envoy-1",
        "correlation_id": "correlation-envoy-1",
        "organization": "Contoso",
        "organization_id": "org-1",
        "department": "Platform",
        "department_id": "department-1",
        "project": "FinOps",
        "project_id": "project-1",
        "agent": "Delivery Engineer",
        "agent_id": "agent-1",
        "user": "Lei",
        "user_id": "lei@example.com",
        "workflow": "interactive",
        "run_id": "run-1",
        "turn_index": "1",
        "provider": "microsoft_foundry",
        "model": "customer-luna-alias",
        "model_id": "model-1",
        "runtime": "Envoy Cache Experiment",
        "api_format": "openai_chat",
        "request_source": "agent-invocation-module",
        "prompt_tokens": 1200,
        "cache_read_tokens": 1000,
        "cache_write_tokens": 128,
        "output_tokens": 30,
        "response_code": 200,
        "latency_ms": 1234,
    }
    row.update(overrides)
    return row


def test_shipper_normalizes_exact_cache_buckets_without_double_counting() -> None:
    event = load_shipper().normalize_access_row(access_row())

    assert event is not None
    assert event["id"] == "request-envoy-1"
    assert event["correlation_id"] == "correlation-envoy-1"
    assert event["input_tokens"] == 72
    assert event["cached_tokens"] == 1128
    assert event["cache_write_tokens"] == 128
    assert event["output_tokens"] == 30
    assert event["estimated"] is False
    assert event["runtime_authoritative"] is False


@pytest.mark.parametrize("nested", (None, "", "-"))
def test_shipper_uses_top_level_cache_only_when_nested_measurement_is_missing(
    nested: object,
) -> None:
    event = load_shipper().normalize_access_row(access_row(
        cache_read_tokens=nested, cache_read_tokens_fallback=1000,
    ))
    assert event is not None
    assert event["cached_tokens"] == 1128
    assert event["input_tokens"] == 72


@pytest.mark.parametrize("nested", (0, "0", 200))
def test_shipper_preserves_explicit_nested_cache_including_zero(nested: object) -> None:
    event = load_shipper().normalize_access_row(access_row(
        cache_read_tokens=nested, cache_read_tokens_fallback=1000,
    ))
    assert event is not None
    assert event["cached_tokens"] == int(str(nested)) + 128
    assert event["input_tokens"] + event["cached_tokens"] == 1200


@pytest.mark.parametrize("runtime", (None, "", "-", "unattributed", "pool-member-runtime"))
def test_only_exact_pool_runtime_metadata_is_authoritative(runtime: object) -> None:
    event = load_shipper().normalize_access_row(access_row(pool_runtime=runtime))
    assert event is not None
    assert event["runtime_authoritative"] is (runtime == "pool-member-runtime")
    if runtime == "pool-member-runtime":
        assert event["runtime"] == runtime
    else:
        assert event["runtime"] == "Envoy Cache Experiment"
    assert load_shipper().normalize_access_row(access_row(
        response_code=503, pool_runtime=runtime,
    )) is None


def test_observer_keeps_fallback_cache_and_pool_identity_in_separate_metadata() -> None:
    template = yaml.safe_load((ADAPTER / "envoy.yaml.template").read_text(encoding="utf-8"))
    listener = template["static_resources"]["listeners"][0]
    config = listener["filter_chains"][0]["filters"][0]["typed_config"]
    filters = {item["name"]: item["typed_config"] for item in config["http_filters"]}
    request_rules = filters["envoy.filters.http.header_to_metadata"]["request_rules"]
    pool = next(rule for rule in request_rules if rule["header"] == "x-turnstile-pool-runtime")
    assert pool["on_header_present"]["key"] == "pool_runtime"
    assert pool["remove"] is True
    rules = filters["envoy.filters.http.json_to_metadata"]["response_rules"]["rules"]
    fallback = next(rule for rule in rules if rule["selectors"] == [
        {"key": "usage"}, {"key": "cached_tokens"},
    ])
    assert fallback["on_present"]["key"] == "cache_read_tokens_fallback"
    nested = next(rule for rule in rules if rule["selectors"] == [
        {"key": "usage"}, {"key": "prompt_tokens_details"}, {"key": "cached_tokens"},
    ])
    assert nested["on_present"]["key"] == "cache_read_tokens"


def test_shipper_skips_failed_or_usage_free_access_rows() -> None:
    normalize = load_shipper().normalize_access_row

    assert normalize(access_row(response_code=500)) is None
    assert normalize(
        access_row(
            prompt_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=0,
        )
    ) is None


def test_shipper_keeps_anthropic_input_exclusive_of_cache_buckets() -> None:
    event = load_shipper().normalize_access_row(
        access_row(
            api_format="anthropic_messages",
            prompt_tokens=10,
            cache_read_tokens=2048,
            cache_write_tokens=256,
            output_tokens=20,
        )
    )

    assert event is not None
    assert event["input_tokens"] == 10
    assert event["cached_tokens"] == 2304
    assert event["cache_write_tokens"] == 256
    assert event["output_tokens"] == 20


def test_shipper_normalizes_responses_input_cache_without_double_counting() -> None:
    event = load_shipper().normalize_access_row(
        access_row(
            api_format="openai_responses",
            prompt_tokens=1200,
            cache_read_tokens=1000,
            cache_write_tokens=0,
            output_tokens=30,
        )
    )

    assert event is not None
    assert event["input_tokens"] == 200
    assert event["cached_tokens"] == 1000
    assert event["output_tokens"] == 30


def test_adapter_is_provider_neutral_and_does_not_log_prompts() -> None:
    envoy = (ADAPTER / "envoy.yaml.template").read_text(encoding="utf-8")
    entrypoint = (ADAPTER / "entrypoint.py").read_text(encoding="utf-8")
    apim = (ADAPTER / "apim.bicep").read_text(encoding="utf-8")

    assert "authorization" not in envoy.lower()
    assert "messages" not in envoy
    assert "prompt_tokens" in envoy
    assert "cache_write_tokens" in envoy
    assert "cache_creation_input_tokens" in envoy
    assert "cache_read_input_tokens" in envoy
    assert "envoy.filters.http.json_to_metadata" in envoy
    assert "max_event_size: 10485760" in envoy
    assert "{ key: usage }, { key: input_tokens_details }, { key: cached_tokens }" in envoy
    assert "{ key: response }, { key: usage }, { key: input_tokens }" in envoy
    assert (
        "{ key: response }, { key: usage }, { key: input_tokens_details }, "
        "{ key: cached_tokens }" in envoy
    )
    assert "{ key: response }, { key: usage }, { key: output_tokens }" in envoy
    assert envoy.count("{ key: usage }, { key: cache_creation_input_tokens }") == 3
    assert envoy.count("{ key: usage }, { key: cache_read_input_tokens }") == 3
    assert "envoy.filters.http.dynamic_forward_proxy" in envoy
    assert "envoy.clusters.dynamic_forward_proxy" in envoy
    assert "host_rewrite_header: x-turnstile-upstream-host" in envoy
    assert "header: x-turnstile-pool-runtime" in envoy
    assert envoy.index("header: x-hive-runtime") < envoy.index(
        "header: x-turnstile-pool-runtime"
    )
    assert "request_headers_to_remove:" in envoy
    for header in (
        "client-ip",
        "disguised-host",
        "was-default-hostname",
        "x-arr-log-id",
        "x-arr-ssl",
        "x-client-ip",
        "x-client-port",
        "x-forwarded-tlsversion",
        "x-original-url",
        "x-site-deployment-id",
        "x-waws-unencoded-url",
    ):
        assert f"- {header}" in envoy
    assert "PROVIDER_HOST" not in envoy
    assert "PROVIDER_HOST" not in entrypoint
    assert "Microsoft.ApiManagement/service/apis" not in apim
    assert "Microsoft.ApiManagement/service/subscriptions" not in apim
    assert "turnstile-envoy-adapter-key" in apim


def test_main_apim_has_an_explicit_all_model_observer_adoption_boundary() -> None:
    main = (ROOT / "infra/main.bicep").read_text(encoding="utf-8")
    integration = (ROOT / "infra/modules/apim-integration.bicep").read_text(
        encoding="utf-8"
    )
    parent_policy = (ROOT / "infra/policies/foundry-finops-policy.xml").read_text(
        encoding="utf-8"
    )
    assert "__USAGE_OBSERVER_HEADERS__" in parent_policy
    assert "finops-legacy-foundry-observer" in integration
    assert "finops-legacy-databricks-observer" in integration
    assert "selectedRoutingManaged" in integration
    assert "selectedModelKnown&quot;, false))" in integration
    assert "streamOptions[&quot;include_usage&quot;] = true" in integration
    assert "x-turnstile-upstream-host" in integration
    assert "x-adapter-key" in integration
    assert "mode: 'disabled'" in main
    assert "keyNamedValue: ''" in main
    assert "param apimUsageObserverLegacyRoutingEnabled bool = false" in main


def test_observer_registry_public_endpoint_is_explicit() -> None:
    main = (ROOT / "infra/envoy-cache-adapter/main.bicep").read_text(encoding="utf-8")

    assert "publicNetworkAccess: 'Enabled'" in main
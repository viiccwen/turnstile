from __future__ import annotations

import hashlib
from dataclasses import replace
from xml.etree import ElementTree as ET

import pytest

from turnstile_core.integrations.apim_control_plane_contract import (
    CompiledGatewayRelease,
)
from turnstile_core.integrations.apim_policy_compiler import (
    compiled_policy_matches,
    compiled_policy_sources,
    policy_sha256,
)
from turnstile_core.integrations.apim_policy_components import (
    parent_readback_matches,
    policy_hash_matches,
)

POLICY = (
    '<policies>\n  <inbound><set-variable value="@(true)" name="guard" /></inbound>\n'
    '</policies>'
)


@pytest.mark.parametrize("legacy", [False, True])
def test_parent_readback_accepts_recorded_raw_and_canonical_identities(legacy: bool) -> None:
    expected = hashlib.sha256(POLICY.encode()).hexdigest() if legacy else policy_sha256(POLICY)
    assert parent_readback_matches(POLICY, expected_contract=None, expected_raw=expected)
    assert not parent_readback_matches(
        POLICY.replace("true", "false"), expected_contract=None, expected_raw=expected,
    )


def test_policy_identity_canonicalizes_incoming_xml_and_fails_closed() -> None:
    normalized = ET.tostring(ET.fromstring(POLICY), encoding="unicode")
    assert policy_sha256(POLICY) == policy_sha256(normalized)
    assert policy_hash_matches(policy_sha256(POLICY), normalized)
    assert not policy_hash_matches(None, POLICY)
    assert not policy_hash_matches("0" * 64, "<policies>")
    changed = POLICY.replace("</policies>", "<!--drift--></policies>")
    assert policy_sha256(POLICY) != policy_sha256(changed)


@pytest.mark.parametrize("field", [
    "chat_completions_policy", "responses_policy", "responses_compact_policy",
    "messages_policy", "count_tokens_policy", "models_policy", "images_generations_policy",
    "availability_probe_policies",
])
def test_compiled_identity_includes_every_api_and_probe(field: str) -> None:
    fields = {
        name: POLICY.replace('name="guard"', f'name="{name}"') for name in (
            "chat_completions_policy", "responses_policy", "responses_compact_policy",
            "messages_policy", "count_tokens_policy", "models_policy", "images_generations_policy",
        )
    }
    compiled = CompiledGatewayRelease(
        **fields, policy_sha256="", backends=(), named_values=(),
        availability_probe_policies=(("probe", POLICY),),
    )
    sources = compiled_policy_sources(compiled)
    assert sources == (*fields.values(), POLICY)
    canonical = policy_sha256(*sources)
    raw = hashlib.sha256("\n".join(sources).encode()).hexdigest()
    assert compiled_policy_matches(compiled, canonical)
    assert compiled_policy_matches(compiled, raw)
    changed = replace(compiled, **{
        field: (("probe", POLICY.replace("true", "false")),)
        if field == "availability_probe_policies" else fields[field].replace("true", "false"),
    })
    assert not compiled_policy_matches(changed, canonical)
    assert not compiled_policy_matches(changed, raw)
from __future__ import annotations

from collections.abc import Iterator

import pytest

from backend.api import app
from backend.http import model_platform, service_dependencies
from backend.http.dependencies import get_repository
from backend.http.session import get_auth_store
from tests.platform.api.api_support import OWNER_SESSION, StubAuthStore, client
from turnstile_core.config import Settings, get_settings
from turnstile_core.persistence.in_memory import InMemoryRepository


@pytest.fixture(autouse=True)
def explicit_demo_repository(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    repository = InMemoryRepository()
    settings = Settings(management_api_key=None, production=False)
    app.dependency_overrides[get_repository] = lambda: repository
    app.dependency_overrides[get_auth_store] = StubAuthStore
    app.dependency_overrides[get_settings] = lambda: settings
    monkeypatch.setattr(service_dependencies, "get_settings", lambda: settings)
    monkeypatch.setattr(model_platform, "get_settings", lambda: settings)
    client.cookies.set("turnstile_session", OWNER_SESSION)
    yield
    client.cookies.clear()
    app.dependency_overrides.pop(get_repository, None)
    app.dependency_overrides.pop(get_auth_store, None)
    app.dependency_overrides.pop(get_settings, None)
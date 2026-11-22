"""Deep-review regressions for Google Workspace auth: per-collector scopes, OAuth token cache re-consent,
service-account key file mode and the token cache write."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import run as google_run
from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.run import (
    GoogleRunConfig,
    build_google_preflight_rows,
    run_google_live,
)


class _ScopedCredentials:
    """Delegated service-account credentials: ``with_scopes`` returns a copy holding only those scopes."""

    def __init__(self, scopes: tuple[str, ...] = ()) -> None:
        self.scopes = scopes

    def with_scopes(self, scopes: list[str]) -> _ScopedCredentials:
        return _ScopedCredentials(tuple(scopes))

    def with_subject(self, _subject: str) -> _ScopedCredentials:
        return self


# ---- R056: each collector runs on a token narrowed to its own scopes --------------------------------------------


def test_r056_each_collector_gets_a_token_with_only_its_own_scopes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.collectors.base import CollectorResult

    seen: dict[str, tuple[str, ...]] = {}

    def collector(name: str, scopes: tuple[str, ...]) -> Any:
        class _Collector:
            required_scopes = scopes

            def run(self, context: dict[str, Any]) -> CollectorResult:
                seen[name] = tuple(getattr(context["client"].credentials, "scopes", ()))
                return CollectorResult(name, "ok", {}, 0, coverage=[{"collector": name, "name": "x", "status": "ok", "item_count": 0}])

        _Collector.name = name
        return _Collector()

    registry = {"a": collector("a", ("scope://a",)), "b": collector("b", ("scope://b1", "scope://b2"))}
    monkeypatch.setattr(google_run, "REGISTRY", registry)
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: _ScopedCredentials(("scope://a", "scope://b1", "scope://b2")))

    run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="scopes", subject="admin@example.com",
                                    service_account_key=tmp_path / "k.json", collectors="a,b"))
    assert seen == {"a": ("scope://a",), "b": ("scope://b1", "scope://b2")}


def test_r056_probe_reads_each_collector_with_its_own_scopes() -> None:
    seen: list[tuple[str, tuple[str, ...]]] = []

    class _Client(GoogleWorkspaceClient):
        def list_alerts(self, **_kwargs: Any) -> list[dict[str, Any]]:
            seen.append(("alerts", tuple(self.credentials.scopes)))
            return []

        def list_devices(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            seen.append((resource, tuple(self.credentials.scopes)))
            return []

    from auditex.google_workspace.collectors import REGISTRY

    client = _Client(_ScopedCredentials(("all",)), delegated=True)
    build_google_preflight_rows(client, ["google_alert_center", "google_devices"], domain=None)
    assert seen == [
        ("alerts", tuple(REGISTRY["google_alert_center"].required_scopes)),
        ("mobile", tuple(REGISTRY["google_devices"].required_scopes)),
    ]


def test_r056_credentials_without_scoping_are_shared_unchanged() -> None:
    client = GoogleWorkspaceClient(object())
    assert client.for_scopes(("scope://a",)) is client

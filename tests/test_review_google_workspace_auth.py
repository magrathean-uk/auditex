"""Deep-review regressions for Google Workspace auth: per-collector scopes, OAuth token cache re-consent,
service-account key file mode and the token cache write."""
from __future__ import annotations

import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import auth as google_auth
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


# ---- R059: the OAuth token cache is re-consented when scopes change or the refresh fails -------------------------


class _GoogleAuthError(Exception):
    pass


class _RefreshError(_GoogleAuthError):
    pass


class _UserCredentials:
    """google.oauth2.credentials.Credentials as the library builds it: explicit scopes win over the cached ones."""

    def __init__(self, scopes: list[str], *, valid: bool = True, refresh_error: bool = False, tag: str = "cached") -> None:
        self.scopes = list(scopes)
        self.valid = valid
        self.expired = not valid
        self.refresh_token = "<REDACTED>"
        self.refresh_error = refresh_error
        self.tag = tag

    @classmethod
    def from_authorized_user_file(cls, path: str, scopes: list[str] | None = None) -> _UserCredentials:
        info = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(scopes if scopes is not None else info.get("scopes") or [], valid=info.get("valid", True),
                   refresh_error=info.get("refresh_error", False))

    def has_scopes(self, scopes: list[str]) -> bool:
        return set(scopes).issubset(self.scopes)

    def refresh(self, _request: Any) -> None:
        if self.refresh_error:
            raise _RefreshError("invalid_grant")
        self.valid, self.expired = True, False

    def to_json(self) -> str:
        return json.dumps({"scopes": self.scopes, "tag": self.tag})


@pytest.fixture
def oauth_modules(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"flows": 0, "flow_error": None}

    class _Flow:
        def __init__(self, scopes: list[str]) -> None:
            self.scopes = scopes

        @classmethod
        def from_client_secrets_file(cls, _path: str, scopes: list[str]) -> _Flow:
            return cls(scopes)

        def run_local_server(self, port: int = 0) -> _UserCredentials:
            state["flows"] += 1
            if state["flow_error"] is not None:
                raise state["flow_error"]
            return _UserCredentials(self.scopes, tag="consented")

    modules = {
        "google": types.ModuleType("google"),
        "google.auth": types.ModuleType("google.auth"),
        "google.auth.exceptions": types.ModuleType("google.auth.exceptions"),
        "google.auth.transport": types.ModuleType("google.auth.transport"),
        "google.auth.transport.requests": types.ModuleType("google.auth.transport.requests"),
        "google.oauth2": types.ModuleType("google.oauth2"),
        "google.oauth2.credentials": types.ModuleType("google.oauth2.credentials"),
        "google_auth_oauthlib": types.ModuleType("google_auth_oauthlib"),
        "google_auth_oauthlib.flow": types.ModuleType("google_auth_oauthlib.flow"),
    }
    modules["google.auth.exceptions"].GoogleAuthError = _GoogleAuthError  # type: ignore[attr-defined]
    modules["google.auth.exceptions"].RefreshError = _RefreshError  # type: ignore[attr-defined]
    modules["google.auth.transport.requests"].Request = object  # type: ignore[attr-defined]
    modules["google.oauth2.credentials"].Credentials = _UserCredentials  # type: ignore[attr-defined]
    modules["google_auth_oauthlib.flow"].InstalledAppFlow = _Flow  # type: ignore[attr-defined]
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(google_auth, "_module_available", lambda _module: True)
    return state


def _oauth_config(tmp_path: Path, scopes: tuple[str, ...]) -> google_auth.GoogleAuthConfig:
    return google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=scopes, oauth_client=tmp_path / "client.json",
                                        token_cache=tmp_path / "cache" / "token.json")


def _write_cache(tmp_path: Path, **info: Any) -> None:
    (tmp_path / "cache").mkdir(exist_ok=True)
    (tmp_path / "cache" / "token.json").write_text(json.dumps(info), encoding="utf-8")


def test_r059_cached_token_without_the_new_scopes_is_re_consented(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a"])
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://b")))
    assert oauth_modules["flows"] == 1
    assert credentials.tag == "consented" and credentials.scopes == ["scope://a", "scope://b"]
    assert json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))["scopes"] == ["scope://a", "scope://b"]


def test_r059_cached_token_with_every_scope_is_reused(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a", "scope://b"])
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 0 and credentials.tag == "cached"


def test_r059_refresh_error_falls_back_to_consent(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], valid=False, refresh_error=True)
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 1 and credentials.tag == "consented"


def test_r059_google_auth_error_ends_the_run_as_google_auth_failed(
    tmp_path: Path, oauth_modules: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    oauth_modules["flow_error"] = _GoogleAuthError("access_denied")
    with pytest.raises(RuntimeError, match="Google sign-in failed"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))

    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    rc = run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path / "out", auth="oauth",
                                         oauth_client=tmp_path / "client.json", token_cache=tmp_path / "cache" / "t.json",
                                         collectors="google_alert_center"))
    assert rc == 2
    assert json.loads(capsys.readouterr().err)["error"] == "google_auth_failed"


# ---- R091: writing the token cache never changes an existing folder, and never writes through a link -------------


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_r091_pre_existing_parent_dir_mode_unchanged(tmp_path: Path) -> None:
    from azure_tenant_audit.secret_hygiene import secure_write_text

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    cache = shared / "token.json"
    cache.write_text("old", encoding="utf-8")
    os.chmod(cache, 0o644)

    secure_write_text(cache, "new")

    assert _mode(shared) == 0o755
    assert _mode(cache) == 0o600
    assert cache.read_text(encoding="utf-8") == "new"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_r091_missing_parent_dirs_are_created_owner_only(tmp_path: Path) -> None:
    from azure_tenant_audit.secret_hygiene import secure_write_text

    target = tmp_path / "a" / "b" / "token.json"
    secure_write_text(target, "x")
    assert _mode(tmp_path / "a") == 0o700 and _mode(tmp_path / "a" / "b") == 0o700
    assert _mode(target) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX symbolic links")
def test_r091_a_link_at_the_cache_path_is_replaced_not_written_through(tmp_path: Path) -> None:
    from azure_tenant_audit.secret_hygiene import secure_write_text

    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("keep", encoding="utf-8")
    link = tmp_path / "token.json"
    link.symlink_to(elsewhere)

    secure_write_text(link, "secret")

    assert elsewhere.read_text(encoding="utf-8") == "keep"
    assert not link.is_symlink() and link.read_text(encoding="utf-8") == "secret"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["elsewhere.txt", "token.json"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_r091_oauth_token_cache_folder_is_created_owner_only(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    previous = os.umask(0o022)
    try:
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    finally:
        os.umask(previous)
    assert _mode(tmp_path / "cache") == 0o700
    assert _mode(tmp_path / "cache" / "token.json") == 0o600


# ---- R092: a domain-wide delegation key readable by others is refused, as the M365 certificate is -----------------


@pytest.fixture
def service_account_module(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    loaded: list[str] = []

    class _Factory:
        @staticmethod
        def from_service_account_file(path: str, *, scopes: list[str]) -> _ScopedCredentials:
            loaded.append(path)
            return _ScopedCredentials(tuple(scopes))

    service_account = types.ModuleType("google.oauth2.service_account")
    service_account.Credentials = _Factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    monkeypatch.setitem(sys.modules, "google.oauth2", types.ModuleType("google.oauth2"))
    monkeypatch.setitem(sys.modules, "google.oauth2.service_account", service_account)
    exceptions = types.ModuleType("google.auth.exceptions")
    exceptions.GoogleAuthError = _GoogleAuthError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google.auth", types.ModuleType("google.auth"))
    monkeypatch.setitem(sys.modules, "google.auth.exceptions", exceptions)
    monkeypatch.setattr(google_auth, "_module_available", lambda _module: True)
    return loaded


def _key(tmp_path: Path, mode: int) -> Path:
    key = tmp_path / "key.json"
    key.write_text(json.dumps({"type": "service_account", "client_email": "sa@example.iam.gserviceaccount.com"}), encoding="utf-8")
    os.chmod(key, mode)
    return key


def _delegation_config(key: Path) -> google_auth.GoogleAuthConfig:
    return google_auth.GoogleAuthConfig(auth_mode="domain-delegation", scopes=("scope://a",), subject="admin@example.com",
                                        service_account_key=key)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_r092_key_readable_by_others_is_refused(tmp_path: Path, service_account_module: list[str], mode: int) -> None:
    with pytest.raises(ValueError, match="owner-only"):
        google_auth.build_google_credentials(_delegation_config(_key(tmp_path, mode)))
    assert service_account_module == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX symbolic links")
def test_r092_key_behind_a_link_is_refused(tmp_path: Path, service_account_module: list[str]) -> None:
    link = tmp_path / "link.json"
    link.symlink_to(_key(tmp_path, 0o600))
    with pytest.raises(ValueError, match="owner-only"):
        google_auth.build_google_credentials(_delegation_config(link))


def test_r092_owner_only_key_is_loaded(tmp_path: Path, service_account_module: list[str]) -> None:
    key = _key(tmp_path, 0o600)
    credentials = google_auth.build_google_credentials(_delegation_config(key))
    assert service_account_module == [str(key)] and credentials.scopes == ("scope://a",)


# ---- in-session review follow-ups ---------------------------------------------------------------------------------


def test_r059_malformed_service_account_key_is_a_sign_in_failure_not_a_traceback(
    tmp_path: Path, service_account_module: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def malformed(path: str, *, scopes: list[str]) -> Any:
        raise _GoogleAuthError("Service account info was not in the expected format, missing fields token_uri.")

    monkeypatch.setattr(sys.modules["google.oauth2.service_account"].Credentials, "from_service_account_file", staticmethod(malformed))
    with pytest.raises(RuntimeError, match="Google sign-in failed"):
        google_auth.build_google_credentials(_delegation_config(_key(tmp_path, 0o600)))


def test_r059_consent_flow_errors_outside_google_auth_are_a_sign_in_failure(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    class AccessDeniedError(Exception):
        pass

    oauth_modules["flow_error"] = AccessDeniedError("access_denied")
    with pytest.raises(RuntimeError, match="Google sign-in failed"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))


def test_r092_missing_key_says_not_found(tmp_path: Path, service_account_module: list[str]) -> None:
    with pytest.raises(ValueError, match="not found"):
        google_auth.build_google_credentials(_delegation_config(tmp_path / "absent.json"))

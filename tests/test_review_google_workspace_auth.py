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
    def __init__(self, *args: Any, retryable: bool = False) -> None:
        super().__init__(*args)
        self.retryable = retryable


class _TransportError(_GoogleAuthError):
    pass


class _UserCredentials:
    """google.oauth2.credentials.Credentials as the library builds it: explicit scopes win over the cached ones."""

    def __init__(self, scopes: list[str], *, valid: bool = True, refresh_error: bool = False, tag: str = "cached",
                 granted: list[str] | None = None, failure: str | None = None, omit_scope: bool = False,
                 empty_scope: bool = False) -> None:
        self.scopes = list(scopes)
        self.valid = valid
        self.expired = not valid
        self.refresh_token = "<REDACTED>"
        self.token_uri = "https://oauth2.googleapis.com/token"
        self.client_id = "constructed-client"
        self.client_secret = "<REDACTED>"
        self.refresh_error = refresh_error
        self.tag = tag
        # What Google's token endpoint grants on a refresh: the cache's ``scopes`` are only what was asked for.
        self.grant = list(granted) if granted is not None else list(scopes)
        self.granted_scopes: list[str] | None = None
        # "retryable": the token endpoint failed after its retries (5xx); "transport": it could not be reached.
        self.failure = failure
        # RFC 6749 5.1: a refresh granting exactly the scopes asked for may leave the ``scope`` field out.
        self.omit_scope = omit_scope
        self.empty_scope = empty_scope

    @classmethod
    def from_authorized_user_file(cls, path: str, scopes: list[str] | None = None) -> _UserCredentials:
        return cls.from_authorized_user_info(json.loads(Path(path).read_text(encoding="utf-8")), scopes)

    @classmethod
    def from_authorized_user_info(cls, info: dict[str, Any], scopes: list[str] | None = None) -> _UserCredentials:
        return cls(scopes if scopes is not None else info.get("scopes") or [], valid=info.get("valid", True),
                   refresh_error=info.get("refresh_error", False), granted=info.get("granted"),
                   failure=info.get("failure"), omit_scope=info.get("omit_scope", False),
                   empty_scope=info.get("empty_scope", False))

    def has_scopes(self, scopes: list[str]) -> bool:
        return set(scopes).issubset(self.scopes)

    def refresh(self, _request: Any) -> None:
        if self.refresh_error:
            # google-auth's shape (oauth2/_client.py _handle_error_response): the details text, then the parsed body.
            raise _RefreshError("invalid_grant: Token has been expired or revoked.",
                                {"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
        if self.failure == "invalid_request_naming_a_grant":
            raise _RefreshError("invalid_request: missing invalid_grant hint",
                                {"error": "invalid_request", "error_description": "missing invalid_grant hint"})
        if self.failure == "retryable":
            raise _RefreshError("internal_failure", retryable=True)
        if self.failure == "transport":
            raise _TransportError("connection refused")
        if self.failure == "plain_text_missing_fields":
            # A token endpoint body that is not JSON reaches RefreshError as one plain-text argument, the same shape as
            # google-auth's local missing-fields text, so it can begin with the same words.
            raise _RefreshError("The credentials do not contain the necessary fields, said the proxy")
        if self.failure == "bad_gateway":
            # google-auth retries only 500, 503, 504, 408 and 429: a 502 HTML page is a non-retryable RefreshError.
            raise _RefreshError("Unexpected response", "<html>502 Bad Gateway</html>")
        self.valid, self.expired = True, False
        if self.empty_scope:
            self.granted_scopes = []
        elif not self.omit_scope:
            self.granted_scopes = list(self.grant)

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
            credentials = _UserCredentials(self.scopes, tag="consented")
            if state.get("consent_grant") is not None:
                credentials.granted_scopes = list(state["consent_grant"])
            return credentials

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
    modules["google.auth.exceptions"].TransportError = _TransportError  # type: ignore[attr-defined]
    modules["google.auth.transport.requests"].Request = object  # type: ignore[attr-defined]
    modules["google.oauth2.credentials"].Credentials = _UserCredentials  # type: ignore[attr-defined]
    modules["google_auth_oauthlib.flow"].InstalledAppFlow = _Flow  # type: ignore[attr-defined]
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(google_auth, "_module_available", lambda _module: True)
    # As in real_oauth: the fallback tests assume a volume that enforces ownership (the test volume may be noowners).
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: True)
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
        def from_service_account_info(info: dict[str, Any], *, scopes: list[str]) -> _ScopedCredentials:
            loaded.append(str(info.get("client_email")))
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
    assert service_account_module == ["sa@example.iam.gserviceaccount.com"] and credentials.scopes == ("scope://a",)


# ---- in-session review follow-ups ---------------------------------------------------------------------------------


def test_r059_malformed_service_account_key_is_a_sign_in_failure_not_a_traceback(
    tmp_path: Path, service_account_module: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def malformed(info: dict[str, Any], *, scopes: list[str]) -> Any:
        raise _GoogleAuthError("Service account info was not in the expected format, missing fields token_uri.")

    monkeypatch.setattr(sys.modules["google.oauth2.service_account"].Credentials, "from_service_account_info", staticmethod(malformed))
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


# ---- repair round 1: the cache is trusted only for the scopes Google grants on a refresh (R059, R022) -------------


def test_r059_valid_cache_claiming_scopes_never_granted_is_re_consented(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    # Written by the old code: it recorded the scopes the run asked for, not the ones granted.
    _write_cache(tmp_path, scopes=["scope://a", "scope://b"], granted=["scope://a"])
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://b")))
    assert oauth_modules["flows"] == 1
    assert credentials.tag == "consented"


def test_r059_refresh_granting_fewer_scopes_is_re_consented(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a", "scope://b"], granted=["scope://a"], valid=False)
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://b")))
    assert oauth_modules["flows"] == 1
    assert credentials.tag == "consented"
    assert json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))["tag"] == "consented"


# ---- repair round 2: a temporary token-endpoint failure or an unreported grant never opens consent (R059, R022) ---


@pytest.mark.parametrize("failure", ["retryable", "transport", "bad_gateway"])
def test_r059_temporary_refresh_failure_on_a_valid_cache_keeps_the_sign_in(
    tmp_path: Path, oauth_modules: dict[str, Any], failure: str
) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], failure=failure, **{google_auth.VERIFIED_SCOPES_KEY: ["scope://a"]})
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 0
    assert credentials.tag == "cached"


@pytest.mark.parametrize("failure", ["retryable", "transport"])
def test_r059_temporary_refresh_failure_on_an_expired_cache_is_a_sign_in_failure_not_consent(
    tmp_path: Path, oauth_modules: dict[str, Any], failure: str
) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], failure=failure, valid=False)
    with pytest.raises(RuntimeError, match="run again"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 0


def test_r059_refresh_that_leaves_out_the_scope_field_keeps_the_sign_in(
    tmp_path: Path, oauth_modules: dict[str, Any]
) -> None:
    _write_cache(tmp_path, scopes=["scope://a", "scope://b"], omit_scope=True)
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://b")))
    assert oauth_modules["flows"] == 0
    assert credentials.tag == "cached"


def test_r059_refresh_reporting_an_empty_grant_is_re_consented(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], empty_scope=True)
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 1
    assert credentials.tag == "consented"


def test_r092_credentials_come_from_the_bytes_that_passed_the_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A key swapped between the owner-only check and the load is never what the credentials are built from."""
    loaded: list[dict[str, Any]] = []

    class _Factory:
        @staticmethod
        def from_service_account_file(path: str, *, scopes: list[str]) -> _ScopedCredentials:
            loaded.append(json.loads(Path(path).read_text(encoding="utf-8")))
            return _ScopedCredentials(tuple(scopes))

        @staticmethod
        def from_service_account_info(info: dict[str, Any], *, scopes: list[str]) -> _ScopedCredentials:
            loaded.append(dict(info))
            return _ScopedCredentials(tuple(scopes))

    service_account = types.ModuleType("google.oauth2.service_account")
    service_account.Credentials = _Factory  # type: ignore[attr-defined]
    exceptions = types.ModuleType("google.auth.exceptions")
    exceptions.GoogleAuthError = _GoogleAuthError  # type: ignore[attr-defined]
    for name, module in {"google": types.ModuleType("google"), "google.oauth2": types.ModuleType("google.oauth2"),
                         "google.oauth2.service_account": service_account, "google.auth": types.ModuleType("google.auth"),
                         "google.auth.exceptions": exceptions}.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(google_auth, "_module_available", lambda _module: True)

    from azure_tenant_audit import certificate_auth

    key = _key(tmp_path, 0o600)
    checked = certificate_auth._read_private_file

    def check_then_swap(path: Any, limit: int, code: str) -> bytes:
        raw = checked(path, limit, code)
        key.write_text(json.dumps({"type": "service_account", "client_email": "swapped@example.net"}), encoding="utf-8")
        os.chmod(key, 0o644)
        return raw

    monkeypatch.setattr(certificate_auth, "_read_private_file", check_then_swap)
    google_auth.build_google_credentials(_delegation_config(key))
    assert [item["client_email"] for item in loaded] == ["sa@example.iam.gserviceaccount.com"]


def test_r092_a_key_that_is_not_json_is_refused_with_a_fixed_message(tmp_path: Path, service_account_module: list[str]) -> None:
    key = tmp_path / "key.json"
    key.write_text("not json PRIVATE", encoding="utf-8")
    os.chmod(key, 0o600)
    with pytest.raises(ValueError, match="service_account_key_invalid") as raised:
        google_auth.build_google_credentials(_delegation_config(key))
    assert "PRIVATE" not in str(raised.value)


# ---- bot review wave 2 (items 16, 18, 26): only an actual grant is trusted, and a fallback is never written back ----

_SCOPE_A = "https://www.googleapis.com/auth/admin.directory.user.readonly"
_SCOPE_B = "https://www.googleapis.com/auth/admin.reports.audit.readonly"


def _real_refresh_error(response: Any, *, retryable: bool = False) -> Exception:
    from google.auth.exceptions import RefreshError
    from google.oauth2 import _client

    try:
        _client._handle_error_response(response, retryable)
    except RefreshError as exc:
        return exc
    raise AssertionError("google-auth did not raise")


def test_item18_grant_errors_match_the_parsed_oauth_error_field_exactly() -> None:
    from google.auth.exceptions import RefreshError

    assert google_auth._is_grant_error(_real_refresh_error({"error": "invalid_grant", "error_description": "revoked"}))
    assert google_auth._is_grant_error(_real_refresh_error({"error": "invalid_scope"}))
    # The grant word only in the description is not a grant error.
    assert not google_auth._is_grant_error(
        _real_refresh_error({"error": "invalid_request", "error_description": "invalid_grant hint"}))
    assert not google_auth._is_grant_error(_real_refresh_error("<html>invalid_grant</html>"))
    assert not google_auth._is_grant_error(_real_refresh_error({"error": "invalid_grant"}, retryable=True))
    assert not google_auth._is_grant_error(_real_refresh_error({"error": ["invalid_grant"]}))
    # A one-argument text is a plain-text endpoint body or google-auth's local text: neither is matched on its words
    # (repair round 1). Missing local fields are found on the credentials before any refresh.
    missing = RefreshError("The credentials do not contain the necessary fields need to refresh the access token. "
                           "You must specify refresh_token, token_uri, client_id, and client_secret.")
    assert not google_auth._is_grant_error(missing)


def test_item18_invalid_request_naming_a_grant_does_not_open_consent(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], failure="invalid_request_naming_a_grant", valid=False)
    with pytest.raises(RuntimeError, match="run again later"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 0


def test_item26_refresh_and_consent_record_the_verified_grant(tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=["scope://a", "scope://b"], granted=["scope://a", "scope://b"], valid=False)
    google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    cache = json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))
    assert cache[google_auth.VERIFIED_SCOPES_KEY] == ["scope://a", "scope://b"]

    _write_cache(tmp_path, scopes=["scope://a"])
    google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://c")))
    assert oauth_modules["flows"] == 1
    cache = json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))
    assert cache["tag"] == "consented" and cache[google_auth.VERIFIED_SCOPES_KEY] == ["scope://a", "scope://c"]


@pytest.fixture
def real_oauth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Authentic google-auth credentials; the token endpoint is down (TransportError) and consent must not start."""
    from google.auth.exceptions import TransportError
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    state: dict[str, Any] = {"during_refresh": None}

    def _refresh(self: Any, _request: Any) -> None:
        if state["during_refresh"] is not None:
            state["during_refresh"]()
        raise TransportError("connection refused")

    monkeypatch.setattr(Credentials, "refresh", _refresh)
    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file",
                        classmethod(lambda *_a, **_k: pytest.fail("consent must not start during an outage")))
    # The test volume may ignore ownership (macOS noowners); the fallback tests below assume one that enforces it, and
    # the noowners case has its own test.
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: True)
    return state


def _real_cache(tmp_path: Path, scopes: list[str], verified: list[str] | None) -> Path:
    from datetime import timedelta

    from google.auth import _helpers
    from google.oauth2.credentials import Credentials

    credentials = Credentials(token="<REDACTED-access>", refresh_token="<REDACTED-refresh>",
                              token_uri="https://oauth2.googleapis.com/token", client_id="constructed-client",
                              client_secret="<REDACTED-secret>", scopes=scopes,
                              expiry=_helpers.utcnow() + timedelta(hours=1))
    info = json.loads(credentials.to_json())
    if verified is not None:
        info[google_auth.VERIFIED_SCOPES_KEY] = verified
    path = tmp_path / "cache" / "token.json"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(info), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_item26_old_cache_cannot_vouch_for_a_scope_during_an_outage(tmp_path: Path, real_oauth: dict[str, Any]) -> None:
    # google-auth serialises the scopes asked for, never the grant: an old-format cache proves nothing about B.
    _real_cache(tmp_path, [_SCOPE_A, _SCOPE_B], verified=None)
    with pytest.raises(RuntimeError, match="run again later"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_B,)))


def test_item26_verified_grant_without_the_scope_fails_closed_during_an_outage(
    tmp_path: Path, real_oauth: dict[str, Any]
) -> None:
    _real_cache(tmp_path, [_SCOPE_A, _SCOPE_B], verified=[_SCOPE_A])
    with pytest.raises(RuntimeError, match="run again later"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_B,)))


def test_item16_fallback_returns_the_cached_token_and_never_writes_it_back(
    tmp_path: Path, real_oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _real_cache(tmp_path, [_SCOPE_A, _SCOPE_B], verified=[_SCOPE_A, _SCOPE_B])
    newer = '{"written": "by another run while this refresh failed"}'
    real_oauth["during_refresh"] = lambda: path.write_text(newer, encoding="utf-8")
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_B,)))
    assert credentials.valid and credentials.token == "<REDACTED-access>"
    assert path.read_text(encoding="utf-8") == newer


def test_item16_a_refused_cache_write_does_not_abort_a_usable_fallback(
    tmp_path: Path, real_oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _real_cache(tmp_path, [_SCOPE_A], verified=[_SCOPE_A])

    def _refused(*_a: Any, **_k: Any) -> None:
        raise PermissionError(13, "refused")

    monkeypatch.setattr(google_auth, "secure_write_text", _refused)
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,)))
    assert credentials.valid


# ---- repair round 1 for group H (items 18, 26) ---------------------------------------------------------------------


def test_item18_plain_text_error_beginning_with_the_missing_fields_words_does_not_open_consent(
    tmp_path: Path, oauth_modules: dict[str, Any]
) -> None:
    _write_cache(tmp_path, scopes=["scope://a"], failure="plain_text_missing_fields", valid=False)
    with pytest.raises(RuntimeError, match="run again later"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a",)))
    assert oauth_modules["flows"] == 0


def test_item18_cache_missing_a_refresh_field_signs_in_again_without_a_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    path = _real_cache(tmp_path, [_SCOPE_A], verified=[_SCOPE_A])
    info = json.loads(path.read_text(encoding="utf-8"))
    info["client_secret"] = None  # present but empty: google-auth loads it and could never refresh it
    path.write_text(json.dumps(info), encoding="utf-8")
    monkeypatch.setattr(Credentials, "refresh", lambda *_a: pytest.fail("a cache that cannot refresh is not sent"))
    consented = Credentials(token="<REDACTED-new>", refresh_token="<REDACTED-refresh>", client_id="constructed-client",
                            client_secret="<REDACTED-secret>", token_uri="https://oauth2.googleapis.com/token",
                            scopes=[_SCOPE_A], granted_scopes=[_SCOPE_A])
    flow = types.SimpleNamespace(run_local_server=lambda port=0: consented)
    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(lambda *_a, **_k: flow))
    assert google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,))) is consented


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="POSIX modes, not as root")
def test_item26_outage_fallback_refuses_a_cache_from_a_folder_others_can_change(
    tmp_path: Path, real_oauth: dict[str, Any]
) -> None:
    path = _real_cache(tmp_path, [_SCOPE_A], verified=[_SCOPE_A])
    os.chmod(path.parent, 0o777)  # another account could have planted this cache and its recorded grant
    try:
        with pytest.raises(PermissionError, match="secret_folder_refused"):
            google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,)))
    finally:
        os.chmod(path.parent, 0o700)


def test_item26_fresh_consent_narrower_than_the_run_is_refused_naming_the_missing_scopes(
    tmp_path: Path, oauth_modules: dict[str, Any]
) -> None:
    oauth_modules["consent_grant"] = ["scope://a"]
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_oauth_config(tmp_path, ("scope://a", "scope://b", "scope://c")))
    message = str(caught.value)
    assert "scope://b" in message and "scope://c" in message and "scope://a" not in message
    assert "REDACTED" not in message and caught.value.__cause__ is None
    assert not (tmp_path / "cache" / "token.json").exists()


# ---- repair round 2 for group H (items 18, 26) ---------------------------------------------------------------------


def _consented(refresh_token: str | None, scopes: list[str]) -> Any:
    from google.oauth2.credentials import Credentials

    return Credentials(token="<REDACTED-new>", refresh_token=refresh_token, client_id="constructed-client",
                       client_secret="<REDACTED-secret>", token_uri="https://oauth2.googleapis.com/token",
                       scopes=scopes, granted_scopes=scopes)


def test_item18_a_cache_auditex_saved_without_a_refresh_token_leads_to_fresh_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Google may leave the refresh token out of a consent response; Auditex saves that cache (google-auth drops the
    # empty field), and the next run must sign in again rather than stop on google-auth's ValueError.
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    consents = [_consented(None, [_SCOPE_A]), _consented("<REDACTED-refresh>", [_SCOPE_A])]
    flow = types.SimpleNamespace(run_local_server=lambda port=0: consents.pop(0))
    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(lambda *_a, **_k: flow))
    monkeypatch.setattr(Credentials, "refresh", lambda *_a: pytest.fail("a cache that cannot refresh is not sent"))
    google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,)))
    assert "refresh_token" not in json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))
    credentials = google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,)))
    assert credentials.refresh_token == "<REDACTED-refresh>" and consents == []


def test_item26_outage_fallback_is_off_where_the_volume_ignores_ownership(
    tmp_path: Path, real_oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # On a macOS volume mounted with "Ignore ownership" every account passes the owner check, so the recorded grant
    # could be another account's: the cached token is not used during an outage.
    _real_cache(tmp_path, [_SCOPE_A], verified=[_SCOPE_A])
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: False)
    with pytest.raises(RuntimeError, match="run again later"):
        google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A,)))


def test_item26_default_oauthlib_partial_consent_names_the_missing_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without scope relaxation oauthlib raises its own Warning on a narrower grant, before any credentials exist.
    from google_auth_oauthlib.flow import InstalledAppFlow
    from oauthlib.oauth2.rfc6749.parameters import parse_token_response

    monkeypatch.delenv("OAUTHLIB_RELAX_TOKEN_SCOPE", raising=False)
    response = json.dumps({"access_token": "<REDACTED-access>", "token_type": "Bearer", "expires_in": 3600,
                           "refresh_token": "<REDACTED-refresh>", "scope": _SCOPE_A})

    def _consent(port: int = 0) -> Any:
        return parse_token_response(response, scope=[_SCOPE_A, _SCOPE_B])

    flow = types.SimpleNamespace(run_local_server=_consent)
    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(lambda *_a, **_k: flow))
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_oauth_config(tmp_path, (_SCOPE_A, _SCOPE_B)))
    message = str(caught.value)
    assert "missing scopes: " + _SCOPE_B in message and _SCOPE_A not in message
    assert "REDACTED" not in message and caught.value.__cause__ is None
    assert not (tmp_path / "cache" / "token.json").exists()


# ---- LIVE-FIX-6 M1a: an optional scope never fails the sign-in or forces another consent ------------------------

_DRIVE_META = "https://www.googleapis.com/auth/drive.metadata.readonly"
_DRIVE_READ = "https://www.googleapis.com/auth/drive.readonly"
_DOMAINS = "https://www.googleapis.com/auth/admin.directory.domain.readonly"


def _preset_auth(tmp_path: Path, **selection: Any) -> google_auth.GoogleAuthConfig:
    from dataclasses import replace

    config = google_run.GoogleRunConfig(tenant_name="Example", out=tmp_path, domain="example.com", auth="oauth",
                                        oauth_client=tmp_path / "client.json",
                                        token_cache=tmp_path / "cache" / "token.json", **selection)
    auth = google_run._auth_config(config, google_run._selected_collectors(config))
    return replace(auth, token_cache=tmp_path / "cache" / "token.json")


def _saved(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))


def test_live_fix_6_m1a_drive_alone_marks_the_domain_scope_optional_and_everything_requires_it(tmp_path: Path) -> None:
    drive = _preset_auth(tmp_path, collectors="google_drive_posture")
    assert drive.scopes == (_DRIVE_META, _DRIVE_READ, _DOMAINS)
    assert drive.optional_scopes == (_DOMAINS,)
    assert drive.required_scopes == (_DRIVE_META, _DRIVE_READ)
    everything = _preset_auth(tmp_path, collector_preset="everything")
    assert _DOMAINS in everything.scopes
    assert everything.optional_scopes == ()
    assert everything.required_scopes == everything.scopes


def test_live_fix_6_m1a_drive_alone_consent_without_the_domain_scope_signs_in(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    oauth_modules["consent_grant"] = [_DRIVE_META, _DRIVE_READ]
    credentials = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert oauth_modules["flows"] == 1 and credentials.tag == "consented"
    saved = _saved(tmp_path)
    assert saved["scopes"] == [_DRIVE_META, _DRIVE_READ]
    assert saved[google_auth.VERIFIED_SCOPES_KEY] == [_DRIVE_META, _DRIVE_READ]
    # The next run reuses that cache: no second consent.
    oauth_modules["consent_grant"] = None
    again = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert oauth_modules["flows"] == 1 and again.tag == "cached"


def test_live_fix_6_m1a_drive_alone_consent_with_the_domain_scope_signs_in(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    oauth_modules["consent_grant"] = [_DRIVE_META, _DRIVE_READ, _DOMAINS]
    credentials = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert oauth_modules["flows"] == 1 and credentials.tag == "consented"
    assert _saved(tmp_path)["scopes"] == [_DRIVE_META, _DRIVE_READ, _DOMAINS]


def test_live_fix_6_m1a_drive_alone_consent_without_a_required_scope_fails(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    oauth_modules["consent_grant"] = [_DRIVE_META, _DOMAINS]
    with pytest.raises(RuntimeError) as raised:
        google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert str(raised.value) == (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        "https://www.googleapis.com/auth/drive.readonly); run again and approve every requested permission."
    )
    assert not (tmp_path / "cache" / "token.json").exists()


@pytest.mark.parametrize("cached", [[_DRIVE_META, _DRIVE_READ], [_DRIVE_META, _DRIVE_READ, _DOMAINS]])
def test_live_fix_6_m1a_drive_alone_cache_with_or_without_the_domain_scope_is_reused(
        tmp_path: Path, oauth_modules: dict[str, Any], cached: list[str]) -> None:
    _write_cache(tmp_path, scopes=cached)
    credentials = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert oauth_modules["flows"] == 0 and credentials.tag == "cached"
    assert _saved(tmp_path)["scopes"] == cached


def test_live_fix_6_m1a_drive_alone_cache_without_a_required_scope_is_re_consented(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    _write_cache(tmp_path, scopes=[_DRIVE_META, _DOMAINS])
    credentials = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert oauth_modules["flows"] == 1 and credentials.tag == "consented"


def test_live_fix_6_m1a_everything_consent_without_the_domain_scope_still_fails(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    auth = _preset_auth(tmp_path, collector_preset="everything")
    oauth_modules["consent_grant"] = [scope for scope in auth.scopes if scope != _DOMAINS]
    with pytest.raises(RuntimeError) as raised:
        google_auth.build_google_credentials(auth)
    assert str(raised.value) == (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        "https://www.googleapis.com/auth/admin.directory.domain.readonly); run again and approve every requested "
        "permission."
    )


@pytest.mark.parametrize(("cached_all", "flows"), [(True, 0), (False, 1)])
def test_live_fix_6_m1a_everything_cache_must_hold_the_domain_scope(
        tmp_path: Path, oauth_modules: dict[str, Any], cached_all: bool, flows: int) -> None:
    auth = _preset_auth(tmp_path, collector_preset="everything")
    _write_cache(tmp_path, scopes=[scope for scope in auth.scopes if cached_all or scope != _DOMAINS])
    google_auth.build_google_credentials(auth)
    assert oauth_modules["flows"] == flows


def test_live_fix_6_m1a_scope_relaxation_is_on_only_for_a_consent_with_optional_scopes(
        tmp_path: Path, oauth_modules: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OAUTHLIB_RELAX_TOKEN_SCOPE", raising=False)
    seen: list[str | None] = []
    flow_class = sys.modules["google_auth_oauthlib.flow"].InstalledAppFlow
    original = flow_class.run_local_server

    def spy(self: Any, port: int = 0) -> Any:
        seen.append(os.environ.get("OAUTHLIB_RELAX_TOKEN_SCOPE"))
        return original(self, port)

    monkeypatch.setattr(flow_class, "run_local_server", spy)
    google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    (tmp_path / "cache" / "token.json").unlink()
    google_auth.build_google_credentials(_preset_auth(tmp_path, collector_preset="everything"))
    assert seen == ["1", None]
    assert "OAUTHLIB_RELAX_TOKEN_SCOPE" not in os.environ


def test_live_fix_6_m1a_a_scope_change_warning_names_only_required_scopes(
        tmp_path: Path, oauth_modules: dict[str, Any]) -> None:
    warning = Warning("Scope has changed")
    warning.new_scope = [_DOMAINS]  # type: ignore[attr-defined]
    oauth_modules["flow_error"] = warning
    with pytest.raises(RuntimeError) as raised:
        google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))
    assert str(raised.value) == (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        "https://www.googleapis.com/auth/drive.metadata.readonly, https://www.googleapis.com/auth/drive.readonly); "
        "run again and approve every requested permission."
    )


def test_live_fix_6_m1a_drive_alone_live_run_without_the_domain_grant_reads_permissions(
        tmp_path: Path, oauth_modules: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Single sign-in: one consent without the optional scope, the Drive reads go on and fall back to permissions."""
    from auditex.google_workspace.drive_scope import read_tenant_domains

    oauth_modules["consent_grant"] = [_DRIVE_META, _DRIVE_READ]
    credentials = google_auth.build_google_credentials(_preset_auth(tmp_path, collectors="google_drive_posture"))

    class _Refused:
        """The OAuth client: one shared token (no narrowing); the domains list is refused (HTTP 403)."""

        credentials_seen = credentials

        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            raise PermissionError("HTTP 403")

    assert read_tenant_domains(_Refused()) is None
    assert oauth_modules["flows"] == 1

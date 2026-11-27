"""LIVE-FIX-7 item 1: an OAuth sign-in never asks for a scope that is only optional.

The OAuth requested set is the union of the selected collectors' required scopes, checked strictly as before. The
Drive collector reads the Directory domains list under OAuth only when that scope is in the requested set (another
selected collector requires it) and the grant holds it; otherwise it does not try, and reads every file's permissions.
Domain-wide delegation keeps the optional scope, read on a token of its own. Real google-auth credentials; the token
endpoint and the consent flow are mocked. No tenant call is made.
"""

from __future__ import annotations

import json
import os
import types
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import auth as google_auth
from auditex.google_workspace import client as google_client
from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import GoogleDrivePostureCollector
from auditex.google_workspace.run import (
    GoogleRunConfig,
    _auth_config,
    _selected_collectors,
    build_google_auth_context_payload,
    google_doctor,
    tenant_domain_read_allowed,
)
from auditex.setup_guide import (
    build_google_setup_guide,
    render_setup_guide_markdown,
)

DRIVE_META = "https://www.googleapis.com/auth/drive.metadata.readonly"
DRIVE_RO = "https://www.googleapis.com/auth/drive.readonly"
DOMAIN = "https://www.googleapis.com/auth/admin.directory.domain.readonly"
DRIVE_ONLY = "google_drive_posture"


def _config(tmp_path: Path, *, auth: str, collectors: str | None = None, preset: str | None = None) -> GoogleRunConfig:
    return GoogleRunConfig(
        tenant_name="Example", out=tmp_path / "out", domain="example.com", auth=auth, collectors=collectors,
        collector_preset=preset, subject="admin@example.com", service_account_key=tmp_path / "key.json",
        oauth_client=tmp_path / "client.json", token_cache=tmp_path / "cache" / "token.json",
    )


def _auth(tmp_path: Path, *, auth: str, collectors: str | None = None, preset: str | None = None) -> Any:
    config = _config(tmp_path, auth=auth, collectors=collectors, preset=preset)
    return _auth_config(config, _selected_collectors(config))


# ---- the requested set ---------------------------------------------------------------------------------------------


def test_oauth_drive_alone_asks_only_for_the_drive_scopes(tmp_path: Path) -> None:
    assert _auth(tmp_path, auth="oauth", collectors=DRIVE_ONLY).scopes == (DRIVE_META, DRIVE_RO)


def test_delegation_drive_alone_keeps_the_optional_domain_scope(tmp_path: Path) -> None:
    assert _auth(tmp_path, auth="domain-delegation", collectors=DRIVE_ONLY).scopes == (DRIVE_META, DRIVE_RO, DOMAIN)


def test_oauth_everything_asks_for_the_domain_scope_once_because_directory_requires_it(tmp_path: Path) -> None:
    scopes = _auth(tmp_path, auth="oauth", preset="everything").scopes
    assert scopes.count(DOMAIN) == 1 and DRIVE_META in scopes and DRIVE_RO in scopes
    assert len(scopes) == 20
    assert _auth(tmp_path, auth="domain-delegation", preset="everything").scopes == scopes


def test_doctor_lists_the_scopes_each_mode_asks_for(tmp_path: Path) -> None:
    oauth = google_doctor(_config(tmp_path, auth="oauth", collectors=DRIVE_ONLY))["auth"]
    assert oauth["scopes"] == [DRIVE_META, DRIVE_RO]
    assert oauth["scopes_csv"] == f"{DRIVE_META},{DRIVE_RO}"
    assert oauth["drive_domain_read"] == "not_requested"
    delegation = google_doctor(_config(tmp_path, auth="domain-delegation", collectors=DRIVE_ONLY))["auth"]
    assert delegation["scopes"] == [DRIVE_META, DRIVE_RO, DOMAIN]
    assert delegation["drive_domain_read"] == "delegation_own_token"


# ---- the consent, the cache and the refresh (real google-auth credentials) -----------------------------------------


@pytest.fixture
def oauth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Real google-auth credentials; consent and the token endpoint are mocked and recorded."""
    from google.oauth2 import reauth
    from google_auth_oauthlib.flow import InstalledAppFlow

    state: dict[str, Any] = {"flow_scopes": [], "refresh_scopes": [], "consent_grant": None, "refresh_grant": None}

    def _from_client_secrets_file(_cls: Any, _path: str, scopes: list[str]) -> Any:
        state["flow_scopes"].append(list(scopes))
        granted = state["consent_grant"] if state["consent_grant"] is not None else list(scopes)
        return types.SimpleNamespace(run_local_server=lambda port=0: _credentials(list(scopes), granted))

    def _refresh_grant(_request: Any, _uri: str, refresh_token: str, *_a: Any, scopes: Any = None, **_k: Any) -> Any:
        state["refresh_scopes"].append(list(scopes or []))
        granted = state["refresh_grant"] if state["refresh_grant"] is not None else list(scopes or [])
        from google.auth import _helpers

        expiry = _helpers.utcnow() + timedelta(hours=1)
        return "<REDACTED-refreshed>", refresh_token, expiry, {"scope": " ".join(granted)}, None

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(_from_client_secrets_file))
    monkeypatch.setattr(reauth, "refresh_grant", _refresh_grant)
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: True)
    return state


def _credentials(scopes: list[str], granted: list[str]) -> Any:
    from google.auth import _helpers
    from google.oauth2.credentials import Credentials

    return Credentials(token="<REDACTED-access>", refresh_token="<REDACTED-refresh>",
                       token_uri="https://oauth2.googleapis.com/token", client_id="constructed-client",
                       client_secret="<REDACTED-secret>", scopes=scopes, granted_scopes=granted,
                       expiry=_helpers.utcnow() + timedelta(hours=1))


def _cache(tmp_path: Path, scopes: list[str]) -> Path:
    info = json.loads(_credentials(scopes, scopes).to_json())
    info[google_auth.VERIFIED_SCOPES_KEY] = sorted(scopes)
    path = tmp_path / "cache" / "token.json"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(info), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _saved(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))


def test_oauth_drive_alone_consent_asks_for_and_saves_only_the_drive_scopes(tmp_path: Path, oauth: dict[str, Any]) -> None:
    config = _auth(tmp_path, auth="oauth", collectors=DRIVE_ONLY)
    credentials = google_auth.build_google_credentials(config)
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert credentials.has_scopes([DOMAIN]) is False
    saved = _saved(tmp_path)
    assert saved["scopes"] == [DRIVE_META, DRIVE_RO]
    assert saved[google_auth.VERIFIED_SCOPES_KEY] == [DRIVE_META, DRIVE_RO]
    assert tenant_domain_read_allowed(config, credentials) is False


def test_oauth_drive_alone_cache_without_the_domain_scope_is_reused_and_refreshed_without_it(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO])
    config = _auth(tmp_path, auth="oauth", collectors=DRIVE_ONLY)
    credentials = google_auth.build_google_credentials(config)
    assert oauth["flow_scopes"] == []
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert credentials.has_scopes([DOMAIN]) is False
    assert _saved(tmp_path)["scopes"] == [DRIVE_META, DRIVE_RO]
    assert tenant_domain_read_allowed(config, credentials) is False


def test_oauth_drive_alone_cache_with_a_granted_domain_scope_is_reused_but_the_domains_read_is_not_attempted(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    # A cache from an earlier run whose consent granted the domain scope: still a real grant, but this run did not
    # ask for it, so the Drive collector does not use it.
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN])
    config = _auth(tmp_path, auth="oauth", collectors=DRIVE_ONLY)
    credentials = google_auth.build_google_credentials(config)
    assert oauth["flow_scopes"] == []
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert tenant_domain_read_allowed(config, credentials) is False


def test_oauth_drive_alone_cache_missing_a_drive_scope_consents_again(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [DRIVE_META, DOMAIN])
    google_auth.build_google_credentials(_auth(tmp_path, auth="oauth", collectors=DRIVE_ONLY))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO]]


def test_oauth_everything_consent_with_the_domain_scope_lets_drive_read_the_domains(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    config = _auth(tmp_path, auth="oauth", preset="everything")
    credentials = google_auth.build_google_credentials(config)
    assert DOMAIN in oauth["flow_scopes"][0] and len(oauth["flow_scopes"][0]) == 20
    assert DOMAIN in _saved(tmp_path)[google_auth.VERIFIED_SCOPES_KEY]
    assert tenant_domain_read_allowed(config, credentials) is True


def test_oauth_everything_consent_without_the_domain_scope_fails_and_saves_nothing(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    config = _auth(tmp_path, auth="oauth", preset="everything")
    oauth["consent_grant"] = [scope for scope in config.scopes if scope != DOMAIN]
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(config)
    assert str(caught.value) == (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        "https://www.googleapis.com/auth/admin.directory.domain.readonly); run again and approve every requested "
        "permission."
    )
    assert not (tmp_path / "cache" / "token.json").exists()


def test_oauth_everything_cache_without_the_domain_scope_consents_again(tmp_path: Path, oauth: dict[str, Any]) -> None:
    config = _auth(tmp_path, auth="oauth", preset="everything")
    _cache(tmp_path, [scope for scope in config.scopes if scope != DOMAIN])
    google_auth.build_google_credentials(config)
    assert oauth["refresh_scopes"] == []
    assert len(oauth["flow_scopes"]) == 1 and DOMAIN in oauth["flow_scopes"][0]


def test_oauth_everything_cache_with_every_scope_is_reused(tmp_path: Path, oauth: dict[str, Any]) -> None:
    config = _auth(tmp_path, auth="oauth", preset="everything")
    _cache(tmp_path, list(config.scopes))
    credentials = google_auth.build_google_credentials(config)
    assert oauth["flow_scopes"] == []
    assert len(oauth["refresh_scopes"]) == 1 and DOMAIN in oauth["refresh_scopes"][0]
    assert tenant_domain_read_allowed(config, credentials) is True


def test_oauth_everything_refresh_that_drops_the_domain_scope_consents_again(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    config = _auth(tmp_path, auth="oauth", preset="everything")
    _cache(tmp_path, list(config.scopes))
    oauth["refresh_grant"] = [scope for scope in config.scopes if scope != DOMAIN]
    credentials = google_auth.build_google_credentials(config)
    assert len(oauth["flow_scopes"]) == 1
    assert credentials.has_scopes([DOMAIN]) is True
    assert DOMAIN in _saved(tmp_path)[google_auth.VERIFIED_SCOPES_KEY]


def test_oauth_grant_without_the_domain_scope_never_allows_the_read() -> None:
    config = google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=(DRIVE_META, DRIVE_RO, DOMAIN))
    assert tenant_domain_read_allowed(config, _credentials([DRIVE_META, DRIVE_RO, DOMAIN], [DRIVE_META, DRIVE_RO])) is False
    assert tenant_domain_read_allowed(config, object()) is False


def test_delegation_always_allows_the_domains_read_on_its_own_token() -> None:
    config = google_auth.GoogleAuthConfig(auth_mode="domain-delegation", scopes=(DRIVE_META, DRIVE_RO, DOMAIN))
    assert tenant_domain_read_allowed(config, object()) is True


# ---- the Drive collector follows the client's permission -----------------------------------------------------------


class _Request:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def execute(self) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class _HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = type("Resp", (), {"status": status})()


def _drive_client(calls: list[str], *, tenant_domain_read: bool) -> GoogleWorkspaceClient:
    files = [
        {"id": "f1", "name": "Theirs", "owners": [{"emailAddress": "a@example.org"}]},
        {"id": "f2", "name": "Ours", "owners": [{"emailAddress": "b@example.com"}]},
    ]
    files_api = type("Files", (), {"list": lambda self, **_k: calls.append("files.list") or _Request({"files": files})})
    permissions_api = type("Permissions", (), {
        "list": lambda self, **k: calls.append(f"permissions.list:{k['fileId']}") or _Request({"permissions": []}),
    })
    drives_api = type("Drives", (), {"list": lambda self, **_k: _Request({"drives": []})})
    domains_api = type("Domains", (), {
        "list": lambda self, **_k: calls.append("domains.list") or _Request({"domains": [{"domainName": "example.com"}]}),
    })
    drive = type("Drive", (), {"files": lambda self: files_api(), "permissions": lambda self: permissions_api(),
                               "drives": lambda self: drives_api()})()
    admin = type("Admin", (), {"domains": lambda self: domains_api()})()
    client = GoogleWorkspaceClient(credentials=None, tenant_domain_read=tenant_domain_read)
    assert client._services is not None
    client._services[("drive", "v3")] = drive
    client._services[("admin", "directory_v1")] = admin
    return client


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(google_client, "_sleep", lambda _delay: None, raising=False)


def test_drive_without_the_permission_never_reads_the_domains_and_reads_every_file() -> None:
    calls: list[str] = []
    result = GoogleDrivePostureCollector().run({"client": _drive_client(calls, tenant_domain_read=False)})
    assert calls == ["files.list", "permissions.list:f1", "permissions.list:f2"]
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert (row["status"], row["item_count"], "out_of_scope_files" in row) == ("ok", 2, False)


def test_drive_with_the_permission_reads_the_domains_and_leaves_out_the_outside_file() -> None:
    calls: list[str] = []
    result = GoogleDrivePostureCollector().run({"client": _drive_client(calls, tenant_domain_read=True)})
    assert calls == ["files.list", "domains.list", "permissions.list:f2"]
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert (row["status"], row["item_count"], row["out_of_scope_files"]) == ("ok", 1, 1)


def test_a_client_built_without_saying_so_never_reads_the_domains() -> None:
    assert GoogleWorkspaceClient(credentials=None).tenant_domain_read is False


# ---- the auth context and the setup guide --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("auth", "collectors", "preset", "expected"),
    [
        ("oauth", DRIVE_ONLY, None, "not_requested"),
        ("oauth", None, "everything", "oauth_required_scope"),
        ("domain-delegation", DRIVE_ONLY, None, "delegation_own_token"),
        ("domain-delegation", None, "everything", "delegation_own_token"),
    ],
)
def test_auth_context_records_how_drive_reads_the_domains(
    tmp_path: Path, auth: str, collectors: str | None, preset: str | None, expected: str
) -> None:
    config = _config(tmp_path, auth=auth, collectors=collectors, preset=preset)
    payload = build_google_auth_context_payload(config, _auth_config(config, _selected_collectors(config)))
    assert payload["drive_domain_read"] == expected


def test_auth_context_has_no_drive_domain_read_without_drive(tmp_path: Path) -> None:
    config = _config(tmp_path, auth="oauth", collectors="google_directory")
    payload = build_google_auth_context_payload(config, _auth_config(config, _selected_collectors(config)))
    assert "drive_domain_read" not in payload


def test_oauth_drive_only_setup_guide_does_not_ask_for_the_optional_scope_or_its_api() -> None:
    guide = build_google_setup_guide(collectors=DRIVE_ONLY, auth="oauth")
    assert guide["scopes_csv"] == f"{DRIVE_META},{DRIVE_RO}"
    assert guide["optional_scopes"] == []
    assert guide["optional_api_enablement"] == []
    assert [(row["scope"], row["collector"]) for row in guide["oauth_unrequested_scopes"]] == [(DOMAIN, DRIVE_ONLY)]
    markdown = render_setup_guide_markdown(guide)
    assert (
        "Optional scopes an OAuth sign-in does not ask for (their read is not attempted):\n\n"
        "- `https://www.googleapis.com/auth/admin.directory.domain.readonly` (for `google_drive_posture`)"
    ) in markdown
    assert "## APIs To Enable\n\n- Google Drive API\n" in markdown and "Admin SDK API" not in markdown


def test_delegation_drive_only_setup_guide_keeps_the_optional_scope_and_its_api() -> None:
    guide = build_google_setup_guide(collectors=DRIVE_ONLY, auth="domain-delegation")
    assert guide["scopes_csv"] == f"{DRIVE_META},{DRIVE_RO},{DOMAIN}"
    assert [(row["scope"], row["collector"]) for row in guide["optional_scopes"]] == [(DOMAIN, DRIVE_ONLY)]
    assert guide["oauth_unrequested_scopes"] == []
    assert [row["api"] for row in guide["optional_api_enablement"]] == ["Admin SDK API"]


def test_oauth_everything_setup_guide_requires_the_domain_scope() -> None:
    guide = build_google_setup_guide(collector_preset="everything", auth="oauth")
    assert DOMAIN in guide["scopes_csv"].split(",")
    assert guide["optional_scopes"] == [] and guide["oauth_unrequested_scopes"] == []


def test_scope_inventory_note_says_when_the_optional_read_applies() -> None:
    from auditex.google_workspace.collectors import REGISTRY
    from azure_tenant_audit.scope_catalog import build_google_scope_catalog

    note = build_google_scope_catalog(registry=REGISTRY)[DRIVE_ONLY]["optional_permission_notes"][DOMAIN]
    assert "Read under domain-wide delegation on a token of its own; under OAuth only when another selected " \
           "collector requires this scope (Directory, DNS posture)" in note

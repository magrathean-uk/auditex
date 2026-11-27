"""SEC-1 item 1: a reloaded OAuth token cache is narrowed to this run's scopes inside its verified grant.

A loaded credential asks for and claims only this run's required scopes, and only when the cache's verified grant holds
them all; otherwise the run signs in again (one consent) without a refresh. A credential returned during a token
endpoint outage claims only verified scopes. An older cache without the verified-scopes key is still refreshed every
run and trusted only for what the token endpoint grants now. A recorded value that is missing a usable shape grants
nothing. Real google-auth credentials; the token endpoint and the consent flow are mocked. No tenant call is made.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import types
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import auth as google_auth
from azure_tenant_audit import secret_hygiene

DRIVE_META = "https://www.googleapis.com/auth/drive.metadata.readonly"
DRIVE_RO = "https://www.googleapis.com/auth/drive.readonly"
DOMAIN = "https://www.googleapis.com/auth/admin.directory.domain.readonly"
DRIVE_RUN = (DRIVE_META, DRIVE_RO)
DOMAIN_RUN = (DRIVE_META, DRIVE_RO, DOMAIN)
# The on-disk field name, written literally: a rename in the code must not pass these tests.
VERIFIED = "auditex_verified_scopes"
# RFC 6749 section 3.3 scope-token: 1*( %x21 / %x23-5B / %x5D-7E ). Each entry below breaks it; written literally.
_NOT_SCOPE_TOKENS = {
    "nul": "https://www.googleapis.com/auth/drive\x00",
    "tab-inside": "https://www.googleapis.com/auth/drive\tfile",
    "del": "https://www.googleapis.com/auth/drive\x7f",
    "quote": 'https://www.googleapis.com/auth/"drive"',
    "backslash": "https://www.googleapis.com/auth\\drive",
    "non-ascii-letter": "https://www.googleapis.com/auth/driv\u00e9.readonly",
}


@pytest.fixture
def oauth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Consent and the token endpoint, mocked and recorded; a scope in ``revoked`` is refused with invalid_scope."""
    from google.auth import exceptions
    from google.oauth2 import reauth
    from google_auth_oauthlib.flow import InstalledAppFlow

    state: dict[str, Any] = {"flow_scopes": [], "refresh_scopes": [], "consent_grant": None, "revoked": set(),
                             "down": False, "consent_error": None, "refresh_grant": None}

    def _from_client_secrets_file(_cls: Any, _path: str, scopes: list[str]) -> Any:
        state["flow_scopes"].append(list(scopes))
        granted = state["consent_grant"] if state["consent_grant"] is not None else list(scopes)

        def _run_local_server(port: int = 0) -> Any:
            if state["consent_error"] is not None:
                raise state["consent_error"]
            return _credentials(list(scopes), granted)

        return types.SimpleNamespace(run_local_server=_run_local_server)

    def _refresh_grant(_request: Any, _uri: str, refresh_token: str, *_a: Any, scopes: Any = None, **_k: Any) -> Any:
        state["refresh_scopes"].append(list(scopes or []))
        if state["down"]:
            raise exceptions.TransportError("connection refused")
        if state["revoked"] & set(scopes or []):
            raise exceptions.RefreshError("invalid_scope: refused", {"error": "invalid_scope"})
        from google.auth import _helpers

        expiry = _helpers.utcnow() + timedelta(hours=1)
        granted = state["refresh_grant"] if state["refresh_grant"] is not None else list(scopes or [])
        return "tok-SYNTHETIC-refreshed", refresh_token, expiry, {"scope": " ".join(granted)}, None

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(_from_client_secrets_file))
    monkeypatch.setattr(reauth, "refresh_grant", _refresh_grant)
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: True)
    return state


def _credentials(scopes: list[str], granted: list[str], *, hours: int = 1) -> Any:
    from google.auth import _helpers
    from google.oauth2.credentials import Credentials

    return Credentials(token="tok-SYNTHETIC-access", refresh_token="tok-SYNTHETIC-refresh",
                       token_uri="https://oauth2.googleapis.com/token", client_id="constructed-client",
                       client_secret="tok-SYNTHETIC-secret", scopes=scopes, granted_scopes=granted,
                       expiry=_helpers.utcnow() + timedelta(hours=hours))


_ABSENT = object()


def _cache(tmp_path: Path, asked: list[str], verified: Any = _ABSENT, **fields: Any) -> Path:
    info = json.loads(_credentials(asked, asked).to_json())
    if verified is not _ABSENT:
        info[VERIFIED] = verified
    info.update(fields)
    path = tmp_path / "cache" / "token.json"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(info), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _config(tmp_path: Path, scopes: tuple[str, ...]) -> google_auth.GoogleAuthConfig:
    return google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=scopes, oauth_client=tmp_path / "client.json",
                                        token_cache=tmp_path / "cache" / "token.json")


def _saved(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "cache" / "token.json").read_text(encoding="utf-8"))


# ---- a scope this run does not need is never asked for on refresh -------------------------------------------------


def test_drive_run_with_a_cache_verified_for_the_domain_scope_refreshes_without_it(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert oauth["flow_scopes"] == []
    assert credentials.scopes == [DRIVE_META, DRIVE_RO]
    assert credentials.has_scopes([DOMAIN]) is False
    assert _saved(tmp_path)["scopes"] == [DRIVE_META, DRIVE_RO]
    assert _saved(tmp_path)[VERIFIED] == [DRIVE_META, DRIVE_RO]


def test_drive_run_never_resends_a_domain_scope_the_user_has_since_revoked(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert oauth["flow_scopes"] == []


def test_drive_run_with_a_cache_that_asked_for_but_was_never_granted_the_domain_scope_refreshes_without_it(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert oauth["flow_scopes"] == []


def test_a_run_needing_a_scope_the_verified_grant_lacks_signs_in_once_without_a_refresh(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    credentials = google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert credentials.token == "tok-SYNTHETIC-access"
    assert _saved(tmp_path)[VERIFIED] == [DOMAIN, DRIVE_META, DRIVE_RO]


def test_a_refresh_refused_for_a_revoked_required_scope_signs_in_once(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]


# ---- the outage fallback claims only verified scopes ---------------------------------------------------------------


def test_outage_fallback_claims_only_this_runs_verified_scopes_and_later_refreshes_ask_for_no_more(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    from google.auth import _helpers

    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DRIVE_META, DRIVE_RO])
    oauth["down"] = True
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["flow_scopes"] == []
    assert credentials.token == "tok-SYNTHETIC-access"
    assert credentials.scopes == [DRIVE_META, DRIVE_RO]
    assert credentials.has_scopes([DOMAIN]) is False
    assert google_auth.granted_scopes(credentials) == frozenset({DRIVE_META, DRIVE_RO})
    # The token expires mid-run and google-auth refreshes it before the next request: still only the run's scopes.
    oauth["down"] = False
    credentials.expiry = _helpers.utcnow() - timedelta(hours=1)
    credentials.before_request(object(), "GET", "https://www.googleapis.com/drive/v3/files", {})
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO], [DRIVE_META, DRIVE_RO]]


def test_outage_with_a_verified_grant_that_does_not_cover_the_run_signs_in_again_instead_of_proceeding(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DRIVE_META, DRIVE_RO])
    oauth["down"] = True
    credentials = google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert credentials.scopes == [DRIVE_META, DRIVE_RO, DOMAIN]


def test_outage_with_a_verified_grant_that_does_not_cover_the_run_and_a_narrower_consent_fails_naming_the_scope(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    path = _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DRIVE_META, DRIVE_RO])
    before = path.read_text(encoding="utf-8")
    oauth["down"] = True
    oauth["consent_grant"] = [DRIVE_META, DRIVE_RO]
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        "https://www.googleapis.com/auth/admin.directory.domain.readonly); run again and approve every requested "
        "permission."
    )
    assert oauth["refresh_scopes"] == []
    assert path.read_text(encoding="utf-8") == before


# ---- an unusable recorded grant grants nothing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "recorded",
    [None, "https://www.googleapis.com/auth/drive.metadata.readonly", 42, True, {"scope": DRIVE_META}, [],
     [DRIVE_META, DRIVE_RO, 3], [DRIVE_META, DRIVE_RO, ""], [DRIVE_META, DRIVE_RO, None],
     [DRIVE_META, DRIVE_RO, " "], [DRIVE_META, DRIVE_RO, "\t\n"], [DRIVE_META, DRIVE_RO, f"{DRIVE_META} {DRIVE_RO}"],
     [DRIVE_META, DRIVE_RO, f" {DRIVE_RO}"]],
    ids=["null", "string", "number", "bool", "mapping", "empty", "list-with-number", "list-with-empty", "list-with-null",
         "list-with-space", "list-with-whitespace", "list-with-joined-scopes", "list-with-padded-scope"],
)
def test_an_unusable_recorded_grant_grants_nothing_and_the_run_signs_in_without_a_refresh(
    tmp_path: Path, oauth: dict[str, Any], recorded: Any
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=recorded)
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO]]


@pytest.mark.parametrize(
    "recorded",
    [None, "https://www.googleapis.com/auth/drive.metadata.readonly", 42, True, {"scope": DRIVE_META}, [],
     [DRIVE_META, 3], [DRIVE_META, ""], [DRIVE_META, " "], [DRIVE_META, f"{DRIVE_RO} "]],
    ids=["null", "string", "number", "bool", "mapping", "empty", "list-with-number", "list-with-empty", "list-with-space",
         "list-with-padded-scope"],
)
def test_recorded_grant_values_that_prove_nothing_are_an_empty_grant(recorded: Any) -> None:
    assert google_auth._recorded_grant({VERIFIED: recorded}) == frozenset()


@pytest.mark.parametrize("entry", list(_NOT_SCOPE_TOKENS.values()), ids=list(_NOT_SCOPE_TOKENS))
def test_a_recorded_entry_outside_the_rfc6749_scope_token_grammar_makes_the_record_grant_nothing(entry: str) -> None:
    assert google_auth._recorded_grant({VERIFIED: [DRIVE_META, DRIVE_RO, entry]}) == frozenset()


def test_recorded_grant_accepts_scope_tokens_at_the_edges_of_the_rfc6749_grammar() -> None:
    assert google_auth._recorded_grant({VERIFIED: ["openid", "!#[]~"]}) == frozenset({"openid", "!#[]~"})


def test_recorded_grant_reads_a_list_of_scopes_and_is_none_only_when_the_key_is_absent() -> None:
    assert google_auth._recorded_grant({VERIFIED: [DRIVE_META, DRIVE_RO]}) == frozenset(
        {"https://www.googleapis.com/auth/drive.metadata.readonly", "https://www.googleapis.com/auth/drive.readonly"}
    )
    assert google_auth._recorded_grant({"scopes": [DRIVE_META]}) is None


# ---- older caches (no verified-scopes key) keep the earlier rule ---------------------------------------------------


def test_older_cache_is_refreshed_with_only_this_runs_scopes_and_saved_with_the_grant(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN])
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert oauth["flow_scopes"] == []
    assert credentials.has_scopes([DOMAIN]) is False
    assert _saved(tmp_path)[VERIFIED] == [DRIVE_META, DRIVE_RO]


def test_older_cache_with_space_separated_scopes_still_loads(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [], scopes=f"{DRIVE_META} {DRIVE_RO} {DOMAIN}")
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert oauth["flow_scopes"] == []


def test_older_cache_that_did_not_ask_for_a_needed_scope_signs_in_once(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO])
    google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]


def test_older_cache_during_an_outage_is_not_used(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO])
    oauth["down"] = True
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert str(caught.value) == "Google sign-in could not be refreshed (temporary error); run again later."
    assert oauth["flow_scopes"] == []


@pytest.mark.parametrize("field", [{"expiry": 42}, {"scopes": 42}, {"scopes": [DRIVE_META, 7]}])
def test_a_wrong_typed_cache_field_signs_in_again_instead_of_raising(
    tmp_path: Path, oauth: dict[str, Any], field: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO], **field)
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO]]
    assert credentials.token == "tok-SYNTHETIC-access"


@pytest.mark.parametrize(
    "malformed",
    [" ", "", "\t", 7, None, *_NOT_SCOPE_TOKENS.values()],
    ids=["space", "empty", "tab", "number", "null", *_NOT_SCOPE_TOKENS],
)
def test_outage_with_a_required_grant_plus_one_malformed_entry_is_not_trusted(
    tmp_path: Path, oauth: dict[str, Any], malformed: Any
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=[DRIVE_META, DRIVE_RO, malformed])
    oauth["down"] = True
    oauth["consent_error"] = RuntimeError("consent window closed")
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert str(caught.value) == "Google sign-in failed (RuntimeError); run again to sign in."
    assert oauth["refresh_scopes"] == []
    assert oauth["flow_scopes"] == [[DRIVE_META, DRIVE_RO]]


# ---- a scope Google refused stays refused until a consent grants it ------------------------------------------------


class _ScopeChanged(Warning):
    """oauthlib's scope-change Warning: the consent granted only ``new_scope``."""

    def __init__(self, new_scope: list[str]) -> None:
        super().__init__("Scope has changed")
        self.new_scope = new_scope


CACHE_BUSY = (
    "Google sign-in stopped: another Auditex sign-in is updating the Google token cache; nothing was recorded; "
    "run again."
)
MISSING_DOMAIN = (
    "Google sign-in did not grant every permission this run needs (missing scopes: "
    "https://www.googleapis.com/auth/admin.directory.domain.readonly); run again and approve every requested "
    "permission."
)


@pytest.mark.parametrize("declined", ["oauthlib-warning", "relaxed-narrower-grant"])
def test_a_refused_scope_and_a_declined_consent_leave_no_stale_grant_for_the_next_run_or_an_outage(
    tmp_path: Path, oauth: dict[str, Any], declined: str
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    if declined == "oauthlib-warning":
        oauth["consent_error"] = _ScopeChanged([DRIVE_META, DRIVE_RO])
    else:
        oauth["consent_grant"] = [DRIVE_META, DRIVE_RO]
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == MISSING_DOMAIN
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    # Google granted nothing on that refresh and the consent declined the scope: the record now grants nothing.
    saved = _saved(tmp_path)
    assert saved[VERIFIED] == []
    assert saved["token"] == "tok-SYNTHETIC-access"
    assert saved["refresh_token"] == "tok-SYNTHETIC-refresh"

    # The next broader run does not resend the refused scope on a refresh; it goes straight to one consent.
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == MISSING_DOMAIN
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert len(oauth["flow_scopes"]) == 2

    # The token endpoint goes down while the old access token (one hour left) is still in date: neither a broader run
    # nor a Drive run gets that token back claiming anything; each signs in again instead.
    oauth["down"] = True
    oauth["consent_error"] = RuntimeError("consent window closed")
    for scopes in (DOMAIN_RUN, DRIVE_RUN):
        with pytest.raises(RuntimeError) as caught:
            google_auth.build_google_credentials(_config(tmp_path, scopes))
        assert str(caught.value) == "Google sign-in failed (RuntimeError); run again to sign in."
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN]]
    assert oauth["flow_scopes"][2:] == [[DRIVE_META, DRIVE_RO, DOMAIN], [DRIVE_META, DRIVE_RO]]

    # A consent that grants the scope again is used and saved with its full grant.
    oauth["down"] = False
    oauth["consent_error"] = None
    oauth["consent_grant"] = None
    oauth["revoked"] = set()
    credentials = google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert credentials.scopes == [DRIVE_META, DRIVE_RO, DOMAIN]
    assert _saved(tmp_path)[VERIFIED] == [DOMAIN, DRIVE_META, DRIVE_RO]


def test_a_refused_refresh_empties_the_record_before_the_consent_starts(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from google_auth_oauthlib.flow import InstalledAppFlow

    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    oauth["revoked"] = {DOMAIN}
    seen: list[Any] = []

    class _Abandoned(Exception):
        pass

    def _record_then_abandon(port: int = 0) -> Any:
        seen.append(_saved(tmp_path)[VERIFIED])
        raise _Abandoned("browser closed")

    def _flow(_cls: Any, _path: str, scopes: list[str]) -> Any:
        return types.SimpleNamespace(run_local_server=_record_then_abandon)

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(_flow))
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == "Google sign-in failed (_Abandoned); run again to sign in."
    assert seen == [[]]
    assert _saved(tmp_path)[VERIFIED] == []


def test_a_refresh_that_grants_less_than_the_run_needs_narrows_the_record_to_that_grant(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    oauth["refresh_grant"] = [DRIVE_META, DRIVE_RO]
    oauth["consent_error"] = _ScopeChanged([DRIVE_META, DRIVE_RO])
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == MISSING_DOMAIN
    assert _saved(tmp_path)[VERIFIED] == [
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    ]
    # A Drive run then reuses the cache without asking for the domain scope.
    oauth["consent_error"] = None
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert oauth["refresh_scopes"] == [[DRIVE_META, DRIVE_RO, DOMAIN], [DRIVE_META, DRIVE_RO]]
    assert len(oauth["flow_scopes"]) == 1


def test_an_older_cache_refused_by_the_endpoint_is_recorded_as_granting_nothing(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN])
    oauth["revoked"] = {DOMAIN}
    oauth["consent_error"] = _ScopeChanged([DRIVE_META, DRIVE_RO])
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == MISSING_DOMAIN
    assert _saved(tmp_path)[VERIFIED] == []


def test_a_newer_cache_saved_by_another_run_during_the_refresh_is_left_as_it_is(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from google.auth import exceptions
    from google.oauth2 import reauth

    path = _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])
    newer = json.dumps({"token": "tok-SYNTHETIC-other-run", VERIFIED: [DOMAIN, DRIVE_META, DRIVE_RO]})

    def _other_run_saves_then_refused(*_a: Any, **_k: Any) -> Any:
        path.write_text(newer, encoding="utf-8")
        raise exceptions.RefreshError("invalid_scope: refused", {"error": "invalid_scope"})

    monkeypatch.setattr(reauth, "refresh_grant", _other_run_saves_then_refused)
    oauth["consent_error"] = _ScopeChanged([DRIVE_META, DRIVE_RO])
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
    assert str(caught.value) == MISSING_DOMAIN
    assert path.read_text(encoding="utf-8") == newer


# ---- an existing cache written with the literal on-disk key still loads --------------------------------------------


def test_an_on_disk_cache_written_with_the_literal_verified_scopes_key_still_loads(
    tmp_path: Path, oauth: dict[str, Any]
) -> None:
    from google.auth import _helpers

    expiry = (_helpers.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    on_disk = (
        '{"token": "tok-SYNTHETIC-access", "refresh_token": "tok-SYNTHETIC-refresh", '
        '"token_uri": "https://oauth2.googleapis.com/token", "client_id": "constructed-client", '
        '"client_secret": "tok-SYNTHETIC-secret", '
        '"scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly", '
        '"https://www.googleapis.com/auth/drive.readonly"], '
        '"universe_domain": "googleapis.com", "account": "", "expiry": "' + expiry + '", '
        '"auditex_verified_scopes": ["https://www.googleapis.com/auth/drive.metadata.readonly", '
        '"https://www.googleapis.com/auth/drive.readonly"]}'
    )
    path = tmp_path / "cache" / "token.json"
    path.parent.mkdir(mode=0o700)
    path.write_text(on_disk, encoding="utf-8")
    os.chmod(path, 0o600)
    # During an outage only the recorded grant lets the cached token stand in, so it must be read from that key.
    oauth["down"] = True
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert credentials.token == "tok-SYNTHETIC-access"
    assert credentials.scopes == [DRIVE_META, DRIVE_RO]
    assert oauth["flow_scopes"] == []
    assert path.read_text(encoding="utf-8") == on_disk


# ---- every rewrite of the cache holds its lock: a concurrent narrower save is never lost ---------------------------


def test_a_narrower_cache_saved_inside_another_runs_narrowing_window_is_kept(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's interleaving: a broad run is granted only the Drive scopes and pauses after comparing the cache
    text, before replacing it; a Drive-metadata run then refreshes and saves its own token granting Drive metadata only.
    The broad run's narrowing must not replace that newer, narrower record with its old token claiming both Drive scopes.
    """
    from google.auth import _helpers, exceptions
    from google.oauth2 import reauth

    path = _cache(tmp_path, [DRIVE_META, DRIVE_RO, DOMAIN], verified=[DOMAIN, DRIVE_META, DRIVE_RO])

    def _refresh_grant(_request: Any, _uri: str, refresh_token: str, *_a: Any, scopes: Any = None, **_k: Any) -> Any:
        asked = list(scopes or [])
        broad = DOMAIN in asked
        granted = [DRIVE_META, DRIVE_RO] if broad else asked
        token = "tok-SYNTHETIC-broad-run" if broad else "tok-SYNTHETIC-meta-run"
        return token, refresh_token, _helpers.utcnow() + timedelta(hours=1), {"scope": " ".join(granted)}, None

    monkeypatch.setattr(reauth, "refresh_grant", _refresh_grant)
    oauth["consent_error"] = _ScopeChanged([DRIVE_META, DRIVE_RO])  # the broad run's consent declines the domain scope

    real_write = google_auth.secure_write_text
    at_window, resume = threading.Event(), threading.Event()
    writes: list[str] = []

    def _write_pausing_the_broad_run(target: Any, content: str, **kwargs: Any) -> Any:
        if threading.current_thread().name == "broad" and not at_window.is_set():
            at_window.set()  # compared, about to replace
            assert resume.wait(10)
        result = real_write(target, content, **kwargs)
        writes.append(threading.current_thread().name)
        return result

    monkeypatch.setattr(google_auth, "secure_write_text", _write_pausing_the_broad_run)
    outcome: dict[str, Any] = {}

    def _run(name: str, scopes: tuple[str, ...]) -> None:
        try:
            outcome[name] = google_auth.build_google_credentials(_config(tmp_path, scopes))
        except Exception as exc:  # noqa: BLE001 - recorded for the assertions below
            outcome[name] = exc

    broad = threading.Thread(target=_run, args=("broad", DOMAIN_RUN), name="broad")
    meta = threading.Thread(target=_run, args=("meta", (DRIVE_META,)), name="meta")
    broad.start()
    assert at_window.wait(10)
    meta.start()
    meta.join(1.0)  # without the lock the metadata run saves at once; with it, it waits for the broad run
    resume.set()
    broad.join(10)
    meta.join(10)

    assert isinstance(outcome["broad"], RuntimeError)
    assert str(outcome["broad"]) == MISSING_DOMAIN
    assert outcome["meta"].token == "tok-SYNTHETIC-meta-run"
    assert writes == ["broad", "meta"]
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["token"] == "tok-SYNTHETIC-meta-run"
    assert saved[VERIFIED] == ["https://www.googleapis.com/auth/drive.metadata.readonly"]

    # A later outage: the old token never comes back claiming both Drive scopes; the metadata run's token claims one.
    def _down(*_a: Any, **_k: Any) -> Any:
        raise exceptions.TransportError("connection refused")

    monkeypatch.setattr(reauth, "refresh_grant", _down)
    oauth["consent_error"] = RuntimeError("consent window closed")
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert str(caught.value) == "Google sign-in failed (RuntimeError); run again to sign in."
    credentials = google_auth.build_google_credentials(_config(tmp_path, (DRIVE_META,)))
    assert credentials.token == "tok-SYNTHETIC-meta-run"
    assert credentials.scopes == ["https://www.googleapis.com/auth/drive.metadata.readonly"]


def test_a_consent_grant_not_recorded_for_the_lock_marks_the_record_unverified_and_stops(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The record does not cover the run, so the run consents; the consent grants all three scopes (not the record) and
    # its save finds the lock taken: the marker is left, the cache keeps its bytes and the run stops.
    path = _cache(tmp_path, [DRIVE_META, DOMAIN], verified=[DOMAIN, DRIVE_META])
    before = path.read_text(encoding="utf-8")
    monkeypatch.setattr(secret_hygiene, "SECRET_LOCK_WAIT", 0.2)
    with secret_hygiene.secret_file_lock(path) as held:
        assert held is True
        with pytest.raises(RuntimeError) as caught:
            google_auth.build_google_credentials(_config(tmp_path, DOMAIN_RUN))
        assert str(caught.value) == CACHE_BUSY
        assert oauth["refresh_scopes"] == []
        assert len(oauth["flow_scopes"]) == 1
        assert path.read_text(encoding="utf-8") == before
    marker = tmp_path / "cache" / ".token.json.unverified"
    assert marker.is_file() and not marker.is_symlink()
    assert marker.read_bytes() == b""


def test_a_refresh_matching_the_record_with_the_lock_taken_continues_without_writing(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=[DRIVE_META, DRIVE_RO])
    before = path.read_text(encoding="utf-8")
    monkeypatch.setattr(secret_hygiene, "SECRET_LOCK_WAIT", 0.2)
    with secret_hygiene.secret_file_lock(path) as held:
        assert held is True
        credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert credentials.token == "tok-SYNTHETIC-refreshed"
    assert path.read_text(encoding="utf-8") == before
    assert not os.path.lexists(tmp_path / "cache" / ".token.json.unverified")


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_the_cache_lock_file_is_created_owner_only_beside_the_cache(tmp_path: Path, oauth: dict[str, Any]) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=[DRIVE_META, DRIVE_RO])
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    lock = tmp_path / "cache" / ".token.json.lock"
    assert stat.S_IMODE(os.stat(lock).st_mode) == 0o600
    assert sorted(entry.name for entry in (tmp_path / "cache").iterdir()) == [".token.json.lock", "token.json"]


@pytest.mark.skipif(os.name != "posix", reason="a link at the lock path")
def test_a_link_at_the_cache_lock_path_is_never_held_or_followed(tmp_path: Path) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    (folder / ".token.json.lock").symlink_to(tmp_path / "elsewhere")
    with secret_hygiene.secret_file_lock(folder / "token.json") as held:
        assert held is False
    assert not (tmp_path / "elsewhere").exists()


def test_the_lock_backend_is_flock_on_posix() -> None:
    if os.name != "posix":
        pytest.skip("POSIX")
    backend = secret_hygiene._lock_backend()
    assert backend is not None and backend[0] == "fcntl"


def test_the_lock_backend_is_msvcrt_where_fcntl_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, int]] = []
    held: set[int] = set()

    def _locking(descriptor: int, mode: int, nbytes: int) -> None:
        assert nbytes == 1
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
        calls.append((mode, nbytes))
        if mode == 2:  # LK_NBLCK
            if descriptor in held:
                raise OSError(36, "Resource deadlock avoided")
            held.add(descriptor)
        elif mode == 0:  # LK_UNLCK
            held.discard(descriptor)

    fake = types.SimpleNamespace(locking=_locking, LK_NBLCK=2, LK_UNLCK=0)
    monkeypatch.setitem(sys.modules, "fcntl", None)  # import fcntl now raises ImportError
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    backend = secret_hygiene._lock_backend()
    assert backend is not None and backend[0] == "msvcrt"
    with secret_hygiene.secret_file_lock(tmp_path / "token.json") as locked:
        assert locked is True
    assert calls == [(2, 1), (0, 1)]


def test_no_lock_backend_means_the_lock_is_never_held(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "fcntl", None)
    monkeypatch.setitem(sys.modules, "msvcrt", None)
    assert secret_hygiene._lock_backend() is None
    with secret_hygiene.secret_file_lock(tmp_path / "token.json") as locked:
        assert locked is False


def test_a_lock_another_run_holds_is_waited_for_then_reported_as_not_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    target = tmp_path / "cache" / "token.json"
    with secret_hygiene.secret_file_lock(target) as first:
        assert first is True
        started = time.monotonic()
        with secret_hygiene.secret_file_lock(target, wait=0.3) as second:
            assert second is False
        assert time.monotonic() - started >= 0.3
    with secret_hygiene.secret_file_lock(target, wait=0.3) as again:
        assert again is True


# ---- SEC-1d: a grant the lock kept from being recorded marks the record unverified; the lock file is owner-only ------

TEMPORARY = "Google sign-in could not be refreshed (temporary error); run again later."


def test_the_cache_lock_waits_sixty_seconds() -> None:
    assert secret_hygiene.SECRET_LOCK_WAIT == 60.0


@pytest.mark.parametrize("endpoint", ["refused", "narrower"])
def test_a_narrowing_missed_for_the_lock_leaves_no_broader_record_for_the_outage_fallback(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    """The reviewer's case: the endpoint grants fewer scopes than the record holds and the narrowing cannot take the
    lock. The run stops before any consent, the marker is left, and a later outage does not return the old token on
    the strength of the broader record, even for a run the record covers."""
    path = _cache(tmp_path, [DRIVE_META, DOMAIN], verified=[DOMAIN, DRIVE_META])
    before = path.read_text(encoding="utf-8")
    if endpoint == "refused":
        oauth["revoked"] = {DOMAIN}
    else:
        oauth["refresh_grant"] = [DRIVE_META]
    monkeypatch.setattr(secret_hygiene, "SECRET_LOCK_WAIT", 0.2)
    with secret_hygiene.secret_file_lock(path) as held:
        assert held is True
        with pytest.raises(RuntimeError) as caught:
            google_auth.build_google_credentials(_config(tmp_path, (DRIVE_META, DOMAIN)))
    assert str(caught.value) == CACHE_BUSY
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True
    assert oauth["flow_scopes"] == []
    assert path.read_text(encoding="utf-8") == before
    marker = tmp_path / "cache" / ".token.json.unverified"
    assert stat.S_IMODE(os.lstat(marker).st_mode) == 0o600
    oauth["revoked"], oauth["refresh_grant"], oauth["down"] = set(), None, True
    for scopes in [(DRIVE_META, DOMAIN), (DRIVE_META,)]:
        with pytest.raises(RuntimeError) as outage:
            google_auth.build_google_credentials(_config(tmp_path, scopes))
        assert str(outage.value) == TEMPORARY


def test_a_locked_rewrite_removes_the_unverified_marker_after_writing(tmp_path: Path, oauth: dict[str, Any]) -> None:
    path = _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=[DRIVE_META, DRIVE_RO])
    marker = tmp_path / "cache" / ".token.json.unverified"
    marker.touch(mode=0o600)
    oauth["down"] = True
    with pytest.raises(RuntimeError) as outage:
        google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert str(outage.value) == TEMPORARY
    oauth["down"] = False
    google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert not os.path.lexists(marker)
    assert json.loads(path.read_text(encoding="utf-8"))["token"] == "tok-SYNTHETIC-refreshed"
    oauth["down"] = True
    credentials = google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert credentials.token == "tok-SYNTHETIC-refreshed"


def test_a_locked_narrowing_removes_the_unverified_marker(tmp_path: Path, oauth: dict[str, Any]) -> None:
    path = _cache(tmp_path, [DRIVE_META, DOMAIN], verified=[DOMAIN, DRIVE_META])
    marker = tmp_path / "cache" / ".token.json.unverified"
    marker.touch(mode=0o600)
    oauth["refresh_grant"] = [DRIVE_META]
    oauth["consent_error"] = RuntimeError("consent window closed")
    with pytest.raises(RuntimeError):
        google_auth.build_google_credentials(_config(tmp_path, (DRIVE_META, DOMAIN)))
    assert json.loads(path.read_text(encoding="utf-8"))[VERIFIED] == [
        "https://www.googleapis.com/auth/drive.metadata.readonly"
    ]
    assert not os.path.lexists(marker)


def test_an_unverified_marker_that_cannot_be_checked_counts_as_present(
    tmp_path: Path, oauth: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _cache(tmp_path, [DRIVE_META, DRIVE_RO], verified=[DRIVE_META, DRIVE_RO])
    real_lstat = os.lstat

    def _lstat(target: Any, *args: Any, **kwargs: Any) -> Any:
        if str(target).endswith(".token.json.unverified"):
            raise PermissionError(13, "Permission denied")
        return real_lstat(target, *args, **kwargs)

    monkeypatch.setattr(secret_hygiene.os, "lstat", _lstat)
    assert secret_hygiene.secret_unverified(tmp_path / "cache" / "token.json") is True
    oauth["down"] = True
    with pytest.raises(RuntimeError) as outage:
        google_auth.build_google_credentials(_config(tmp_path, DRIVE_RUN))
    assert str(outage.value) == TEMPORARY


@pytest.mark.skipif(os.name != "posix", reason="a link at the marker path")
def test_the_unverified_marker_is_created_owner_only_and_never_through_a_link(tmp_path: Path) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    target = folder / "token.json"
    assert secret_hygiene.secret_unverified(target) is False
    secret_hygiene.mark_secret_unverified(target)
    assert stat.S_IMODE(os.lstat(folder / ".token.json.unverified").st_mode) == 0o600
    secret_hygiene.mark_secret_unverified(target)  # already there: kept
    assert secret_hygiene.secret_unverified(target) is True
    secret_hygiene.clear_secret_unverified(target)
    assert secret_hygiene.secret_unverified(target) is False
    (folder / ".token.json.unverified").symlink_to(tmp_path / "elsewhere")
    secret_hygiene.mark_secret_unverified(target)
    assert not (tmp_path / "elsewhere").exists()
    assert secret_hygiene.secret_unverified(target) is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o620, 0o602, 0o610, 0o666])
def test_a_pre_existing_lock_file_with_group_or_other_bits_is_never_held(tmp_path: Path, mode: int) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    lock = folder / ".token.json.lock"
    lock.touch(mode=0o600)
    os.chmod(lock, mode)
    with secret_hygiene.secret_file_lock(folder / "token.json") as held:
        assert held is False
    assert stat.S_IMODE(os.lstat(lock).st_mode) == mode


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_a_loose_lock_file_stops_a_narrowing_without_writing_the_cache(tmp_path: Path, oauth: dict[str, Any]) -> None:
    path = _cache(tmp_path, [DRIVE_META, DOMAIN], verified=[DOMAIN, DRIVE_META])
    before = path.read_text(encoding="utf-8")
    lock = tmp_path / "cache" / ".token.json.lock"
    lock.touch(mode=0o600)
    os.chmod(lock, 0o666)
    oauth["revoked"] = {DOMAIN}
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path, (DRIVE_META, DOMAIN)))
    assert str(caught.value) == CACHE_BUSY
    assert path.read_text(encoding="utf-8") == before
    assert os.path.lexists(tmp_path / "cache" / ".token.json.unverified")


@pytest.mark.parametrize("name", [".token.json.lock", ".token.json.unverified", ".x.lock", ".x.unverified"])
def test_a_token_cache_named_like_a_lock_or_marker_is_refused(tmp_path: Path, oauth: dict[str, Any], name: str) -> None:
    config = google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=DRIVE_RUN, oauth_client=tmp_path / "client.json",
                                          token_cache=tmp_path / "cache" / name)
    with pytest.raises(ValueError) as caught:
        google_auth.build_google_credentials(config)
    assert str(caught.value) == (
        "token_cache_refused: the token cache file name is reserved for Auditex lock and marker files "
        "(.<name>.lock, .<name>.unverified); choose another name."
    )
    assert oauth["flow_scopes"] == []


@pytest.mark.parametrize("name", [".token.json.lock", ".token.json.unverified"])
def test_a_secret_write_never_replaces_a_lock_or_marker(tmp_path: Path, name: str) -> None:
    folder = tmp_path / "cache"
    with secret_hygiene.secret_file_lock(folder / "token.json") as held:
        assert held is True
        lock_before = os.lstat(folder / ".token.json.lock")
        with pytest.raises(PermissionError) as caught:
            secret_hygiene.secure_write_text(folder / name, "{}")
        assert str(caught.value).startswith("[Errno 13] secret_file_refused:")
        lock_after = os.lstat(folder / ".token.json.lock")
        assert (lock_after.st_ino, lock_after.st_size) == (lock_before.st_ino, 0)
    assert not os.path.lexists(folder / ".token.json.unverified")


@pytest.mark.parametrize(
    ("name", "reserved"),
    [(".token.json.lock", True), (".token.json.unverified", True), ("token.json", False), ("token.lock", False),
     (".token.json", False), ("token.json.unverified", False)],
)
def test_reserved_secret_names(name: str, reserved: bool) -> None:
    assert secret_hygiene.reserved_secret_name(name) is reserved


@pytest.mark.skipif(os.name != "posix", reason="a link stands in for a Windows link or junction")
def test_the_native_lock_open_refuses_a_link_before_opening(tmp_path: Path) -> None:
    lock = tmp_path / ".token.json.lock"
    lock.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(secret_hygiene._LockFileRefused):
        secret_hygiene._open_native_lock_file(lock)
    assert not (tmp_path / "elsewhere").exists()


def test_the_native_lock_open_refuses_a_reparse_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = tmp_path / ".token.json.lock"
    lock.touch()
    real_lstat = os.lstat

    def _lstat(target: Any, *args: Any, **kwargs: Any) -> Any:
        info = real_lstat(target, *args, **kwargs)
        if str(target) == str(lock):
            return types.SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                         st_file_attributes=0x400)
        return info

    monkeypatch.setattr(secret_hygiene.os, "lstat", _lstat)
    with pytest.raises(secret_hygiene._LockFileRefused):
        secret_hygiene._open_native_lock_file(lock)


@pytest.mark.skipif(os.name != "posix", reason="a link stands in for a Windows link or junction")
def test_the_native_lock_open_refuses_a_link_put_in_place_while_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / ".token.json.lock"
    real_open = os.open
    opened: list[int] = []

    def _open_then_swap(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(target, flags, *args, **kwargs)
        if str(target) == str(lock):
            opened.append(descriptor)
            os.unlink(lock)
            lock.symlink_to(tmp_path / "elsewhere")
        return descriptor

    monkeypatch.setattr(secret_hygiene.os, "open", _open_then_swap)
    with pytest.raises(secret_hygiene._LockFileRefused):
        secret_hygiene._open_native_lock_file(lock)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])  # closed on refusal


def test_the_native_lock_open_returns_a_regular_lock_file(tmp_path: Path) -> None:
    lock = tmp_path / ".token.json.lock"
    descriptor = secret_hygiene._open_native_lock_file(lock)
    try:
        assert stat.S_ISREG(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)
    assert lock.is_file()


def test_clearing_the_unverified_marker_removes_only_a_regular_file_this_account_owns(tmp_path: Path) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    cache = folder / "token.json"
    marker = folder / ".token.json.unverified"
    marker.touch(mode=0o600)
    secret_hygiene.clear_secret_unverified(cache)
    assert not os.path.lexists(marker)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and dir_fd lookups")
def test_clearing_the_unverified_marker_leaves_a_link_and_its_target_in_place(tmp_path: Path) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    marker = folder / ".token.json.unverified"
    marker.symlink_to(victim)
    secret_hygiene.clear_secret_unverified(folder / "token.json")
    assert os.path.islink(marker)
    assert victim.read_text(encoding="utf-8") == "keep"
    assert secret_hygiene.secret_unverified(folder / "token.json") is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and dir_fd lookups")
def test_clearing_the_unverified_marker_leaves_another_accounts_file_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    marker = folder / ".token.json.unverified"
    marker.touch(mode=0o600)
    real_stat = os.stat

    def other_owner(name: Any, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(name, *args, **kwargs)
        if name == ".token.json.unverified":
            values = list(info)
            values[stat.ST_UID] = info.st_uid + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(secret_hygiene.os, "stat", other_owner)
    secret_hygiene.clear_secret_unverified(folder / "token.json")
    assert os.path.lexists(marker)

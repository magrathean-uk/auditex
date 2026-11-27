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
import types
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import auth as google_auth

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


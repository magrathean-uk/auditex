"""SEC-1 item 2: OAuth dependency loggers never write token material while Google sign-in runs.

The root logger and every dependency logger (and a child of each) are set to DEBUG with a capturing handler. The mocked
consent and token endpoint log a synthetic code, token and refresh token through those loggers, as requests-oauthlib,
oauthlib, google-auth-oauthlib, google-auth and urllib3 do. None of it may reach a handler, Auditex's own logging must
be unchanged, and every logger's level and propagate setting must be back afterwards, after an exception too.
"""

from __future__ import annotations

import json
import logging
import os
import types
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import auth as google_auth

SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
SECRET = "tok-SYNTHETIC"
DEPENDENCY_LOGGERS = (
    "requests_oauthlib",
    "requests_oauthlib.oauth2_session",
    "oauthlib",
    "oauthlib.oauth2.rfc6749.parameters",
    "google_auth_oauthlib",
    "google_auth_oauthlib.flow",
    "google.auth",
    "google.auth.transport",
    "google.auth.transport.requests",
    "google.oauth2",
    "google.oauth2._client",
    "urllib3",
    "urllib3.connectionpool",
)
OWN_LOGGER = "auditex.google_workspace.sec1_probe"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(f"{record.name}: {record.getMessage()}")


def _leak(stage: str) -> None:
    """What the dependencies log on the consent and refresh paths, with synthetic material."""
    for name in DEPENDENCY_LOGGERS:
        logger = logging.getLogger(name)
        logger.debug("%s: Request body was code=%s-code&client_secret=%s-secret", stage, SECRET, SECRET)
        logger.debug("%s: Obtained token {'access_token': '%s-access', 'refresh_token': '%s-refresh'}", stage, SECRET,
                     SECRET)
        logger.info('%s: "GET /?state=x&code=%s-code HTTP/1.1" 200 65', stage, SECRET)
        logger.warning("%s: warning with no token material", stage)
    logging.getLogger(OWN_LOGGER).debug("%s: auditex debug line", stage)


@pytest.fixture
def loggers() -> Iterator[dict[str, Any]]:
    """Root and every dependency logger at DEBUG with a capturing handler; everything restored after the test."""
    names = ("", *DEPENDENCY_LOGGERS, OWN_LOGGER)
    before = {name: (logging.getLogger(name).level, logging.getLogger(name).propagate) for name in names}
    root_capture, direct_capture = _Capture(), _Capture()
    root = logging.getLogger()
    root.addHandler(root_capture)
    for name in names:
        logging.getLogger(name).setLevel(logging.DEBUG)
    # A handler attached directly to a dependency logger, and one that does not propagate: both must be restored.
    logging.getLogger("requests_oauthlib.oauth2_session").addHandler(direct_capture)
    logging.getLogger("urllib3.connectionpool").propagate = False
    logging.getLogger("urllib3.connectionpool").addHandler(direct_capture)
    try:
        yield {"root": root_capture, "direct": direct_capture}
    finally:
        root.removeHandler(root_capture)
        logging.getLogger("requests_oauthlib.oauth2_session").removeHandler(direct_capture)
        logging.getLogger("urllib3.connectionpool").removeHandler(direct_capture)
        for name, (level, propagate) in before.items():
            logging.getLogger(name).setLevel(level)
            logging.getLogger(name).propagate = propagate


def _assert_restored() -> None:
    for name in DEPENDENCY_LOGGERS:
        assert logging.getLogger(name).level == logging.DEBUG, name
    assert logging.getLogger().level == logging.DEBUG
    assert logging.getLogger("urllib3.connectionpool").propagate is False
    assert logging.getLogger("requests_oauthlib.oauth2_session").propagate is True


def _all(captures: dict[str, Any]) -> list[str]:
    return captures["root"].messages + captures["direct"].messages


@pytest.fixture
def oauth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from google.auth import _helpers
    from google.oauth2 import reauth
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    state: dict[str, Any] = {"consent_error": None, "consents": 0, "refreshes": 0}

    def _credentials() -> Any:
        return Credentials(token=f"{SECRET}-access", refresh_token=f"{SECRET}-refresh",
                           token_uri="https://oauth2.googleapis.com/token", client_id="constructed-client",
                           client_secret=f"{SECRET}-secret", scopes=[SCOPE], granted_scopes=[SCOPE],
                           expiry=_helpers.utcnow() + timedelta(hours=1))

    def _run_local_server(port: int = 0) -> Any:
        state["consents"] += 1
        _leak("consent")
        if state["consent_error"] is not None:
            raise state["consent_error"]
        return _credentials()

    def _from_client_secrets_file(_cls: Any, _path: str, _scopes: list[str]) -> Any:
        return types.SimpleNamespace(run_local_server=_run_local_server)

    def _refresh_grant(_request: Any, _uri: str, refresh_token: str, *_a: Any, scopes: Any = None, **_k: Any) -> Any:
        state["refreshes"] += 1
        _leak("refresh")
        return f"{SECRET}-refreshed", refresh_token, _helpers.utcnow() + timedelta(hours=1), {"scope": SCOPE}, None

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(_from_client_secrets_file))
    monkeypatch.setattr(reauth, "refresh_grant", _refresh_grant)
    monkeypatch.setattr(google_auth, "ownership_enforced", lambda _path: True)
    state["credentials"] = _credentials
    return state


def _config(tmp_path: Path) -> google_auth.GoogleAuthConfig:
    return google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=(SCOPE,), oauth_client=tmp_path / "client.json",
                                        token_cache=tmp_path / "cache" / "token.json")


def _write_cache(tmp_path: Path, oauth: dict[str, Any]) -> None:
    info = json.loads(oauth["credentials"]().to_json())
    info[google_auth.VERIFIED_SCOPES_KEY] = [SCOPE]
    path = tmp_path / "cache" / "token.json"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(info), encoding="utf-8")
    os.chmod(path, 0o600)


def test_consent_never_logs_token_material_and_levels_come_back(
    tmp_path: Path, oauth: dict[str, Any], loggers: dict[str, Any]
) -> None:
    google_auth.build_google_credentials(_config(tmp_path))
    assert oauth["consents"] == 1
    messages = _all(loggers)
    assert [line for line in messages if SECRET in line] == []
    assert "auditex.google_workspace.sec1_probe: consent: auditex debug line" in messages
    assert "requests_oauthlib.oauth2_session: consent: warning with no token material" in messages
    _assert_restored()


def test_refresh_never_logs_token_material_and_levels_come_back(
    tmp_path: Path, oauth: dict[str, Any], loggers: dict[str, Any]
) -> None:
    _write_cache(tmp_path, oauth)
    google_auth.build_google_credentials(_config(tmp_path))
    assert (oauth["refreshes"], oauth["consents"]) == (1, 0)
    messages = _all(loggers)
    assert [line for line in messages if SECRET in line] == []
    assert "auditex.google_workspace.sec1_probe: refresh: auditex debug line" in messages
    _assert_restored()


def test_a_failed_consent_never_logs_token_material_and_levels_come_back(
    tmp_path: Path, oauth: dict[str, Any], loggers: dict[str, Any]
) -> None:
    oauth["consent_error"] = ValueError(f"oauthlib text quoting {SECRET}-code")
    with pytest.raises(RuntimeError) as caught:
        google_auth.build_google_credentials(_config(tmp_path))
    assert str(caught.value) == "Google sign-in failed (ValueError); run again to sign in."
    assert [line for line in _all(loggers) if SECRET in line] == []
    _assert_restored()


def test_dependency_logging_outside_sign_in_is_untouched(loggers: dict[str, Any]) -> None:
    _leak("outside")
    assert "requests_oauthlib.oauth2_session: outside: Obtained token {'access_token': 'tok-SYNTHETIC-access', " \
           "'refresh_token': 'tok-SYNTHETIC-refresh'}" in loggers["root"].messages


def test_overlapping_guards_restore_only_when_the_last_one_ends(loggers: dict[str, Any]) -> None:
    outer = google_auth.quiet_auth_dependency_logs()
    inner = google_auth.quiet_auth_dependency_logs()
    outer.__enter__()
    inner.__enter__()
    outer.__exit__(None, None, None)
    assert logging.getLogger("requests_oauthlib").level == logging.WARNING
    _leak("overlap")
    assert [line for line in _all(loggers) if SECRET in line] == []
    inner.__exit__(None, None, None)
    _assert_restored()


def test_a_logger_already_above_warning_is_left_as_it_is() -> None:
    logger = logging.getLogger("oauthlib")
    before = logger.level
    logger.setLevel(logging.ERROR)
    try:
        with google_auth.quiet_auth_dependency_logs():
            assert logger.level == logging.ERROR
        assert logger.level == logging.ERROR
    finally:
        logger.setLevel(before)

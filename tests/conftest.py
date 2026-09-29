"""Shared pytest fixtures.

The single most important guardrail here: redirect every auditex
secrets path (``.secrets/m365-auth.env`` and friends) to an
isolated tmp directory for the duration of every test session.

Without this, a test that exercises the guided flow (or any code
path that reaches ``save_local_auth_values`` / ``_persist_local_defaults``)
silently overwrites the developer's real credentials with the
test's fixture values. Discovered live on 2026-05-09 when ``make test``
clobbered a working app-registration secret with
``AZURE_CLIENT_ID=app-id, AZURE_CLIENT_SECRET=app-secret`` from
``test_guided_run_requires_exchange_login_when_requested``.

The fixture is ``autouse=True`` and ``session``-scoped so:
- every test inherits the redirect by default
- per-test ``monkeypatch`` calls inside individual tests still work
  (they shadow the session env)
- the real ``.secrets/`` directory in the repo is never touched
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_auditex_secrets():
    """Redirect AUDITEX_LOCAL_AUTH_ENV, AUDITEX_AUTH_CONTEXTS_PATH and
    AUDITEX_M365_HOME to a session-scoped tmp directory before any test
    imports auditex code."""
    tmp_dir = tempfile.mkdtemp(prefix="auditex-test-secrets-")
    auth_env_path = Path(tmp_dir) / "m365-auth.env"
    contexts_path = Path(tmp_dir) / "auditex-auth-contexts.json"

    previous: dict[str, str | None] = {}
    for key, value in (
        ("AUDITEX_LOCAL_AUTH_ENV", str(auth_env_path)),
        ("AUDITEX_AUTH_CONTEXTS_PATH", str(contexts_path)),
        ("AUDITEX_M365_HOME", str(Path(tmp_dir) / "m365-home")),
    ):
        previous[key] = os.environ.get(key)
        os.environ[key] = value

    try:
        yield tmp_dir
    finally:
        for key, prev in previous.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

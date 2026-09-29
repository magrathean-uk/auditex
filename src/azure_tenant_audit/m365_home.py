"""Keep the Microsoft 365 CLI (``m365``) sign-in files out of the user's home folder.

``m365`` has no setting for where it keeps its tokens and connections
(``.cli-m365-tokens.json``, ``.cli-m365-connection.json`` and similar): it derives the
folder from the home directory. Auditex therefore starts ``m365`` with ``HOME`` pointing
at a private folder. Only the ``m365`` child process sees the changed ``HOME``.

The folder is chosen like this:

1. ``AUDITEX_M365_HOME`` when it is set. Set it to an empty value to keep the ``m365``
   default (the home folder).
2. Otherwise ``$XDG_DATA_HOME/auditex/m365`` when ``XDG_DATA_HOME`` is set.
3. Otherwise no change: ``m365`` runs exactly as before.

``scripts/m365-home.sh`` applies the same rule for the shell scripts, so a sign-in made
by ``scripts/tenant-audit-login`` is found by the Python commands and the other way round.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Sequence

M365_HOME_ENV_VAR = "AUDITEX_M365_HOME"
XDG_DATA_HOME_ENV_VAR = "XDG_DATA_HOME"


def m365_home(environ: Mapping[str, str] | None = None) -> Path | None:
    """Return the folder to use as ``HOME`` for ``m365``, or ``None`` to leave it alone."""
    if os.name == "nt":
        # m365 derives its folder from USERPROFILE on Windows; there is no HOME to point elsewhere.
        return None
    env = os.environ if environ is None else environ
    if M365_HOME_ENV_VAR in env:
        configured = env[M365_HOME_ENV_VAR].strip()
        return Path(configured).expanduser().resolve() if configured else None
    data_home = env.get(XDG_DATA_HOME_ENV_VAR, "").strip()
    if data_home:
        return (Path(data_home).expanduser() / "auditex" / "m365").resolve()
    return None


def is_m365_command(command: Sequence[str] | None) -> bool:
    return bool(command) and Path(str(command[0])).name == "m365"


def m365_environment(command: Sequence[str] | None) -> dict[str, str] | None:
    """Environment for running ``command``, or ``None`` when the caller's own is right.

    Only ``m365`` gets a different one: a copy of ``os.environ`` whose ``HOME`` is the
    private folder, created with mode 700 when it does not exist yet.
    """
    if not is_m365_command(command):
        return None
    home = m365_home()
    if home is None:
        return None
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(home)
    return env


def m365_subprocess_kwargs(command: Sequence[str] | None) -> dict[str, dict[str, str]]:
    """``subprocess`` keyword arguments for ``command``: ``{"env": ...}`` for a routed ``m365``, else ``{}``."""
    env = m365_environment(command)
    return {} if env is None else {"env": env}

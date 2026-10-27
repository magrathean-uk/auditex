"""ScubaGear-shaped evidence projection.

P1 deliberately produces no sections. P2 will fill this mapping from a run's
``normalized/*.json`` artefacts, retaining collection gaps and named enum values.
An absent key means not collected, never an empty successful collection or null.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def project_run(run_dir: str | Path) -> dict[str, Any]:
    """Return the P1 stub; no tenant content or credentials are read."""
    return {}

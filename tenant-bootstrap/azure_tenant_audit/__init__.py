"""Compatibility package that forwards imports to the canonical runtime."""

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_DIR.parents[1]
_CANONICAL_PACKAGE_DIR = _REPO_ROOT / "src" / "azure_tenant_audit"

if _CANONICAL_PACKAGE_DIR.exists():
    __path__.insert(0, str(_CANONICAL_PACKAGE_DIR))

from .cli import main  # noqa: E402

__all__ = ["main"]

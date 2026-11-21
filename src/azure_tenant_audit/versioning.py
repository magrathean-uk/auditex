from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _source_tree_version() -> str | None:
    """The version in this package's own source checkout, when the engine is imported from its src tree.

    An editable install keeps the metadata of the day it was installed, so after a pull the checkout's
    pyproject.toml is the truth; an installed wheel has no such file beside it and falls through.
    """
    here = Path(__file__).resolve()
    root = here.parents[2]
    pyproject_path = root / "pyproject.toml"
    if (root / "src" / "azure_tenant_audit" / "versioning.py").resolve() != here or not pyproject_path.is_file():
        return None
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    project_version = data.get("project", {}).get("version")
    if isinstance(project_version, str) and project_version.strip():
        return project_version.strip()
    return None


def _installed_version() -> str | None:
    try:
        return version("auditex")
    except PackageNotFoundError:
        return None


@lru_cache(maxsize=1)
def package_version() -> str:
    return _source_tree_version() or _installed_version() or "0+unknown"


def package_user_agent(product_name: str = "auditex") -> str:
    return f"{product_name}/{package_version()}"


def package_version_line(product_name: str = "auditex") -> str:
    return f"{product_name} {package_version()}"

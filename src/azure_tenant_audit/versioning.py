from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


@lru_cache(maxsize=1)
def package_version() -> str:
    try:
        return version("auditex")
    except PackageNotFoundError:
        pass

    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if pyproject_path.exists():
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        project_version = data.get("project", {}).get("version")
        if isinstance(project_version, str) and project_version.strip():
            return project_version.strip()
    return "0+unknown"


def package_user_agent(product_name: str = "auditex") -> str:
    return f"{product_name}/{package_version()}"


def package_version_line(product_name: str = "auditex") -> str:
    return f"{product_name} {package_version()}"

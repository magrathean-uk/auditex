from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from .reporting import render_report


BUILTIN_EXPORTERS: dict[str, dict[str, Any]] = {
    "csv": {"name": "csv", "description": "Write finding rows as CSV", "formats": ["csv"], "builtin": True},
    "html": {"name": "html", "description": "Write a standalone HTML audit report", "formats": ["html"], "builtin": True},
    "json": {"name": "json", "description": "Write the selected report sections as JSON", "formats": ["json"], "builtin": True},
    "md": {"name": "md", "description": "Write a Markdown report summary", "formats": ["md"], "builtin": True},
    "sarif": {"name": "sarif", "description": "Write findings in SARIF 2.1.0 (GitHub Code Scanning compatible)", "formats": ["sarif"], "builtin": True},
    "oscal": {"name": "oscal", "description": "Write findings as an OSCAL Assessment Results document", "formats": ["oscal"], "builtin": True},
}


def _entry_points() -> list[EntryPoint]:
    try:
        return list(entry_points(group="auditex.exporters"))
    except TypeError:
        return list(entry_points().get("auditex.exporters", []))  # type: ignore[union-attr]


def _external_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in _entry_points():
        module_name = getattr(item, "module", None) or item.value.split(":", 1)[0]
        rows.append({"name": item.name, "description": f"External exporter from {module_name}", "formats": [], "builtin": False})
    return rows


def list_exporters() -> list[dict[str, Any]]:
    return sorted([*BUILTIN_EXPORTERS.values(), *_external_rows()], key=lambda row: row["name"])


def _run_builtin(
    name: str,
    *,
    run_dir: str,
    include_sections: list[str] | None,
    exclude_sections: list[str] | None,
    output_path: str | None,
) -> dict[str, Any]:
    result = render_report(
        run_dir=run_dir,
        format_name=name,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
        output_path=output_path,
    )
    return {"name": name, "artifacts": [{"path": result["output_path"], "format": name}]}


def _invoke_plugin(plugin: Any, **kwargs: Any) -> dict[str, Any]:
    runner: Callable[..., Any] | None = plugin if callable(plugin) else getattr(plugin, "run", None)
    if runner is None:
        raise TypeError("Exporter plugin must be callable or expose run().")
    result = runner(**kwargs)
    if not isinstance(result, dict):
        raise TypeError("Exporter plugin returned a non-dict result.")
    return result


def run_exporter(
    *,
    name: str,
    run_dir: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    if name in BUILTIN_EXPORTERS:
        return _run_builtin(
            name,
            run_dir=run_dir,
            include_sections=include_sections,
            exclude_sections=exclude_sections,
            output_path=output_path,
        )

    for item in _entry_points():
        if item.name == name:
            return _invoke_plugin(
                item.load(),
                run_dir=run_dir,
                include_sections=include_sections,
                exclude_sections=exclude_sections,
                output_path=output_path,
            )
    raise KeyError(f"Unknown exporter: {name}")

"""Confine MCP tool path arguments to one configured root.

An MCP client is an untrusted caller: a path argument must not let it read or write outside the
directory the operator chose. The root is ``AUDITEX_MCP_ROOT`` when set, otherwise the server's
working directory. A relative path is resolved against the root; an absolute path must already be
inside it. ``..`` components, a leading ``~``, NUL bytes and symbolic links that lead outside the
root are refused.

A root that confines nothing is refused: ``/`` always, and the home directory when the root comes
from the working directory because ``AUDITEX_MCP_ROOT`` is unset (start the server from a project
directory or set the variable). Tenant and run names become part of a run directory name, so they
are validated the same way (no ``/``, ``\\``, ``..`` or control characters).
"""
from __future__ import annotations

import functools
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from azure_tenant_audit.output import validate_bundle_name

if TYPE_CHECKING:
    from .mcp_registry import McpToolEntry

MCP_ROOT_ENV = "AUDITEX_MCP_ROOT"


class McpPathError(ValueError):
    """A tool path argument is outside the MCP root or is not a plain path."""


def mcp_root() -> Path:
    """The directory MCP path arguments are confined to.

    Raises McpPathError when that directory would confine nothing: ``/``, or the home directory
    when it is only the working directory because ``AUDITEX_MCP_ROOT`` is unset.
    """
    configured = os.environ.get(MCP_ROOT_ENV, "").strip()
    base = (Path(configured).expanduser() if configured else Path.cwd()).resolve()
    if base == Path(base.anchor):
        raise McpPathError(
            f"the MCP root is {base}, which confines nothing; set {MCP_ROOT_ENV} to the directory the tools may use"
        )
    if not configured and base == Path.home().resolve():
        raise McpPathError(
            f"the MCP server was started in your home directory and {MCP_ROOT_ENV} is not set; "
            f"start it from a project directory or set {MCP_ROOT_ENV}"
        )
    return base


def confine_name(value: str, *, argument: str = "name") -> str:
    """A tenant or run name that is safe to use inside a run directory name, or McpPathError."""
    if value is None or value == "":
        return value
    if not isinstance(value, str):
        raise McpPathError(f"{argument} must be a string")
    try:
        validate_bundle_name(value, argument)
    except ValueError as exc:
        raise McpPathError(str(exc)) from exc
    return value


def confine_path(value: str, *, argument: str = "path", root: Path | None = None) -> str:
    """Resolved absolute path of ``value`` inside the MCP root, or McpPathError."""
    base = (root or mcp_root()).resolve()
    if not isinstance(value, str):
        raise McpPathError(f"{argument} must be a string path")
    if "\x00" in value:
        raise McpPathError(f"{argument} contains a NUL byte")
    if value.startswith("~"):
        raise McpPathError(f"{argument} must not start with '~'; give a path under {base}")
    candidate = Path(value)
    if ".." in candidate.parts:
        raise McpPathError(f"{argument} must not contain '..'")
    resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    if resolved != base and base not in resolved.parents:
        raise McpPathError(f"{argument} is outside the MCP root {base}")
    return str(resolved)


def confine_value(value: Any, *, argument: str = "path", root: Path | None = None) -> Any:
    """Confine a string, or every string in a list; an empty or missing value means 'not given'."""
    if value is None or value == "":
        return value
    if isinstance(value, (list, tuple)):
        return [confine_path(item, argument=argument, root=root) for item in value]
    return confine_path(value, argument=argument, root=root)


def confine_handler(entry: "McpToolEntry", handler: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool handler so its declared path arguments are confined before it runs.

    ``entry.name_args`` (tenant and run names) are validated as plain names. ``entry.path_args`` are always confined, defaults included. ``entry.resource_args`` name inputs
    whose default is a shipped read-only file (configs, schemas, examples): the default passes
    through, any other value is confined.
    """
    if not (entry.path_args or entry.resource_args or entry.name_args):
        return handler
    signature = inspect.signature(handler)
    unknown = [name for name in (*entry.path_args, *entry.resource_args, *entry.name_args) if name not in signature.parameters]
    if unknown:
        raise TypeError(f"{entry.name} declares path arguments the handler does not take: {', '.join(unknown)}")

    @functools.wraps(handler)
    def confined(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        for name in entry.name_args:
            bound.arguments[name] = confine_name(bound.arguments[name], argument=name)
        root = mcp_root() if (entry.path_args or entry.resource_args) else None
        for name in entry.path_args:
            bound.arguments[name] = confine_value(bound.arguments[name], argument=name, root=root)
        for name in entry.resource_args:
            value = bound.arguments[name]
            if value != signature.parameters[name].default:
                bound.arguments[name] = confine_value(value, argument=name, root=root)
        return handler(*bound.args, **bound.kwargs)

    return confined

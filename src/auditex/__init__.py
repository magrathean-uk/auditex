"""Auditex product wrapper for the Azure tenant audit engine."""

from azure_tenant_audit.provider_registry import register_provider


def _google_collectors():
    from .google_workspace.collectors import REGISTRY

    return REGISTRY


# Every product entry point imports this package, including reports and exports
# that consume existing Google bundles without running a Google collector first.
register_provider("google_workspace", _google_collectors)


def main() -> int:
    from .cli import main as cli_main

    return cli_main()


__all__ = ["main"]

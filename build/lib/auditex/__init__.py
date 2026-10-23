"""Auditex product wrapper for the Azure tenant audit engine."""


def main() -> int:
    from .cli import main as cli_main

    return cli_main()


__all__ = ["main"]

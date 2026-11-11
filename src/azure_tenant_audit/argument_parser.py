"""Privacy-preserving argparse factory, also shipped with the bootstrap kit."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

PARSER_ERROR_MESSAGE = "error: invalid arguments"


def _raise_without_context(exc: BaseException) -> NoReturn:
    """Raise a public exception without retaining the active private exception."""
    try:
        raise exc from None
    except BaseException:
        # Even ``from None`` retains __context__. Clear it after the raise,
        # then re-raise the same object so Python does not attach it again.
        exc.__context__ = None
        raise


class _PublicVersionAction(argparse._VersionAction):
    """Print the static version text without passing through error diagnostics."""

    def __call__(self, parser: DiagnosticRedactingArgumentParser, namespace: argparse.Namespace,
                 values: Any, option_string: str | None = None) -> None:
        version = self.version if self.version is not None else parser.version
        formatter = parser._get_formatter()
        formatter.add_text(version)
        parser._print_public_message(formatter.format_help(), sys.stdout)
        parser.exit()


class DiagnosticRedactingArgumentParser(argparse.ArgumentParser):
    """Only print static usage and a fixed message on argument errors."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.register("action", "version", _PublicVersionAction)

    def add_subparsers(self, **kwargs: Any) -> Any:
        if "parser_class" in kwargs and kwargs["parser_class"] is not build_argument_parser:
            raise ValueError("subparsers must use the shared argument parser factory")
        kwargs["parser_class"] = build_argument_parser
        return super().add_subparsers(**kwargs)

    def parse_args(self, args: Sequence[str] | None = None,
                   namespace: argparse.Namespace | None = None) -> argparse.Namespace:
        try:
            return super().parse_args(args, namespace)
        except argparse.ArgumentError:
            # On newer Python versions parse_args itself raises for unknown
            # arguments after parse_known_args has returned.
            _raise_without_context(argparse.ArgumentError(None, PARSER_ERROR_MESSAGE))

    def parse_known_args(self, args: Sequence[str] | None = None,
                         namespace: argparse.Namespace | None = None) -> tuple[argparse.Namespace, list[str]]:
        try:
            return super().parse_known_args(args, namespace)
        except argparse.ArgumentError:
            # exit_on_error=False must preserve the exception type, but neither
            # its text nor its repr may retain argparse's raw argument value.
            _raise_without_context(argparse.ArgumentError(None, PARSER_ERROR_MESSAGE))

    if hasattr(argparse.ArgumentParser, "parse_intermixed_args"):
        def parse_intermixed_args(self, args: Sequence[str] | None = None,
                                  namespace: argparse.Namespace | None = None) -> argparse.Namespace:
            try:
                return super().parse_intermixed_args(args, namespace)
            except argparse.ArgumentError:
                _raise_without_context(argparse.ArgumentError(None, PARSER_ERROR_MESSAGE))

    if hasattr(argparse.ArgumentParser, "_parse_known_args2"):
        # Python 3.14's intermixed parsers bypass parse_known_args.
        def _parse_known_args2(self, *args: Any, **kwargs: Any) -> tuple[argparse.Namespace, list[str]]:
            try:
                return super()._parse_known_args2(*args, **kwargs)
            except argparse.ArgumentError:
                _raise_without_context(argparse.ArgumentError(None, PARSER_ERROR_MESSAGE))

    def _print_public_message(self, message: str, file: Any) -> None:
        super()._print_message(message, file)

    def print_usage(self, file: Any = None) -> None:
        self._print_public_message(self.format_usage(), file or sys.stdout)

    def print_help(self, file: Any = None) -> None:
        self._print_public_message(self.format_help(), file or sys.stdout)

    def _print_message(self, message: str | None, file: Any = None) -> None:
        # Help, version and usage go through the explicit public methods above.
        # Any other message may contain argv, even when argparse built it.
        if message:
            destination = file or sys.stderr
            self._print_public_message(self.format_usage(), destination)
            self._print_public_message(PARSER_ERROR_MESSAGE + "\n", destination)

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if type(status) is int and status == 0 and not message:
            raise SystemExit(0)
        # A status can itself be a string; propagating it as SystemExit.code
        # would print the untrusted value when the exception is uncaught.
        self._print_message(PARSER_ERROR_MESSAGE, sys.stderr)
        _raise_without_context(SystemExit(2))

    def error(self, message: str) -> None:
        self.exit(2)

    def error_prevalidated(self, message: str) -> NoReturn:
        """Print an already value-free validation message, never raw argv or paths."""
        self.print_usage(sys.stderr)
        self._print_public_message(f"error: {message}\n", sys.stderr)
        _raise_without_context(SystemExit(2))


def build_argument_parser(*args: Any, **kwargs: Any) -> DiagnosticRedactingArgumentParser:
    """Construct every public parser and subparser with the same privacy policy."""
    if kwargs.setdefault("allow_abbrev", False) is not False:
        raise ValueError("argument abbreviation is not supported")
    return DiagnosticRedactingArgumentParser(*args, **kwargs)

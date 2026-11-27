"""Hold dependency logger families at a floor level while sign-in or token exchange runs.

A dependency can log codes, tokens or raw token endpoint bodies; a host with a DEBUG root logger (an embedding
application, the MCP server, a user) would write them out. The hold changes logger levels, which are process-wide: while
any hold of a family is open, every message below the floor from that family is dropped, whichever thread logs it.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager


class LoggerHold:
    """Raise a family of loggers (each name and every existing child with a level of its own) to ``level`` or higher.

    Each logger's own level and ``propagate`` setting are put back when the last overlapping hold ends, on an exception
    too. A logger already at or above ``level`` is left as it is. A NOTSET (0) logger would inherit, so it is pinned too.
    """

    def __init__(self, names: tuple[str, ...], level: int) -> None:
        self.names = names
        self.level = level
        self._lock = threading.Lock()
        self._depth = 0
        self._saved: list[tuple[logging.Logger, int, bool]] = []

    def loggers(self) -> list[logging.Logger]:
        names = set(self.names)
        prefixes = tuple(f"{name}." for name in self.names)
        existing = list(logging.Logger.manager.loggerDict.items())
        names.update(name for name, item in existing if isinstance(item, logging.Logger) and name.startswith(prefixes))
        return [logging.getLogger(name) for name in sorted(names)]

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self._lock:
            if self._depth == 0:
                for logger in self.loggers():
                    self._saved.append((logger, logger.level, logger.propagate))
                    if logger.level < self.level:
                        logger.setLevel(self.level)
            self._depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._depth -= 1
                if self._depth == 0:
                    for logger, level, propagate in reversed(self._saved):
                        logger.setLevel(level)
                        logger.propagate = propagate
                    self._saved.clear()

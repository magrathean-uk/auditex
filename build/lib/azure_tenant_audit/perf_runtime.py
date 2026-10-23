from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass
class EndpointAccumulator:
    """Bounded-memory collector helper for paged Graph responses.

    It keeps a small representative sample while allowing full rows to be written to
    chunk files. Coverage can then record item counts, page counts, chunk counts, and
    truncation without retaining every tenant row in memory.
    """

    sample_limit: int = 20
    item_count: int = 0
    page_count: int = 0
    chunk_files: list[str] = field(default_factory=list)
    sample: list[dict[str, Any]] = field(default_factory=list)

    def add_page(self, rows: Iterable[Mapping[str, Any]], *, chunk_file: str | None = None) -> list[dict[str, Any]]:
        page_rows = [dict(row) for row in rows if isinstance(row, Mapping)]
        self.page_count += 1
        self.item_count += len(page_rows)
        if chunk_file:
            self.chunk_files.append(str(chunk_file))
        if len(self.sample) < self.sample_limit:
            self.sample.extend(page_rows[: self.sample_limit - len(self.sample)])
        return page_rows

    @property
    def chunk_count(self) -> int:
        return len(self.chunk_files)

    @property
    def sample_truncated(self) -> bool:
        return self.item_count > len(self.sample)

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "value": self.sample,
            "item_count": self.item_count,
            "page_count": self.page_count,
            "sample_truncated": self.sample_truncated,
        }
        if self.chunk_files:
            result["chunk_files"] = list(self.chunk_files)
            result["chunk_count"] = self.chunk_count
        return result

    def coverage_fields(self) -> dict[str, Any]:
        return {
            "item_count": self.item_count,
            "page_count": self.page_count,
            "sample_count": len(self.sample),
            "sample_truncated": self.sample_truncated,
            "chunk_count": self.chunk_count,
        }


@dataclass(frozen=True)
class PageWindow:
    requested_limit: int
    remaining: int

    @classmethod
    def from_limit(cls, limit: int | None) -> "PageWindow":
        if limit is None:
            return cls(requested_limit=-1, remaining=-1)
        normalized = max(int(limit), 0)
        return cls(requested_limit=normalized, remaining=normalized)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def take(self, rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], "PageWindow"]:
        if self.remaining < 0:
            return rows, self
        selected = rows[: self.remaining]
        return selected, PageWindow(self.requested_limit, max(self.remaining - len(selected), 0))


def sqlite_bulk_pragmas() -> tuple[str, ...]:
    """Pragmas appropriate while rebuilding the local evidence index."""

    return (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA temp_store=MEMORY",
    )


def json_size_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def write_metric_snapshot(path: str | Path, metrics: Mapping[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(metrics), indent=2, default=str), encoding="utf-8")
    return target

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TypedDict

from .collectors.base import CollectorResult

AuditLogger = Callable[[str, str, dict[str, Any] | None], None]
ChunkWriter = Callable[[str, str, int, list[dict[str, Any]], dict[str, Any] | None], str | None]
ExportRecordsWriter = Callable[[str, str, int, list[dict[str, Any]], dict[str, Any] | None], str | None]
ExportSummaryWriter = Callable[[str, str, dict[str, Any]], str | None]
ExportCheckpointWriter = Callable[..., Any]


class CoverageRow(TypedDict, total=False):
    collector: str
    type: str
    name: str
    endpoint: str
    status: str
    item_count: int
    duration_ms: float
    error_class: str | None
    error: str | None


class ResultRow(TypedDict, total=False):
    name: str
    status: str
    item_count: int
    message: str
    error: str | None
    coverage_rows: int
    error_class: str | None


class CollectorLike(Protocol):
    name: str

    def run(self, context: dict[str, Any]) -> CollectorResult: ...


class CollectorRunWriter(Protocol):
    def log_event(self, event: str, message: str, details: dict[str, Any] | None = None) -> None: ...

    def write_raw(self, name: str, payload: dict[str, Any]) -> Any: ...

    def write_index_records(self, records: list[dict[str, Any]]) -> Any: ...

    def write_checkpoint(self, collector_name: str, payload: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class CollectorRunHooks:
    write_export_checkpoint: ExportCheckpointWriter | None = None
    write_export_records: ExportRecordsWriter | None = None
    write_export_summary: ExportSummaryWriter | None = None
    chunk_writer: ChunkWriter | None = None
    audit_logger: AuditLogger | None = None
    run_dir: str | Path | None = None


@dataclass(frozen=True)
class CollectorRunContext:
    client: Any
    top: int | None
    page_size: int | None = None
    plane: str = "inventory"
    since: str | None = None
    until: str | None = None
    collector_checkpoint_state: Mapping[str, Any] = field(default_factory=dict)
    operation_checkpoint_state: Mapping[str, Any] = field(default_factory=dict)
    hooks: CollectorRunHooks = field(default_factory=CollectorRunHooks)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_legacy_dict(self) -> dict[str, Any]:
        context = {
            "client": self.client,
            "top": self.top,
            "page_size": self.page_size,
            "plane": self.plane,
            "since": self.since,
            "until": self.until,
            "collector_checkpoint_state": dict(self.collector_checkpoint_state),
            "operation_checkpoint_state": dict(self.operation_checkpoint_state),
            "write_export_checkpoint": self.hooks.write_export_checkpoint,
            "write_export_records": self.hooks.write_export_records,
            "write_export_summary": self.hooks.write_export_summary,
            "chunk_writer": self.hooks.chunk_writer,
            "audit_logger": self.hooks.audit_logger,
            "run_dir": self.hooks.run_dir,
        }
        context.update(self.extra)
        return context


@dataclass(frozen=True)
class CollectorRunOptions:
    write_raw: bool = True
    write_coverage: bool = True
    write_checkpoint: bool = True


@dataclass(frozen=True)
class CollectorRunOutput:
    result: CollectorResult
    result_row: ResultRow
    coverage_rows: list[dict[str, Any]]
    crashed: bool = False


class AuditWriterCollectorAdapter:
    def __init__(self, writer: Any) -> None:
        self.writer = writer

    def log_event(self, event: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.writer.log_event(event, message, details)

    def write_raw(self, name: str, payload: dict[str, Any]) -> Any:
        return self.writer.write_raw(name, payload)

    def write_index_records(self, records: list[dict[str, Any]]) -> Any:
        return self.writer.write_index_records(records)

    def write_checkpoint(self, collector_name: str, payload: dict[str, Any]) -> Any:
        return self.writer.write_checkpoint(collector_name, payload)

    def hooks(self) -> CollectorRunHooks:
        return CollectorRunHooks(
            write_export_checkpoint=getattr(self.writer, "write_export_checkpoint", None),
            write_export_records=self._write_export_records if hasattr(self.writer, "write_export_records") else None,
            write_export_summary=self._write_export_summary if hasattr(self.writer, "write_export_summary") else None,
            chunk_writer=self._write_chunk_records if hasattr(self.writer, "write_chunk_records") else None,
            audit_logger=self.log_event,
            run_dir=getattr(self.writer, "run_dir", None),
        )

    def _relative(self, path: Any) -> str:
        run_dir = getattr(self.writer, "run_dir", None)
        if run_dir is not None and hasattr(path, "relative_to"):
            return str(path.relative_to(run_dir))
        return str(path)

    def _write_export_records(
        self,
        collector: str,
        operation: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return self._relative(self.writer.write_export_records(collector, operation, page_number, records, metadata))

    def _write_export_summary(self, collector: str, operation: str, payload: dict[str, Any]) -> str:
        return self._relative(self.writer.write_export_summary(collector, operation, payload))

    def _write_chunk_records(
        self,
        collector: str,
        endpoint: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return self._relative(self.writer.write_chunk_records(collector, endpoint, page_number, records, metadata))


class CollectorRunner:
    def __init__(self, writer: CollectorRunWriter | None = None) -> None:
        self.writer = writer

    def run(
        self,
        collector: CollectorLike,
        context: CollectorRunContext | Mapping[str, Any],
        *,
        name: str | None = None,
        options: CollectorRunOptions | None = None,
    ) -> CollectorRunOutput:
        options = options or CollectorRunOptions()
        collector_name = name or getattr(collector, "name", collector.__class__.__name__)
        legacy_context = self._legacy_context(context)
        self._log(legacy_context, "collector.started", "Collector started", {"collector": collector_name})

        try:
            result = collector.run(legacy_context)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            self._log(
                legacy_context,
                "collector.failed",
                "Collector crashed",
                {"collector": collector_name, "error": error},
            )
            row: ResultRow = {
                "name": collector_name,
                "status": "failed",
                "item_count": 0,
                "message": "collector crashed",
                "error": error,
                "coverage_rows": 0,
            }
            if options.write_checkpoint:
                self._write_checkpoint(collector_name, row)
            return CollectorRunOutput(
                result=CollectorResult(
                    name=collector_name,
                    status="failed",
                    payload={},
                    item_count=0,
                    message="collector crashed",
                    error=error,
                    coverage=[],
                ),
                result_row=row,
                coverage_rows=[],
                crashed=True,
            )

        coverage_rows = list(result.coverage or [])
        if options.write_coverage and coverage_rows:
            self._write_coverage(coverage_rows)
        if options.write_raw:
            self._write_raw(collector_name, result.payload)

        row = self._result_row(result, coverage_rows)
        self._log(
            legacy_context,
            "collector.finished",
            "Collector finished",
            {
                "collector": collector_name,
                "status": result.status,
                "item_count": result.item_count,
                "coverage_rows": len(coverage_rows),
                "error": result.error,
            },
        )
        if options.write_checkpoint:
            self._write_checkpoint(collector_name, row)
        return CollectorRunOutput(result=result, result_row=row, coverage_rows=coverage_rows)

    @staticmethod
    def _legacy_context(context: CollectorRunContext | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(context, CollectorRunContext):
            return context.to_legacy_dict()
        return dict(context)

    @staticmethod
    def _result_row(result: CollectorResult, coverage_rows: list[dict[str, Any]]) -> ResultRow:
        row: ResultRow = {
            "name": result.name,
            "status": result.status,
            "item_count": result.item_count,
            "message": result.message or ("ok" if result.status == "ok" else "partial"),
            "error": result.error,
            "coverage_rows": len(coverage_rows),
        }
        return row

    def _log(
        self,
        context: Mapping[str, Any],
        event: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        if self.writer is not None and hasattr(self.writer, "log_event"):
            self.writer.log_event(event, message, details)
            return
        audit_logger = context.get("audit_logger")
        if audit_logger:
            audit_logger(event, message, details)

    def _write_raw(self, name: str, payload: dict[str, Any]) -> None:
        if self.writer is not None and hasattr(self.writer, "write_raw"):
            self.writer.write_raw(name, payload)

    def _write_coverage(self, coverage_rows: list[dict[str, Any]]) -> None:
        if self.writer is not None and hasattr(self.writer, "write_index_records"):
            self.writer.write_index_records(coverage_rows)

    def _write_checkpoint(self, collector_name: str, row: ResultRow) -> None:
        if self.writer is not None and hasattr(self.writer, "write_checkpoint"):
            self.writer.write_checkpoint(collector_name, dict(row))

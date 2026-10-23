from __future__ import annotations

from typing import Any, Callable, Optional
from math import ceil

from ..adapters import get_adapter
from .base import Collector, CollectorResult


class PurviewCollector(Collector):
    name = "purview"
    description = "Purview retention policy, DLP, and audit posture/export inventory via adapter-backed collectors."
    required_permissions = [
        "AuditLog.Read.All",
    ]
    # Every command here passes the shared read allowlist (adapters/read_guard.py): the m365 command
    # must end in list, get or status. Removed because they were guesses at CLI spellings, not reads
    # the CLI documents: "m365 purview audit-log search", "m365 purview auditlog search" (a search
    # submits an audit-log query job on the tenant), "m365 purview auditlog export create" (creates
    # an export; it was only ever probed with --help) and the bare "m365 purview" group probe.
    command_collectors = [
        {
            "name": "purviewReadiness",
            "category": "readiness",
            "commands": [
                "m365 purview auditlog list --output json --help",
            ],
            "optional": True,
        },
        {
            "name": "retentionLabels",
            "category": "policy",
            "commands": [
                "m365 purview retentionlabel list --output json",
                "m365 purview retention label list --output json",
            ],
        },
        {
            "name": "retentionPolicies",
            "category": "policy",
            "commands": [
                "m365 purview retentionpolicy list --output json",
                "m365 purview retention policy list --output json",
            ],
        },
        {
            "name": "dlpPolicies",
            "category": "policy",
            "commands": [
                "m365 purview dlp policy list --output json",
                "m365 purview dlppolicy list --output json",
            ],
        },
        {
            "name": "auditLogJobs",
            "category": "export",
            "commands": [
                "m365 purview auditlog list --output json",
            ],
            "plane": "export",
        },
        {
            "name": "auditLogExports",
            "category": "export",
            "commands": [
                "m365 purview auditlog list --output json --top 100",
            ],
            "plane": "export",
        },
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get(
            "audit_logger"
        )
        plane = str(context.get("plane", "inventory")).lower()
        include_export = plane in {"full", "export"}
        operation_checkpoint_state = context.get("operation_checkpoint_state") or {}
        write_export_checkpoint = context.get("write_export_checkpoint")
        write_export_records = context.get("write_export_records")
        write_export_summary = context.get("write_export_summary")
        payload: dict[str, Any] = {}
        total = 0
        coverage: list[dict[str, Any]] = []

        for command in self.command_collectors:
            command_plane = str(command.get("plane", "inventory"))
            if command_plane == "export" and not include_export:
                continue
            command_variants = command.get("commands")
            if not isinstance(command_variants, list):
                command_variants = [str(command.get("command", ""))]

            operation_name = str(command["name"])
            if command_plane == "export" and operation_checkpoint_state.get(operation_name, {}).get("status") == "ok":
                response = {
                    "operation": operation_name,
                    "source": "checkpoint",
                    "status": "ok",
                    "item_count": operation_checkpoint_state.get(operation_name, {}).get("item_count", 0),
                    "message": "Export operation skipped due to checkpoint resume.",
                    "checkpoint_state": operation_checkpoint_state.get(operation_name, {}),
                    "value": [],
                }
            else:
                response = self._run_command_variants(command_variants, operation_name, log_event)
                if command_plane == "export" and response.get("error") is None:
                    values = response.get("value")
                    if not isinstance(values, list):
                        values = []
                    response["operation"] = operation_name
                    response["checkpoint_resumed"] = False
                    chunk_size = int(context.get("page_size") or 100) if int(context.get("page_size") or 100) > 0 else 100
                    item_count = len(values)
                    total_chunks = max(1, ceil(item_count / chunk_size)) if item_count else 1
                    for page_number in range(total_chunks):
                        start = page_number * chunk_size
                        end = start + chunk_size
                        page_records = values[start:end]
                        if write_export_records:
                            path = write_export_records("purview", operation_name, page_number + 1, page_records, {
                                "operation": operation_name,
                                "command": response.get("command"),
                                "page_number": page_number + 1,
                                "source": "purview",
                                "chunk_count": total_chunks,
                            })
                            response.setdefault("chunk_files", []).append(path)
                    if write_export_summary:
                        write_export_summary(
                            "purview",
                            operation_name,
                            {
                                "operation": operation_name,
                                "status": "ok",
                                "item_count": item_count,
                                "command": response.get("command"),
                                "command_variants": command_variants,
                            },
                        )
                    if write_export_checkpoint:
                        write_export_checkpoint(
                            "purview",
                            operation_name,
                            status="ok",
                            item_count=item_count,
                            message="Export operation completed",
                            extra={"summary_path": f"raw/purview/{operation_name}/summary.json"},
                        )
            payload_name = str(command["name"])
            payload[payload_name] = response
            optional_failure = False
            if command_plane == "inventory" and response.get("error") and bool(command.get("optional")):
                response["error_class"] = "command_optional_failure"
                optional_failure = True
            item_count = self._item_count(response)
            total += item_count
            status = "failed" if response.get("error") else "ok"
            error_class = response.get("error_class") or ("command_error" if response.get("error") else None)
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "category": command.get("category", "policy"),
                    "name": payload_name,
                    "source": response.get("source", "command"),
                    "command": response.get("command", ""),
                    "command_variants": response.get("command_variants"),
                    "status": status,
                    "item_count": item_count,
                    "duration_ms": response.get("duration_ms", 0.0),
                    "error_class": error_class,
                    "error": response.get("error"),
                    "plane": plane,
                }
            )

            if optional_failure:
                # Optional readiness checks should not hard-fail inventory collection.
                coverage[-1]["error_class"] = "command_optional_failure"

        partial = any(
            entry.get("status") not in {"ok", "skipped"}
            and entry.get("error_class") != "command_optional_failure"
            for entry in coverage
        )
        status = "partial" if partial else "ok"

        return CollectorResult(
            name=self.name,
            status=status,
            payload=payload,
            item_count=total,
            message="Purview collector partially completed" if partial else "",
            coverage=coverage,
        )

    @staticmethod
    def _item_count(response: dict[str, Any]) -> int:
        value = response.get("value")
        return len(value) if isinstance(value, list) else 0

    def _run_command_variants(
        self,
        commands: list[str],
        operation: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        last_response: dict[str, Any] = {}
        for command in commands:
            response = self._run_command(command, log_event)
            response["command_variants"] = commands
            response["operation"] = operation
            response.setdefault("source", "command")
            if response.get("error") is None:
                return response
            if operation == "purviewReadiness" and response.get("error_class") == "command_not_simulated":
                response["error"] = "command_output_parse_error"
                response["error_class"] = "command_output_parse_error"
            if not self._should_fallback(response):
                return response
            last_response = response
        if not last_response:
            return {
                "error": "command_all_variants_failed",
                "error_class": "command_error",
                "operation": operation,
                "command_variants": commands,
                "source": "command",
            }
        return last_response

    def _run_command(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        adapter = get_adapter("m365_cli")
        response = adapter.run(command, log_event=log_event)
        response.setdefault("command", command)
        return response

    @staticmethod
    def _should_fallback(response: dict[str, Any]) -> bool:
        if response.get("error") is None:
            return False
        return response.get("error_class") in {
            "command_not_found",
            "command_not_authenticated",
            "command_output_empty",
            "command_parse_error",
            "command_not_simulated",
        }

from __future__ import annotations

from typing import Any, Callable, Optional

from ..adapters import get_adapter
from .base import Collector, CollectorResult, run_graph_endpoints


class EDiscoveryCollector(Collector):
    name = "ediscovery"
    description = "eDiscovery case/search/operation inventory and export metadata."
    required_permissions = [
        "eDiscovery.Read.All",
        "SecurityIncident.Read.All",
    ]
    command_collectors = [
        {
            "name": "caseOverview",
            "category": "inventory",
            "commands": [
                "m365 purview ediscovery case list --output json",
            ],
        },
        {
            "name": "searchList",
            "category": "inventory",
            "commands": [
                "m365 purview ediscovery search list --output json",
                "m365 purview ediscovery case search list --output json",
            ],
        },
        {
            "name": "exportJobs",
            "category": "export",
            "commands": [
                "m365 purview ediscoveryexport list --output json",
                "m365 purview ediscovery export list --output json",
            ],
            "plane": "export",
        },
        {
            "name": "reviewSets",
            "category": "export",
            "commands": [
                "m365 purview reviewset list --output json",
                "m365 purview ediscovery reviewset list --output json",
            ],
            "plane": "export",
        },
        {
            "name": "holdList",
            "category": "inventory",
            "commands": [
                "m365 purview hold list --output json",
                "m365 purview legal hold list --output json",
            ],
        },
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        graph_client = context["client"]
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get(
            "audit_logger"
        )
        top = context.get("top", 500)
        page_size = context.get("page_size")
        plane = str(context.get("plane", "inventory")).lower()
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0
        operation_checkpoint_state = context.get("operation_checkpoint_state") or {}
        write_export_checkpoint = context.get("write_export_checkpoint")
        write_export_records = context.get("write_export_records")
        write_export_summary = context.get("write_export_summary")

        base_queries = {
            "cases": {"endpoint": "/security/cases/ediscoveryCases", "params": {}},
        }
        base_payload, base_coverage = run_graph_endpoints(
            self.name,
            graph_client,
            base_queries,
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=log_event,
        )
        coverage.extend(base_coverage)
        payload.update(base_payload)
        total += sum(row.get("item_count", 0) for row in base_coverage if row.get("type") == "graph")

        cases = (base_payload.get("cases", {}) or {}).get("value", []) or []
        if isinstance(cases, list):
            for case in cases:
                case_id = case.get("id")
                if not isinstance(case_id, str):
                    continue

                case_payload, case_coverage = run_graph_endpoints(
                    self.name,
                    graph_client,
                    {
                        "searches": {
                            "endpoint": f"/security/cases/ediscoveryCases/{case_id}/searches",
                            "params": {},
                        },
                        "operations": {
                            "endpoint": f"/security/cases/ediscoveryCases/{case_id}/operations",
                            "params": {},
                            "query_page_minimum": None,
                        },
                    },
                    top=max(1, top // 2),
                    page_size=page_size,
                    chunk_writer=context.get("chunk_writer"),
                    log_event=log_event,
                )
                section = f"case_{case_id}"
                payload[section] = {
                    "searches": case_payload.get("searches", {}),
                    "operations": case_payload.get("operations", {}),
                }
                coverage.extend(case_coverage)
                total += sum(row.get("item_count", 0) for row in case_coverage if row.get("type") == "graph")

        for command in self.command_collectors:
            command_plane = str(command.get("plane", "inventory"))
            include_export = plane in {"full", "export"}
            if command_plane == "export" and not include_export:
                continue
            operation_name = str(command["name"])

            if command_plane == "export" and operation_checkpoint_state.get(operation_name, {}).get("status") == "ok":
                response = {
                    "operation": operation_name,
                    "source": "checkpoint",
                    "status": "ok",
                    "item_count": operation_checkpoint_state.get(operation_name, {}).get("item_count", 0),
                    "message": "Export operation skipped due to checkpoint resume.",
                    "checkpoint_state": operation_checkpoint_state.get(operation_name, {}),
                }
                payload[operation_name] = response
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "command",
                        "category": command.get("category", "export"),
                        "name": operation_name,
                        "source": "checkpoint",
                        "command": operation_checkpoint_state.get(operation_name, {}).get("command"),
                        "status": "ok",
                        "item_count": response.get("item_count", 0),
                        "duration_ms": 0.0,
                        "error_class": None,
                        "error": None,
                        "plane": plane,
                        "checkpoint_resume": True,
                    }
                )
                total += response.get("item_count", 0)
                continue

            if command_plane == "export":
                response = self._run_command_variants(list(command["commands"]), command["name"], log_event)
                payload[operation_name] = response
                count = self._item_count(response)
                total += count
                if response.get("error") is None and write_export_records:
                    chunk_size = int(page_size or 100) if int(page_size or 100) > 0 else 100
                    total_chunks = max(1, (count + chunk_size - 1) // chunk_size) if count else 1
                    values = response.get("value")
                    if not isinstance(values, list):
                        values = []
                    for page_number in range(total_chunks):
                        start = page_number * chunk_size
                        end = start + chunk_size
                        page_records = values[start:end]
                        path = write_export_records(
                            "ediscovery",
                            operation_name,
                            page_number + 1,
                            page_records,
                            {
                                "operation": operation_name,
                                "command": response.get("command"),
                                "page_number": page_number + 1,
                                "source": "ediscovery",
                            },
                        ) if write_export_records else None
                        response.setdefault("chunk_files", []).append(path)
                    if write_export_summary:
                        write_export_summary(
                            "ediscovery",
                            operation_name,
                            {
                                "operation": operation_name,
                                "status": "ok",
                                "item_count": count,
                                "command": response.get("command"),
                                "command_variants": command.get("commands"),
                            },
                        )
                    if write_export_checkpoint:
                        write_export_checkpoint(
                            "ediscovery",
                            operation_name,
                            status="ok",
                            item_count=count,
                            message="Export operation completed",
                            extra={"summary_path": f"raw/ediscovery/{operation_name}/summary.json"},
                        )
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "command",
                        "category": command.get("category", "export"),
                        "name": operation_name,
                        "source": response.get("source", "command"),
                        "command": response.get("command"),
                        "status": "failed" if response.get("error") else "ok",
                        "item_count": count,
                        "duration_ms": response.get("duration_ms", 0.0),
                        "error_class": response.get("error_class"),
                        "error": response.get("error"),
                        "plane": plane,
                    }
                )
                continue

            response = self._run_command_variants(list(command["commands"]), command["name"], log_event)
            payload[command["name"]] = response
            count = self._item_count(response)
            total += count
            status = "failed" if response.get("error") else "ok"
            error_class = response.get("error_class") or ("command_error" if response.get("error") else None)
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "category": command.get("category", "inventory"),
                    "name": command["name"],
                    "source": response.get("source", "command"),
                    "command": response.get("command"),
                    "status": status,
                    "item_count": count,
                    "duration_ms": response.get("duration_ms", 0.0),
                    "error_class": error_class,
                    "error": response.get("error"),
                    "plane": plane,
                }
            )

        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="eDiscovery collector partially completed" if partial else "",
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

    def _run_command(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        adapter = get_adapter("m365_cli")
        response = adapter.run(command, log_event=log_event)
        response.setdefault("command", command)
        return response

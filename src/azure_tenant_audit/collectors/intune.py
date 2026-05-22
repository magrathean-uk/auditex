from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class IntuneCollector(Collector):
    name = "intune"
    description = "Endpoint management, policies, compliance and devices."
    required_permissions = [
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        page_size = context.get("page_size")
        endpoints = {
            "managedDevices": {
                "endpoint": "/deviceManagement/managedDevices",
                "params": {
                    "$select": "id,deviceName,manufacturer,model,osVersion,operatingSystem,complianceState,azureADDeviceId,lastSyncDateTime",
                },
            },
            "deviceCompliancePolicies": {
                "endpoint": "/deviceManagement/deviceCompliancePolicies",
                "params": {},
            },
            "deviceConfigurationProfiles": {
                "endpoint": "/deviceManagement/deviceConfigurations",
                "params": {},
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            endpoints,
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune collector partially completed" if partial else "",
            coverage=coverage,
        )

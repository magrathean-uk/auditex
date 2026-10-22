from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from ..os_lifecycle import FAMILY_WINDOWS, os_family
from ._endpoint_reads import assignment_fanout, collector_partial, protection_state_fanout, scoped_gap_message
from .base import Collector, CollectorResult, run_graph_endpoints

# ``managedDeviceOwnerType`` is the v1.0 name of the ownership field (``ownerType`` exists only on beta);
# ``isEncrypted`` and ``jailBroken`` feed the encryption and jailbreak rules, ``lastSyncDateTime`` the
# stale-sync rule, ``osVersion`` and ``operatingSystem`` the end-of-life rule.
MANAGED_DEVICE_SELECT = (
    "id,deviceName,manufacturer,model,osVersion,operatingSystem,complianceState,azureADDeviceId,lastSyncDateTime,"
    "isEncrypted,jailBroken,managedDeviceOwnerType,enrolledDateTime,deviceEnrollmentType"
)


class IntuneCollector(Collector):
    name = "intune"
    description = "Endpoint management, policies, compliance, device posture and Defender antivirus state."
    required_permissions = [
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        endpoints = {
            "managedDevices": {
                "endpoint": "/deviceManagement/managedDevices",
                "params": {"$select": MANAGED_DEVICE_SELECT},
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
        run_dir = context.get("run_dir")

        # Which compliance policies exist is not enough: a policy assigned to nobody enforces nothing.
        section, rows = assignment_fanout(
            collector=self.name,
            client=client,
            name="deviceCompliancePolicyAssignments",
            source=payload.get("deviceCompliancePolicies"),
            run_dir=run_dir,
            endpoint_for=lambda policy_id: f"/deviceManagement/deviceCompliancePolicies/{policy_id}/assignments",
            endpoint_template="/deviceManagement/deviceCompliancePolicies/{id}/assignments",
            scope="compliance_policies",
        )
        payload["deviceCompliancePolicyAssignments"] = section
        coverage.extend(rows)

        # Defender antivirus state is a per-device GET: the Intune reports API that returns it for every
        # device at once (DefenderAgents) is an export job started with POST, which the audit plane refuses.
        section, rows = protection_state_fanout(
            collector=self.name,
            client=client,
            name="windowsProtectionStates",
            source=payload.get("managedDevices"),
            run_dir=run_dir,
            endpoint_template="/deviceManagement/managedDevices/{id}/windowsProtectionState",
            windows_only=lambda device: os_family(device.get("operatingSystem")) == FAMILY_WINDOWS,
        )
        payload["windowsProtectionStates"] = section
        coverage.extend(rows)

        total = sum(item.get("item_count", 0) for item in coverage)
        # The compliance assignments and the Defender state are per-object reads whose gaps stay in their own
        # sections (the rules that read them say so); only a failed or cut base list makes the collector partial.
        partial = collector_partial(coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune collector partially completed" if partial else scoped_gap_message("Intune collector", coverage),
            coverage=coverage,
        )

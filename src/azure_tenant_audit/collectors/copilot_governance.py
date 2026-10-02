"""Capability-gated collector for Microsoft 365 Copilot governance posture."""
from __future__ import annotations

from typing import Any

from ._capability_gated import build_collector_result, run_capability_gated_endpoints
from .base import Collector

# Aggregate counts only: the per-user detail report and interaction APIs are not collected.
USER_COUNT_SUMMARY_ENDPOINT = "/copilot/reports/getMicrosoft365CopilotUserCountSummary(period='D30')"
LIMITED_MODE_ENDPOINT = "/copilot/admin/settings/limitedMode"


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _user_count_summary_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for row in rows:
        period = row.get("Report Period")
        summary.append(
            {
                "id": f"D{period}" if period else "summary",
                "reportPeriod": f"D{period}" if period else None,
                "reportRefreshDate": row.get("Report Refresh Date"),
                "assignedUsers": _int_or_none(row.get("Any App Enabled Users")),
                "activeUsers": _int_or_none(row.get("Any App Active Users")),
                "copilotChatEnabledUsers": _int_or_none(row.get("Copilot Chat Enabled Users")),
                "copilotChatActiveUsers": _int_or_none(row.get("Copilot Chat Active Users")),
            }
        )
    return summary


class CopilotGovernanceCollector(Collector):
    name = "copilot_governance"
    description = (
        "Microsoft 365 Copilot governance posture: limited-mode setting and aggregate usage counts. "
        "Capability-gated; requires a Copilot license and Reports.Read.All for usage reports. "
        "Limited mode is readable with delegated access only."
    )
    required_permissions = [
        "Reports.Read.All",
        "CopilotSettings-LimitedMode.Read",
    ]

    def run(self, context: dict[str, Any]) -> Any:
        payload, coverage = run_capability_gated_endpoints(
            self.name,
            context.get("client"),
            [
                ("copilotAdminSettings", LIMITED_MODE_ENDPOINT),
                ("copilotUsageReports", USER_COUNT_SUMMARY_ENDPOINT),
            ],
            log_event=context.get("audit_logger"),
            skip_reason="no Graph client; Copilot likely unlicensed",
            csv_rows={"copilotUsageReports": _user_count_summary_rows},
        )
        return build_collector_result(
            self,
            payload,
            coverage,
            partial_message="Copilot governance collection partial; check capability matrix",
        )

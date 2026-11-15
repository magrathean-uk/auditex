from __future__ import annotations

from typing import Any

from .base import Collector, CollectorResult

# Why every operation of this collector is skipped: the CLI for Microsoft 365 is no longer used for live collection
# (DEC-108 D2). Exchange Online is read by exchange_policy with the reader app's certificate.
REASON_M365_CLI_NOT_USED = "m365_cli_not_used"
M365_CLI_NOT_USED_TEXT = (
    "Not collected: the CLI for Microsoft 365 is no longer used; exchange_policy reads Exchange Online "
    "with the reader app's certificate."
)


class ExchangeCollector(Collector):
    """The retired CLI for Microsoft 365 Exchange collector.

    Kept by name so an explicit selection and old bundles still resolve; it reads nothing and records each of its
    former operations as a named skip, so the run is not partial because of it.
    """

    name = "exchange"
    description = "Retired Exchange readiness checks of the CLI for Microsoft 365; exchange_policy reads Exchange."
    required_permissions: list[str] = []
    operations: tuple[tuple[str, str, bool], ...] = (
        ("exchangeConnectivityCheck", "readiness", False),
        ("exchangeTenantInfo", "posture", False),
        ("mailboxCount", "posture", False),
        ("mailboxQuotaStatus", "posture", False),
        ("mailboxStorage", "posture", False),
        ("mailActivityCounts", "posture", False),
        ("roomLists", "posture", True),
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:  # noqa: ARG002 - nothing is read
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        for name, category, optional in self.operations:
            payload[name] = {
                "value": [],
                "status": "skipped",
                "reason": REASON_M365_CLI_NOT_USED,
                "operation": name,
                "category": category,
            }
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "category": category,
                    "optional": optional,
                    "name": name,
                    "source": "command",
                    "status": "skipped",
                    "reason": REASON_M365_CLI_NOT_USED,
                    "item_count": 0,
                    "duration_ms": 0.0,
                    "error_class": None,
                    "error": None,
                }
            )
        return CollectorResult(
            name=self.name,
            status="ok",
            payload=payload,
            item_count=0,
            message=M365_CLI_NOT_USED_TEXT,
            coverage=coverage,
        )

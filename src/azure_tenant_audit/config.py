from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .selection import select_collectors

MIXED_CREDENTIALS_MESSAGE = (
    "Certificate authentication runs in app mode with a client ID and no other credential: "
    "remove the client secret, access token, Azure CLI token or interactive sign-in."
)


@dataclass
class AuthConfig:
    tenant_id: str
    client_id: str | None
    auth_mode: str = "app"
    client_secret: str | None = field(default=None, repr=False)
    access_token: str | None = field(default=None, repr=False)
    authority: str = "https://login.microsoftonline.com/"
    graph_scope: str = "https://graph.microsoft.com/.default"
    interactive_scopes: list[str] | None = None
    timeout_seconds: int = 60
    throttle_mode: str = "safe"
    # A loaded azure_tenant_audit.certificate_auth.CertificateCredential; app mode only, never with a secret.
    certificate: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.certificate is not None:
            check_single_credential(self)


def check_single_credential(auth: AuthConfig) -> None:
    """Refuse a certificate mixed with any other credential, before any request is made."""
    if auth.certificate is None:
        return
    if (
        auth.auth_mode != "app"
        or auth.client_secret
        or auth.access_token
        or not isinstance(auth.client_id, str)
        or not auth.client_id.strip()
    ):
        raise ValueError(MIXED_CREDENTIALS_MESSAGE)


@dataclass
class RunConfig:
    tenant_name: str
    output_dir: Path
    collectors: list[str] | None = None
    excluded_collectors: list[str] | None = None
    include_exchange: bool = False
    offline: bool = False
    sample_path: Path | None = None
    run_name: str | None = None
    top_items: int | None = None
    page_size: int = 100
    auditor_profile: str = "auto"
    default_collectors: tuple[str, ...] = ()
    plane: str = "inventory"
    since: str | None = None
    until: str | None = None

    def selected_collectors(self, available: Iterable[str]) -> list[str]:
        return select_collectors(
            available=available,
            profile_default_collectors=self.default_collectors,
            explicit_collectors=self.collectors,
            excluded_collectors=self.excluded_collectors,
            include_exchange=self.include_exchange,
        )


@dataclass
class CollectorDefinition:
    collector_id: str
    description: str
    enabled: bool
    required_permissions: list[str]
    query_plan: list[str]
    command_collectors: list[dict] | None = None


@dataclass
class CollectorConfig:
    collectors: dict[str, CollectorDefinition]
    default_order: list[str]

    @classmethod
    def from_path(cls, path: str | Path) -> CollectorConfig:
        from .resources import read_selected_resource
        payload = json.loads(read_selected_resource(path, default="configs/collector-definitions.json", field="config"))
        collectors = {
            key: CollectorDefinition(
                collector_id=key,
                description=value.get("description", ""),
                enabled=bool(value.get("enabled", False)),
                required_permissions=value.get("required_permissions", []),
                query_plan=value.get("query_plan", []),
                command_collectors=value.get("command_collectors"),
            )
            for key, value in payload.get("collectors", {}).items()
        }
        return cls(collectors=collectors, default_order=payload.get("default_order", list(collectors.keys())))

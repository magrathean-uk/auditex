"""Strict Teams adapters for the private, in-memory rule view.

Partner domains are represented only by their count. Model eligibility remains
the responsibility of the projection's existing shape gate.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from azure_tenant_audit.external_sharing import (
    FEDERATION_ALLOW_LIST,
    FEDERATION_OPEN,
    federation_allow_list,
)

from .scuba_projection import Bundle, _boolean, _fields, _nullable_text, _require, _text


def _rows(bundle: Bundle, operation: str, spec: dict[str, Callable[[Any], bool]]) -> list:
    rows = bundle.operation("teams_policy", operation)
    result = []
    for row in rows:
        item = _fields(row, spec)
        bundle.known_fields(row, set(spec) | {"source_name", "key", "kind"})
        result.append(item)
    return result


def _allowed_domains_value(raw: Any) -> list:
    if isinstance(raw, list):
        if not raw:
            return []
        total = 0
        for item in raw:
            _require(isinstance(item, dict), "AllowedDomains", "invalid_type")
            domains = item.get("AllowedDomain")
            _require(isinstance(domains, list) and bool(domains), "AllowedDomains", "invalid_type")
            total += len(domains)
    else:
        state, total = federation_allow_list(raw)
        if state == FEDERATION_OPEN:
            return []
        # Bare domain text is outside the supported cmdlet object contract.
        # An empty allow list permits nobody; mapping it to [] would mean open.
        _require(state == FEDERATION_ALLOW_LIST and isinstance(raw, dict) and total >= 1,
                 "AllowedDomains", "invalid_type")
    return [{"AllowedDomain": ["Domain=<withheld>"] * total}]


def _broadcast_policies(bundle: Bundle) -> list:
    return _rows(bundle, "broadcastPolicies", {"Identity": _text, "BroadcastRecordingMode": _text})


def _client_configuration(bundle: Bundle) -> list:
    return _rows(bundle, "clientConfiguration", {"Identity": _nullable_text, "AllowEmailIntoChannel": _boolean})


def _app_policies(bundle: Bundle) -> list:
    return _rows(bundle, "appPermissionPolicies", {
        "Identity": _text, "DefaultCatalogAppsType": _text,
        "GlobalCatalogAppsType": _text, "PrivateCatalogAppsType": _text,
    })


def _federation_configuration(bundle: Bundle) -> list:
    rows = _rows(bundle, "tenantFederationConfiguration", {
        "Identity": _text, "AllowFederatedUsers": _boolean, "AllowTeamsConsumer": _boolean,
        "AllowTeamsConsumerInbound": _boolean, "AllowedDomains": lambda value: True,
    })
    for item in rows:
        item["AllowedDomains"] = _allowed_domains_value(item["AllowedDomains"])
    return rows


TEAMS_ADAPTERS: dict[str, Callable[[Bundle], Any]] = {
    "broadcast_policies": _broadcast_policies,
    "client_configuration": _client_configuration,
    "app_policies": _app_policies,
    "federation_configuration": _federation_configuration,
}
ADAPTERS = TEAMS_ADAPTERS

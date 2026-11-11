"""Strict Teams adapters for the private, in-memory rule view.

Partner domains are represented only by their count. Model eligibility remains
the responsibility of the projection's existing shape gate.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

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
    if isinstance(raw, str):
        # Only the complete cmdlet marker means open, never embedded domain text.
        _require(raw.strip().casefold() == "allowallknowndomains",
                 "AllowedDomains", "invalid_type")
        return []
    if isinstance(raw, list):
        if not raw:
            return []
        total = 0
        for item in raw:
            _require(isinstance(item, dict), "AllowedDomains", "invalid_type")
            domains = item.get("AllowedDomain")
            _require(isinstance(domains, list) and bool(domains), "AllowedDomains", "invalid_type")
            _require(all(str(entry).strip().casefold() != "allowallknowndomains" for entry in domains),
                     "AllowedDomains", "invalid_type")
            total += len(domains)
    elif isinstance(raw, dict):
        if raw == {}:
            return []
        # Read only recognised allow-list attributes, never marker substrings.
        total = 0
        for name, value in raw.items():
            if re.sub(r"[^a-z0-9]", "", str(name).lower()) not in {
                "alloweddomain", "alloweddomains", "domains", "domain", "alloweddomainsasalist",
            }:
                continue
            if isinstance(value, (list, tuple)):
                domains = [entry for entry in value if entry not in (None, "")]
            elif isinstance(value, str) and value.strip():
                domains = [value]
            else:
                continue
            _require(all(str(entry).strip().casefold() != "allowallknowndomains" for entry in domains),
                     "AllowedDomains", "invalid_type")
            total = len(domains)
            break
        # An empty allow list permits nobody; mapping it to [] would mean open.
        _require(total >= 1, "AllowedDomains", "invalid_type")
    else:
        _require(False, "AllowedDomains", "invalid_type")
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

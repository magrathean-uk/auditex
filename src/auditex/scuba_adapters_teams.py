"""Strict Teams adapters for the private, in-memory rule view.

Partner domains are represented only by their count. Model eligibility remains
the responsibility of the projection's existing shape gate.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from azure_tenant_audit.collection_gaps import (
    REASON_TEAMS_POWERSHELL_NOT_SUPPORTED,
    SECTION_SCOPED,
)

from .scuba_projection import (
    Bundle,
    Unavailable,
    _boolean,
    _clean_text,
    _fields,
    _names,
    _nullable_text,
    _require,
    _text,
)


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


# ScubaGear's tenant_app_settings input for certificate authentication: the org-wide unified app settings
# cannot be read app-only, so MS.TEAMS 5.1-5.3 are judged from the legacy app permission policies.
CERTIFICATE_AUTH_MARKER = {"CertificateBasedAuth": True}


APP_SETTINGS_OPERATION = "tenantAppSettings"
# The certificate skip exactly as the collector writes it; any other key (``incomplete``, a truncation flag,
# a different error class) is a conflicting failure signal.
_CERTIFICATE_SKIP = {"value": [], "status": "skipped", "reason": REASON_TEAMS_POWERSHELL_NOT_SUPPORTED,
                     SECTION_SCOPED: True, "error_class": REASON_TEAMS_POWERSHELL_NOT_SUPPORTED}
_CERTIFICATE_SKIP_TEXT = {"error", "command"}
_COVERAGE_SOURCES = ("coverage.json", "normalized/coverage_ledger.json", "normalized/collection_gaps.json")


def _certificate_skip(envelope: Any) -> bool:
    return (isinstance(envelope, dict)
            and all(key in envelope and envelope[key] == value for key, value in _CERTIFICATE_SKIP.items())
            and set(envelope) <= set(_CERTIFICATE_SKIP) | _CERTIFICATE_SKIP_TEXT
            and all(isinstance(envelope[key], str) for key in _CERTIFICATE_SKIP_TEXT & set(envelope)))


_FAILURE_MARKERS = ("incomplete", "partial", "collection_truncated", "truncation_reason", "bounded_sample",
                    "resolver_error", "@odata.nextLink", "item_count", "rows_collected")


def _certificate_skip_row(row: dict[str, Any]) -> bool:
    """A coverage row or collection gap about the app settings read that records only the certificate skip."""
    reason = REASON_TEAMS_POWERSHELL_NOT_SUPPORTED
    return (row.get("coverage_status", row.get("status")) == "skipped" and row.get("reason") == reason
            and row.get("error_class", reason) == reason and row.get("error_classes", [reason]) == [reason]
            and row.get(SECTION_SCOPED, True) is True and row.get("complete", False) is False
            and "actual_status" not in row and not any(row.get(key) for key in _FAILURE_MARKERS)
            and all(row.get(key, "skipped") == "skipped" for key in ("read_state", "collection_status")))


def _manifest_names_read(value: Any) -> bool:
    """Whether a manifest coverage gap names the app settings read: a dict naming it, or ``teams_policy.<read>`` text."""
    if isinstance(value, dict):
        if value.get("collector") == "teams_policy":
            key = next((k for k in ("list", "section", "name", "item") if value.get(k)), None)
            return key is not None and APP_SETTINGS_OPERATION in _names(value[key])
        return False
    return isinstance(value, str) and value.startswith("teams_policy.") \
        and APP_SETTINGS_OPERATION in _names(value[len("teams_policy."):])


def _check_manifest_gaps(value: Any) -> None:
    """Every manifest gap naming the app settings read must be the certificate skip's section gap."""
    if _manifest_names_read(value):
        _require(isinstance(value, dict) and _certificate_skip_row(value), "coverage_gaps")
    elif isinstance(value, dict):
        for child in value.values():
            _check_manifest_gaps(child)
    elif isinstance(value, list):
        for child in value:
            _check_manifest_gaps(child)


def _check_certificate_skip(bundle: Bundle) -> None:
    """Withhold unless every source agrees the app settings read is only the certificate skip.

    Coverage rows, collection gaps and manifest gaps naming the read must record that skip, with no failed
    ``read_state`` or ``collection_status``; a ledger diagnostic naming it is a failure, since a section-scoped skip
    never produces one. The collector's own health and the rest of its coverage
    then go through the shared check, which tolerates the skip as a failure of a read this section does not use.
    """
    _check_manifest_gaps(bundle.manifest.get("coverage_gaps", []))
    for path in _COVERAGE_SOURCES:
        try:
            data = bundle.read(path)
        except Unavailable as exc:
            if exc.reason == "missing_artifact":
                continue
            raise
        rows = data.get("records") if isinstance(data, dict) else data
        _require(isinstance(rows, list))
        for row in rows:
            _require(isinstance(row, dict))
            source = row.get("source", "")
            if row.get("collector") != "teams_policy" and not (
                    isinstance(source, str) and source.startswith("teams_policy.")):
                continue
            groups, named = bundle._attribution(row, "teams_policy")
            if not any(APP_SETTINGS_OPERATION in names for names in groups or ()):
                continue
            # A ledger row names the read only in a diagnostic, which a section-scoped skip never produces.
            _require(named and _certificate_skip_row(row), "coverage")
    bundle.collector_health("teams_policy", frozenset())


def _tenant_app_settings(bundle: Bundle) -> list:
    payload, _ = bundle._collector_payload("teams_policy")
    envelope = (payload or {}).get(APP_SETTINGS_OPERATION)
    # Only the app-only certificate run names this skip: without the certificate token the read is
    # teams_token_unavailable and the section stays not collected, as does every failed read.
    if isinstance(envelope, dict) and envelope.get("reason") == REASON_TEAMS_POWERSHELL_NOT_SUPPORTED:
        _require(_certificate_skip(envelope), APP_SETTINGS_OPERATION)
        _check_certificate_skip(bundle)
        return [dict(CERTIFICATE_AUTH_MARKER)]
    result = []
    for row in bundle.operation("teams_policy", APP_SETTINGS_OPERATION):
        _require(isinstance(row, dict), "$", "invalid_type")
        _require(_text(row.get("SettingName")), "SettingName", "missing_field")
        bundle.known_fields(row, {"SettingName", "SettingValue", "source_name", "key", "kind"})
        item = {"SettingName": row["SettingName"]}
        if "SettingValue" in row:
            # The rules judge a missing or non-string value themselves; text is still checked for control characters.
            _require(not isinstance(row["SettingValue"], str) or _clean_text(row["SettingValue"]),
                     "SettingValue", "invalid_type")
            item["SettingValue"] = row["SettingValue"]
        result.append(item)
    return result


TEAMS_ADAPTERS: dict[str, Callable[[Bundle], Any]] = {
    "broadcast_policies": _broadcast_policies,
    "client_configuration": _client_configuration,
    "app_policies": _app_policies,
    "federation_configuration": _federation_configuration,
    "tenant_app_settings": _tenant_app_settings,
}
ADAPTERS = TEAMS_ADAPTERS

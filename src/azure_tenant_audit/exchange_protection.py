"""Exchange Online mail protection settings, read the way the Cyber Essentials malware rules need them.

Four read-only cmdlets feed this module (see ``collectors/exchange_policy.py``): ``Get-MalwareFilterPolicy``,
``Get-TransportConfig``, ``Get-CASMailbox`` (a count of the mailboxes that switch SMTP AUTH back on) and
``Get-DkimSigningConfig``. Their rows are normalized into ``exchange_policy_objects``
records; this module judges those records. A setting that was not returned (a blocked session, a property that
is absent, a value that is not a boolean) is unknown and never reads as a pass or a failure.

DKIM overlaps with the DNS lookup in ``dns_posture``: that rule says no DKIM selector is published, this one
says Exchange Online has signing switched off. A domain the DNS rule already reports is left to it, so one
gap is one finding; the Exchange rule then reads ``not_assessed`` for that run, never ``pass``.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

SOURCE_MALWARE = "malwareFilterPolicy"
SOURCE_TRANSPORT = "transportConfig"
SOURCE_DKIM = "dkimSigningConfig"
SOURCE_DOMAINS = "acceptedDomains"
# A count of mailboxes whose own ``SmtpClientAuthenticationDisabled`` is false: the tenant default can be switched off and
# still be overridden mailbox by mailbox. No address is kept.
SOURCE_CAS_SMTP = "casMailboxSmtpAuth"

RULE_MALWARE = "exchange.malware_filter_weakened"
RULE_SMTP_AUTH = "exchange.smtp_auth_enabled_tenant_wide"
RULE_DKIM = "exchange.dkim_signing_disabled"
RULES = frozenset({RULE_MALWARE, RULE_SMTP_AUTH, RULE_DKIM})

_SOURCE_BY_RULE = {RULE_MALWARE: SOURCE_MALWARE, RULE_SMTP_AUTH: SOURCE_TRANSPORT, RULE_DKIM: SOURCE_DKIM}
_MAILBOX_ONLY_SUFFIXES = (".onmicrosoft.com", ".mail.onmicrosoft.com")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def _count(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


# ``AcceptedDomainType`` as the Exchange Online REST cmdlets number it when PowerShell writes the enumeration as an integer.
_DOMAIN_TYPE_BY_NUMBER = {0: "Authoritative", 1: "InternalRelay", 2: "ExternalRelay"}
_DOMAIN_KEYS = ("Domain", "DomainName", "Address", "SmtpDomain", "Name", "Value", "value")
_ENUM_KEYS = ("Value", "value", "Name", "name", "DisplayName")


def _unwrap_enum(value: Any) -> Any:
    """An enumeration that arrives as ``{"value": 0, "Value": "Authoritative"}`` is its inner value."""
    while isinstance(value, Mapping):
        inner = next((value[key] for key in _ENUM_KEYS if value.get(key) not in (None, "")), None)
        if inner is None:
            return None
        value = inner
    return value


def domain_type_text(value: Any) -> str | None:
    """``Authoritative``, ``InternalRelay`` or ``ExternalRelay`` from the name, its integer or a wrapped value; else ``None``."""
    value = _unwrap_enum(value)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _DOMAIN_TYPE_BY_NUMBER.get(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return _DOMAIN_TYPE_BY_NUMBER.get(int(text))
        return text or None
    return None


def domain_text(value: Any) -> str | None:
    """A domain name from a string or from the object shapes Exchange returns (``{"Domain": "contoso.example"}`` and the like)."""
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, Mapping):
        for key in _DOMAIN_KEYS:
            text = domain_text(value.get(key))
            if text:
                return text
    return None


def _status_text(value: Any) -> Any:
    value = _unwrap_enum(value)
    return value.strip() if isinstance(value, str) else value


def protection_fields(source_name: str, item: Mapping[str, Any]) -> dict[str, Any]:
    """The mail-protection fields of one Exchange row, for the normalized ``exchange_policy_object`` record."""
    if source_name == SOURCE_MALWARE:
        return {
            "is_default": _bool(item.get("IsDefault")),
            "enable_file_filter": _bool(item.get("EnableFileFilter")),
            "zap_enabled": _bool(item.get("ZapEnabled")),
        }
    if source_name == SOURCE_TRANSPORT:
        return {"smtp_client_auth_disabled": _bool(item.get("SmtpClientAuthenticationDisabled"))}
    if source_name == SOURCE_DKIM:
        return {"dkim_enabled": _bool(item.get("Enabled")), "dkim_status": _status_text(item.get("Status"))}
    if source_name == SOURCE_CAS_SMTP:
        return {"smtp_auth_enabled_mailbox_count": _count(item.get("Count"))}
    if source_name == SOURCE_DOMAINS:
        return {"domain_type": domain_type_text(item.get("DomainType")), "default_domain": _bool(item.get("Default"))}
    return {}


def _records(snapshot: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    payload = snapshot.get(section) if isinstance(snapshot, Mapping) else None
    rows = payload.get("records") if isinstance(payload, Mapping) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def source_records(snapshot: Mapping[str, Any] | None, source_name: str) -> list[dict[str, Any]]:
    return [row for row in _records(snapshot, "exchange_policy_objects") if row.get("source_name") == source_name]


def source_read_in_full(snapshot: Mapping[str, Any] | None, source_name: str) -> bool:
    """Whether the command's rows were read without error, cut or unreadable rows."""
    wanted = f"exchange_policy.{source_name}"
    for row in _records(snapshot, "normalization_coverage"):
        if row.get("source") == wanted:
            return row.get("collection_status") == "collected" and row.get("complete") is True
    return False


def default_malware_policy(records: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    return next((row for row in records if row.get("is_default") is True), None)


def malware_filter_weaknesses(policy: Mapping[str, Any]) -> list[str]:
    """What a malware policy has switched off: the common attachment filter, zero-hour auto purge."""
    weaknesses = []
    if policy.get("enable_file_filter") is False:
        weaknesses.append("common_attachment_filter_off")
    if policy.get("zap_enabled") is False:
        weaknesses.append("zero_hour_auto_purge_off")
    return weaknesses


def smtp_auth_enabled_mailbox_count(snapshot: Mapping[str, Any] | None) -> int | None:
    """How many mailboxes switch SMTP AUTH back on for themselves, or ``None`` when the count was not returned."""
    counts = [row.get("smtp_auth_enabled_mailbox_count") for row in source_records(snapshot, SOURCE_CAS_SMTP)]
    known = [count for count in counts if isinstance(count, int) and not isinstance(count, bool)]
    return max(known) if known else None


def custom_domains(snapshot: Mapping[str, Any] | None) -> list[str]:
    """Authoritative accepted domains other than ``*.onmicrosoft.com``, lower-cased: the domains whose mail Exchange signs."""
    names = []
    for row in source_records(snapshot, SOURCE_DOMAINS):
        name = (domain_text(row.get("domain_name")) or "").lower()
        # A record from before the shape was normalized can still hold the integer enumeration or an object.
        if name and (domain_type_text(row.get("domain_type")) or "").lower() == "authoritative" and not name.endswith(_MAILBOX_ONLY_SUFFIXES):
            names.append(name)
    return sorted(set(names))


def dns_reports_dkim_missing(record: Mapping[str, Any]) -> bool:
    """Whether ``dns_posture.dkim_missing`` fires for this DNS posture record (kept in step with findings.py)."""
    if record.get("resolver_error"):
        return False
    return not record.get("managed_by_microsoft") and not record.get("dkim_selectors_present")


def dns_dkim_domains(snapshot: Mapping[str, Any] | None) -> set[str]:
    """Domains the DNS rule already reports as having no DKIM selector."""
    return {
        str(row.get("domain") or row.get("id") or "").strip().lower()
        for row in _records(snapshot, "dns_posture_objects")
        if dns_reports_dkim_missing(row) and (row.get("domain") or row.get("id"))
    }


def dkim_by_domain(snapshot: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {(domain_text(row.get("domain_name")) or "").lower(): row for row in source_records(snapshot, SOURCE_DKIM) if domain_text(row.get("domain_name"))}


def dkim_disabled_domains(snapshot: Mapping[str, Any] | None) -> list[str]:
    """Custom authoritative domains whose DKIM signing is switched off in Exchange Online."""
    states = dkim_by_domain(snapshot)
    return [name for name in custom_domains(snapshot) if (states.get(name) or {}).get("dkim_enabled") is False]


def inputs_gap(rule_id: str, snapshot: Mapping[str, Any] | None) -> str | None:
    """Why ``rule_id`` cannot be judged from the normalized snapshot, or ``None`` when it can."""
    if snapshot is None:
        return "inputs_not_available"
    if not source_read_in_full(snapshot, _SOURCE_BY_RULE[rule_id]):
        return f"{_SOURCE_BY_RULE[rule_id]}_not_read_in_full"
    records = source_records(snapshot, _SOURCE_BY_RULE[rule_id])
    if rule_id == RULE_MALWARE:
        if default_malware_policy(records) is None:
            return "default_malware_policy_not_identified"
        # Every policy is judged, not only the default: a custom policy that covers some recipients with the file filter
        # or zero-hour auto purge off weakens protection for them whatever the default says.
        if any(
            not isinstance(row.get("enable_file_filter"), bool) or not isinstance(row.get("zap_enabled"), bool)
            for row in records
        ):
            return "malware_filter_settings_not_returned"
        return None
    if rule_id == RULE_SMTP_AUTH:
        if not records:
            return "transport_config_not_returned"
        if any(not isinstance(row.get("smtp_client_auth_disabled"), bool) for row in records):
            return "smtp_auth_setting_not_returned"
        # The tenant default can be off while a mailbox switches SMTP AUTH back on for itself: the per-mailbox
        # settings have to be read too, or a clean tenant default proves nothing.
        if not source_read_in_full(snapshot, SOURCE_CAS_SMTP):
            return f"{SOURCE_CAS_SMTP}_not_read_in_full"
        if smtp_auth_enabled_mailbox_count(snapshot) is None:
            return "mailbox_smtp_auth_count_not_returned"
        return None
    if not source_read_in_full(snapshot, SOURCE_DOMAINS):
        return "acceptedDomains_not_read_in_full"
    domains = custom_domains(snapshot)
    if not domains:
        return "no_custom_domains"
    states = dkim_by_domain(snapshot)
    if any(not isinstance((states.get(name) or {}).get("dkim_enabled"), bool) for name in domains):
        return "dkim_state_not_returned_for_domain"
    if set(dkim_disabled_domains(snapshot)) & dns_dkim_domains(snapshot):
        return "reported_by:dns_posture.dkim_missing"
    return None

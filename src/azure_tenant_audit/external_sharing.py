"""External sharing and federation settings, read the way the rules need them.

The tenant sharing settings reach Auditex in more than one spelling: Microsoft Graph
``/admin/sharepoint/settings`` returns camelCase names and string enums
(``sharingCapability: "externalUserAndGuestSharing"``), the SharePoint Online Management Shell
returns PascalCase names and, in some exports, the enum's integer (``SharingCapability: 2``). The
Teams ``Get-CsTenantFederationConfiguration`` allow list is an object rather than a list. This module
turns each into one canonical value, and anything it does not recognise into ``None`` (unknown),
never into a pass and never into a failure. The grading helpers sit beside the parsers so that
normalization, the finding builders and baseline alignment agree on what a setting means.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SECTION = "sharepoint_tenant_settings"
KIND = "sharepoint_tenant_settings"

CAPABILITY_DISABLED = "disabled"
CAPABILITY_EXISTING_GUESTS = "existingExternalUserSharingOnly"
CAPABILITY_GUESTS = "externalUserSharingOnly"
CAPABILITY_ANYONE = "externalUserAndGuestSharing"

# Least to most permissive. A site cannot be more permissive than the tenant, so a site whose own
# value ranks above the tenant's is an inconsistency worth listing.
_CAPABILITY_RANK = {
    CAPABILITY_DISABLED: 0,
    CAPABILITY_EXISTING_GUESTS: 1,
    CAPABILITY_GUESTS: 2,
    CAPABILITY_ANYONE: 3,
}
# ``SharingCapability`` as the SharePoint Online Management Shell numbers it.
_CAPABILITY_BY_NUMBER = {
    0: CAPABILITY_DISABLED,
    1: CAPABILITY_GUESTS,
    2: CAPABILITY_ANYONE,
    3: CAPABILITY_EXISTING_GUESTS,
}
_DOMAIN_MODE_BY_NUMBER = {0: "none", 1: "allowList", 2: "blockList"}
_DOMAIN_MODES = {"none": "none", "allowlist": "allowList", "blocklist": "blockList"}
# ``SharingLinkType`` as the SharePoint Online Management Shell numbers it.
_LINK_TYPE_BY_NUMBER = {0: "none", 1: "direct", 2: "internal", 3: "anonymous"}
_LINK_TYPES = {
    "none": "none",
    "direct": "direct",
    "specificpeople": "direct",
    "internal": "internal",
    "organization": "internal",
    "organisation": "internal",
    "organizationonly": "internal",
    "anonymous": "anonymous",
    "anonymousaccess": "anonymous",
    "anyone": "anonymous",
}
_ANONYMOUS_LINK_TYPE_BY_NUMBER = {0: "none", 1: "view", 2: "edit"}
_ANONYMOUS_LINK_TYPES = {"none": "none", "view": "view", "edit": "edit"}

# Anonymous links that expire within this many days, and cannot edit, are a reduced exposure.
ANONYMOUS_LINK_EXPIRY_LIMIT_DAYS = 30

_SETTING_NAMES = {
    "sharing_capability": ("sharingCapability",),
    "onedrive_sharing_capability": ("oneDriveSharingCapability", "odbSharingCapability"),
    "sharing_domain_restriction_mode": ("sharingDomainRestrictionMode",),
    "allowed_domains": ("sharingAllowedDomainList",),
    "blocked_domains": ("sharingBlockedDomainList",),
    "default_sharing_link_type": ("defaultSharingLinkType",),
    "anonymous_link_expiry_days": ("requireAnonymousLinksExpireInDays",),
    "file_anonymous_link_type": ("fileAnonymousLinkType",),
    "folder_anonymous_link_type": ("folderAnonymousLinkType",),
}


def _key(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    return None


def _enum(value: Any, by_number: Mapping[int, str], by_name: Mapping[str, str]) -> str | None:
    number = _integer(value)
    if number is not None and not isinstance(value, str):
        return by_number.get(number)
    if isinstance(value, str):
        text = _key(value)
        if text in by_name:
            return by_name[text]
        number = _integer(value)
        if number is not None:
            return by_number.get(number)
    return None


def canonical_sharing_capability(value: Any) -> str | None:
    """``disabled``, ``existingExternalUserSharingOnly``, ``externalUserSharingOnly``,
    ``externalUserAndGuestSharing``, or ``None`` for a value this tool does not recognise."""
    names = {_key(name): name for name in _CAPABILITY_RANK}
    return _enum(value, _CAPABILITY_BY_NUMBER, names)


def capability_rank(value: Any) -> int | None:
    """0 (disabled) to 3 (anyone links) for a recognised capability, else ``None``."""
    capability = canonical_sharing_capability(value)
    return _CAPABILITY_RANK.get(capability) if capability else None


def canonical_domain_restriction_mode(value: Any) -> str | None:
    return _enum(value, _DOMAIN_MODE_BY_NUMBER, _DOMAIN_MODES)


def canonical_link_type(value: Any) -> str | None:
    return _enum(value, _LINK_TYPE_BY_NUMBER, _LINK_TYPES)


def canonical_anonymous_link_type(value: Any) -> str | None:
    return _enum(value, _ANONYMOUS_LINK_TYPE_BY_NUMBER, _ANONYMOUS_LINK_TYPES)


def anonymous_link_expiry_days(value: Any) -> int | None:
    """Days before an anonymous link expires; 0 when links never expire; ``None`` when not read.

    SharePoint reports no expiry as 0 and, on a tenant that never set it, as -1.
    """
    number = _integer(value)
    if number is None:
        return None
    return number if number > 0 else 0


def _domain_count(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return len([item for item in value if str(item).strip()])
    if isinstance(value, str):
        return len([item for item in re.split(r"[\s,;]+", value) if item])
    return None


def _lookup(settings: Mapping[str, Any], setting: str) -> tuple[bool, Any]:
    wanted = {_key(name) for name in _SETTING_NAMES[setting]}
    for name, value in settings.items():
        if _key(name) in wanted:
            return True, value
    return False, None


def tenant_settings_fields(settings: Mapping[str, Any]) -> dict[str, Any]:
    """The canonical sharing settings in a ``sharePointSettings`` payload.

    A setting the payload does not carry is absent from the result (``None``); one it carries in a form
    this tool does not recognise is listed in ``unrecognised`` with its raw text. Domain lists are kept
    as counts only: the names of partner domains are not needed to judge whether a list exists.
    """
    fields: dict[str, Any] = {}
    unrecognised: dict[str, str] = {}
    parsers = {
        "sharing_capability": canonical_sharing_capability,
        "onedrive_sharing_capability": canonical_sharing_capability,
        "sharing_domain_restriction_mode": canonical_domain_restriction_mode,
        "default_sharing_link_type": canonical_link_type,
        "anonymous_link_expiry_days": anonymous_link_expiry_days,
        "file_anonymous_link_type": canonical_anonymous_link_type,
        "folder_anonymous_link_type": canonical_anonymous_link_type,
    }
    for setting, parse in parsers.items():
        present, raw = _lookup(settings, setting)
        if not present or raw in (None, ""):
            continue
        parsed = parse(raw)
        if parsed is None:
            unrecognised[setting] = str(raw)[:80]
        else:
            fields[setting] = parsed
    for setting, count_name in (("allowed_domains", "allowed_domain_count"), ("blocked_domains", "blocked_domain_count")):
        present, raw = _lookup(settings, setting)
        count = _domain_count(raw) if present else None
        if count is not None:
            fields[count_name] = count
    if unrecognised:
        fields["unrecognised"] = unrecognised
    return fields


# Rules that read a tenant sharing setting. Each rule lists what it needs before it can say anything; a
# requirement is a group of settings of which any one will do (OneDrive reads its own capability when
# the payload has it and SharePoint's otherwise).
SETTING_RULES: dict[str, tuple[tuple[str, ...], ...]] = {
    "onedrive.external_sharing_enabled": (("onedrive_sharing_capability", "sharing_capability"),),
    "sharepoint.external_sharing_broad": (("sharing_capability",),),
    "sharepoint.sharing_domains_unrestricted": (("sharing_capability",), ("sharing_domain_restriction_mode",)),
    "sharepoint.default_link_type_broad": (("default_sharing_link_type",),),
}

# Which collector's reading to prefer when both read the same singleton.
_COLLECTOR_PREFERENCE = ("sharepoint_access", "onedrive_posture")


def _records(snapshot: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    if not isinstance(snapshot, Mapping):
        return []
    payload = snapshot.get(section)
    rows = payload.get("records") if isinstance(payload, Mapping) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def tenant_settings(snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
    """The tenant sharing settings this run read, merged across the collectors that read them.

    Each setting is the first value any collector's record carries. A bundle written before the
    ``sharepoint_tenant_settings`` section existed has only the tenant value copied onto each OneDrive
    site record; that copy stands in for ``sharing_capability`` so an older bundle still grades.
    ``read`` is True when some record was read at all.
    """
    rows = sorted(
        _records(snapshot, SECTION),
        key=lambda row: _COLLECTOR_PREFERENCE.index(row.get("collector")) if row.get("collector") in _COLLECTOR_PREFERENCE else 99,
    )
    merged: dict[str, Any] = {"read": False, "collectors": []}
    for row in rows:
        if row.get("read_state") != "collected":
            continue
        merged["read"] = True
        merged["collectors"].append(row.get("collector"))
        for name, value in row.items():
            if name in {"kind", "source", "id", "key", "collector", "read_state", "source_name"}:
                continue
            if name == "unrecognised":
                merged.setdefault("unrecognised", {}).update({k: v for k, v in value.items() if k not in merged["unrecognised"]})
            elif name not in merged:
                merged[name] = value
    if "sharing_capability" not in merged:
        copies = [
            canonical_sharing_capability(site.get("sharing_capability"))
            for site in _records(snapshot, "onedrive_posture_objects")
            if site.get("sharing_capability_source") != "site"
        ]
        ranks = [(capability_rank(item), item) for item in copies if item]
        if ranks:
            merged["read"] = True
            merged["sharing_capability"] = max(ranks, key=lambda pair: pair[0])[1]
            merged["sharing_capability_from_sites"] = True
    return merged


def setting_inputs_gap(rule_id: str, snapshot: Mapping[str, Any] | None) -> str | None:
    """Why a sharing-setting rule cannot be judged from ``snapshot``, or ``None`` when it can."""
    if snapshot is None:
        return "inputs_not_available"
    needed = SETTING_RULES.get(rule_id)
    if needed is None:
        return None
    settings = tenant_settings(snapshot)
    if not settings["read"]:
        return "sharepoint_settings_not_collected"
    for alternatives in needed:
        if all(settings.get(setting) is None for setting in alternatives):
            return f"sharing_setting_not_read:{alternatives[-1]}"
    return None


# --- OneDrive: one graded tenant-level finding -----------------------------------------------------

SITE_EVIDENCE_LIMIT = 50


def onedrive_capability(settings: Mapping[str, Any]) -> tuple[str | None, str]:
    """The OneDrive sharing capability and where it came from.

    OneDrive has its own setting (``OneDriveSharingCapability``) that can only be as permissive as
    SharePoint's. Graph returns SharePoint's value alone, which OneDrive inherits unless set stricter.
    """
    if settings.get("onedrive_sharing_capability"):
        return settings["onedrive_sharing_capability"], "onedrive_setting"
    if settings.get("sharing_capability"):
        return settings["sharing_capability"], "sharepoint_setting_inherited"
    return None, "not_read"


def grade_onedrive_sharing(capability: str | None, *, anyone_sites: int, known_sites: int) -> str | None:
    """Severity of tenant-level OneDrive external sharing, or ``None`` when it needs no finding.

    Anyone links are ``high``; new and existing guests are ``low``; existing guests only and sharing
    off need no finding. With a site inventory, anyone links on fewer than half of the personal sites
    are ``medium``. A site inventory in which every site only repeats the tenant value always shows
    all of them, so it never softens the grade.
    """
    rank = capability_rank(capability)
    if rank is None or rank < 2:
        return None
    if rank == 2:
        return "low"
    if known_sites and anyone_sites * 2 < known_sites:
        return "medium"
    return "high"


# --- SharePoint: the settings behind a sharing link ------------------------------------------------


def grade_anyone_links(settings: Mapping[str, Any]) -> tuple[str | None, list[str], list[str]]:
    """Severity, observed mitigations and unread settings for anyone links.

    ``None`` unless anyone links are on. ``high`` by default; ``medium`` only when the links are known
    to expire within ``ANONYMOUS_LINK_EXPIRY_LIMIT_DAYS`` days and both file and folder links are
    known to be view-only. A setting that was not read is never assumed to mitigate.
    """
    if settings.get("sharing_capability") != CAPABILITY_ANYONE:
        return None, [], []
    expiry = settings.get("anonymous_link_expiry_days")
    file_type = settings.get("file_anonymous_link_type")
    folder_type = settings.get("folder_anonymous_link_type")
    not_read = [
        name
        for name, value in (
            ("anonymous_link_expiry_days", expiry),
            ("file_anonymous_link_type", file_type),
            ("folder_anonymous_link_type", folder_type),
        )
        if value is None
    ]
    mitigations: list[str] = []
    if isinstance(expiry, int) and 0 < expiry <= ANONYMOUS_LINK_EXPIRY_LIMIT_DAYS:
        mitigations.append(f"anonymous links expire within {expiry} days")
    if file_type == "view" and folder_type == "view":
        mitigations.append("anonymous links are view-only")
    return ("medium" if len(mitigations) == 2 else "high"), mitigations, not_read


# Frameworks whose controls the SharePoint rules map to, and whether each is breached by a finding.
_CIS = "cis_m365_v7"
_SCUBA = "cisa_scuba"
_CE = "cyber_essentials"


def grade_external_sharing(settings: Mapping[str, Any]) -> dict[str, Any] | None:
    """The external sharing capability graded against what each benchmark allows, or ``None``.

    CIS 7.2.3 allows new and existing guests, so only anyone links breach it. ScubaGear's
    MS.SHAREPOINT.1.1v1 passes only for existing guests or sharing off, so new and existing guests
    already breach it. Anyone links are ``high`` (``medium`` when the anonymous-link settings were read
    and mitigate); new and existing guests are ``low`` and breach SCuBA only. For Cyber Essentials (users are
    authenticated before access: ``ce.sc.user_authentication``, supporting evidence) only anyone links are anonymous
    access; an authenticated guest is not.
    """
    rank = capability_rank(settings.get("sharing_capability"))
    if rank is None or rank < 2:
        return None
    if rank == 3:
        severity, mitigations, not_read = grade_anyone_links(settings)
        return {
            "severity": severity,
            "scope": "anyone_links",
            "breaches": {_CIS: True, _SCUBA: True, _CE: True},
            "mitigations": mitigations,
            "not_read": not_read,
        }
    return {
        "severity": "low",
        "scope": "new_and_existing_guests",
        "breaches": {_CIS: False, _SCUBA: True, _CE: False},
        "mitigations": [],
        "not_read": [],
    }


def grade_domain_restriction(settings: Mapping[str, Any]) -> dict[str, Any] | None:
    """External sharing that is not limited to an allow list of domains, or ``None``.

    ScubaGear's MS.SHAREPOINT.1.3v1 passes only with an allow list (sharing off is not applicable), so
    a block list breaches it. CIS 7.2.6 accepts an allow list or a block list, so only no list at all
    breaches CIS. No list is ``medium`` (``low`` when only existing guests may be shared with); a block
    list is ``low``.
    """
    rank = capability_rank(settings.get("sharing_capability"))
    mode = settings.get("sharing_domain_restriction_mode")
    if rank is None or rank < 1 or mode not in {"none", "blockList"}:
        return None
    if mode == "blockList":
        return {"severity": "low", "breaches": {_CIS: False, _SCUBA: True}}
    return {"severity": "low" if rank == 1 else "medium", "breaches": {_CIS: True, _SCUBA: True}}


def grade_default_link_type(settings: Mapping[str, Any]) -> dict[str, Any] | None:
    """A default sharing link that is not for specific people, or ``None``.

    CIS 7.2.7 and SCuBA MS.SHAREPOINT.2.1v1 both need ``Direct`` (specific people). An anyone link is
    ``high``; an organisation-wide link, or ``None`` (no default set), is ``low``. Unread is unknown.
    """
    link_type = settings.get("default_sharing_link_type")
    if link_type == "anonymous":
        severity = "high"
    elif link_type in {"internal", "none"}:
        severity = "low"
    else:
        return None
    return {"severity": severity, "breaches": {_CIS: True, _SCUBA: True}}


# --- Teams federation ------------------------------------------------------------------------------

FEDERATION_OPEN = "open"
FEDERATION_ALLOW_LIST = "allow_list"
FEDERATION_UNKNOWN = "unknown"

_ALLOW_LIST_KEYS = ("alloweddomain", "alloweddomains", "domains", "domain", "alloweddomainsasalist")


def _entries(value: Any) -> list[Any] | None:
    if isinstance(value, (list, tuple)):
        return [item for item in value if item not in (None, "")]
    return None


def federation_allow_list(value: Any) -> tuple[str, int]:
    """State of ``AllowedDomains`` and the number of domains in it.

    The Teams module returns ``AllowAllKnownDomains`` (federation with every domain) or an allow list
    object. ``open`` means no allow list restricts federation; ``allow_list`` means one does (an allow
    list object with no domains is still an allow list: it allows federation with none); ``unknown``
    means the field was not collected, is empty, or has a shape this tool does not recognise.
    """
    if value is None:
        return FEDERATION_UNKNOWN, 0
    if isinstance(value, str):
        text = value.strip()
        if "allowallknowndomains" in _key(text):
            return FEDERATION_OPEN, 0
        domains = [item for item in re.split(r"[\s,;]+", text) if item]
        return (FEDERATION_ALLOW_LIST, len(domains)) if domains else (FEDERATION_UNKNOWN, 0)
    listed = _entries(value)
    if listed is not None:
        # A bare list is not a shape the module returns for either case; only a non-empty one is read.
        return (FEDERATION_ALLOW_LIST, len(listed)) if listed else (FEDERATION_UNKNOWN, 0)
    if isinstance(value, Mapping):
        if not value:
            return FEDERATION_OPEN, 0
        for name, item in value.items():
            if _key(name) in _ALLOW_LIST_KEYS:
                entries = _entries(item)
                if entries is None and isinstance(item, str) and item.strip():
                    entries = [item]
                if entries is not None:
                    # An allow list object with no domains allows federation with none: it is not open.
                    return FEDERATION_ALLOW_LIST, len(entries)
        if any("allowallknowndomains" in _key(f"{name}{item}") for name, item in value.items()):
            return FEDERATION_OPEN, 0
    return FEDERATION_UNKNOWN, 0


def federation_block_count(value: Any) -> int | None:
    """Number of blocked federation domains; ``None`` when ``BlockedDomains`` was not collected."""
    if value is None:
        return None
    listed = _entries(value)
    if listed is not None:
        return len(listed)
    if isinstance(value, str):
        return len([item for item in re.split(r"[\s,;]+", value) if item])
    if isinstance(value, Mapping):
        for name, item in value.items():
            entries = _entries(item)
            if _key(name) in {"blockeddomain", "blockeddomains", "domains", "domain"} and entries is not None:
                return len(entries)
        return 0 if not value else None
    return None

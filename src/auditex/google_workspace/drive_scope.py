"""Which Drive files are owned outside the tenant, so their sharing is not the organisation's exposure.

A file owned by an account outside the tenant, outside any shared drive, is someone else's file the subject can see:
its sharing is that owner's, not the organisation's. Auditex does not read its permissions one by one and does not
count it as a sharing gap. Only a positive answer leaves a file out: unknown tenant domains, a shared drive, or
owners that are missing, empty, malformed, without an email or inside the tenant all keep the file in scope.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from azure_tenant_audit.exposure_lookup import is_safe_domain_name

DOMAIN_SCOPE = "https://www.googleapis.com/auth/admin.directory.domain.readonly"
# The Drive collector's optional scope, as the scope inventory and the setup guide name it.
DOMAIN_SCOPE_NOTE = (
    "Optional for google_drive_posture, read-only: Directory domains.list, the tenant's domain and alias names only "
    "(blast radius: reading those names; no write is possible). It tells My Drive files owned outside the tenant. "
    "Read under domain-wide delegation on a token of its own; under OAuth only when another selected collector "
    "requires this scope (Directory, DNS posture), since an OAuth sign-in never asks for an optional scope. When it "
    "is not read every file stays in scope and its sharing is read as before."
)


TenantDomains = Callable[[], "frozenset[str] | None"]

# An owner address proves a domain only in its plain form: an RFC 5322 dot-atom local part of ASCII atext (no
# whitespace, control or quoted characters, no leading, trailing or doubled dot), exactly one "@", then a domain
# is_safe_domain_name accepts. Anything else (a space, a tab, a second "@", an empty side) is unknown, never
# stripped and accepted (LIVE-FIX-5 B3).
_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*", re.ASCII)


def owner_address_domain(email: Any) -> str | None:
    """The lower-cased domain of one well-formed owner address, or ``None`` when the address proves nothing."""
    if not isinstance(email, str) or len(email) > 254 or email.count("@") != 1:
        return None
    local, domain = email.split("@")
    if len(local) > 64 or not _LOCAL_PART.fullmatch(local) or not is_safe_domain_name(domain):
        return None
    return domain.lower()


def tenant_domain_names(rows: Any) -> frozenset[str] | None:
    """Every domain and domain alias name in a Directory domains list, lower-cased; ``None`` unless it is complete.

    Unverified names are kept too: a name the tenant holds keeps a file in scope. A list that was cut short, is
    empty, or holds a row or alias that cannot be read is not a complete answer.
    """
    if not isinstance(rows, list) or not rows:
        return None
    if getattr(rows, "page_error", None) is not None or getattr(rows, "truncated", False):
        return None
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not is_safe_domain_name(row.get("domainName")):
            return None
        names.add(row["domainName"].lower())
        aliases = row.get("domainAliases", [])
        if not isinstance(aliases, list):
            return None
        for alias in aliases:
            if not isinstance(alias, dict) or not is_safe_domain_name(alias.get("domainAliasName")):
                return None
            names.add(alias["domainAliasName"].lower())
    return frozenset(names)


def owner_domains(drive_file: Any) -> frozenset[str] | None:
    """The domains of a My Drive file's owners, or ``None`` when they cannot be told or the file is in a shared drive."""
    if not isinstance(drive_file, dict) or "driveId" in drive_file:
        return None
    owners = drive_file.get("owners")
    if not isinstance(owners, list) or not owners:
        return None
    domains: set[str] = set()
    for owner in owners:
        domain = owner_address_domain(owner.get("emailAddress") if isinstance(owner, dict) else None)
        if domain is None:
            return None
        domains.add(domain)
    return frozenset(domains)


def owned_outside(drive_file: Any, tenant_domains: frozenset[str] | None) -> bool:
    """Whether every owner of a My Drive file is positively outside the tenant (exact, case-insensitive domains)."""
    if not tenant_domains:
        return False
    domains = owner_domains(drive_file)
    return bool(domains) and domains.isdisjoint(tenant_domains)


def read_tenant_domains(client: Any) -> frozenset[str] | None:
    """The tenant's domains from the Directory domains list, read on a token asking for that scope alone.

    A separate token keeps a delegation without the domain scope from failing the Drive reads. Any failure is
    ``None`` (unknown), never an empty set. The read is attempted only when the client says it may be
    (``tenant_domain_read``: domain-wide delegation, or an OAuth grant holding the scope because another selected
    collector requires it); otherwise nothing is read and every file stays in scope (LIVE-FIX-7).
    """
    if getattr(client, "tenant_domain_read", False) is not True:
        return None
    narrow = getattr(client, "for_scopes", None)
    try:
        domain_client = narrow((DOMAIN_SCOPE,)) if narrow is not None else client
        rows = domain_client.list_directory("domains")
    except Exception:  # noqa: BLE001 - unknown domains keep every file in scope
        return None
    return tenant_domain_names(rows)

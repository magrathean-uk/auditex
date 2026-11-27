"""Which Drive files are owned outside the tenant, so their sharing is not the organisation's exposure.

A file owned by an account outside the tenant, outside any shared drive, is someone else's file the subject can see:
its sharing is that owner's, not the organisation's. Auditex does not read its permissions one by one and does not
count it as a sharing gap. Only a positive answer leaves a file out: unknown tenant domains, a shared drive, or
owners that are missing, empty, malformed, without an email or inside the tenant all keep the file in scope.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from azure_tenant_audit.exposure_lookup import is_safe_domain_name

DOMAIN_SCOPE = "https://www.googleapis.com/auth/admin.directory.domain.readonly"

TenantDomains = Callable[[], "frozenset[str] | None"]


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
        email = owner.get("emailAddress") if isinstance(owner, dict) else None
        if not isinstance(email, str) or email.count("@") != 1:
            return None
        local, domain = email.split("@")
        if not local or not is_safe_domain_name(domain):
            return None
        domains.add(domain.lower())
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
    ``None`` (unknown), never an empty set.
    """
    narrow = getattr(client, "for_scopes", None)
    try:
        domain_client = narrow((DOMAIN_SCOPE,)) if narrow is not None else client
        rows = domain_client.list_directory("domains")
    except Exception:  # noqa: BLE001 - unknown domains keep every file in scope
        return None
    return tenant_domain_names(rows)

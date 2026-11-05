"""Read-only Exchange projections for the in-memory deterministic rule view."""
from __future__ import annotations

from typing import Any

from auditex.scuba_projection import (
    Bundle, Unavailable, _boolean, _fields, _nullable_text, _strings, _text,
)


def _exchange_rows(bundle: Bundle, operation: str) -> list[dict[str, Any]]:
    """Read health-checked rows for EXO 1.1, 6.1, 6.2 and 7.1 without projecting message content."""
    return bundle.operation('exchange_policy', operation)


def remote_domains(bundle: Bundle) -> list[dict[str, Any]]:
    """Project the domain and forwarding flag read by MS.EXO.1.1 without names or other remote-domain settings."""
    rows = _exchange_rows(bundle, 'remoteDomains')
    if not rows:
        raise Unavailable(field='$', kind='empty_remote_domains')
    result = []
    for row in rows:
        item = _fields(row, {'DomainName': _text, 'AutoForwardEnabled': _boolean})
        item['DomainName'] = item['DomainName'].lower()
        bundle.known_fields(row, {'Name', 'DomainName', 'TrustedMailOutboundEnabled', 'AutoReplyEnabled',
                                  'AutoForwardEnabled', 'source_name', 'key', 'kind'})
        result.append(item)
    return result


def transport_rule(bundle: Bundle) -> list[dict[str, Any]]:
    """Project the four fields read by MS.EXO.7.1 without rule names, priorities, recipients or disclaimer text."""
    result = []
    for row in _exchange_rows(bundle, 'transportRules'):
        item = _fields(row, {'State': _text, 'Mode': _text,
                             'FromScope': _nullable_text, 'PrependSubject': _nullable_text})
        allowed = {'Name', 'State', 'Priority', 'Mode', 'RedirectMessageTo', 'BlindCopyTo', 'CopyTo',
                   'ApplyHtmlDisclaimerText', 'FromScope', 'PrependSubject', 'source_name', 'key', 'kind'}
        bundle.known_fields(row, allowed)
        # Record deliberately dropped collector fields by their fixed names, never their values.
        bundle.ignored_fields.update(row.keys() & (allowed - item.keys()))
        result.append(item)
    return result


def sharing_policy(bundle: Bundle) -> list[dict[str, Any]]:
    """Project the name and string domains read by MS.EXO.6.1 and 6.2 without other sharing-policy settings."""
    result = []
    for row in _exchange_rows(bundle, 'sharingPolicy'):
        item = _fields(row, {'Name': _text, 'Domains': _strings})
        bundle.known_fields(row, {'Name', 'Domains', 'source_name', 'key', 'kind'})
        result.append(item)
    return result


ADAPTERS = {'remote_domains': remote_domains, 'transport_rule': transport_rule,
            'sharing_policy': sharing_policy}

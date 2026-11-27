"""LIVE-FIX-4: Drive sharing findings leave out a My Drive file owned wholly outside the tenant.

Only a positive answer hides a file: the Directory domains list complete (``internal_domains_status`` known, source
the Directory), no shared-drive marker, and every owner one valid address outside the tenant. Everything else keeps
the current findings.
"""

from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot

DIRECTORY = [{"domainName": "example.com", "isPrimary": True, "verified": True, "domainAliases": [{"domainAliasName": "alias.example.net"}]}]
LINK = {"id": "p1", "type": "anyone", "role": "reader"}
DISCOVERABLE = {"id": "p2", "type": "anyone", "role": "reader", "allowFileDiscovery": True}
EXTERNAL = {"id": "p3", "type": "user", "role": "reader", "emailAddress": "third@outside.test"}
OUTSIDE_DOMAIN = {"id": "p4", "type": "domain", "role": "reader", "domain": "outside.test"}
INSIDE_DOMAIN = {"id": "p5", "type": "domain", "role": "reader", "domain": "example.com"}
ALL_PERMISSIONS = [LINK, DISCOVERABLE, EXTERNAL, OUTSIDE_DOMAIN, INSIDE_DOMAIN]
KEPT = [
    "google.drive_anyone_with_link",
    "google.drive_domain_permission",
    "google.drive_external_permission",
    "google.drive_external_permission",
    "google.drive_public_discoverable",
]
LINK_ONLY = ["google.drive_anyone_with_link", "google.drive_public_discoverable"]


def _snapshot(drive_files: list[dict[str, Any]], *, directory: Any = DIRECTORY, **kwargs: Any) -> dict[str, Any]:
    payloads: dict[str, Any] = {"google_drive_posture": {"driveFiles": {"value": drive_files}}}
    if directory is not None:
        payloads["google_directory"] = {"domains": {"value": directory}}
    return build_google_normalized_snapshot(
        tenant_name="Example", run_id="run-1", collector_payloads=payloads, domain=kwargs.pop("domain", "example.com"), **kwargs
    )


def _drive_rules(snapshot: dict[str, Any]) -> list[str]:
    return sorted(
        str(item["rule_id"]) for item in build_google_findings(snapshot) if str(item["rule_id"]).startswith("google.drive_")
    )


def _file(file_id: str = "f1", owners: Any = ("owner@outside.test",), **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"id": file_id, "name": "Plan", "permissions": list(ALL_PERMISSIONS)}
    if owners is not None:
        row["owners"] = owners if not isinstance(owners, tuple) else [{"emailAddress": email} for email in owners]
    row.update(extra)
    return row


def test_file_owned_wholly_outside_raises_no_drive_findings() -> None:
    assert _drive_rules(_snapshot([_file()])) == []


def test_file_owned_wholly_outside_raises_nothing_but_inside_files_keep_every_finding() -> None:
    snapshot = _snapshot([_file("f1"), _file("f2", owners=("owner@example.com",))])
    assert _drive_rules(snapshot) == KEPT


def test_every_owner_outside_is_left_out_including_uppercase_and_two_outside_domains() -> None:
    assert _drive_rules(_snapshot([_file(owners=("A@OUTSIDE.TEST", "b@example.org"))])) == []


def test_one_owner_inside_keeps_the_file_in_scope() -> None:
    assert _drive_rules(_snapshot([_file(owners=("a@outside.test", "b@example.com"))])) == KEPT


def test_tenant_alias_domain_owner_is_inside() -> None:
    assert _drive_rules(_snapshot([_file(owners=("a@alias.example.net",))])) == KEPT


def test_uppercase_tenant_domain_owner_is_inside() -> None:
    assert _drive_rules(_snapshot([_file(owners=("a@EXAMPLE.COM",))])) == KEPT


def test_the_domain_label_is_part_of_the_tenant_even_when_the_directory_lacks_it() -> None:
    snapshot = _snapshot([_file(owners=("a@label.test",))], domain="label.test")
    assert snapshot["snapshot"]["internal_domains_source"] == "directory+label"
    assert _drive_rules(snapshot) == KEPT


def test_suffix_lookalike_of_a_tenant_domain_is_outside_not_inside() -> None:
    assert _drive_rules(_snapshot([_file(owners=("a@example.com.evil.test",))])) == []


def test_tenant_domain_as_a_subdomain_of_the_owner_domain_is_not_a_suffix_match() -> None:
    assert _drive_rules(_snapshot([_file(owners=("a@sub.example.com",))])) == []


@pytest.mark.parametrize(
    "owners",
    [
        None,
        [],
        "owner@outside.test",
        {"emailAddress": "owner@outside.test"},
        [None],
        ["owner@outside.test"],
        [{}],
        [{"displayName": "Someone"}],
        [{"emailAddress": None}],
        [{"emailAddress": ""}],
        [{"emailAddress": 7}],
        [{"emailAddress": "no-at-sign"}],
        [{"emailAddress": "a@b@outside.test"}],
        [{"emailAddress": "@outside.test"}],
        [{"emailAddress": "a@"}],
        [{"emailAddress": "a@bad domain.test"}],
        [{"emailAddress": "a@outside.test"}, {"displayName": "no email"}],
        [{"emailAddress": "a@outside.test"}, "b@outside.test"],
    ],
)
def test_unreadable_owners_keep_every_finding(owners: Any) -> None:
    assert _drive_rules(_snapshot([_file(owners=owners)])) == KEPT


def test_shared_drive_file_keeps_every_finding_even_with_outside_owners() -> None:
    assert _drive_rules(_snapshot([_file(driveId="drive-1")])) == KEPT


def test_record_without_the_shared_drive_marker_is_unknown_and_kept() -> None:
    snapshot = _snapshot([_file()])
    record = snapshot["google_drive_files"]["records"][0]
    assert record["in_shared_drive"] is False
    del record["in_shared_drive"]
    assert _drive_rules(snapshot) == KEPT


def test_shared_drive_marker_is_written() -> None:
    snapshot = _snapshot([_file("f1"), _file("f2", driveId="drive-1")])
    markers = {r["id"]: r["in_shared_drive"] for r in snapshot["google_drive_files"]["records"]}
    assert markers == {"f1": False, "f2": True}


@pytest.mark.parametrize(
    "directory,domain,expected",
    [
        (None, "example.com", KEPT),  # the label alone is not a complete list
        ([], "example.com", KEPT),  # an empty Directory list leaves the label alone
        (None, None, LINK_ONLY),  # nothing known: no principal is judged external, as before this fix
    ],
)
def test_label_only_empty_or_unknown_domains_keep_every_finding(directory: Any, domain: Any, expected: list[str]) -> None:
    snapshot = _snapshot([_file()], directory=directory, domain=domain)
    assert snapshot["snapshot"]["internal_domains_status"] in {"label_only", "unknown"}
    assert _drive_rules(snapshot) == expected


def test_partial_directory_list_keeps_every_finding() -> None:
    snapshot = _snapshot(
        [_file()],
        coverage_rows=[{"collector": "google_directory", "name": "domains", "status": "partial"}],
    )
    assert snapshot["snapshot"]["internal_domains_status"] == "partial"
    assert _drive_rules(snapshot) == KEPT


def test_snapshot_without_a_domains_status_keeps_every_finding() -> None:
    snapshot = _snapshot([_file()])
    for key in ("internal_domains_status", "internal_domains_source"):
        del snapshot["snapshot"][key]
    assert _drive_rules(snapshot) == KEPT


def test_label_only_status_is_not_a_complete_list_even_if_marked_known() -> None:
    snapshot = _snapshot([_file()], directory=None)
    snapshot["snapshot"]["internal_domains_status"] = "known"
    assert _drive_rules(snapshot) == KEPT


@pytest.mark.parametrize("declared", [None, "example.com", {"example.com": 1}])
def test_unreadable_declared_domains_fall_back_to_the_label_and_keep_every_finding(declared: Any) -> None:
    snapshot = _snapshot([_file()])
    snapshot["snapshot"]["internal_domains"] = declared
    assert _drive_rules(snapshot) == KEPT


def test_empty_declared_domains_keep_every_file_in_scope() -> None:
    snapshot = _snapshot([_file()])
    snapshot["snapshot"]["internal_domains"] = []
    assert _drive_rules(snapshot) == LINK_ONLY


def test_files_without_permissions_and_malformed_owner_rows_do_not_break_findings() -> None:
    snapshot = _snapshot([{"id": "f1", "owners": "x"}, _file("f2", owners=("a@example.com",))])
    assert _drive_rules(snapshot) == KEPT


# ---- LIVE-FIX-6 L1a: a domain or alias row that cannot be read makes the domain set partial ---------------------

PRIMARY = {"domainName": "example.com", "isPrimary": True, "verified": True}
UNREADABLE_DIRECTORIES = [
    [{**PRIMARY, "domainAliases": [None]}],
    [{**PRIMARY, "domainAliases": [{}]}],
    [{**PRIMARY, "domainAliases": [{"domainAliasName": None}]}],
    [{**PRIMARY, "domainAliases": [{"domainAliasName": ""}]}],
    [{**PRIMARY, "domainAliases": [{"domainAliasName": 5}]}],
    [{**PRIMARY, "domainAliases": [{"domainAliasName": "not a domain"}]}],
    [{**PRIMARY, "domainAliases": ["alias.example.net"]}],
    [{**PRIMARY, "domainAliases": None}],
    [{**PRIMARY, "domainAliases": "alias.example.net"}],
    [{**PRIMARY, "domainAliases": {"domainAliasName": "alias.example.net"}}],
    [PRIMARY, None],
    [PRIMARY, "example.org"],
    [PRIMARY, {"domainName": None}],
    [PRIMARY, {"domainName": ""}],
    [PRIMARY, {"domainName": "-bad-.example"}],
    [PRIMARY, {"domain": "example.org"}],
]


@pytest.mark.parametrize("directory", UNREADABLE_DIRECTORIES)
def test_live_fix_6_l1a_an_unreadable_domain_or_alias_row_keeps_every_finding(directory: list[Any]) -> None:
    from auditex.google_workspace.drive_scope import tenant_domain_names

    snapshot = _snapshot([_file()], directory=directory)
    assert snapshot["snapshot"]["internal_domains_status"] == "partial"
    assert _drive_rules(snapshot) == KEPT
    # The collector's reading of the same list agrees: not a complete set.
    assert tenant_domain_names(directory) is None


def test_live_fix_6_l1a_reviewer_scenario_an_owner_on_an_alias_lost_to_a_null_alias_row() -> None:
    """The alias was in the complete baseline; a null alias row in the later list must not make its owner outside."""
    owned = _file(owners=("owner@alias.example.net",))
    complete = _snapshot([owned])
    assert complete["snapshot"]["internal_domains_status"] == "known"
    assert _drive_rules(complete) == KEPT
    broken = _snapshot([owned], directory=[{**PRIMARY, "domainAliases": [None]}])
    assert broken["snapshot"]["internal_domains_status"] == "partial"
    assert _drive_rules(broken) == KEPT


@pytest.mark.parametrize("marker", [
    {"error_class": "malformed_response", "error": "domains: a read of this list failed or could not be read in full "
                                                   "(malformed_response)."},
    {"status": "partial", "error_class": "client_error"},
    {"collection_truncated": True, "truncation_reason": "pagination_failed"},
])
def test_live_fix_6_l1a_a_marked_domains_section_is_partial(marker: dict[str, Any]) -> None:
    payloads = {"google_drive_posture": {"driveFiles": {"value": [_file()]}},
                "google_directory": {"domains": {"value": DIRECTORY, **marker}}}
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="run-1", collector_payloads=payloads, domain="example.com")
    assert snapshot["snapshot"]["internal_domains_status"] == "partial"
    assert _drive_rules(snapshot) == KEPT


def test_live_fix_6_l1a_a_readable_list_stays_known_for_both_readers() -> None:
    from auditex.google_workspace.drive_scope import tenant_domain_names

    directory = [{**PRIMARY, "domainAliases": [{"domainAliasName": "alias.example.net"}]},
                 {"domainName": "Example.ORG", "isPrimary": False}]
    snapshot = _snapshot([_file()], directory=directory)
    assert snapshot["snapshot"]["internal_domains_status"] == "known"
    assert tenant_domain_names(directory) == frozenset({"example.com", "alias.example.net", "example.org"})
    assert _drive_rules(snapshot) == []


# ---- LIVE-FIX-7 item 3: an alias list of the wrong type never crashes normalisation; the set is partial ------------

@pytest.mark.parametrize("aliases", [True, False, 5, 1.5, "alias.example.net", {"domainAliasName": "alias.example.net"}, ""])
def test_live_fix_7_domain_aliases_of_the_wrong_type_make_the_domain_set_partial(aliases: Any) -> None:
    owned = _file(owners=("owner@alias.example.net",))
    snapshot = _snapshot([owned], directory=[{**PRIMARY, "domainAliases": aliases}])
    assert snapshot["snapshot"]["internal_domains_status"] == "partial"
    assert [record["domain_name"] for record in snapshot["google_domains"]["records"]] == ["example.com"]
    assert _drive_rules(snapshot) == KEPT

"""LIVE-FIX-8: the Reports customer id paths are checked through every object beneath them, against discovery.

Activity.id, resourceDetails (and everything under it), ownerDetails, ownerIdentity and UsageReport.entity must have
their Admin Reports v1 discovery shape at every level: each object only its own members, each member of its own type,
each array only items of its item type. Anything off schema withholds the top-level field whole.

The validator's table is compared with a vendored subset of the discovery document
(``tests/fixtures/admin-reports-v1-customer-id-paths.json``), and that subset with the document shipped with the
installed google-api-python-client, so a member Google adds or changes fails here instead of passing or leaking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import customer_id as cid
from auditex.google_workspace.customer_id import CustomerIds

CUSTOMER = "C00000000"
_TIME = "2026-11-01T00:00:00Z"
_FIXTURE = Path(__file__).parent / "fixtures" / "admin-reports-v1-customer-id-paths.json"
# The roots the scrub checks as top-level fields: owner member names and the members they read.
_ROOTS = (("Activity", ("id", "resourceDetails")), ("UsageReport", ("entity",)))
# Refinements the validator applies to a discovery type (its form, not a different type).
_REFINED = {"application-name": "string"}


def _discovery_type(owner: str, member: str, node: dict[str, Any], inline: dict[str, dict[str, Any]]) -> Any:
    if "$ref" in node:
        return node["$ref"]
    kind, form = node.get("type"), node.get("format")
    if kind == "array":
        return ("array", _discovery_type(owner, member, node["items"], inline))
    if kind == "object" and "properties" in node:
        name = f"{owner}.{member}"
        inline[name] = node
        return name
    if kind == "string":
        return {None: "string", "int64": "int64", "date-time": "date-time"}.get(form, f"string:{form}")
    if kind == "integer":
        return "int32" if form == "int32" else f"integer:{form}"
    if kind == "boolean" and form is None:
        return "boolean"
    return f"unsupported:{json.dumps(node, sort_keys=True)}"


def _reachable(schemas: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every object type reachable from the customer id roots, as {schema: {member: type}}, in the validator's terms."""
    table: dict[str, dict[str, Any]] = {}
    inline: dict[str, dict[str, Any]] = {}
    todo: list[Any] = []
    for owner, members in _ROOTS:
        for member in members:
            todo.append(_discovery_type(owner, member, schemas[owner]["properties"][member], inline))
    while todo:
        kind = todo.pop()
        if isinstance(kind, tuple):
            todo.append(kind[1])
            continue
        if kind in table or kind in {"string", "int64", "date-time", "int32", "boolean"} or ":" in kind:
            continue
        node = inline.get(kind) or schemas[kind]
        table[kind] = {
            member: _discovery_type(kind, member, spec, inline) for member, spec in node.get("properties", {}).items()
        }
        todo.extend(table[kind].values())
    return table


def _root_types(schemas: dict[str, Any]) -> dict[str, Any]:
    """The discovery type of each customer id root member itself (a list of ResourceDetails, an Activity id object),
    so a change of a root's container shows up even when the objects beneath it are unchanged."""
    inline: dict[str, dict[str, Any]] = {}
    return {
        f"{owner}.{member}": _discovery_type(owner, member, schemas[owner]["properties"][member], inline)
        for owner, members in _ROOTS
        for member in members
    }


def _validator_table() -> dict[str, dict[str, Any]]:
    return {
        name: {member: _REFINED.get(kind, kind) if isinstance(kind, str) else kind for member, kind in members}
        for name, members in cid._report_shapes().items()
    }


def test_validator_covers_every_member_of_the_vendored_discovery_subset_and_no_other() -> None:
    expected = _reachable(json.loads(_FIXTURE.read_text(encoding="utf-8"))["schemas"])
    actual = _validator_table()
    assert sorted(actual) == sorted(expected), "Reports object types differ from discovery"
    for name in expected:
        assert actual[name] == expected[name], f"{name}: validator members differ from discovery"


def test_vendored_subset_matches_the_installed_google_api_python_client_document() -> None:
    googleapiclient = pytest.importorskip("googleapiclient")
    path = Path(googleapiclient.__file__).parent / "discovery_cache" / "documents" / "admin.reports_v1.json"
    assert path.is_file(), f"google-api-python-client no longer ships {path.name}"
    installed = json.loads(path.read_text(encoding="utf-8"))
    vendored = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert _root_types(installed["schemas"]) == _root_types(vendored["schemas"]), (
        f"admin.reports_v1 revision {installed.get('revision')} changed the type of a customer id root; update "
        "customer_id._malformed_report_field, customer_id._report_shapes and the fixture"
    )
    assert _reachable(installed["schemas"]) == _reachable(vendored["schemas"]), (
        f"admin.reports_v1 revision {installed.get('revision')} changed a customer id path object; update "
        "customer_id._report_shapes and the fixture"
    )


def _good(kind: Any) -> Any:
    if isinstance(kind, tuple):
        return [_good(kind[1])]
    return {"string": "x", "boolean": True, "int64": "1", "int32": 1, "date-time": _TIME,
            "application-name": "admin"}.get(kind, {})


_SWEEP = [
    (name, member, kind) for name, members in cid._report_shapes().items() for member, kind in members
    # Checked as fields of their own (tests/test_google_customer_identity.py): a malformed one is withheld alone, as
    # is a customerIdentity whose id is not a string.
    if not cid._own_field(member) and "CustomerIdentity" not in (name, kind)
]


@pytest.mark.parametrize(("name", "member", "kind"), _SWEEP, ids=[f"{n}.{m}" for n, m, _ in _SWEEP])
def test_every_member_refuses_a_value_of_another_type_and_accepts_its_own(name: str, member: str, kind: Any) -> None:
    assert cid._conforms({member: _good(kind)}, name)
    wrong = [CUSTOMER, 7, 1.5, True, None, [CUSTOMER], [7], {"x": CUSTOMER}, [{"x": CUSTOMER}]]
    accepted = [value for value in wrong if cid._conforms({member: value}, name)]
    allowed = {"string": [CUSTOMER], "boolean": [True], "int32": [7], ("array", "string"): [[CUSTOMER]]}.get(kind, [])
    assert accepted == allowed


@pytest.mark.parametrize("name", sorted(cid._report_shapes()))
def test_every_object_refuses_an_undeclared_member_and_a_value_of_another_shape(name: str) -> None:
    for value in ({"owner": CUSTOMER}, CUSTOMER, [CUSTOMER], [{}], 7, None):
        assert not cid._conforms(value, name) or (name == "CustomerIdentity" and cid._malformed_container(
            "customeridentity", value)), value


# ---- literal values: AppliedLabel, FieldValue and Reason ---------------------------------------------------------


def _activity(applied_labels: Any) -> dict[str, Any]:
    return {"kind": "admin#reports#activity", "id": {"time": _TIME, "uniqueQualifier": "1"},
            "resourceDetails": [{"id": "r1", "appliedLabels": applied_labels}]}


def _label(**members: Any) -> dict[str, Any]:
    return {"id": "l1", "title": "Secret", **members}


def _field(**members: Any) -> dict[str, Any]:
    return {"id": "f1", "displayName": "Owner", "type": "TEXT", **members}


WRONG_LABELS = [
    # The reviewer's reproduction: a scalar customer id as a FieldValue.
    [{"fieldValues": [CUSTOMER]}],
    # AppliedLabel level.
    CUSTOMER, [CUSTOMER], [[CUSTOMER]], [_label(owner=CUSTOMER)], [_label(title=[CUSTOMER])],
    [_label(fieldValues=CUSTOMER)], [_label(fieldValues={"id": CUSTOMER})],
    # FieldValue level.
    [_label(fieldValues=[[CUSTOMER]])], [_label(fieldValues=[_field(owner=CUSTOMER)])],
    [_label(fieldValues=[_field(textValue=[CUSTOMER])])], [_label(fieldValues=[_field(textValue=5)])],
    [_label(fieldValues=[_field(longTextValue={"v": CUSTOMER})])], [_label(fieldValues=[_field(id=None)])],
    [_label(fieldValues=[_field(integerValue=CUSTOMER)])], [_label(fieldValues=[_field(integerValue=5)])],
    [_label(fieldValues=[_field(integerValue="1.5")])], [_label(fieldValues=[_field(unsetValue="true")])],
    [_label(fieldValues=[_field(unsetValue=CUSTOMER)])],
    # Reason, under AppliedLabel and under FieldValue.
    [_label(reason=CUSTOMER)], [_label(reason=[CUSTOMER])], [_label(reason={"reasonType": [CUSTOMER]})],
    [_label(reason={"reasonType": 5})], [_label(reason={"owner": CUSTOMER})],
    [_label(fieldValues=[_field(reason=CUSTOMER)])], [_label(fieldValues=[_field(reason=[CUSTOMER])])],
    [_label(fieldValues=[_field(reason={"reasonType": {"id": CUSTOMER}})])],
    [_label(fieldValues=[_field(reason={"reasonType": "USER", "customer": CUSTOMER})])],
    # Date.
    [_label(fieldValues=[_field(dateValue=CUSTOMER)])], [_label(fieldValues=[_field(dateValue=[2026, 11, 1])])],
    [_label(fieldValues=[_field(dateValue={"day": "1"})])], [_label(fieldValues=[_field(dateValue={"day": True})])],
    [_label(fieldValues=[_field(dateValue={"year": 2**31})])],
    [_label(fieldValues=[_field(dateValue={"year": 2026, "era": CUSTOMER})])],
    # Selection value and selection list.
    [_label(fieldValues=[_field(selectionValue=CUSTOMER)])], [_label(fieldValues=[_field(selectionValue=[CUSTOMER])])],
    [_label(fieldValues=[_field(selectionValue={"badged": "yes"})])],
    [_label(fieldValues=[_field(selectionValue={"id": 5})])],
    [_label(fieldValues=[_field(selectionValue={"id": "s1", "owner": CUSTOMER})])],
    [_label(fieldValues=[_field(selectionListValue=CUSTOMER)])],
    [_label(fieldValues=[_field(selectionListValue=[{"id": "s1"}])])],
    [_label(fieldValues=[_field(selectionListValue={"values": CUSTOMER})])],
    [_label(fieldValues=[_field(selectionListValue={"values": [CUSTOMER]})])],
    [_label(fieldValues=[_field(selectionListValue={"values": [{"id": [CUSTOMER]}]})])],
    [_label(fieldValues=[_field(selectionListValue={"values": [], "owner": CUSTOMER})])],
    # Text list.
    [_label(fieldValues=[_field(textListValue=CUSTOMER)])], [_label(fieldValues=[_field(textListValue=[CUSTOMER])])],
    [_label(fieldValues=[_field(textListValue={"values": CUSTOMER})])],
    [_label(fieldValues=[_field(textListValue={"values": [5]})])],
    [_label(fieldValues=[_field(textListValue={"values": [[CUSTOMER]]})])],
    [_label(fieldValues=[_field(textListValue={"values": [{"v": CUSTOMER}]})])],
    # User value and user list.
    [_label(fieldValues=[_field(userValue=CUSTOMER)])], [_label(fieldValues=[_field(userValue=[CUSTOMER])])],
    [_label(fieldValues=[_field(userValue={"email": 5})])],
    [_label(fieldValues=[_field(userValue={"email": "ada@example.com", "id": CUSTOMER})])],
    [_label(fieldValues=[_field(userListValue=CUSTOMER)])],
    [_label(fieldValues=[_field(userListValue={"values": [CUSTOMER]})])],
    [_label(fieldValues=[_field(userListValue={"values": [{"email": [CUSTOMER]}]})])],
    [_label(fieldValues=[_field(userListValue={"values": {"email": "ada@example.com"}})])],
]


@pytest.mark.parametrize("applied_labels", WRONG_LABELS)
def test_applied_labels_off_schema_at_any_level_withhold_the_resource_details_whole(applied_labels: Any) -> None:
    rows = [_activity(applied_labels)]
    safe, changed = CustomerIds().evidence(rows)
    assert safe == [{"kind": "admin#reports#activity", "id": {"time": _TIME, "uniqueQualifier": "1"},
                     "resourceDetails": "<customer-id>"}]
    assert changed is False
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


WELL_FORMED_FIELDS = [
    _field(textValue="Finance", reason={"reasonType": "USER_APPLIED"}),
    _field(type="LONG_TEXT", longTextValue="Quarterly figures"),
    _field(type="INTEGER", integerValue="-9223372036854775808"),
    _field(type="DATE", dateValue={"year": 2026, "month": 11, "day": 1}),
    _field(type="DATE", dateValue={"year": 2026, "month": 0, "day": 0}),
    _field(type="SELECTION", selectionValue={"id": "s1", "displayName": "Confidential", "badged": True}),
    _field(type="SELECTION_LIST", selectionListValue={"values": [
        {"id": "s1", "displayName": "Confidential", "badged": False}, {"id": "s2"}]}),
    _field(type="TEXT_LIST", textListValue={"values": ["alpha", "beta"]}),
    _field(type="USER", userValue={"email": "ada@example.com"}),
    _field(type="USER_LIST", userListValue={"values": [{"email": "ada@example.com"}, {"email": "bob@example.com"}]}),
    _field(unsetValue=True),
    {},
]


def test_a_well_formed_applied_label_with_every_field_value_kind_is_kept_whole() -> None:
    rows = [_activity([_label(fieldValues=WELL_FORMED_FIELDS, reason={"reasonType": "AUTOMATIC"}), {}])]
    assert CustomerIds().evidence(rows) == (rows, False)
    assert CustomerIds().scrub(rows) == rows
    # Every FieldValue member of the discovery document appears above, so none is kept only by being absent.
    kinds = {member for field in WELL_FORMED_FIELDS for member in field}
    assert kinds == set(dict(cid._report_shapes()["FieldValue"]))


def test_a_root_container_change_is_caught_even_when_the_objects_beneath_it_are_unchanged() -> None:
    vendored = json.loads(_FIXTURE.read_text(encoding="utf-8"))["schemas"]
    changed = json.loads(json.dumps(vendored))
    changed["Activity"]["properties"]["resourceDetails"] = {"$ref": "ResourceDetails"}
    assert _reachable(changed) == _reachable(vendored)
    assert _root_types(changed) != _root_types(vendored)
    assert _root_types(vendored)["Activity.resourceDetails"] == ("array", "ResourceDetails")

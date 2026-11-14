"""D5: every directory person's name is masked in shareable output, using synthetic values only."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest
from test_reporting import _write_run

from azure_tenant_audit import output_redaction as redaction
from azure_tenant_audit.output_redaction import (
    PSEUDONYM_KEY_PATH,
    RedactionContext,
    ensure_pseudonym_key,
    pseudonym,
    redact_output,
)

NAME = "Priya Kovalenko"
UPN = "priya.kovalenko@contoso.example"
SHAREABLE_PROFILES = ("shareable", "customer_pack", "explainer")
TOKENS = ("priya", "kovalenko")
KEY = bytes(range(32))


def _no_tokens(text: str) -> bool:
    return not any(word.lower() in TOKENS for word in re.findall(r"[A-Za-z]+", text))


def _user(name: str = NAME, upn: str = UPN, **extra: object) -> dict:
    return {"kind": "user", "display_name": name, "principal_name": upn, "user_type": "Member", **extra}


def _run(root: Path, users: list[dict], narrative: str = f"Mailbox of {NAME} was shared") -> Path:
    _write_run(root)
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"]["narrative"] = narrative
    report.write_text(json.dumps(payload))
    (root / "normalized" / "users.json").write_text(json.dumps({"kind": "users", "records": users}))
    ensure_pseudonym_key(root)  # as collection does when it seals a run
    return root


def _key(root: Path) -> bytes:
    """The run's private key, read as plain bytes (the pseudonyms of every output derived from the run)."""
    return (root / PSEUDONYM_KEY_PATH).read_bytes()


@pytest.fixture
def run(tmp_path: Path) -> Path:
    return _run(tmp_path / "run", [_user()])


def _context(*users: dict, key: bytes = KEY, vocabulary: frozenset[str] = frozenset()) -> RedactionContext:
    """A context whose index holds ``users``, as ``context_for_run`` builds it from a run."""
    found = redaction._Found()
    redaction._collect({"records": list(users)}, found, names=True)
    index = redaction._build_index(found.persons, redaction._vocabulary_phrases(vocabulary))
    return RedactionContext(key=key, vocabulary=vocabulary, unmatched_names=index.counts(), _index=index)


def _prose(key: bytes = KEY, name: str = NAME) -> str:
    return "User " + pseudonym(key, name)


def _id(key: bytes = KEY, name: str = NAME) -> str:
    return "user-" + pseudonym(key, name)


# 1. narrative text in another section, every non-local profile; local keeps it


@pytest.mark.parametrize("profile", SHAREABLE_PROFILES)
def test_non_privileged_user_name_in_another_section_is_masked(run: Path, profile: str) -> None:
    from auditex.reporting import preview_report

    for fmt in ("json", "md", "html"):
        content = preview_report(run_dir=str(run), format_name=fmt, include_sections=["executive_summary"], profile=profile)["content"]
        assert _no_tokens(content), (fmt, content)
        assert _prose(_key(run)) in content


def test_local_profile_keeps_the_name(run: Path) -> None:
    from auditex.reporting import preview_report

    content = preview_report(run_dir=str(run), format_name="md", include_sections=["executive_summary"], profile="local")["content"]
    assert NAME in content
    assert redact_output({"text": NAME}, profile="local", context=redaction.context_for_run(run)) == {"text": NAME}


# 2. person shapes


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "google_user", "full_name": NAME, "primary_email": UPN},
        {"@odata.type": "#microsoft.graph.user", "displayName": NAME, "userPrincipalName": UPN},
        {"kind": "admin#directory#user", "primaryEmail": UPN, "name": {"givenName": "Priya", "familyName": "Kovalenko", "fullName": NAME}},
        {"id": "1", "displayName": NAME, "userPrincipalName": UPN},  # a user reference (audit initiator)
    ],
)
def test_person_shapes_are_discovered(record: dict) -> None:
    result = redact_output({"who": record, "text": f"changed by {NAME}"}, context=RedactionContext(key=KEY))
    assert result["text"] == f"changed by {_prose()}"
    assert _no_tokens(json.dumps(result))


def test_groups_and_service_principals_are_not_persons() -> None:
    value = {"records": [{"principalType": "Group", "displayName": "Bodatix Kemuraz", "userPrincipalName": "g@x.example"}],
             "text": "Bodatix Kemuraz"}
    assert redact_output(value, context=RedactionContext())["text"] == "Bodatix Kemuraz"


# 3. id forms


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("login priya.kovalenko today", f"login {_id()} today"),
        ("https://contoso-my.sharepoint.com/personal/priya_kovalenko_contoso_example/Documents",
         f"https://contoso-my.sharepoint.com/personal/{_id()}/Documents"),
        ("sam priya-kovalenko", f"sam {_id()}"),
        ("concatenated priyakovalenko here", f"concatenated {_prose()} here"),
        ("path /home/priyakovalenko/x", f"path /home/{_id()}/x"),
        ("PRIYA_KOVALENKO", _id()),
    ],
)
def test_id_forms_are_masked(text: str, expected: str) -> None:
    assert redact_output(text, context=_context(_user())) == expected


def test_single_token_local_part_is_masked_in_full_address_form() -> None:
    context = _context(_user("Priya Kovalenko", "akovalenko@contoso.example"))
    out = redact_output("site /personal/akovalenko_contoso_example/ and akovalenko alone", context=context)
    assert out == f"site /personal/{_id()}/ and akovalenko alone"


def test_id_form_has_no_whitespace_and_url_stays_one_token() -> None:
    out = redact_output("https://x.example/personal/priya_kovalenko_contoso_example?x=1", context=_context(_user()))
    assert " " not in out and _no_tokens(out)


# 4. prose pseudonym equals the structured one


def test_prose_pseudonym_equals_structured_display_name(run: Path) -> None:
    context = redaction.context_for_run(run)
    out = redact_output({"user": _user(), "text": f"{NAME} signed in"}, context=context)
    assert out["user"]["display_name"] == _prose(_key(run))
    assert out["text"] == f"{_prose(_key(run))} signed in"


# 5. variants and boundaries


@pytest.mark.parametrize("text", ["priya kovalenko", "PRIYA KOVALENKO", "Priya \n\t Kovalenko", "\uff30riya Kovalenko", "Priya\u00a0Kovalenko"])
def test_case_whitespace_and_nfkc_variants_match(text: str) -> None:
    assert redact_output(text, context=_context(_user())) == _prose()


def test_possessive_keeps_the_suffix() -> None:
    assert redact_output(f"{NAME}'s mailbox", context=_context(_user())) == f"{_prose()}'s mailbox"


def test_sentence_full_stop_keeps_prose_form() -> None:
    assert redact_output(f"Owned by {NAME}.", context=_context(_user())) == f"Owned by {_prose()}."


@pytest.mark.parametrize("text", ["Mpriya Kovalenkoers", "priya_kovalenkoers", "Priya2 Kovalenko", "mpriya.kovalenko"])
def test_partial_tokens_do_not_match(text: str) -> None:
    assert redact_output(text, context=_context(_user())) == text


# 6. false-positive guard and the unmatched report


GUARDED = [
    ("Open", "open@contoso.example", "vocabulary"),
    ("Global Administrator", "ga@contoso.example", "vocabulary"),  # a role name found by discovery
    ("Finance Team", "ft@contoso.example", "common_word"),
    ("Admin", "admin@contoso.example", "common_word"),
    ("svc_backup", "svc@contoso.example", "structural"),
    ("Meeting Room", "mr@contoso.example", "common_word"),
    ("Bo", "bo@contoso.example", "too_short"),
    ("12345", "n@contoso.example", "no_letters"),
    ("Aa Bb Cc Dd Ee Ff Gg", "seven@contoso.example", "too_many_tokens"),
    ("Ops Crew", "crew@contoso.example", "vocabulary"),  # a group name found by discovery
]


def test_guard_keeps_words_and_reports_reasons_without_names() -> None:
    users = [_user(name, upn) for name, upn, _ in GUARDED]
    vocabulary = frozenset({"global administrator", "ops crew"})
    context = _context(*users, vocabulary=vocabulary)
    for name, _upn, _reason in GUARDED:
        assert redact_output(f"x {name} y", context=context) == f"x {name} y", name
    structured = redact_output({"records": users}, context=context)["records"]
    for row, (name, _upn, _reason) in zip(structured, GUARDED, strict=False):
        assert row["display_name"] == _prose(name=name)
    expected: dict[str, int] = {}
    for _name, _upn, reason in GUARDED:
        expected[reason] = expected.get(reason, 0) + 1
    assert dict(context.unmatched_names) == expected
    assert [reason for reason, _ in context.unmatched_names] == [r for r in redaction.D5_REASONS if r in expected]
    note = redaction.unmatched_names_note(context)
    assert note.startswith(f"Name masking: {len(GUARDED)} directory people")
    assert not any(name in note for name, _upn, _reason in GUARDED if len(name) > 2)


def test_guard_from_a_run_counts_role_and_group_names(tmp_path: Path) -> None:
    root = _run(tmp_path / "run", [_user(), _user("Ops Crew", "crew@contoso.example")])
    (root / "normalized" / "groups.json").write_text(json.dumps({"records": [{"principalType": "Group", "displayName": "Ops Crew"}]}))
    context = redaction.context_for_run(root)
    assert context.unmatched_names == (("vocabulary", 1),)
    assert redact_output("Ops Crew and Priya Kovalenko", context=context) == f"Ops Crew and {_prose(_key(root))}"


def test_value_level_group_name_is_checked_at_lookup() -> None:
    context = _context(_user("Kemi Rotax", "kemi.rotax@contoso.example"))
    value = {"groups": [{"principalType": "Group", "displayName": "Kemi Rotax"}], "text": "Kemi Rotax"}
    assert redact_output(value, context=context)["text"] == "Kemi Rotax"


def test_a_short_spelling_is_reported_even_when_another_spelling_masks_the_person() -> None:
    context = _context(_user("Bo", "bo@contoso.example", given_name="Bodil", surname="Ostergaard"))
    assert context.unmatched_names == (("too_short", 1),)  # "Bo" as written stays readable, so it is counted
    assert redact_output("Bodil Ostergaard", context=context) == _prose(name="Bo")
    assert redact_output("Ostergaard Bodil", context=context) == _prose(name="Bo")  # family plus given


@pytest.mark.parametrize("given", [{}, {"given_name": "Priya", "surname": "Kovalenko"}])
def test_comma_form_and_its_swap_are_masked_in_narrative(given: dict) -> None:
    listed = "Kovalenko, Priya"
    context = _context(_user(listed, UPN, **given))
    assert context.unmatched_names == ()
    text = f"Mailbox of {listed} and of Kovalenko,Priya was shared; Priya Kovalenko agreed."
    out = redact_output(text, context=context, profile="shareable")
    pseudonymised = _prose(name=listed)
    assert out == f"Mailbox of {pseudonymised} and of {pseudonymised} was shared; {pseudonymised} agreed.", out
    assert _no_tokens(out)


def test_a_spelling_the_matcher_cannot_follow_is_reported() -> None:
    context = _context(_user("Kovalenko (Priya)", UPN, given_name="Priya", surname="Kovalenko"))
    assert context.unmatched_names == (("separator", 1),)
    assert "(separator 1)" in redaction.unmatched_names_note(context)
    assert redact_output({"records": [_user("Kovalenko (Priya)", UPN)]}, context=context)["records"][0][
        "display_name"] == _prose(name="Kovalenko (Priya)")


def test_a_separator_spelling_in_another_record_is_reported() -> None:
    reference = {"initiatedBy": {"user": {"id": "u1", "displayName": "Kovalenko (Priya)", "userPrincipalName": UPN}}}
    context = _context(_user(id="u1"), reference)
    assert context.unmatched_names == (("separator", 1),)
    out = redact_output("Updated by Kovalenko (Priya); Priya Kovalenko agreed", context=context)
    assert out.startswith("Updated by Kovalenko (Priya); User ")  # readable, and never with an empty count


def test_the_note_is_true_for_every_reason() -> None:
    for reason in redaction.D5_REASONS:
        note = redaction.unmatched_names_note(RedactionContext(unmatched_names=((reason, 1),)))
        assert note.startswith("Name masking: 1 directory people have names that cannot be matched safely in free text")
        assert f"({reason} 1)" in note and "too short or too common" not in note
        assert "a person whose name is a vocabulary word is still masked in values and free text." in note
        assert "left as written" not in note


def test_distinct_namesakes_are_two_people() -> None:
    namesakes = _context(_user("Bo", "bo@contoso.example", id="obj-1"), _user("Bo", "bo@fabrikam.example", id="obj-2"))
    assert namesakes.unmatched_names == (("too_short", 2),)
    no_id = _context(_user("Bo", "bo@contoso.example"), _user("Bo", "bo@fabrikam.example"))
    assert no_id.unmatched_names == (("too_short", 2),)
    covered = _context(
        _user(id="obj-1"),
        _user(upn="priya.k@fabrikam.example", id="obj-2"),
        {"initiatedBy": {"user": {"id": "obj-2", "displayName": "Kovalenko (Priya)", "userPrincipalName": UPN}}},
    )
    assert covered.unmatched_names == (("separator", 1),)  # a matched namesake neither covers nor joins obj-2


def test_repeated_references_to_one_person_count_once() -> None:
    context = _context(
        _user("Bo", "bo@contoso.example", id="OBJ-1"),
        {"initiatedBy": {"user": {"id": "obj-1", "displayName": "Bo", "userPrincipalName": "BO@contoso.example"}}},
        {"@odata.type": "#microsoft.graph.user", "id": "obj-1", "displayName": "Bo"},
        {"principalType": "User", "principalId": "obj-1", "roles": ["Reader"], "displayName": "Bo"},
        {"userPrincipalName": "bo@contoso.example", "displayName": "Bo"},
    )
    assert context.unmatched_names == (("too_short", 1),)


def test_two_object_ids_sharing_a_upn_are_two_people() -> None:
    reused = "bo@contoso.example"
    context = _context(_user("Bo", reused, id="obj-1"), _user("Bo", reused, id="obj-2"))
    assert context.unmatched_names == (("too_short", 2),)
    # A principal-name-only reference to the reused name cannot be attributed to either, so it is its own person.
    ambiguous = _context(_user("Bo", reused, id="obj-1"), _user("Bo", reused, id="obj-2"),
                         {"userPrincipalName": reused, "displayName": "Bo"})
    assert ambiguous.unmatched_names == (("too_short", 3),)


def test_a_upn_only_reference_joins_the_object_id_person() -> None:
    separator = "Kovalenko (Priya)"
    records = [
        _user(id="obj-1"),  # matched
        {"initiatedBy": {"user": {"id": "obj-1", "displayName": separator, "userPrincipalName": UPN}}},
        {"userPrincipalName": UPN.upper(), "displayName": separator},  # no object id: joins obj-1 through the UPN
    ]
    for ordered in (records, records[::-1], [records[2], records[0], records[1]]):
        assert _context(*ordered).unmatched_names == (("separator", 1),)
    # Joined to a person matched in every other record, the reference still counts that one person.
    assert _context(records[0], records[2]).unmatched_names == (("separator", 1),)
    unknown = {"userPrincipalName": "someone@contoso.example", "displayName": separator}
    assert _context(*records, unknown).unmatched_names == (("separator", 2),)


def test_three_merged_runs_keep_the_alias_links(tmp_path: Path) -> None:
    separator = "Kovalenko (Priya)"
    full = _run(tmp_path / "a", [_user(id="obj-1")])
    by_id = _run(tmp_path / "b", [_user(), {"principalType": "User", "principalId": "obj-1", "roles": ["Reader"],
                                            "displayName": separator}])
    by_upn = _run(tmp_path / "c", [_user(), {"userPrincipalName": UPN, "displayName": separator}])
    runs = [full, by_id, by_upn]
    for ordered in (runs, runs[::-1], [by_id, full, by_upn], [by_upn, by_id, full]):
        assert redaction.context_for_runs(ordered).unmatched_names == (("separator", 1),)
    assert redaction.context_for_runs([full, by_upn]).unmatched_names == (("separator", 1),)
    # Without the run that ties obj-1 to the UPN, nothing links the two references: two people.
    assert redaction.context_for_runs([by_id, by_upn]).unmatched_names == (("separator", 2),)


def test_two_run_merge_counts_each_person_once(tmp_path: Path) -> None:
    bo = {"id": "obj-1"}
    short = _run(tmp_path / "a", [_user("Bo", "bo@contoso.example", **bo)])
    full = _run(tmp_path / "b", [_user("Bodil Ostergaard", "bo@contoso.example", **bo)])
    again = _run(tmp_path / "c", [_user("Bo", "BO@contoso.example", **bo)])
    other = _run(tmp_path / "d", [_user("Bo", "bo@fabrikam.example", id="obj-2")])
    assert redaction.context_for_run(short).unmatched_names == (("too_short", 1),)
    assert redaction.context_for_run(full).unmatched_names == ()
    # A spelling matched in one run never covers a spelling that cannot be masked in another.
    assert redaction.context_for_runs([short, full]).unmatched_names == (("too_short", 1),)
    assert redaction.context_for_runs([full, short]).unmatched_names == (("too_short", 1),)
    assert redaction.context_for_runs([short, again]).unmatched_names == (("too_short", 1),)
    assert redaction.context_for_runs([short, again, other]).unmatched_names == (("too_short", 2),)
    assert redaction.context_for_runs([full, other]).unmatched_names == (("too_short", 1),)


def test_a_privileged_person_is_one_entry_through_context_for_run(tmp_path: Path) -> None:
    def admin(name: str, **extra: object) -> dict:
        return {"principalType": "User", "principalId": "obj-9", "roles": ["Reader"], "displayName": name, **extra}

    short = redaction.context_for_run(_run(tmp_path / "short", [admin("Bo")]))
    assert "Bo" in short.protected_names
    assert short.unmatched_names == (("too_short", 1),)  # one person, not a real and a synthetic one
    full_root = _run(tmp_path / "full", [admin("Bodil Ostergaard"), _user("Bodil Ostergaard", "bo@contoso.example")])
    full = redaction.context_for_run(full_root)
    assert full.unmatched_names == ()
    assert redact_output("Bodil Ostergaard", context=full) == _prose(_key(full_root), "Bodil Ostergaard")
    both = redaction.context_for_runs([tmp_path / "short", full_root])
    assert both.unmatched_names == (("too_short", 1),)
    # A context not built from a run still indexes the names it was given.
    given = RedactionContext(protected_names=frozenset({"Bodil Ostergaard"}))
    assert redact_output("Bodil Ostergaard", context=given) == _prose(given.key, "Bodil Ostergaard")


def test_key_saturation_keeps_the_required_forms_and_reports_limit() -> None:
    ids = {f: f"priya.kovalenko{n}@d{n}.example" for n, f in enumerate(
        ("user_principal_name", "primary_email", "mail", "mail_nickname", "on_premises_sam_account_name"))}
    user = _user("Kovalenko, Priya", UPN, full_name="Priya Q Kovalenko", given_name="Priya", surname="Kovalenko", **ids)
    found = redaction._Found()
    redaction._collect(user, found, names=True)
    (person,) = found.persons
    keys, reason = redaction._person_keys(person, frozenset())
    assert reason == "limit" and len(keys) == redaction._D5_MAX_KEYS_PER_PERSON
    assert {"kovalenko priya", "priya q kovalenko", "priya kovalenko"} <= set(keys[:3])
    context = _context(user)
    assert context.unmatched_names == (("limit", 1),)
    for text in ("Kovalenko, Priya", "Priya Kovalenko", "Kovalenko Priya", "Priya Q Kovalenko"):
        assert _no_tokens(redact_output(f"by {text}.", context=context)), text


# 7. the report note


def test_reports_carry_the_note_only_when_names_are_unmatched(tmp_path: Path) -> None:
    from auditex.reporting import preview_report

    plain = _run(tmp_path / "plain", [_user()])
    short = _run(tmp_path / "short", [_user(), _user("Bo", "bo@contoso.example")])
    options = {"include_sections": ["executive_summary"]}
    for fmt in ("md", "html"):
        assert "Name masking:" not in preview_report(run_dir=str(plain), format_name=fmt, profile="shareable", **options)["content"]
        content = preview_report(run_dir=str(short), format_name=fmt, profile="shareable", **options)["content"]
        assert "Name masking: 1 directory people have names that cannot be matched safely in free text" in content
        assert "(too_short 1)" in content
        if fmt == "html":
            assert content.index("Name masking:") < content.rindex("</body>")
    assert "Name masking:" not in preview_report(run_dir=str(short), format_name="json", profile="shareable", **options)["content"]
    assert "Name masking:" not in preview_report(run_dir=str(short), format_name="md", include_sections=["executive_summary"], profile="local")["content"]


# 8. mapping keys


def test_mapping_keyed_by_a_name_is_rewritten_with_collision_suffix() -> None:
    context = _context(_user())
    value = {NAME: 1, "priya kovalenko": 2, _prose(): 3, "priya_kovalenko": 4, "display_name": 5, "PriyaKovalenko": 6,
             "priya_kovalenko_mailbox": 7}
    out = redact_output(value, context=context)
    assert out == {_prose(): 3, f"{_prose()}#2": 1, f"{_prose()}#3": 2, _id(): 4, "display_name": 5, f"{_prose()}#4": 6,
                   "priya_kovalenko_mailbox": 7}  # a structural key is masked only when it is the name as a whole


# 9. group and role names (DEC-003)


def test_group_and_role_names_containing_a_full_name_are_masked() -> None:
    context = _context(_user())
    value = {"groups": [{"principalType": "Group", "displayName": f"Team {NAME}"}], "roles": [f"{NAME} Delegates"],
             "role_name": "Global Administrator", "group_name": "Operations Group"}
    out = redact_output(value, context=context)
    assert out["groups"][0]["displayName"] == f"Team {_prose()}"
    assert out["roles"] == [f"{_prose()} Delegates"]
    assert out["role_name"] == "Global Administrator" and out["group_name"] == "Operations Group"


# 10. idempotence


def test_second_pass_changes_nothing_and_user_does_not_rematch() -> None:
    context = _context(_user(), _user("User", "user@contoso.example"), _user("User Kovalenko", "us@contoso.example"))
    value = {"text": f"{NAME} met priya.kovalenko at /personal/priya_kovalenko_contoso_example"}
    once = redact_output(value, context=context)
    assert redact_output(once, context=context) == once
    assert redact_output(once, context=context, markup=True) == once
    assert "User Kovalenko" not in once["text"]


# 11. markup


def test_markup_pass_keeps_tags_entities_and_css_and_skips_single_token_keys() -> None:
    context = _context(_user(), _user("Bodatix", "bx@contoso.example"), _user("Sans Serif", "ss@contoso.example"))
    html = (
        '<html><head><style>body { font-family: bodatix; }</style></head>'
        '<body><p class="bodatix">priyakovalenko &amp; Bodatix</p><td>Priya Kovalenko</td>'
        '<a href="/personal/priya_kovalenko_contoso_example">x</a></body></html>'
    )
    out = redact_output(html, context=context, markup=True)
    assert 'class="bodatix"' in out and "font-family: bodatix;" in out and "priyakovalenko &amp; Bodatix" in out
    assert f"<td>{_prose()}</td>" in out
    assert redact_output('<span title="Sans Serif">', context=context, markup=True) == '<span title="Sans Serif">'


# 12. exporters and customer pack


@pytest.mark.parametrize("name", ["csv", "html", "json", "md", "sarif", "oscal"])
def test_every_builtin_exporter_masks_names(run: Path, tmp_path: Path, name: str) -> None:
    from auditex.exporters import run_exporter

    report = run / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload.setdefault("findings", []).append(
        {"id": "f-1", "title": f"Mailbox of {NAME} forwards", "severity": "high", "status": "open",
         "description": f"priya.kovalenko forwards to an external address; owner {NAME}"}
    )
    report.write_text(json.dumps(payload))
    target = tmp_path / f"export.{name}"
    run_exporter(name=name, run_dir=str(run), output_path=str(target))
    assert _no_tokens(target.read_text()), name


def test_customer_pack_contains_no_person_token(tmp_path: Path) -> None:
    from support import make_contract_valid
    from test_auditex_product import _build_customer_pack_run

    from auditex import cli as auditex_cli

    run_dir = _build_customer_pack_run(tmp_path)
    (run_dir / "normalized").mkdir(exist_ok=True)
    (run_dir / "normalized" / "users.json").write_text(json.dumps({"records": [_user(), _user("Bo", "bo@contoso.example")]}))
    (run_dir / "bundle-hashes.json").unlink(missing_ok=True)
    make_contract_valid(run_dir)
    output_dir = tmp_path / "customer-pack"
    assert auditex_cli.main(["report", "customer-pack", str(run_dir), "--output-dir", str(output_dir)]) == 0
    texts = [path.read_text(errors="replace") for path in output_dir.rglob("*") if path.is_file()]
    assert texts and all(_no_tokens(text) for text in texts)
    assert any("Name masking: 1 directory people" in text for text in texts)


# 13. notification and MCP payloads


def test_notification_payload_masks_names(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    payload = {"tenant_name": "acme", "overall_status": "ok", "finding_count": 1, "open_count": 1, "blocker_count": 0,
               "action_plan": [{"id": "f1", "title": f"Review {NAME}'s forwarding", "owner_hint": "priya.kovalenko"}]}
    monkeypatch.setattr(notify_module, "_build_payload", lambda run_dir: payload)
    result = notify_module.send_notification(run_dir=str(run), sink="teams", dry_run=True)
    body = json.dumps(result)
    assert _no_tokens(body)
    assert _prose(_key(run)) in body and _id(_key(run)) in body


def test_mcp_report_payload_masks_names(run: Path) -> None:
    from auditex.mcp_server import preview_report

    result = preview_report(str(run), "md", include_sections="executive_summary")
    assert _no_tokens(json.dumps(result))


# 14 and 15. determinism and multi-run contexts


def test_pseudonyms_are_deterministic_per_run_path(tmp_path: Path) -> None:
    first = _run(tmp_path / "a", [_user()])
    second = _run(tmp_path / "b", [_user()])
    text = f"{NAME} here"
    one = redact_output(text, context=redaction.context_for_run(first))
    assert one == redact_output(text, context=redaction.context_for_run(first)) == f"{_prose(_key(first))} here"
    assert one != redact_output(text, context=redaction.context_for_run(second))


def test_two_run_context_masks_names_from_both_runs_with_the_first_key(tmp_path: Path) -> None:
    first = _run(tmp_path / "a", [_user()])
    second = _run(tmp_path / "b", [_user("Kemi Rotax", "kemi.rotax@contoso.example")])
    context = redaction.context_for_runs([first, second])
    out = redact_output(f"{NAME} and Kemi Rotax", context=context)
    key = _key(first)
    assert out == f"{_prose(key)} and {_prose(key, 'Kemi Rotax')}"
    payload = redaction.redact_payload({"text": "kemi.rotax"}, run_dirs=[first, second])
    assert payload == {"text": _id(key, "Kemi Rotax")}


# 16. no run


def test_context_without_run_masks_persons_found_in_the_value() -> None:
    context = RedactionContext()
    out = redact_output({"user": _user(), "note": f"{NAME} owns it"}, context=context)
    assert out["note"] == f"{_prose(context.key)} owns it"
    assert out["user"]["display_name"] == _prose(context.key)
    # Without a context the key is a fresh random one: consistent within the call, never recomputable.
    bare = redact_output({"user": _user(), "note": f"{NAME} owns it"})
    assert re.fullmatch(r"User [0-9a-f]{16} owns it", bare["note"])
    assert bare["note"] == f"{bare['user']['display_name']} owns it" != out["note"]


# 17. failure paths keep D3 behaviour


def test_incomplete_discovery_still_refuses(run: Path) -> None:
    (run / "normalized" / "broken.json").write_text("{not json")
    with pytest.raises(redaction.ContextIncompleteError):
        redact_output(NAME, context=redaction.context_for_run(run))


def test_non_string_name_is_ignored() -> None:
    value = {"user": {"kind": "user", "display_name": 42, "principal_name": ["x"]}, "text": "42 and Priya"}
    assert redact_output(value, context=RedactionContext()) == value


# 18. middle initials, titles and name-equal mapping keys (M04-T04)

JOHN = "John Smith"
JANE = "Jane Doe"
TITLES = sorted(redaction._D5_TITLES)


def _people(*names: str) -> RedactionContext:
    return _context(*(_user(name, name.lower().replace(" ", ".").replace("..", ".") + "@contoso.example") for name in names))


@pytest.mark.parametrize("text", ["John A. Smith", "John A Smith", "John a smith", "John A. B. Smith", "JOHN Q. SMITH"])
def test_middle_initial_of_a_name_recorded_without_it_is_masked(text: str) -> None:
    out = redact_output(f"Report by {text}, today.", context=_people(JOHN))
    assert out == f"Report by {_prose(name=JOHN)}, today.", out


def test_middle_initial_recorded_in_the_name_masks_every_written_form() -> None:
    recorded = "John A. Smith"
    context = _people(recorded)
    assert context.unmatched_names == ()  # ``. `` now joins, so the spelling as written is followed
    for text in (recorded, "John A Smith", JOHN, "John B. Smith", "JohnSmith"):
        assert redact_output(f"by {text} now", context=context) == f"by {_prose(name=recorded)} now", text


@pytest.mark.parametrize("title", TITLES)
def test_title_before_a_name_is_masked_with_it(title: str) -> None:
    written = title.capitalize()
    out = redact_output(f"Signed by {written}. Jane Doe and {written} Jane Doe.", context=_people(JANE))
    assert out == f"Signed by {_prose(name=JANE)} and {_prose(name=JANE)}.", out


def test_title_recorded_in_the_name_masks_the_bare_name() -> None:
    recorded = "Dr. Jane Doe"
    context = _people(recorded)
    assert context.unmatched_names == ()
    for text in (recorded, "Dr Jane Doe", JANE, "Prof. Dr. Jane Doe", "Dr. Jane Q. Doe", "JaneDoe"):
        assert redact_output(f"by {text} now", context=context) == f"by {_prose(name=recorded)} now", text


def test_title_without_a_name_or_written_in_lower_case_is_left() -> None:
    context = _people(JANE, JOHN)
    assert redact_output("Dr. Doe said Mr. Smith agreed", context=context) == "Dr. Doe said Mr. Smith agreed"
    assert redact_output("we miss Jane Doe", context=context) == f"we miss {_prose(name=JANE)}"
    assert redact_output("Dr. (Jane Doe)", context=context) == f"Dr. ({_prose(name=JANE)})"  # ``. (`` does not join
    assert redact_output("Dr. Mr", context=context) == "Dr. Mr"


def test_initial_and_title_joins_take_a_separator_then_whitespace_only() -> None:
    context = _people(JOHN)
    for text in ("John A . Smith", "John A.. Smith", "John A (Smith)", "John AB Smith", "John 4 Smith"):
        assert redact_output(text, context=context) == text, text
    assert redact_output("Dr .John Smith", context=context) == f"Dr .{_prose(name=JOHN)}"  # `` .`` does not join it
    assert redact_output("A. Smith", context=context) == "A. Smith"  # an initial for the given name is not masked
    assert redact_output("John A.Smith", context=context) == _id(name=JOHN)  # a separator with no space: id form


@pytest.mark.parametrize("text", ["John A. Smith", "John A Smith", "John A. B. Smith", "Dr. John A. Smith"])
def test_initial_on_another_keys_path_still_masks_the_name(text: str) -> None:
    # ``john a`` is a prefix of the first.m.last sign-in name ``john.a.jones``: the path takes the initial, dies at
    # ``smith`` and retries once without it (B1 of the privacy review).
    context = _context(_user(JOHN, "john.smith@contoso.example"), _user("Johnny Jones", "john.a.jones@contoso.example"))
    assert redact_output(f"Report by {text}, today.", context=context) == f"Report by {_prose(name=JOHN)}, today."
    jones = _prose(name="Johnny Jones")
    assert redact_output("John A. Jones and john.a.jones", context=context) == f"{jones} and {_id(name='Johnny Jones')}"
    recorded = _people(JOHN, "John A. Jones")  # the same prefix from another person's recorded initial
    assert redact_output(f"by {text} now", context=recorded) == f"by {_prose(name=JOHN)} now"


@pytest.mark.parametrize("text", ["John A. Smith", "John A Smith", "Dr. John A. Smith"])
def test_initial_on_a_key_that_runs_on_past_the_name_still_masks_it(text: str) -> None:
    # ``john a smith`` is only a prefix of a longer key, so the walk does not die at ``smith``: the person's own admin
    # sign-in name ``john.a.smith.adm`` or another person's recorded ``John A. Smith-Jones``. The phrase without the
    # initial is probed once and held while the walk follows the longer key (B1 variant of the privacy re-check).
    own = _context(_user(JOHN, "john.smith@contoso.example"), _user(JOHN, "john.a.smith.adm@contoso.example"))
    assert redact_output(f"Report by {text}, today.", context=own) == f"Report by {_prose(name=JOHN)}, today."
    assert redact_output("john.a.smith.adm", context=own) == _id(name=JOHN)
    other = "John A. Smith-Jones"
    hyphen = _context(_user(JOHN, "john.smith@contoso.example"), _user(other, "jsj@contoso.example"))
    assert redact_output(f"Report by {text}, today.", context=hyphen) == f"Report by {_prose(name=JOHN)}, today."
    assert redact_output("John A. Smith Jones", context=hyphen) == _prose(name=other)  # the longer key still wins


def test_a_longer_name_with_an_initial_still_wins_over_the_form_without_it() -> None:
    # The form without the initial is tried only after the walk, so it never narrows the window or takes the hit of
    # a longer name: a six-token name with an initial, and a name the walk reaches through the miss fallback.
    long = "Ana M. de la Cruz Silva"
    assert redact_output(f"by {long} and Ana M de la Cruz Silva", context=_people(long)) == (
        f"by {_prose(name=long)} and {_prose(name=long)}")
    jones = "John Smith Jones"
    context = _context(_user(JOHN, "john.a.smith.adm@contoso.example"), _user(jones, "jsj@contoso.example"))
    assert redact_output("John A. Smith Jones and John A. Smith", context=context) == (
        f"{_prose(name=jones)} and {_prose(name=JOHN)}")


def test_a_comma_never_joins_a_title_to_a_name() -> None:
    context = _people(JANE)
    for lead in ("Dear Sir, ", "Ask the Prof., ", "Dr, "):
        assert redact_output(f"{lead}Jane Doe signed", context=context) == f"{lead}{_prose(name=JANE)} signed", lead
    assert redact_output("Dear Sir Jane Doe", context=context) == f"Dear {_prose(name=JANE)}"


@pytest.mark.parametrize("profile", SHAREABLE_PROFILES)
def test_initial_and_title_spellings_are_masked_in_every_shareable_profile(tmp_path: Path, profile: str) -> None:
    from auditex.reporting import preview_report

    root = _run(tmp_path / "run", [_user(JOHN, "john.smith@contoso.example"), _user(JANE, "jane.doe@contoso.example")],
                narrative="John A. Smith asked Dr. Jane Doe to review it.")
    key = _key(root)
    out = preview_report(run_dir=str(root), format_name="md", include_sections=["executive_summary"], profile=profile)
    assert f"{_prose(key, JOHN)} asked {_prose(key, JANE)} to review it." in out["content"]
    assert not re.search(r"\b(?:John|Smith|Jane|Doe|Dr)\b", out["content"])


def test_mapping_key_equal_to_a_name_is_masked_as_a_whole() -> None:
    context = _people(NAME, JOHN)
    value = {"priya_kovalenko": 1, "Priya-Kovalenko": 2, "PriyaKovalenko": 3, "john_a_smith": 4, "dr_john_smith": 5,
             "priya_kovalenko_mailbox": 6, "display_name": 7, "userPrincipalName": 8, "kovalenko": 9}
    out = redact_output(value, context=context)
    assert out == {_id(): 1, f"{_id()}#2": 2, _prose(): 3, redaction.TEXT_PLACEHOLDER: 4, f"{redaction.TEXT_PLACEHOLDER}#2": 5,
                   "priya_kovalenko_mailbox": 6, "display_name": 7, "userPrincipalName": 8, "kovalenko": 9}
    assert redact_output(out, context=context) == out  # a pseudonym key is never matched again


def test_mapping_key_equal_to_a_group_name_in_the_value_is_left() -> None:
    context = _people("Kemi Rotax")
    value = {"groups": [{"principalType": "Group", "displayName": "Kemi Rotax"}], "kemi_rotax": 1}
    assert redact_output(value, context=context)["kemi_rotax"] == 1


def test_initial_title_and_mapping_key_pseudonyms_come_from_the_matcher_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    index = redaction._build_index(redaction._names_as_persons([JOHN, "Dr. Jane Doe"]), frozenset())
    calls: list[tuple[bytes, str]] = []
    real = redaction.pseudonym
    monkeypatch.setattr(redaction, "pseudonym", lambda key, text: calls.append((key, text)) or real(key, text))
    text = "John A. Smith wrote to Prof. Jane Doe"
    outputs = []
    for key in (KEY, bytes(range(32, 64))):
        matcher = redaction._NameMatcher(index.table, key)
        out = matcher.mask(text)
        assert out == f"{_prose(key, JOHN)} wrote to {_prose(key, 'Dr. Jane Doe')}", out
        assert matcher.whole("john_smith") == _id(key, JOHN)
        assert matcher.whole("JaneDoe") == _prose(key, "Dr. Jane Doe")
        outputs.append(out)
    assert outputs[0] != outputs[1]
    assert calls and all(len(key) == redaction.PSEUDONYM_KEY_BYTES and key in (KEY, bytes(range(32, 64)))
                         for key, _ in calls)
    for canonical in (JOHN, "Dr. Jane Doe"):  # never an unkeyed hash of the name
        assert hashlib.sha256(canonical.encode()).hexdigest()[:16] not in "".join(outputs)


# 19. product field names, derived forms and recorded spellings (M04-T04 repair)


def _product_field_names() -> set[str]:
    """Every product field name, normalised as ``_D5_FIELD_NAMES`` holds them: property names in ``schemas/``, keys
    in ``configs/``, and the identifier-shaped strings the code under ``src/`` writes as mapping keys (dict displays,
    ``dict()`` keywords, subscript stores) or holds in a module-level constant (surface and collector names). A hex
    digest (eight or more hex characters, one a digit) is neither a field name nor a person's key and is left out."""
    root = Path(__file__).resolve().parents[1]
    names: set[str] = set()

    def walk(node: object, schema: bool) -> None:
        if isinstance(node, dict):
            if not schema:
                names.update(node)
            elif isinstance(node.get("properties"), dict):
                names.update(node["properties"])
            if schema and isinstance(node.get("required"), list):
                names.update(name for name in node["required"] if isinstance(name, str))
            for item in node.values():
                walk(item, schema)
        elif isinstance(node, list):
            for item in node:
                walk(item, schema)

    for path in sorted((root / "schemas").glob("*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")), True)
    for path in sorted((root / "configs").rglob("*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")), False)
    for path in sorted((root / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                names.update(node.value for node in ast.walk(statement.value) if isinstance(node, ast.Constant))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                names.update(key.value for key in node.keys if isinstance(key, ast.Constant))
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store) and isinstance(node.slice, ast.Constant):
                names.add(node.slice.value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
                names.update(keyword.arg for keyword in node.keywords if keyword.arg)
    return {
        redaction._norm(name) for name in names
        if isinstance(name, str) and redaction._D5_STRUCTURAL_KEY_RE.match(name)
        and len(redaction._norm(name)) >= redaction._D5_MIN_KEY_CHARS
        and not re.fullmatch(r"(?=[a-f]*[0-9])[0-9a-f]{8,}", redaction._norm(name))
    }


def test_every_product_field_name_is_exempt_from_whole_key_masking() -> None:
    exempt = redaction._D5_FIELD_NAMES
    assert all(redaction._norm(name) == name for name in exempt)
    missing = sorted(_product_field_names() - exempt)
    assert not missing, "regenerate _D5_FIELD_NAMES in src/azure_tenant_audit/output_redaction.py; missing: " + " ".join(missing)



def test_product_field_keys_are_kept_when_a_person_has_that_name() -> None:
    people = ("Break Glass", "Emergency Access", "Data Protection", "Display Name")
    context = _people(*people)
    assert context.unmatched_names == (("vocabulary", 4),)  # counted in the note
    value = {"synthesis": {"break_glass": {"accounts": 1}}, "surfaces": {"emergency_access": 1, "data_protection": 2},
             "breakGlass": 3, "Break-Glass": 4, "records": [_user(JOHN, "john.smith@contoso.example")],
             "note": "Break Glass signed in"}
    out = redact_output(value, context=context)
    assert out["synthesis"] == {"break_glass": {"accounts": 1}}
    assert out["surfaces"] == {"emergency_access": 1, "data_protection": 2}
    assert out["breakGlass"] == 3 and out["Break-Glass"] == 4
    assert set(out["records"][0]) == set(value["records"][0])  # ``display_name`` stays a field name
    assert out["note"] == f"{_prose(name='Break Glass')} signed in"  # free text is still masked
    # A person found only in the value (the per-value overlay) is held to the same rule.
    found = redact_output({"records": [_user("Break Glass", "break.glass@contoso.example")], "break_glass": 1},
                          context=RedactionContext(key=KEY))
    assert found["break_glass"] == 1
    assert redaction._NameMatcher({"break glass": "Break Glass"}, KEY).whole("break_glass") == "break_glass"


@pytest.mark.parametrize(("recorded", "other"), [(JOHN, "John A. Smith"), (JANE, "Dr. Jane Doe")])
def test_a_derived_form_never_takes_another_persons_recorded_spelling(recorded: str, other: str) -> None:
    text = f"{recorded} met {other}."
    expected = f"{_prose(name=recorded)} met {_prose(name=other)}."
    assert redact_output(text, context=_people(recorded, other)) == expected
    assert redact_output(text, context=_people(other, recorded)) == expected
    for base, found in ((recorded, other), (other, recorded)):  # one in the context, the other only in the value
        value = {"records": [_user(found, found.lower().replace(".", "").replace(" ", ".") + "@contoso.example")],
                 "text": text}
        assert redact_output(value, context=_people(base))["text"] == expected, (base, found)


# Other-vendor review regressions, invented directory identities only.


@pytest.mark.parametrize("title", ["", "Dr. "])
@pytest.mark.parametrize("initials", ["A B C D E", "A. B. C. D. E."])
def test_shorter_name_does_not_expose_an_unresolved_initial_extension(title: str, initials: str) -> None:
    context = _people("Neral", "Neral Vosk")
    text = f"{title}Neral {initials} Vosk wrote"
    assert redact_output(text, context=context) == redaction.TEXT_PLACEHOLDER


@pytest.mark.parametrize("composed, decomposed", [
    ("\u0958neral Vosk", "\u0915\u093cneral Vosk"),
    ("\u09dcneral Vosk", "\u09a1\u09bcneral Vosk"),
    ("\u0f43neral Vosk", "\u0f42\u0fb7neral Vosk"),
])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("markup", [False, True])
def test_combining_marks_across_scripts_preserve_equivalent_names_and_source_offsets(
    composed: str, decomposed: str, reverse: bool, markup: bool,
) -> None:
    recorded, written = (decomposed, composed) if reverse else (composed, decomposed)
    matcher = redaction._NameMatcher(_people(recorded)._index.table, KEY)
    prefix, suffix = ("<b>e\u0301: ", "</b>") if markup else ("e\u0301: ", "!")
    text = f"{prefix}{written}; {written}{suffix}"
    expected = f"{prefix}{_prose(name=recorded)}; {_prose(name=recorded)}{suffix}"
    assert matcher.mask(text, markup=markup) == expected
    assert matcher.probes <= 4 * 6
    assert matcher.widest <= 6
    assert matcher.mask(expected, markup=markup) == expected


@pytest.mark.parametrize("initials", ["A. B.", "A B", "A. B. C.", "A B C"])
@pytest.mark.parametrize("repetitions", [1, 80])
def test_two_and_three_initials_with_admin_upn_and_trailing_word_mask_or_withhold(
    initials: str, repetitions: int,
) -> None:
    name = "Neral Vosk"
    context = _context(_user(name, "neral.a.vosk.adm@example.invalid"))
    text = f"Neral {initials} Vosk wrote; " * repetitions
    out = redact_output(text, context=context)
    assert out == redaction.TEXT_PLACEHOLDER or out == f"{_prose(name=name)} wrote; " * repetitions
    assert "Neral" not in out and "Vosk" not in out


@pytest.mark.parametrize("recorded", ["Néral Vosk", "Ne\u0301ral Vosk"])
@pytest.mark.parametrize("written", ["Néral Vosk", "Ne\u0301ral Vosk", "Néral É. Vosk", "Ne\u0301ral E\u0301. Vosk"])
def test_composed_and_decomposed_names_and_initials_share_token_boundaries(recorded: str, written: str) -> None:
    # The two composed-name cases already passed before the fix; retain them as guards.
    # The other six cases require combining marks to stay in their original token.
    context = _people(recorded)
    assert redact_output(f"by {written}, today", context=context) == f"by {_prose(name=recorded)}, today"
    assert redact_output(f"<b>{written}</b>", context=context, markup=True) == f"<b>{_prose(name=recorded)}</b>"


@pytest.mark.parametrize("separator", [" ", "\t", ", ", ".", "_", "-", "'", "’"])
@pytest.mark.parametrize("initial", ["", "É. ", "E\u0301. ", "É ", "E\u0301 "])
@pytest.mark.parametrize("markup", [False, True])
def test_unicode_name_matching_preserves_source_offsets_and_budgets(
    separator: str, initial: str, markup: bool,
) -> None:
    recorded = "Néral Vosk"
    context = _people(recorded)
    matcher = redaction._NameMatcher(context._index.table, KEY)
    # Call the matcher directly to check offsets in the original decomposed string.
    # Multiple hits and decomposed surrounding text expose any shifted source offsets.
    written = f"Ne\u0301ral{separator}{initial}Vosk"
    prefix, suffix = ("<b>e\u0301: ", "</b>") if markup else ("e\u0301: ", "!")
    text = f"{prefix}{written}; {written}{suffix}"
    replacement = _id(name=recorded) if separator in (".", "_", "-", "'", "’") else _prose(name=recorded)
    expected = f"{prefix}{replacement}; {replacement}{suffix}"
    assert matcher.mask(text, markup=markup) == expected
    pattern = redaction._D5_MARKUP_TOKEN_RE if markup else redaction._D5_TOKEN_RE
    tokens = sum(m.lastgroup == "tok" for m in pattern.finditer(text))
    assert matcher.probes <= tokens * 6
    assert matcher.widest <= 6
    assert matcher.mask(expected, markup=markup) == expected


@pytest.mark.parametrize("recorded, mapping_key", [
    ("Neral A. B. Vosk", "NeralABVosk"),
    ("Neral A. B. C. Vosk", "NeralABCVosk"),
    ("Neral Vosk", "neral_a_vosk"),
    ("Neral Vosk", "neral_a_b_vosk"),
    ("Neral Vosk", "dr_neral_vosk"),
    ("Neral Vosk", "prof_dr_neral_a_vosk"),
])
def test_whole_mapping_keys_cover_joined_names_titles_and_initials(recorded: str, mapping_key: str) -> None:
    context = _people(recorded)
    expected = redaction.TEXT_PLACEHOLDER if "_" in mapping_key else _prose(name=recorded)
    out = redact_output({mapping_key: 1, mapping_key + "_mailbox": 2, "display_name": 3}, context=context)
    assert out == {expected: 1, mapping_key + "_mailbox": 2, "display_name": 3}
    assert redact_output(out, context=context) == out


def test_whole_mapping_key_with_competing_initial_names_is_withheld() -> None:
    context = _people("Neral Vosk", "Neral A. Vosk")
    assert redact_output({"neral_a_vosk": 1}, context=context) == {redaction.TEXT_PLACEHOLDER: 1}


@pytest.mark.parametrize("parts", [
    {"given_name": "Neral", "surname": "Vosk"},
    {"name": {"givenName": "Neral", "familyName": "Vosk"}},
])
def test_parts_only_directory_records_mask_parts_and_associated_narrative(parts: dict) -> None:
    user = {"kind": "user", **parts}
    context = _context(user)
    out = redact_output({"records": [user], "narrative": "Neral Vosk wrote"}, context=context)
    assert out["narrative"] == f"{_prose(name='Neral Vosk')} wrote"
    masked = out["records"][0]
    if "name" in parts:
        assert masked["name"] == {"givenName": redaction.TEXT_PLACEHOLDER, "familyName": redaction.TEXT_PLACEHOLDER}
    else:
        assert masked["given_name"] == masked["surname"] == redaction.TEXT_PLACEHOLDER
    assert "Neral" not in json.dumps(out) and "Vosk" not in json.dumps(out)


@pytest.mark.parametrize("parts", [{"given_name": "Neral"}, {"surname": "Vosk"}])
def test_incomplete_name_parts_do_not_invent_a_directory_identity(parts: dict) -> None:
    assert redaction._person({redaction._norm(k): v for k, v in parts.items()}) is None

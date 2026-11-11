"""D5: every directory person's name is masked in shareable output, using synthetic values only."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from test_reporting import _write_run

from azure_tenant_audit import output_redaction as redaction
from azure_tenant_audit.output_redaction import (
    RedactionContext,
    pseudonym,
    redact_output,
    run_salt,
)

NAME = "Priya Kovalenko"
UPN = "priya.kovalenko@contoso.example"
SHAREABLE_PROFILES = ("shareable", "customer_pack", "explainer")
TOKENS = ("priya", "kovalenko")


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
    return root


@pytest.fixture
def run(tmp_path: Path) -> Path:
    return _run(tmp_path / "run", [_user()])


def _context(*users: dict, salt: str = "s", vocabulary: frozenset[str] = frozenset()) -> RedactionContext:
    """A context whose index holds ``users``, as ``context_for_run`` builds it from a run."""
    found = redaction._Found()
    redaction._collect({"records": list(users)}, found, names=True)
    index = redaction._build_index(found.persons, redaction._vocabulary_phrases(vocabulary))
    return RedactionContext(salt=salt, vocabulary=vocabulary, unmatched_names=index.counts(), _index=index)


def _prose(salt: str = "s", name: str = NAME) -> str:
    return "User " + pseudonym(salt, name)


def _id(salt: str = "s", name: str = NAME) -> str:
    return "user-" + pseudonym(salt, name)


# 1. narrative text in another section, every non-local profile; local keeps it


@pytest.mark.parametrize("profile", SHAREABLE_PROFILES)
def test_non_privileged_user_name_in_another_section_is_masked(run: Path, profile: str) -> None:
    from auditex.reporting import preview_report

    for fmt in ("json", "md", "html"):
        content = preview_report(run_dir=str(run), format_name=fmt, include_sections=["executive_summary"], profile=profile)["content"]
        assert _no_tokens(content), (fmt, content)
        assert _prose(run_salt(run)) in content


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
    result = redact_output({"who": record, "text": f"changed by {NAME}"}, context=RedactionContext(salt="s"))
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
    assert out["user"]["display_name"] == _prose(run_salt(run))
    assert out["text"] == f"{_prose(run_salt(run))} signed in"


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
    assert redact_output("Ops Crew and Priya Kovalenko", context=context) == f"Ops Crew and {_prose(run_salt(root))}"


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


def test_privacy_item_1_a_separator_spelling_in_another_record_is_reported() -> None:
    reference = {"initiatedBy": {"user": {"id": "u1", "displayName": "Kovalenko (Priya)", "userPrincipalName": UPN}}}
    context = _context(_user(id="u1"), reference)
    assert context.unmatched_names == (("separator", 1),)
    out = redact_output("Updated by Kovalenko (Priya); Priya Kovalenko agreed", context=context)
    assert out.startswith("Updated by Kovalenko (Priya); User ")  # readable, and never with an empty count


def test_privacy_item_2_the_note_is_true_for_every_reason() -> None:
    for reason in redaction.D5_REASONS:
        note = redaction.unmatched_names_note(RedactionContext(unmatched_names=((reason, 1),)))
        assert note.startswith("Name masking: 1 directory people have names that cannot be matched safely in free text")
        assert f"({reason} 1)" in note and "too short or too common" not in note


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


def test_codex_item_4_two_object_ids_sharing_a_upn_are_two_people() -> None:
    reused = "bo@contoso.example"
    context = _context(_user("Bo", reused, id="obj-1"), _user("Bo", reused, id="obj-2"))
    assert context.unmatched_names == (("too_short", 2),)
    # A principal-name-only reference to the reused name cannot be attributed to either, so it is its own person.
    ambiguous = _context(_user("Bo", reused, id="obj-1"), _user("Bo", reused, id="obj-2"),
                         {"userPrincipalName": reused, "displayName": "Bo"})
    assert ambiguous.unmatched_names == (("too_short", 3),)


def test_codex_item_3_a_upn_only_reference_joins_the_object_id_person() -> None:
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


def test_codex_item_3_three_merged_runs_keep_the_alias_links(tmp_path: Path) -> None:
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


def test_codex_item_2_a_privileged_person_is_one_entry_through_context_for_run(tmp_path: Path) -> None:
    def admin(name: str, **extra: object) -> dict:
        return {"principalType": "User", "principalId": "obj-9", "roles": ["Reader"], "displayName": name, **extra}

    short = redaction.context_for_run(_run(tmp_path / "short", [admin("Bo")]))
    assert "Bo" in short.protected_names
    assert short.unmatched_names == (("too_short", 1),)  # one person, not a real and a synthetic one
    full_root = _run(tmp_path / "full", [admin("Bodil Ostergaard"), _user("Bodil Ostergaard", "bo@contoso.example")])
    full = redaction.context_for_run(full_root)
    assert full.unmatched_names == ()
    assert redact_output("Bodil Ostergaard", context=full) == _prose(run_salt(full_root), "Bodil Ostergaard")
    both = redaction.context_for_runs([tmp_path / "short", full_root])
    assert both.unmatched_names == (("too_short", 1),)
    # A context not built from a run still indexes the names it was given.
    given = RedactionContext(protected_names=frozenset({"Bodil Ostergaard"}))
    assert redact_output("Bodil Ostergaard", context=given) == _prose("", "Bodil Ostergaard")


def test_codex_item_1_key_saturation_keeps_the_required_forms_and_reports_limit() -> None:
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
    out = redact_output({NAME: 1, "priya kovalenko": 2, _prose(): 3, "priya_kovalenko": 4, "display_name": 5}, context=context)
    assert out == {_prose(): 3, f"{_prose()}#2": 1, f"{_prose()}#3": 2, "priya_kovalenko": 4, "display_name": 5}


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
    assert _prose(run_salt(run)) in body and _id(run_salt(run)) in body


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
    assert one == redact_output(text, context=redaction.context_for_run(first)) == f"{_prose(run_salt(first))} here"
    assert one != redact_output(text, context=redaction.context_for_run(second))


def test_two_run_context_masks_names_from_both_runs_with_the_first_salt(tmp_path: Path) -> None:
    first = _run(tmp_path / "a", [_user()])
    second = _run(tmp_path / "b", [_user("Kemi Rotax", "kemi.rotax@contoso.example")])
    context = redaction.context_for_runs([first, second])
    out = redact_output(f"{NAME} and Kemi Rotax", context=context)
    salt = run_salt(first)
    assert out == f"{_prose(salt)} and {_prose(salt, 'Kemi Rotax')}"
    payload = redaction.redact_payload({"text": "kemi.rotax"}, run_dirs=[first, second])
    assert payload == {"text": _id(salt, "Kemi Rotax")}


# 16. no run


def test_context_without_run_masks_persons_found_in_the_value() -> None:
    out = redact_output({"user": _user(), "note": f"{NAME} owns it"})
    assert out["note"] == f"{_prose('')} owns it"
    assert out["user"]["display_name"] == _prose("")


# 17. failure paths keep D3 behaviour


def test_incomplete_discovery_still_refuses(run: Path) -> None:
    (run / "normalized" / "broken.json").write_text("{not json")
    with pytest.raises(redaction.ContextIncompleteError):
        redact_output(NAME, context=redaction.context_for_run(run))


def test_non_string_name_is_ignored() -> None:
    value = {"user": {"kind": "user", "display_name": 42, "principal_name": ["x"]}, "text": "42 and Priya"}
    assert redact_output(value, context=RedactionContext()) == value

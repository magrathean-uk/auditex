"""Regression tests for the second independent review of the report-output redaction boundary (S1 to S8).

Each test reproduces one finding with the review's input; every identifier is synthetic. S9 (the wildcard
expansion of the sink inventory) is in ``tests/test_output_redaction.py``.
"""
from __future__ import annotations

import json
import os
import signal
from dataclasses import replace
from pathlib import Path

import pytest

from auditex import mcp_server
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.citations import build_citation_summary
from azure_tenant_audit.output_redaction import (
    PROFILE_POLICY,
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    ContextIncompleteError,
    RedactionContext,
    RedactionError,
    context_for_run,
    redact_output,
    redact_payload,
    settle_citations,
)

PLACEHOLDER = orx.SECRET_PLACEHOLDER


def _run(tmp_path: Path, records: list[dict] | None = None) -> Path:
    run = tmp_path / "run-s"
    (run / "normalized").mkdir(parents=True)
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "s"}), encoding="utf-8")
    if records is not None:
        (run / "normalized" / "z-privileged.json").write_text(json.dumps({"records": records}), encoding="utf-8")
    return run


PRIV = {"display_name": "Priya Nairplanted", "OnPremisesImmutableId": "Zm9vYmFyLXBsYW50ZWQtaWQ="}
NARRATIVE = "Priya Nairplanted (Zm9vYmFyLXBsYW50ZWQtaWQ=) approved it"


def _no_priv(text: str) -> None:
    assert "Priya Nairplanted" not in text and "Zm9vYmFyLXBsYW50ZWQtaWQ=" not in text


# -- S1 -----------------------------------------------------------------------------------------------------------


def test_s1_structural_values_are_never_name_substituted() -> None:
    context = RedactionContext(protected_names=frozenset({"MS.EXO.4.1v1", "DmarcPolicy", "not_collected"}))
    value = {"id": "MS.EXO.4.1v1", "setting": "DmarcPolicy", "reason": "not_collected"}
    assert redact_output(value, context=context) == value
    assert redact_output(value, context=context, profile=PROFILE_EXPLAINER) == value


@pytest.mark.parametrize(
    "key",
    ["id", "policy_id", "finding_id", "setting", "reason", "reason_code", "code", "status", "verdict", "section", "kind", "cell"],
)
def test_s1_every_structural_key_keeps_its_value(key: str) -> None:
    name = "Sectionfour Planted"
    context = RedactionContext(protected_names=frozenset({name}))
    value = {"items": [{key: name, "note": f"{name} was here"}]}
    out = redact_output(value, context=context)
    assert out["items"][0][key] == name
    assert name not in out["items"][0]["note"] and out["items"][0]["note"].startswith("User ")


def test_s1_shape_protects_ids_codes_and_enum_words_in_free_text_and_the_name_field_is_still_pseudonymised() -> None:
    names = ["MS.EXO.4.1v1", "not_collected", "Warning", "DmarcPolicy"]
    records = [{"display_name": n, "OnPremisesImmutableId": f"IMMUT-{i}-ABCDEF"} for i, n in enumerate(names)]
    value = {
        "records": records,
        "findings": [{"id": "MS.EXO.4.1v1", "setting": "DmarcPolicy", "reason": "not_collected", "status": "Warning"}],
        "text": "MS.EXO.4.1v1 is not_collected; Warning; DmarcPolicy",
        "reasons": ["not_collected"],
    }
    out = redact_output(value)
    assert out["findings"] == value["findings"]
    assert out["reasons"] == ["not_collected"]
    assert out["text"].startswith("MS.EXO.4.1v1 is not_collected; Warning; User ")  # only the CamelCase name is a name
    assert all(r["display_name"].startswith("User ") for r in out["records"])
    assert redact_output(out) == out


def test_s1_a_real_report_json_keeps_its_finding_id_and_setting(tmp_path: Path) -> None:
    run = _run(tmp_path, [{"display_name": "MS.EXO.4.1v1", "OnPremisesImmutableId": "ABCDEF123456="}, {"display_name": "DmarcPolicy", "OnPremisesImmutableId": "ABCDEF654321="}])
    report = json.dumps({"findings": [{"id": "MS.EXO.4.1v1", "setting": "DmarcPolicy", "reason": "not_collected"}]})
    out = json.loads(redact_output(report, context=context_for_run(run)))
    assert out == {"findings": [{"id": "MS.EXO.4.1v1", "setting": "DmarcPolicy", "reason": "not_collected"}]}


# -- S2 -----------------------------------------------------------------------------------------------------------


def test_s2_identities_from_twenty_embedded_records_are_all_collected() -> None:
    people = [(f"Person Number{i} Plantedsurname{i}", f"IMMUTABLE-ID-{i:03d}-ZZZZ=") for i in range(24)]
    embedded = [json.dumps({"records": [{"display_name": n, "OnPremisesImmutableId": i}]}) for n, i in people]
    narrative = "; ".join(f"{n} ({i})" for n, i in people)
    out = redact_output([*embedded, narrative])
    text = json.dumps(out)
    for name, ident in people:
        assert name not in text and ident not in text, name


# -- S3 and S4 ----------------------------------------------------------------------------------------------------


def test_s3_no_silent_file_count_limit_drops_later_files(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    for index in range(450):
        (run / "normalized" / f"a-{index:03d}.json").write_text("{}", encoding="utf-8")
    context = context_for_run(run)
    assert "Priya Nairplanted" in context.protected_names and not context.incomplete
    _no_priv(redact_output(NARRATIVE, context=context, profile=PROFILE_EXPLAINER))


def test_s3_a_file_count_over_the_limit_is_flagged_not_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path, [PRIV])
    for index in range(5):
        (run / "normalized" / f"a-{index}.json").write_text(json.dumps({"records": [{"display_name": f"Early Person{index}", "OnPremisesImmutableId": f"EARLY-ID-{index}-XX"}]}), encoding="utf-8")
    monkeypatch.setattr(orx, "_MAX_SCAN_FILES", 3)
    context = context_for_run(run)
    assert context.incomplete and any("limit" in reason for reason in context.incomplete_reasons)
    assert {"Early Person0", "Early Person1", "Early Person2"} <= set(context.protected_names)
    with pytest.raises(ContextIncompleteError):
        redact_output(NARRATIVE, context=context)


@pytest.mark.parametrize("kind", ["dangling", "malformed", "oversize"])
def test_s3_per_file_errors_keep_found_identities_and_mark_the_context_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    run = _run(tmp_path, [PRIV])
    target = run / "normalized" / "users.json"
    if kind == "dangling":
        target.symlink_to(run / "normalized" / "missing-target.json")
    elif kind == "malformed":
        target.write_text("{not json", encoding="utf-8")
    else:
        target.write_text(json.dumps({"pad": "x" * 1000}), encoding="utf-8")
        monkeypatch.setattr(orx, "_MAX_FILE_BYTES", 300)
        (run / "normalized" / "z-privileged.json").write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    context = context_for_run(run)
    assert "Priya Nairplanted" in context.protected_names and "Zm9vYmFyLXBsYW50ZWQtaWQ=" in context.protected_ids
    assert context.incomplete and context.incomplete_reasons
    assert all(str(run) not in reason for reason in context.incomplete_reasons)


@pytest.mark.parametrize("profile", [PROFILE_SHAREABLE, PROFILE_EXPLAINER, PROFILE_CUSTOMER_PACK])
def test_s3_an_incomplete_context_refuses_the_profiles_that_pseudonymise_identities(tmp_path: Path, profile: str) -> None:
    run = _run(tmp_path, [PRIV])
    (run / "normalized" / "users.json").write_text("[", encoding="utf-8")
    context = context_for_run(run)
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output(NARRATIVE, context=context, profile=profile)
    assert isinstance(caught.value, RedactionError) and "users.json" in str(caught.value)
    # The report-pack profile keeps identifiers by decision and is not refused.
    assert redact_output("x", context=context, profile=PROFILE_REPORT_PACK) == "x"
    # The decision is the caller's: a context repaired by the caller is accepted.
    assert redact_output(NARRATIVE, context=replace(context, incomplete=False, incomplete_reasons=())).startswith("User ")


def test_s3_contexts_for_several_runs_are_incomplete_when_any_run_is(tmp_path: Path) -> None:
    good = _run(tmp_path, [PRIV])
    bad = tmp_path / "run-bad"
    (bad / "normalized").mkdir(parents=True)
    (bad / "normalized" / "x.json").symlink_to(bad / "normalized" / "nope.json")
    context = orx.context_for_runs([good, bad])
    assert context.incomplete and "Priya Nairplanted" in context.protected_names


def test_s4_a_fifo_named_like_a_record_never_blocks_discovery(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    os.mkfifo(run / "normalized" / "pipe.json")

    def _timeout(signum, frame):  # pragma: no cover - only on failure
        raise TimeoutError("context_for_run blocked on a FIFO")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(3)
    try:
        context = context_for_run(run)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert context.incomplete and "Priya Nairplanted" in context.protected_names
    assert any("non-regular" in reason for reason in context.incomplete_reasons)


def test_s4_symlinks_are_followed_only_inside_the_run_and_only_to_regular_files(tmp_path: Path) -> None:
    run = _run(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    (run / "normalized" / "escape.json").symlink_to(outside)
    context = context_for_run(run)
    assert context.incomplete and not context.protected_names  # the outside file was not read
    (run / "normalized" / "escape.json").unlink()
    (run / "normalized" / "device.json").symlink_to("/dev/zero")

    def _timeout(signum, frame):  # pragma: no cover
        raise TimeoutError("blocked")

    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(3)
    try:
        context = context_for_run(run)
    finally:
        signal.alarm(0)
    assert context.incomplete and not context.protected_names
    (run / "normalized" / "device.json").unlink()
    (run / "normalized" / "real.json").write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    (run / "normalized" / "inside.json").symlink_to(run / "normalized" / "real.json")
    context = context_for_run(run)
    assert not context.incomplete and "Priya Nairplanted" in context.protected_names


# -- S5 -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", [PROFILE_SHAREABLE, PROFILE_EXPLAINER, PROFILE_REPORT_PACK])
def test_s5_credential_assignments_in_keys_are_redacted_with_collision_protection(profile: str) -> None:
    out = redact_output({"password=independent-secret": 1, "password=another-secret": 2, "Authorization: Basicsecretvalue": 3, "plain": 4}, profile=profile)
    text = json.dumps(out)
    assert "independent-secret" not in text and "another-secret" not in text and "Basicsecretvalue" not in text
    assert sorted(out.values()) == [1, 2, 3, 4]  # no value lost
    assert out["plain"] == 4
    assert redact_output(out, profile=profile) == out


def test_s5_the_key_of_an_embedded_report_is_redacted_too() -> None:
    report = json.dumps({"findings": [{"evidence": {"password=independent-secret": 1}}]})
    assert "independent-secret" not in redact_output(report)


# -- S6 -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "literal", ["0.12345678901234567890123456789", "1e400", "-0", "1.0", "1E5", "123456789012345678901234567890", "-1.50e-7", "0.1000"]
)
def test_s6_embedded_json_numbers_are_preserved_exactly(literal: str) -> None:
    embedded = f'{{"threshold":{literal},"list":[{literal},"jane@plantedcorp.example"]}}'
    out = redact_output(embedded)
    assert out == f'{{"threshold":{literal},"list":[{literal},"***@plantedcorp.example"]}}'
    assert "Infinity" not in out and "NaN" not in out
    assert redact_output(out) == out


def test_s6_non_standard_constants_are_not_parsed_and_never_emitted_as_json() -> None:
    out = redact_output('{"a": NaN, "b": Infinity}')
    assert out == '{"a": NaN, "b": Infinity}'  # not JSON: handled as text, untouched
    out = redact_output('{"a": NaN, "u": "jane@plantedcorp.example"}')
    assert "jane" not in out


# -- S7 -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("address", ["canary%40review.example", "canary＠review.example", "canary&#64;review.example", "canary\\u0040review.example"])
def test_s7_the_domain_flip_discovers_domains_in_every_address_representation(address: str) -> None:
    context = RedactionContext(policy=replace(PROFILE_POLICY[PROFILE_SHAREABLE], redact_domains=True))
    out = redact_output({"a": address, "b": "see review.example for details", "c": "canary@review.example"}, context=context)
    text = json.dumps(out)
    assert "review.example" not in text and "canary" not in text
    assert out["a"].count("domain-") == 1 and ".invalid" in out["a"]


# -- S8 -----------------------------------------------------------------------------------------------------------


def _pack_payload() -> dict:
    citations = [
        {"artifact_path": "normalized/identity_users.json", "reason": "user", "record_key": "user:jane.doe@plantedcorp.example"},
        {"artifact_path": "normalized/identity_users.json", "reason": "user", "record_key": "user:john.roe@plantedcorp.example"},
    ]
    pack = {"citations": [dict(c) for c in citations], "citation_summary": build_citation_summary(citations)}
    return {
        "citations": [dict(c) for c in citations],
        "citation_summary": build_citation_summary(citations),
        "report_pack": pack,
        "report_pack_citation_summary": dict(pack["citation_summary"]),
    }


def test_s8_nested_citation_containers_and_copied_summaries_are_reconciled() -> None:
    payload = _pack_payload()
    assert payload["report_pack"]["citation_summary"]["citation_count"] == 2
    out = redact_payload(payload)
    recomputed = build_citation_summary(out["citations"])
    assert recomputed["citation_count"] == 1
    assert out["citation_summary"] == recomputed
    assert len(out["report_pack"]["citations"]) == 1
    assert out["report_pack"]["citation_summary"] == build_citation_summary(out["report_pack"]["citations"])
    assert out["report_pack_citation_summary"] == out["report_pack"]["citation_summary"]
    assert settle_citations(out) == out


def test_s8_a_citation_count_field_beside_the_list_follows_the_list() -> None:
    rows = [{"artifact_path": "a.json", "record_key": "k"}, {"artifact_path": "a.json", "record_key": "k"}]
    out = settle_citations({"inner": [{"citations": rows, "citation_count": 2}]})
    assert out["inner"][0]["citation_count"] == 1 and len(out["inner"][0]["citations"]) == 1

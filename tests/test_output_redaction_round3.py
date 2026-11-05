"""Regression tests for the third independent review of the report-output redaction boundary (F02 to F14) and the
two product decisions of 5 November 2026 (per-profile policy; fail-closed refusal that names the file safely).

Every identifier is synthetic. Each test reproduces one finding with the review's input.
"""
from __future__ import annotations

import json
import os
import re
import signal
import stat
import time
from contextlib import contextmanager
from dataclasses import fields, replace
from pathlib import Path
from typing import Iterator

import pytest

from auditex import reporting
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.citations import build_citation_summary
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_POLICY,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    ContextIncompleteError,
    ProfilePolicy,
    RedactionContext,
    context_for_run,
    redact_output,
)

PLACEHOLDER = orx.SECRET_PLACEHOLDER
TEXT = orx.TEXT_PLACEHOLDER
ALL_PROFILES = [PROFILE_REPORT_PACK, PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER]
FREE_TEXT_REDACTED = [PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER]
FREE_TEXT_KEPT = [PROFILE_SHAREABLE, PROFILE_REPORT_PACK]
GUID = "3f2a9c1e-7b4d-4e8a-9c3b-1d2e3f4a5b6c"
PRIV = {"display_name": "Priya Nairplanted", "OnPremisesImmutableId": "Zm9vYmFyLXBsYW50ZWQtaWQ="}
NARRATIVE = "Priya Nairplanted (Zm9vYmFyLXBsYW50ZWQtaWQ=) approved it"


@contextmanager
def deadline(seconds: int) -> Iterator[None]:
    def _timeout(signum, frame):  # pragma: no cover - only on failure
        raise TimeoutError(f"blocked for more than {seconds} s")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _run(tmp_path: Path, records: list[dict] | None = None, name: str = "run-t") -> Path:
    run = tmp_path / name
    (run / "normalized").mkdir(parents=True)
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "t"}), encoding="utf-8")
    if records is not None:
        (run / "normalized" / "z-privileged.json").write_text(json.dumps({"records": records}), encoding="utf-8")
    return run


# -- product decision 1: the per-profile policy -------------------------------------------------------------------


def test_the_policy_is_per_profile_and_the_table_is_what_the_document_says() -> None:
    assert not hasattr(orx, "PENDING_PRODUCT_POLICY") and not hasattr(orx, "PendingProductPolicy")
    assert set(PROFILE_POLICY) == set(orx.PROFILES) == set(ALL_PROFILES)
    assert {f.name for f in fields(ProfilePolicy)} == {
        "redact_guids", "redact_domains", "redact_group_names", "redact_free_text_keys",
    }
    for name in (PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER):
        policy = PROFILE_POLICY[name]
        assert policy.redact_guids and not policy.redact_domains and not policy.redact_group_names
    assert PROFILE_POLICY[PROFILE_CUSTOMER_PACK].redact_free_text_keys
    assert PROFILE_POLICY[PROFILE_EXPLAINER].redact_free_text_keys
    assert not PROFILE_POLICY[PROFILE_SHAREABLE].redact_free_text_keys
    assert not PROFILE_POLICY[PROFILE_REPORT_PACK].redact_free_text_keys
    with pytest.raises(TypeError):
        PROFILE_POLICY[PROFILE_SHAREABLE] = ProfilePolicy()  # type: ignore[index]
    with pytest.raises(Exception):
        PROFILE_POLICY[PROFILE_SHAREABLE].redact_free_text_keys = True  # type: ignore[misc]


def _planted_free_text() -> dict:
    return {
        "owner": "Planted Owner",
        "justification": "Planted justification text",
        "comment": "Planted comment",
        "comments": ["Planted comment one", {"by": "Planted Person", "owner": "Planted Nested Owner"}],
        "notes": {"deep": {"notes": ["Planted deep note", ("Planted tuple note",)]}, "count": 3},
        "waivers": [{"policy": "MS.AAD.1.1v1", "waiver": {"owner": "Planted Deep Owner", "comment": "Planted Deep Comment"}}],
        "title": "Planted title is not a free-text key",
        "empty": {"notes": "", "comments": []},
    }


def _planted_strings(value: object) -> list[str]:
    return [m for m in re.findall(r"Planted [A-Za-z ]+?(?=\"|$)", json.dumps(value))]


@pytest.mark.parametrize("profile", FREE_TEXT_REDACTED)
def test_free_text_keys_are_redacted_at_every_depth_and_as_container_values(profile: str) -> None:
    out = redact_output(_planted_free_text(), profile=profile)
    dumped = json.dumps(out)
    for planted in ("Planted Owner", "Planted justification", "Planted comment", "Planted Person", "Planted Nested Owner",
                    "Planted deep note", "Planted tuple note", "Planted Deep Owner", "Planted Deep Comment"):
        assert planted not in dumped, planted
    assert out["owner"] == TEXT and out["justification"] == TEXT and out["comment"] == TEXT
    assert out["comments"][0] == TEXT and out["comments"][1] == {"by": TEXT, "owner": TEXT}
    assert out["notes"]["deep"]["notes"][0] == TEXT and out["notes"]["count"] == 3
    assert out["waivers"][0]["waiver"] == {"owner": TEXT, "comment": TEXT} and out["waivers"][0]["policy"] == "MS.AAD.1.1v1"
    assert out["title"] == "Planted title is not a free-text key"  # not a free-text key: kept
    assert out["empty"] == {"notes": "", "comments": []}  # empty stays empty
    assert redact_output(out, profile=profile) == out  # idempotent


@pytest.mark.parametrize("profile", FREE_TEXT_KEPT)
def test_free_text_keys_are_kept_in_the_local_report_and_the_report_pack(profile: str) -> None:
    value = _planted_free_text()
    out = redact_output(value, profile=profile)
    assert out == value
    assert redact_output(out, profile=profile) == out


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_the_decided_identifier_classes_in_every_profile(profile: str) -> None:
    value = {
        "mail": "jane.doe@tenant.example",
        "text": f"see mail.tenant.example and {GUID}",
        "group": {"principal_type": "group", "display_name": "Planted Finance Group"},
        "roles": ["Global Administrator", "Planted Custom Role"],
        "role": "Planted Custom Role",
        "text_roles": "Planted Custom Role holds Global Administrator",
    }
    out = redact_output(value, profile=profile)
    dumped = json.dumps(out)
    assert "tenant.example" in dumped  # domains kept (the address local part is masked as before)
    assert out["group"]["display_name"] == "Planted Finance Group"  # group names kept
    assert out["roles"] == value["roles"] and out["role"] == value["role"] and out["text_roles"] == value["text_roles"]
    if profile == PROFILE_REPORT_PACK:
        assert GUID in dumped  # the secrets-only working artifact keeps references exact (documented)
    else:
        assert GUID not in dumped and "00000000-0000-4000-8000-" in dumped  # GUIDs redacted
    assert redact_output(out, profile=profile) == out


def test_a_policy_override_in_the_context_wins_over_the_profile_table() -> None:
    context = RedactionContext(policy=replace(PROFILE_POLICY[PROFILE_SHAREABLE], redact_free_text_keys=True, redact_domains=True,
                                              redact_group_names=True, redact_guids=False))
    out = redact_output({"owner": "Planted Owner", "m": f"x@tenant.example {GUID}",
                         "g": {"principal_type": "group", "display_name": "Planted Group"}}, context=context)
    assert out["owner"] == TEXT and GUID in out["m"] and "tenant.example" not in out["m"]
    assert out["g"]["display_name"].startswith("Group ")


def test_the_explainer_call_path_is_unchanged() -> None:
    context = RedactionContext(salt="s")
    text = f"The user Priya Nairplanted ({GUID}) has no MFA; see MS.AAD.1.1v1 and not_collected."
    context = replace(context, protected_names=frozenset({"Priya Nairplanted"}))
    out = redact_output(text, profile=PROFILE_EXPLAINER, context=context)
    assert "Priya Nairplanted" not in out and GUID not in out and "MS.AAD.1.1v1" in out and "not_collected" in out
    assert out == redact_output(out, profile=PROFILE_EXPLAINER, context=context)
    mapping = redact_output({"explanation": text, "owner": "Planted Owner"}, profile=PROFILE_EXPLAINER, context=context)
    assert mapping["owner"] == TEXT and mapping["explanation"] == out


# -- product decision 2 and F03: the refusal names the file safely ---------------------------------------------------


SECRETY = "Alice Privatecanary-alice@tenant.example-password=privatecanary.json"


def _forbidden(text: str, run: Path) -> None:
    for word in ("Alice", "Privatecanary", "privatecanary", "alice@", "tenant.example", "password", str(run), str(run.parent)):
        assert word not in text, word


def test_f03_a_filename_with_a_name_an_address_and_a_credential_is_never_echoed(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    (run / "normalized" / SECRETY).write_text('{"secret": "privatecanary", "x": ', encoding="utf-8")
    context = context_for_run(run)
    assert context.incomplete
    for reason in context.incomplete_reasons:
        _forbidden(reason, run)
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output(NARRATIVE, context=context)
    error = caught.value
    for text in (str(error), repr(error), " ".join(map(str, error.args)), repr(error.files)):
        _forbidden(text, run)
    assert "malformed JSON" in str(error) and "<redacted-segment-" in str(error)
    assert error.files and all(len(item) == 2 for item in error.files)


def test_the_message_names_the_file_by_run_relative_path_and_reason_class_with_no_content(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    (run / "normalized" / "broken.json").write_text('{"client_secret": "privatecanary", ', encoding="utf-8")
    context = context_for_run(run)
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output(NARRATIVE, context=context, profile=PROFILE_CUSTOMER_PACK)
    error = caught.value
    assert "normalized/broken.json" in str(error) and "malformed JSON" in str(error)
    assert "privatecanary" not in f"{error}{error!r}{error.args}{error.files}" and str(run) not in str(error)
    assert error.files == (("normalized/broken.json", "malformed JSON"),)
    assert error.omitted == 0


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("malformed", "malformed JSON"), ("dangling", "dangling link"), ("fifo", "non-regular"), ("oversize", "oversize"),
     ("unreadable", "unreadable"), ("outside", "outside run")],
)
def test_every_reason_class_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, expected: str) -> None:
    run = _run(tmp_path, [PRIV])
    target = run / "normalized" / "odd.json"
    if kind == "malformed":
        target.write_text("{no", encoding="utf-8")
    elif kind == "dangling":
        target.symlink_to(run / "normalized" / "nowhere.json")
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "oversize":
        target.write_text(json.dumps({"pad": "x" * 400}), encoding="utf-8")
        monkeypatch.setattr(orx, "_MAX_FILE_BYTES", 200)
    elif kind == "unreadable":
        target.write_text("{}", encoding="utf-8")
        target.chmod(0)
    else:
        outside = tmp_path / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        target.symlink_to(outside)
    try:
        with deadline(5):
            context = context_for_run(run)
    finally:
        target.chmod(0o600) if kind == "unreadable" else None
    assert context.incomplete
    assert any(reason.endswith(f": {expected}") and "normalized/odd.json" in reason for reason in context.incomplete_reasons), context.incomplete_reasons
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output("x", context=context)
    assert ("normalized/odd.json", expected) in caught.value.files and str(run) not in str(caught.value)


def test_several_files_are_listed_sorted_with_a_capped_list_and_a_count_of_the_rest(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    for index in (7, 3, 11, 1, 25, 2, 9, 14, 5, 18, 21, 4, 16):
        (run / "normalized" / f"bad_{index:02d}.json").write_text("{", encoding="utf-8")
    context = context_for_run(run)
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output("x", context=context)
    error = caught.value
    listed = [label for label, _ in error.files]
    assert listed == sorted(listed) and len(listed) == orx._MAX_LISTED_FILES == 10
    assert listed[0] == "normalized/bad_01.json" and error.omitted == 3
    assert "and 3 more" in str(error) and "13 file" in str(error)
    again = context_for_run(run)
    with pytest.raises(ContextIncompleteError) as caught_again:
        redact_output("x", context=again)
    assert str(caught_again.value) == str(error) and caught_again.value.files == error.files


def test_segments_that_look_like_names_guids_or_credentials_are_replaced_with_a_stable_placeholder(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    deep = run / "normalized" / "Alice Privatecanary-alice@tenant.example"
    deep.mkdir()
    (deep / f"{GUID}.json").write_text("{", encoding="utf-8")
    (run / "normalized" / "token_hunter2.json").write_text("{", encoding="utf-8")
    context = context_for_run(run)
    text = " | ".join(context.incomplete_reasons)
    for word in ("Alice", "alice@", "tenant.example", GUID, "hunter2"):
        assert word not in text, word
    assert "normalized/<redacted-segment-2>/<redacted-segment-3>" in text and "normalized/<redacted-segment-2>" in text
    assert text == " | ".join(context_for_run(run).incomplete_reasons)


# -- F02: a warm context is never reused after a change ------------------------------------------------------------------


def test_f02_a_changed_unreadable_or_replaced_file_is_seen_by_the_next_context(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    assert not context_for_run(run).incomplete and not context_for_run(run).incomplete
    target = run / "normalized" / "z-privileged.json"
    original = target.read_bytes()
    stat_before = target.stat()
    # Same length, different administrator, modification time put back.
    replacement = original.replace(b"Priya Nairplanted", b"Maria Newplantedy")
    assert len(replacement) == len(original)
    with open(target, "r+b") as handle:
        handle.write(replacement)
    os.utime(target, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    context = context_for_run(run)
    assert "Maria Newplantedy" in context.protected_names and "Priya Nairplanted" not in context.protected_names
    assert "Maria Newplantedy" not in redact_output("Maria Newplantedy approved", context=context)
    # Same-size malformed replacement.
    with open(target, "r+b") as handle:
        handle.write(b"{" * len(original))
    os.utime(target, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    assert context_for_run(run).incomplete
    # Unreadable after a warm context.
    target.write_bytes(original)
    assert not context_for_run(run).incomplete
    target.chmod(0)
    try:
        assert context_for_run(run).incomplete
    finally:
        target.chmod(0o600)


# -- F04: the real writer never blocks on a FIFO --------------------------------------------------------------------------


def _report_run(tmp_path: Path) -> Path:
    run = tmp_path / "report-run"
    (run / "reports").mkdir(parents=True)
    (run / "normalized").mkdir()
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "r", "run_dir": str(run)}), encoding="utf-8")
    (run / "summary.json").write_text(json.dumps({"tenant_name": "planted", "overall_status": "ok"}), encoding="utf-8")
    return run


def test_f04_preview_report_with_a_fifo_in_normalized_refuses_instead_of_blocking(tmp_path: Path) -> None:
    run = _report_run(tmp_path)
    os.mkfifo(run / "normalized" / "pipe.json")
    with deadline(4):
        with pytest.raises(ContextIncompleteError) as caught:
            reporting.preview_report(run_dir=str(run), format_name="json", include_sections=["summary"])
    assert "normalized/pipe.json" in str(caught.value) and "non-regular" in str(caught.value) and str(run) not in str(caught.value)
    with deadline(4):
        sections = reporting._load_normalized_sections(run)  # the loader itself never opens a FIFO
    assert sections == {}


def test_f04_the_report_loader_reads_only_bounded_regular_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _report_run(tmp_path)
    (run / "normalized" / "good.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    (run / "normalized" / "big.json").write_text(json.dumps({"pad": "x" * 500}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"outside": True}), encoding="utf-8")
    (run / "normalized" / "escape.json").symlink_to(outside)
    monkeypatch.setattr(orx, "_MAX_FILE_BYTES", 200)
    assert reporting._load_normalized_sections(run) == {"good": {"a": 1}}


# -- F05: ancestor and final-component swaps -------------------------------------------------------------------------------


def _swapping_open(monkeypatch: pytest.MonkeyPatch, name: str, replace_with: Path) -> list[str]:
    real_open = os.open
    swapped: list[str] = []

    def hostile(path, flags, mode=0o777, *, dir_fd=None):
        if not swapped and path == name and dir_fd is not None:
            swapped.append(name)
            os.rename(name, name + ".moved", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.symlink(str(replace_with), name, dir_fd=dir_fd)
        return real_open(path, flags, mode, dir_fd=dir_fd) if dir_fd is not None else real_open(path, flags, mode)

    monkeypatch.setattr(orx.os, "open", hostile)
    return swapped


def test_f05_a_directory_swapped_for_a_symlink_after_listing_is_refused_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    (run / "normalized" / "sub").mkdir()
    (run / "normalized" / "sub" / "inner.json").write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inner.json").write_text(
        json.dumps({"records": [{"display_name": "Outside Administrator", "OnPremisesImmutableId": "OUTSIDE-IMMUTABLE-1"}]}),
        encoding="utf-8",
    )
    swapped = _swapping_open(monkeypatch, "sub", outside)
    context = context_for_run(run)
    assert swapped, "the swap hook never ran"
    assert context.incomplete and "Outside Administrator" not in context.protected_names
    with pytest.raises(ContextIncompleteError):
        redact_output("Outside Administrator approved", context=context)


def test_f05_a_file_swapped_for_a_symlink_after_listing_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    (run / "normalized" / "a.json").write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"records": [{"display_name": "Outside Administrator", "OnPremisesImmutableId": "OUTSIDE-IMMUTABLE-1"}]}), encoding="utf-8")
    swapped = _swapping_open(monkeypatch, "a.json", outside)
    context = context_for_run(run)
    assert swapped and context.incomplete and "Outside Administrator" not in context.protected_names


def test_f05_a_symlinked_ancestor_directory_is_never_followed(tmp_path: Path) -> None:
    run = _run(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inner.json").write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    (run / "normalized" / "sub").symlink_to(outside)
    context = context_for_run(run)
    assert context.incomplete and not context.protected_names


# -- F06: discovery covers what redaction covers --------------------------------------------------------------------------


def test_f06_a_large_embedded_record_below_the_documented_bound_is_still_discovered(tmp_path: Path) -> None:
    embedded = json.dumps({"records": [PRIV], "pad": "x" * 4_500_000})
    run = _run(tmp_path)
    (run / "normalized" / "wrap.json").write_text(json.dumps({"payload": embedded}), encoding="utf-8")
    context = context_for_run(run)
    assert not context.incomplete and "Priya Nairplanted" in context.protected_names
    assert "Priya Nairplanted" not in redact_output(NARRATIVE, context=context)


def test_f06_an_embedded_record_above_the_bound_makes_the_context_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orx, "_MAX_EMBEDDED_JSON_CHARS", 500)
    embedded = json.dumps({"records": [PRIV], "pad": "x" * 2000})
    run = _run(tmp_path)
    (run / "normalized" / "wrap.json").write_text(json.dumps({"payload": embedded}), encoding="utf-8")
    context = context_for_run(run)
    assert context.incomplete and any(reason.endswith(": limit") and "normalized/wrap.json" in reason for reason in context.incomplete_reasons)
    for profile in (PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER):
        with pytest.raises(ContextIncompleteError):
            redact_output(NARRATIVE, context=context, profile=profile)
    # The same bound applies to a value handed to the redactor directly.
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output({"payload": embedded, "t": NARRATIVE})
    assert caught.value.files == (("<output value>", "limit"),)
    assert redact_output({"payload": embedded}, profile=PROFILE_REPORT_PACK) == {"payload": embedded}


def test_f06_records_inside_sets_tuples_and_frozensets_are_discovered() -> None:
    record = json.dumps({"records": [PRIV]})
    for container in (frozenset({record}), {record}, (record,), [record]):
        out = redact_output({"c": container, "t": NARRATIVE})
        assert "Priya Nairplanted" not in out["t"], type(container)


# -- F07: the free-text flip composes with the ordinary rules ----------------------------------------------------------------


@pytest.mark.parametrize("profile", FREE_TEXT_REDACTED)
def test_f07_flipped_keys_still_get_key_masking_and_whole_credential_replacement(profile: str) -> None:
    value = {"notes": {"alice@tenant.example": "x", "password": 123456789, "password=privatecanary": None,
                       "list": [{"client_secret": {"a": 1}, "m": "bob@tenant.example"}], "kept_number": 7, "flag": True}}
    out = redact_output(value, profile=profile)
    dumped = json.dumps(out)
    for planted in ("alice@", "123456789", "privatecanary", "bob@"):
        assert planted not in dumped, planted
    notes = out["notes"]
    assert notes["password"] == PLACEHOLDER and "***@tenant.example" in notes
    assert notes["list"][0] == {"client_secret": PLACEHOLDER, "m": TEXT}
    assert notes["kept_number"] == 7 and notes["flag"] is True
    assert redact_output(out, profile=profile) == out


# -- F08: domain masking is linear on dotted negative input --------------------------------------------------------------------


def _domain_context(*domains: str) -> RedactionContext:
    return RedactionContext(domains=frozenset(domains), policy=replace(PROFILE_POLICY[PROFILE_SHAREABLE], redact_domains=True))


def test_f08_dotted_negative_input_is_linear() -> None:
    context = _domain_context("tenant.example")
    for count in (1000, 100_000):
        started = time.monotonic()
        with deadline(20):
            out = redact_output("a." * count, context=context)
        assert out == "a." * count
        assert time.monotonic() - started < 5, count
    with deadline(20):
        out = redact_output("a." * 100_000 + "tenant.example", context=context)
    assert "tenant.example" not in out and out.endswith(".invalid") and out.startswith("domain-")
    with deadline(20):
        redact_output("-." * 100_000 + "a" * 100_000, context=context)


@pytest.mark.parametrize(
    "text",
    ["see tenant.example now", "mail.tenant.example.", "a.b.c.tenant.example/path", "x@tenant.example", "x%40tenant.example",
     "x\\u0040tenant.example", "TENANT.Example"],
)
def test_f08_positive_matches_still_mask_the_domain_and_its_subdomains(text: str) -> None:
    context = _domain_context("tenant.example")
    out = redact_output(text, context=context)
    assert "tenant.example" not in out.lower() and ".invalid" in out
    assert redact_output(out, context=context) == out


def test_f08_boundaries_are_kept() -> None:
    context = _domain_context("tenant.example")
    for text in ("xtenant.example", "tenant.examples", "tenant.example-two", "tenant.example_x", "tenant.example9"):
        assert redact_output(text, context=context) == text, text
    out = redact_output("a-b.c_d.tenant.example", context=context)
    assert out.startswith("domain-") and "a-b" not in out


# -- F09: URL credentials -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_f09_url_userinfo_passwords_and_credential_query_parameters_are_redacted(profile: str) -> None:
    text = (
        "https://host.example/path?token=privatecanary&sig=privatecanary&x=1 "
        "https://canary:privatecanary@host.example/ "
        "https://host.example/a?sv=2022-11-02&se=2030-01-01&sp=r&sig=privatecanary%2Fabc "
        "https://host.example/cb?code=privatecanary&state=ok#access_token=privatecanary "
        "https://host.example/?client_secret=privatecanary&password=privatecanary&key=privatecanary&signature=privatecanary"
    )
    out = redact_output({"title": text, "evidence": [text]}, profile=profile)
    dumped = json.dumps(out)
    assert "privatecanary" not in dumped and "2022-11-02" not in dumped
    assert "x=1" in dumped and "state=ok" in dumped and "https://host.example/path?" in dumped  # URL syntax intact
    assert re.search(r"https://canary:\*\*\*(?:redacted\*\*\*)?@host\.example/", dumped)  # the e-mail mask may shorten it
    assert redact_output(out, profile=profile) == out
    assert "privatecanary" not in redact_output(text, profile=profile, markup=True)


def test_f09_html_escaped_and_ordinary_urls_survive_without_credentials() -> None:
    text = "<a href=\"https://host.example/p?a=1&amp;token=privatecanary&amp;b=2\">https://host.example/docs?page=2</a>"
    out = redact_output(text, profile=PROFILE_SHAREABLE, markup=True)
    assert "privatecanary" not in out and "page=2" in out and "a=1" in out and "b=2" in out


# -- F10: the normalized root --------------------------------------------------------------------------------------------------


def test_f10_a_dangling_symlink_or_a_file_in_place_of_the_normalized_root_is_incomplete(tmp_path: Path) -> None:
    run = tmp_path / "run-root"
    run.mkdir()
    assert not context_for_run(run).incomplete  # absent is complete
    (run / "normalized").symlink_to(tmp_path / "nowhere")
    context = context_for_run(run)
    assert context.incomplete and any(r.endswith(": dangling link") for r in context.incomplete_reasons)
    (run / "normalized").unlink()
    (run / "normalized").write_text("x", encoding="utf-8")
    context = context_for_run(run)
    assert context.incomplete and any("non-regular" in r for r in context.incomplete_reasons)
    (run / "normalized").unlink()
    real = tmp_path / "real-normalized"
    real.mkdir()
    (run / "normalized").symlink_to(real)
    assert context_for_run(run).incomplete  # a symlinked root is an ancestor symlink: refused


# -- F13, F14, F11: the finding-id exemption ---------------------------------------------------------------------------------------


def _scanned_namespaces() -> set[str]:
    root = Path(orx.__file__).resolve().parents[1]
    pattern = re.compile(r"[\"'](?:id|finding_id|rule_id|check_id)[\"']\s*[:=]\s*f?[\"']([a-z][a-z0-9_]*):")
    found: set[str] = set()
    for path in root.rglob("*.py"):
        if path.name == "output_redaction.py":
            continue
        found.update(pattern.findall(path.read_text(encoding="utf-8")))
    return found


def test_f11_the_namespace_list_covers_every_namespace_the_finding_producers_emit() -> None:
    scanned = _scanned_namespaces()
    assert len(scanned) >= 25
    assert scanned <= set(orx._ID_NAMESPACES), sorted(scanned - set(orx._ID_NAMESPACES))
    assert not set(orx._ID_NAMESPACES) & orx._CREDENTIAL_NAMESPACES


REAL_IDS = [
    f"identity:global_admin_stale_password:{GUID}",
    "identity:stale_password_policy",
    "identity:global_admin_stale_password:" + "ab" * 16,
    "intune:compliance_policy:windows10",
]


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize("finding_id", REAL_IDS[:2] + REAL_IDS[3:])
def test_f11_real_finding_ids_survive_as_values_keys_and_prose(profile: str, finding_id: str) -> None:
    out = redact_output({"id": finding_id, "text": f"Finding {finding_id}, see more.", finding_id: 1}, profile=profile)
    if profile == PROFILE_REPORT_PACK or GUID not in finding_id:
        assert out["id"] == finding_id and finding_id in out["text"] and finding_id in out
    else:
        assert out["id"].startswith("identity:global_admin_stale_password:00000000-0000-4000-8000-")
    assert "***redacted***" not in json.dumps(out)


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("config:db_password:privatecanary", "privatecanary"),
        ("identity:db_password:hunter2", "hunter2"),
        ("identity:db_password:hunter", "hunter"),
        ("identity:db_password: hunter", "hunter"),
        ("identity:db_password=hunter", "hunter"),
        ("identity:global_admin_stale_password:Hunter2", "Hunter2"),
        ("the identity:global_admin_stale_password:hunter2x is set", "hunter2x"),
        ("x identity:global_admin_stale_password:" + "z" * 20, "z" * 20),
        ("password:hunter2 and secret: v3ry", "hunter2"),
        ("db_password=hunter2", "hunter2"),
        ("identity:global_admin_stale_password:" + GUID + ":hunter", "hunter"),
        ("config:identity:db_password:hunter", "hunter"),
    ],
)
def test_f11_secret_shaped_prose_is_not_exempted(profile: str, text: str, secret: str) -> None:
    for value in (text, {"text": text}):
        out = json.dumps(redact_output(value, profile=profile))
        assert secret not in out, (profile, text)


def test_f13_the_exemption_is_linear_and_iterative_on_flat_text() -> None:
    flat = ("identity:global_admin_stale_password:" + GUID + "/") * 3000
    for profile in (PROFILE_SHAREABLE, PROFILE_REPORT_PACK):
        with deadline(10):
            out = redact_output(flat, profile=profile)
        assert "***redacted***" not in out and out.count("identity:global_admin_stale_password:") == 3000
    sizes = []
    for text in ("a:b_c " * 100_000, "x_y_z:" * 100_000, ":" * 600_000, "identity:a_b:" * 50_000,
                 ("identity:global_admin_stale_password:" + "ab" * 16 + " ") * 20_000):
        started = time.monotonic()
        with deadline(20):
            redact_output(text, profile=PROFILE_CUSTOMER_PACK)
        sizes.append(time.monotonic() - started)
    assert max(sizes) < 8, sizes
    ids_1k = ("identity:x_password:" + "ab" * 16 + " ") * 1000
    ids_16k = ids_1k * 16
    started = time.monotonic()
    redact_output(ids_1k)
    small = time.monotonic() - started
    started = time.monotonic()
    with deadline(20):
        redact_output(ids_16k)
    assert time.monotonic() - started < max(small * 16 * 4, 1.0)


# -- F11 minor: immutable ids ---------------------------------------------------------------------------------------------------------


def test_minor_immutable_ids_are_protected_by_value_case_insensitively_whatever_their_shape() -> None:
    context = RedactionContext(salt="s", protected_ids=frozenset({"planted_immutable_id"}))
    for text in ("Approved by planted_immutable_id", "Approved by PLANTED_IMMUTABLE_ID.", "x:planted_Immutable_ID;"):
        out = redact_output(text, context=context)
        assert "immutable_id" not in out.lower() and "Id " in out, text
        assert redact_output(out, context=context) == out
    out = redact_output({"OnPremisesImmutableId": "planted_immutable_id", "t": "by planted_immutable_id"}, context=context)
    assert out["t"] == "by " + out["OnPremisesImmutableId"]  # one pseudonym for one value


# -- F12: citation counts after redaction, everywhere --------------------------------------------------------------------------------


def test_minor_nested_report_section_citations_are_reconciled_in_every_format(tmp_path: Path) -> None:
    run = _report_run(tmp_path)
    citations = [
        {"artifact_path": "normalized/identity_users.json", "reason": "user", "record_key": "user:jane.doe@plantedcorp.example"},
        {"artifact_path": "normalized/identity_users.json", "reason": "user", "record_key": "user:john.roe@plantedcorp.example"},
    ]
    appendix = {"citations": [dict(c) for c in citations], "citation_count": 2, "citation_summary": build_citation_summary(citations)}
    pack = {"technical_appendix": appendix}
    (run / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    preview = reporting.preview_report(run_dir=str(run), format_name="json", include_sections=["technical_appendix"])
    section = json.loads(preview["content"])["sections"]["technical_appendix"]
    assert len(section["citations"]) == 1 and section["citation_count"] == 1
    assert section["citation_summary"] == build_citation_summary(section["citations"])
    assert "plantedcorp" in json.dumps(section) and "jane.doe@" not in json.dumps(section)


def test_the_directory_walk_never_leaves_file_descriptors_open(tmp_path: Path) -> None:
    run = _run(tmp_path, [PRIV])
    (run / "normalized" / "sub" / "deeper").mkdir(parents=True)
    (run / "normalized" / "sub" / "deeper" / "x.json").write_text("{", encoding="utf-8")
    os.mkfifo(run / "normalized" / "pipe.json")
    before = len(os.listdir("/dev/fd"))
    for _ in range(5):
        assert context_for_run(run).incomplete
    assert len(os.listdir("/dev/fd")) == before
    assert stat.S_ISREG(os.stat(run / "normalized" / "z-privileged.json").st_mode)


def test_the_document_has_the_per_output_class_table_and_the_limits_section() -> None:
    text = (Path(__file__).resolve().parents[1] / "docs" / "reference" / "security-privacy.md").read_text(encoding="utf-8")
    assert "PENDING_PRODUCT_POLICY` is gone" in text and "redact_free_text_keys" in text
    table = text[text.index("### What each profile redacts"):text.index("The detail of each class:")]
    header = next(line for line in table.splitlines() if line.startswith("| Class |"))
    for profile in ALL_PROFILES:
        assert f"`{profile}`" in header
    for row in ("GUIDs", "Domains", "Group display names", "Role names", "Free-text keys", "Secrets", "E-mail", "Privileged-user names"):
        assert any(line.startswith(f"| {row}") for line in table.splitlines()), row
    assert "### What this module still does not protect" in text and "—" not in text

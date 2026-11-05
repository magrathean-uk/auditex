"""Regression tests for the fourth review of the report-output redaction boundary (V4-04 to V4-06, V4-09 to V4-11).

Every identifier is synthetic. Each test reproduces one finding with the review's input; the review was a source
review (nothing executed), so a test that shows a derivation to be wrong says so in its docstring.
"""
from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    ContextIncompleteError,
    RedactionContext,
    context_for_run,
    redact_output,
)

ALL_PROFILES = [PROFILE_REPORT_PACK, PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER]
GUID = "3f2a9c1e-7b4d-4e8a-9c3b-1d2e3f4a5b6c"
PRIV = {"display_name": "Priya Nairplanted", "OnPremisesImmutableId": "Zm9vYmFyLXBsYW50ZWQtaWQ="}
NARRATIVE = "Priya Nairplanted (Zm9vYmFyLXBsYW50ZWQtaWQ=) approved it"


class Blocked(BaseException):
    """Not an ``Exception``: production code that catches ``OSError`` (``TimeoutError`` is one) must not swallow it."""


@contextmanager
def deadline(seconds: int) -> Iterator[None]:
    def _timeout(signum, frame):  # pragma: no cover - only on failure
        raise Blocked(f"blocked for more than {seconds} s")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _run(tmp_path: Path, name: str = "run-t") -> Path:
    run = tmp_path / name
    (run / "normalized").mkdir(parents=True)
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "t"}), encoding="utf-8")
    return run


# -- V4-04: the id exemption is closed over recognised finding definitions -----------------------------------------------


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("identity:db_password:654321", "654321"),
        ("identity:db_password:deadbeefcafebabe", "deadbeefcafebabe"),
        ("identity:db_password:" + "ab" * 16, "ab" * 16),
        ("identity:db_password:" + GUID, GUID),
        ("app:client_secret:12345678901234567", "12345678901234567"),
        ("exchange:smtp_password:98765432109876543210", "98765432109876543210"),
        ("identity:global_admin_stale_password:654321", "654321"),  # a recognised name, but not a producer's suffix shape
        ("see identity:db_password:654321, then", "654321"),
    ],
)
def test_v4_04_numeric_and_hex_passwords_under_any_unrecognised_name_are_credentials(profile: str, text: str, secret: str) -> None:
    for value in (text, {"text": text}, [text]):
        assert secret not in json.dumps(redact_output(value, profile=profile)), (profile, text)


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize(
    "finding_id",
    [
        f"identity:global_admin_stale_password:{GUID}",
        "identity:global_admin_stale_password:" + "ab" * 16,
        "identity:global_admin_stale_password:" + "1" * 21,
        "identity:global_admin_stale_password",
    ],
)
def test_v4_04_the_recognised_definition_keeps_every_suffix_shape_a_producer_writes(profile: str, finding_id: str) -> None:
    out = redact_output({"id": finding_id, "t": f"Finding {finding_id}, see more."}, profile=profile)
    assert "***redacted***" not in json.dumps(out)
    assert out["id"].startswith("identity:global_admin_stale_password")


# -- V4-05: discovery and redaction recognise the same embedded JSON ---------------------------------------------------------


_WHITESPACE = [chr(i) for i in range(sys.maxunicode + 1) if chr(i).isspace()]


def test_v4_05_every_whitespace_character_str_strip_removes_is_one_the_discovery_test_accepts() -> None:
    """The review derived the mismatch for ``\\r``; the same holds for every other whitespace ``str.strip`` removes."""
    assert "\r" in _WHITESPACE and len(_WHITESPACE) >= 25
    for char in _WHITESPACE:
        record = json.dumps({"records": [PRIV]})
        assert orx._maybe_json(char + record + char) is not None, repr(char)
    assert orx._maybe_json("x" + json.dumps({"a": 1})) is None


@pytest.mark.parametrize("lead", ["\r", "\x0b", "\x0c", "\x1c", "\x85", "\xa0", "\u2003", "\u3000", "\r\n\t "])
def test_v4_05_a_record_embedded_after_any_whitespace_is_discovered_and_its_name_is_redacted_in_prose(lead: str) -> None:
    embedded = lead + json.dumps({"records": [PRIV]})
    out = redact_output({"payload": embedded, "narrative": NARRATIVE})
    dumped = json.dumps(out)
    assert "Priya Nairplanted" not in dumped and "Zm9vYmFyLXBsYW50ZWQtaWQ=" not in dumped, repr(lead)


@pytest.mark.parametrize("lead", ["\r", "\x0b", "\u00a0"])
def test_v4_05_a_run_whose_file_embeds_a_record_after_whitespace_knows_the_administrator(tmp_path: Path, lead: str) -> None:
    run = _run(tmp_path)
    (run / "normalized" / "snapshot.json").write_text(json.dumps({"payload": lead + json.dumps({"records": [PRIV]})}), encoding="utf-8")
    context = context_for_run(run)
    assert not context.incomplete and "Priya Nairplanted" in context.protected_names
    assert "Priya Nairplanted" not in redact_output(NARRATIVE, context=context)


# -- V4-06: a refusal shows only recognised public section labels ---------------------------------------------------------------


@pytest.mark.parametrize("name", ["alice_smith.json", "alicesmith.json", "acme_corp.json", "hunter2.json", "alice.smith.json"])
def test_v4_06_a_filename_spelling_is_never_mistaken_for_a_section_name(tmp_path: Path, name: str) -> None:
    run = _run(tmp_path)
    (run / "normalized" / name).write_text("{", encoding="utf-8")
    context = context_for_run(run)
    assert context.incomplete
    with pytest.raises(ContextIncompleteError) as caught:
        redact_output("x", context=context)
    error = caught.value
    stem = name[: -len(".json")]
    for text in (str(error), repr(error), repr(error.files), " ".join(context.incomplete_reasons)):
        assert stem not in text and name not in text
    assert error.files == (("normalized/<redacted-segment-2>#1", "malformed JSON"),)


def test_v4_06_a_recognised_section_and_directory_keep_their_label_and_a_nested_unknown_one_does_not(tmp_path: Path) -> None:
    run = _run(tmp_path)
    (run / "normalized" / "users.json").write_text("{", encoding="utf-8")
    (run / "normalized" / "alice_dir").mkdir()
    (run / "normalized" / "alice_dir" / "devices.json").write_text("{", encoding="utf-8")
    labels = sorted(label for label, _ in context_for_run(run).incomplete_files)
    assert labels == ["normalized/<redacted-segment-2>/devices.json#1", "normalized/users.json"]


def test_v4_06_the_public_label_list_covers_every_section_the_producers_name() -> None:
    root = Path(orx.__file__).resolve().parents[1]
    literal = re.compile(r"normalized/([a-z][a-z0-9_]*)\.json|write_normalized\(\s*[\"']([a-z][a-z0-9_]*)[\"']")
    found: set[str] = set()
    for path in root.rglob("*.py"):
        if path.name == "output_redaction.py":
            continue
        for first, second in literal.findall(path.read_text(encoding="utf-8")):
            found.add(first or second)
    assert len(found) >= 8
    assert found <= orx._PUBLIC_SECTION_LABELS, sorted(found - orx._PUBLIC_SECTION_LABELS)
    assert all(re.fullmatch(r"[a-z][a-z0-9_]*", label) for label in orx._PUBLIC_SECTION_LABELS)


# -- V4-09: bytes really read are charged, and a file that changes while it is read is not used ---------------------------------


def _fd_of(directory: Path) -> int:
    return os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))


def test_v4_09_a_file_that_grew_within_the_per_file_limit_after_it_was_listed_is_changed_not_read(tmp_path: Path) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    path.write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    listed = os.stat(path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(" " * 5000)  # same inode, still far below the per-file limit
    fd = _fd_of(path.parent)
    try:
        with pytest.raises(orx._Unsafe) as caught:
            orx._read_file_at(fd, "users.json", listed)
    finally:
        os.close(fd)
    assert caught.value.reason == orx.REASON_CHANGED


def test_v4_09_growth_during_the_scan_makes_the_context_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    path.write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    real = orx._read_file_at

    def growing(parent_fd: int, name: str, expected: os.stat_result, cap: int = orx._MAX_FILE_BYTES) -> bytes:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(" " * 5000)
        return real(parent_fd, name, expected, cap)

    monkeypatch.setattr(orx, "_read_file_at", growing)
    context = context_for_run(run)
    assert context.incomplete and ("normalized/users.json", orx.REASON_CHANGED) in context.incomplete_files
    with pytest.raises(ContextIncompleteError):
        redact_output(NARRATIVE, context=context)


def test_v4_09_a_file_rewritten_during_the_read_with_the_same_size_is_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    body = json.dumps({"records": [PRIV]})
    path.write_text(body, encoding="utf-8")
    real_read = os.read
    state = {"done": False}

    def read_then_rewrite(descriptor: int, size: int) -> bytes:
        chunk = real_read(descriptor, size)
        if chunk and not state["done"]:
            state["done"] = True
            time.sleep(0.01)
            path.write_text(body.replace("Priya", "Priyb"), encoding="utf-8")  # same length, same inode
        return chunk

    monkeypatch.setattr(orx.os, "read", read_then_rewrite)
    context = context_for_run(run)
    assert context.incomplete and ("normalized/users.json", orx.REASON_CHANGED) in context.incomplete_files


def test_v4_09_the_read_is_capped_by_what_is_left_of_the_aggregate_budget(tmp_path: Path) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    path.write_text(json.dumps({"pad": "x" * 200}), encoding="utf-8")
    fd = _fd_of(path.parent)
    try:
        with pytest.raises(orx._Unsafe) as caught:
            orx._read_file_at(fd, "users.json", os.stat(path), 50)
        assert caught.value.reason == orx.REASON_LIMIT
        assert len(orx._read_file_at(fd, "users.json", os.stat(path), 10_000)) == path.stat().st_size
    finally:
        os.close(fd)


def test_v4_09_the_aggregate_budget_is_charged_the_bytes_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    for name in ("users.json", "devices.json"):
        (run / "normalized" / name).write_text(json.dumps({"pad": "x" * 100}), encoding="utf-8")
    size = (run / "normalized" / "users.json").stat().st_size
    monkeypatch.setattr(orx, "_MAX_SCAN_BYTES", size * 2)
    assert not context_for_run(run).incomplete  # exactly the budget: both read
    monkeypatch.setattr(orx, "_MAX_SCAN_BYTES", size * 2 - 1)
    context = context_for_run(run)
    assert context.incomplete and any(reason == orx.REASON_LIMIT for _, reason in context.incomplete_files)


def test_v4_09_discovery_binds_to_a_snapshot_and_a_later_change_is_refused(tmp_path: Path) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    path.write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    context = context_for_run(run)
    assert context.snapshot and context.snapshot == orx.snapshot_run(run)
    orx.assert_snapshot_stable(run, context.snapshot)  # unchanged: no error
    time.sleep(0.01)
    path.write_text(json.dumps({"records": [PRIV, PRIV]}), encoding="utf-8")
    with pytest.raises(ContextIncompleteError) as caught:
        orx.assert_snapshot_stable(run, context.snapshot)
    assert ("<run>", orx.REASON_CHANGED) in caught.value.files and str(run) not in str(caught.value)
    (run / "normalized" / "devices.json").write_text("{}", encoding="utf-8")  # a file added
    with pytest.raises(ContextIncompleteError):
        orx.assert_snapshot_stable(run, context.snapshot)


def test_v4_09_redact_payload_refuses_when_the_run_changed_while_it_was_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _run(tmp_path)
    path = run / "normalized" / "users.json"
    path.write_text(json.dumps({"records": [PRIV]}), encoding="utf-8")
    assert orx.redact_payload({"t": NARRATIVE}, run_dirs=[run])["t"].startswith("User ")
    real = orx.redact_output

    def touching(*args, **kwargs):
        result = real(*args, **kwargs)
        time.sleep(0.01)
        path.write_text(json.dumps({"records": [PRIV, {"display_name": "Late Arrival"}]}), encoding="utf-8")
        return result

    monkeypatch.setattr(orx, "redact_output", touching)
    with pytest.raises(ContextIncompleteError):
        orx.redact_payload({"t": NARRATIVE}, run_dirs=[run])
    with pytest.raises(ContextIncompleteError):
        orx.redact_payload({"t": NARRATIVE}, run_dirs=[run, run])


# -- V4-10: immutable ids are protected by value in narrative, whatever they touch --------------------------------------------


@pytest.mark.parametrize("identifier", ["abcde", "abcd", "ZZ-99", "Zm9vYmFyLXBsYW50ZWQtaWQ="])
def test_v4_10_a_known_id_is_masked_in_narrative_whatever_its_length(identifier: str) -> None:
    context = RedactionContext(salt="s", protected_ids=frozenset({identifier}))
    structured = redact_output({"immutable_id": identifier}, context=context)["immutable_id"]
    out = redact_output(f"Approved by {identifier}", context=context)
    assert identifier not in out and out == f"Approved by {structured}"
    assert redact_output(out, context=context) == out


@pytest.mark.parametrize("template", ["immutable_id={}", "id=({})", "/users/{}/devices", "a-{}", "user={}&x=1", "k={}", "{}/x", "-{}-"])
def test_v4_10_an_adjacent_equals_slash_or_hyphen_no_longer_hides_the_id(template: str) -> None:
    identifier = "Zm9vYmFyLXBsYW50ZWQtaWQ="
    context = RedactionContext(salt="s", protected_ids=frozenset({identifier}))
    out = redact_output(template.format(identifier), context=context)
    assert identifier not in out and "Id " in out
    assert redact_output(out, context=context) == out


def test_v4_10_the_remaining_limits_are_word_characters_and_the_floor() -> None:
    context = RedactionContext(salt="s", protected_ids=frozenset({"abcde", "abc"}))
    assert redact_output("xabcde abcdex", context=context) == "xabcde abcdex"  # inside a longer word: not the id
    assert redact_output("by abc", context=context) == "by abc"  # under the narrative floor (documented)
    assert redact_output({"immutable_id": "abc"}, context=context)["immutable_id"].startswith("Id ")  # structured: always


# -- V4-11: URL userinfo in every form --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize(
    "url",
    [
        "x://u:privatecanary@host.example",
        "a+b.c-d://u:privatecanary@host.example/p",
        "//u:privatecanary@host.example/p",
        "see (//u:privatecanary@host.example) now",
        "ftp://:privatecanary@host.example",
        "S" * 32 + "://u:privatecanary@host.example",
        "HTTPS://user:privatecanary@host.example:8443/p?x=1",
    ],
)
def test_v4_11_userinfo_passwords_are_redacted_for_every_scheme_form(profile: str, url: str) -> None:
    out = redact_output({"title": url, "evidence": [url]}, profile=profile)
    assert "privatecanary" not in json.dumps(out), (profile, url)
    assert "privatecanary" not in redact_output(url, profile=profile, markup=True)
    assert redact_output(out, profile=profile) == out


def test_v4_11_text_that_is_not_userinfo_is_left_alone() -> None:
    for text in ("a//b:c@d", "see http://host:8080/x@y", "path //host/a:b", "https://host.example/a?b=c@d", "12:30//5:00@x"):
        assert redact_output(text, profile=PROFILE_REPORT_PACK) == text, text


def test_v4_11_the_userinfo_pattern_is_linear_on_dotted_and_plus_runs() -> None:
    for text in ("a." * 100_000, "a+" * 100_000, ("a-b." * 50_000) + "//", "x:" * 100_000, "//" * 100_000):
        started = time.monotonic()
        with deadline(20):
            redact_output(text, profile=PROFILE_REPORT_PACK)
        assert time.monotonic() - started < 8, text[:8]


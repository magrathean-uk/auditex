"""D5: JSON export stability.

The JSON exporter (``auditex.reporting._render_json``) feeds external
pipelines that diff bundles between runs. Contract:

1. ``sort_keys=True`` — the keys at every nesting level appear in
   alphabetical order so two semantically-equivalent inputs yield
   identical bytes.
2. 2-space indent — RFC 7159 valid, human-diffable.
3. Trailing newline — POSIX-tool friendly (sha256sum / git / diff
   treat the file as line-terminated).
4. Byte-equal output for the same input across re-renders.
"""
from __future__ import annotations

import json

from auditex.reporting import _render_json

_SAMPLE_SECTIONS = {
    "findings": [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "evidence_refs": [{"record_key": "section:obj-1"}],
        },
        {
            "id": "f2",
            "rule_id": "rule.beta",
            "severity": "medium",
            "title": "Beta",
            "evidence_refs": [{"record_key": "section:obj-2"}],
        },
    ],
    "summary": {"tenant_name": "acme", "schema_version": "2026-04-21"},
    "manifest": {"run_id": "run-1"},
}


def test_json_export_keys_are_sorted_at_every_level() -> None:
    output = _render_json(_SAMPLE_SECTIONS)
    document = json.loads(output)

    def assert_sorted(value, path):  # noqa: ANN001
        if isinstance(value, dict):
            keys = list(value.keys())
            assert keys == sorted(keys), f"{path}: keys not sorted: {keys}"
            for key, child in value.items():
                assert_sorted(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                assert_sorted(child, f"{path}[{index}]")

    assert_sorted(document, "root")


def test_json_export_uses_two_space_indent() -> None:
    output = _render_json(_SAMPLE_SECTIONS)
    # The first line is the opening brace; the second line should be
    # indented by exactly two spaces.
    second_line = output.splitlines()[1]
    assert second_line.startswith("  "), f"second line lacks 2-space indent: {second_line!r}"
    # Three-space indent (or four) would be a regression.
    assert not second_line.startswith("   "), f"second line has too much indent: {second_line!r}"


def test_json_export_ends_with_trailing_newline() -> None:
    output = _render_json(_SAMPLE_SECTIONS)
    assert output.endswith("\n"), "JSON export must end with a trailing newline"
    # Exactly one trailing newline — multiple would be wasteful.
    assert not output.endswith("\n\n"), "JSON export has multiple trailing newlines"


def test_json_export_is_byte_equal_across_renders() -> None:
    """Same input → byte-equal output. D5 idempotency."""
    a = _render_json(_SAMPLE_SECTIONS)
    b = _render_json(_SAMPLE_SECTIONS)
    assert a == b


def test_json_export_byte_equal_when_inner_dicts_built_in_different_order() -> None:
    """sort_keys must dominate insertion order — two semantically-equal
    dicts built in different key orders must produce identical JSON."""
    sections_a = {"summary": {"a": 1, "b": 2, "c": 3}}
    sections_b = {"summary": {"c": 3, "a": 1, "b": 2}}
    assert _render_json(sections_a) == _render_json(sections_b)


def test_json_export_handles_unicode_without_escaping() -> None:
    """ensure_ascii=False is part of the contract — non-ASCII tenant
    names (German umlauts, accents, etc.) must round-trip without
    escape codes."""
    sections = {"summary": {"tenant_name": "München-örg-éxample"}}
    output = _render_json(sections)
    assert "München-örg-éxample" in output
    assert "\\u" not in output


def test_json_export_is_valid_json() -> None:
    """Trailing newline must not break the parser."""
    output = _render_json(_SAMPLE_SECTIONS)
    document = json.loads(output)
    assert document["sections"]["findings"][0]["id"] == "f1"

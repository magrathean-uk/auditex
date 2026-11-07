"""A refused managed-device chunk leaves a section-scoped coverage gap for the Defender state (synthetic runs only).

The Intune collector stays ``ok`` for section-scoped reads by design; the gap must still reach the section-gap
records, so the normalised snapshot and manifest do not present the device list as complete.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.collection_gaps import SECTION_SCOPED, section_gap_records
from azure_tenant_audit.collectors._endpoint_reads import collector_partial, protection_state_fanout

CANARY = "inline-only-device-canary"
PRIVATE = "private-operator-canary-row"
NAME = "windowsProtectionStates"
VARIANTS = ("symlink", "hardlink", "outside")


class _Client:
    """Records every request; a refused device list must trigger none."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _note(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(str(args[0]) if args else "")
        return {}

    get_json = get_all = iter_pages = iter_items = get_batch = _note


def _run(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    private = root / "operator-inputs"
    private.mkdir(parents=True, mode=0o700)
    # The private pair is left untouched (no extra links), so the run stays admissible.
    (private / "sensitive-users.txt").write_text(json.dumps({"id": PRIVATE}) + "\n", encoding="utf-8")
    (private / "sensitive-users.key").write_bytes(b"k" * 32)
    (root / "chunks").mkdir(mode=0o700)
    return root


def _device(token: str) -> dict[str, Any]:
    return {"id": token, "deviceName": token, "operatingSystem": "Windows"}


def _write(root: Path, name: str, rows: list[dict[str, Any]]) -> str:
    fd = os.open(root / "chunks" / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return f"chunks/{name}"


def _refused(root: Path, variant: str, name: str) -> str:
    """A chunk entry the guard refuses, built only from chunk-side files so the private pair is not linked."""
    if variant == "symlink":
        real = _write(root, f"real-{name}", [_device("refused-device")])
        (root / "chunks" / name).symlink_to(root / real)
        return f"chunks/{name}"
    if variant == "hardlink":
        real = _write(root, f"real-{name}", [_device("refused-device")])
        os.link(root / real, root / "chunks" / name)
        return f"chunks/{name}"
    return f"../{name}"


def _source(chunks: list[str], count: int) -> dict[str, Any]:
    return {"value": [_device(CANARY)], "chunk_files": chunks, "chunk_count": len(chunks), "item_count": count}


def _fanout(root: Path, source: Any, client: _Client) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return protection_state_fanout(
        collector="intune", client=client, name=NAME, source=source, run_dir=root,
        endpoint_template="/deviceManagement/managedDevices/{id}/windowsProtectionState",
        windows_only=lambda row: row.get("operatingSystem") == "Windows",
    )


def _assert_gap(section: dict[str, Any], coverage: list[dict[str, Any]], client: _Client, tmp_path: Path) -> None:
    assert section["error_class"] == "incomplete_evidence" and "value" not in section
    assert client.calls == []
    row = next(item for item in coverage if item["name"] == f"{NAME}Fanout")
    assert row[SECTION_SCOPED] is True and row["status"] == "partial" and row["error_class"] == "incomplete_evidence"
    assert row["input_complete"] is False and row["input_unreadable"] is True
    assert row["input_issues"] and all(set(issue) <= {"code", "chunk_index"} for issue in row["input_issues"])
    assert collector_partial(coverage) is False  # section-scoped semantics: the collector stays ok
    records = [item for item in section_gap_records(coverage) if item["section"] == NAME]
    assert len(records) == 1 and records[0]["collector"] == "intune" and records[0]["status"] == "partial"
    rendered = json.dumps(section) + json.dumps(coverage) + json.dumps(records)
    assert CANARY not in rendered and PRIVATE not in rendered and "refused-device" not in rendered
    assert str(tmp_path) not in rendered and "sensitive-users" not in rendered


@pytest.mark.parametrize("variant", VARIANTS)
def test_refused_device_chunks_leave_a_section_gap_and_no_device_requests(tmp_path: Path, variant: str) -> None:
    root = _run(tmp_path)
    client = _Client()
    section, coverage = _fanout(root, _source([_refused(root, variant, "devices-1.jsonl")], 1), client)
    _assert_gap(section, coverage, client, tmp_path)


@pytest.mark.parametrize("variant", VARIANTS)
def test_mixed_readable_and_refused_chunks_leave_the_same_gap(tmp_path: Path, variant: str) -> None:
    root = _run(tmp_path)
    client = _Client()
    chunks = [_write(root, "devices-1.jsonl", [_device("readable-device")]), _refused(root, variant, "devices-2.jsonl")]
    section, coverage = _fanout(root, _source(chunks, 2), client)
    _assert_gap(section, coverage, client, tmp_path)
    assert "readable-device" not in json.dumps(coverage)


def test_valid_chunks_are_expanded_with_no_gap(tmp_path: Path) -> None:
    root = _run(tmp_path)
    client = _Client()
    chunk = _write(root, "devices-1.jsonl", [_device("w1")])
    section, coverage = _fanout(root, _source([chunk], 1), client)

    assert "error_class" not in section and section["fanout"]["input_complete"] is True
    assert client.calls
    assert next(item for item in coverage if item["name"] == f"{NAME}Fanout")["status"] == "ok"
    assert not [item for item in section_gap_records(coverage) if item["section"] == NAME]


def test_a_failed_device_list_keeps_its_section_error_without_a_new_row(tmp_path: Path) -> None:
    client = _Client()
    section, coverage = _fanout(_run(tmp_path), {"error": "denied", "error_class": "access_denied"}, client)

    assert section["error_class"] == "incomplete_evidence"
    assert coverage == [] and client.calls == []

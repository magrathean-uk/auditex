"""Structured refusals at the gate CLI boundary and at the chunk reader.

A run argument the descriptor guard refuses keeps the gate's public JSON contract (blocked, exit 2).
When metadata alone shows an ordinary absent, empty or malformed run, the gate's stable code is kept;
anything else is ``unsafe_input`` with a fixed reason plus the guard's own refusal line. Reasons carry
no path and no file content, and a refused input never reaches the gate, a child file or a writer.
"""
from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from gate_support import offline_run

SENTINEL = "structured-refusal-sentinel@example.invalid"


def _main(args: list[str]) -> tuple[int, str]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, buffer.getvalue()


def _tree(root: Path) -> dict[str, tuple[int, int, bytes | None]]:
    state: dict[str, tuple[int, int, bytes | None]] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        state[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, content)
    return state


@pytest.fixture
def unreachable_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.gate as gate

    def unreachable(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a refused run reached the gate")

    monkeypatch.setattr(gate, "gate_findings", unreachable)
    monkeypatch.setattr(gate, "gate_drift", unreachable)


def _blocked(
    args: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str], code: str, label: str
) -> str:
    before = _tree(tmp_path)
    rc, stdout = _main(args)
    err = capsys.readouterr().err
    payload = json.loads(stdout)
    assert rc == 2
    assert payload == {"pass": False, "status": "blocked", "code": code, "reason": payload["reason"]}
    assert payload["reason"].startswith(label + " ")
    assert f"blocked ({code})" in err
    for text in (stdout, err):
        assert str(tmp_path) not in text and tmp_path.name not in text
        assert SENTINEL not in text
    # Nothing was written, created or removed anywhere under the test root.
    assert _tree(tmp_path) == before
    return err


def _ordinary(tmp_path: Path, condition: str) -> Path:
    if condition == "missing":
        return tmp_path / "missing"
    if condition == "empty":
        path = tmp_path / "empty"
        path.mkdir()
        return path
    if condition == "file":
        path = tmp_path / "plain-file"
        path.write_text("{}", encoding="utf-8")
        return path
    run = offline_run(tmp_path / condition, condition)
    (run / "run-manifest.json").write_text("not json" if condition == "not-json" else "[]", encoding="utf-8")
    return run


_ORDINARY_CODES = {
    "missing": "run_dir_missing", "file": "run_dir_missing", "empty": "missing_manifest",
    "not-json": "unreadable_manifest", "array": "unreadable_manifest",
}


def test_valid_runs_still_pass_both_gates(tmp_path: Path) -> None:
    run = offline_run(tmp_path / "one", "one")
    rc, stdout = _main(["gate", str(run), "--fail-on", "high"])
    assert rc == 0 and json.loads(stdout)["pass"] is True
    baseline = offline_run(tmp_path / "baseline", "baseline")
    current = offline_run(tmp_path / "current", "current")
    rc, stdout = _main(["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"])
    assert rc == 0 and json.loads(stdout)["pass"] is True


@pytest.mark.parametrize("condition", sorted(_ORDINARY_CODES))
def test_gate_keeps_its_stable_code_for_an_ordinary_unusable_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], unreachable_gate: None, condition: str
) -> None:
    target = _ordinary(tmp_path, condition)
    err = _blocked(["gate", str(target), "--fail-on", "low"], tmp_path, capsys, _ORDINARY_CODES[condition], "run")
    assert "Refusing" not in err


@pytest.mark.parametrize("side", ["baseline", "current"])
@pytest.mark.parametrize("condition", ["empty", "not-json"])
def test_gate_drift_keeps_its_stable_code_and_names_only_the_side(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], unreachable_gate: None, side: str, condition: str
) -> None:
    valid = offline_run(tmp_path / "valid", "valid")
    target = _ordinary(tmp_path, condition)
    baseline, current = (target, valid) if side == "baseline" else (valid, target)
    args = ["gate-drift", f"--baseline={baseline}", "--current", str(current), "--fail-on", "high"]
    err = _blocked(args, tmp_path, capsys, _ORDINARY_CODES[condition], f"{side} run")
    assert "Refusing" not in err


def _damaged(tmp_path: Path, damage: str) -> Path:
    run = offline_run(tmp_path / "damaged", "damaged")
    if damage == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(run, target_is_directory=True)
        return alias
    manifest = run / "run-manifest.json"
    if damage == "fifo":
        manifest.unlink()
        os.mkfifo(manifest)
        return run
    # The manifest is another name for a private operator input.
    private = run / "operator-inputs"
    private.mkdir(mode=0o700, exist_ok=True)
    (private / "sensitive-users.txt").write_text(SENTINEL + "\n", encoding="utf-8")
    (private / "sensitive-users.key").write_bytes(b"k" * 32)
    manifest.unlink()
    os.link(private / "sensitive-users.txt", manifest)
    return run


@pytest.mark.parametrize("damage,form", [
    ("symlink", "gate"), ("symlink", "gate-selector"), ("symlink", "drift-baseline"), ("symlink", "drift-current-inline"),
    ("fifo", "gate"), ("fifo", "drift-current-inline"),
    ("private-alias", "gate"), ("private-alias", "drift-baseline"),
])
def test_unsafe_run_arguments_are_blocked_with_a_fixed_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], unreachable_gate: None, damage: str, form: str
) -> None:
    target = _damaged(tmp_path, damage)
    if form == "gate":
        args, field, label = ["gate", str(target), "--fail-on", "low"], "run-dir", "run"
    else:
        valid = offline_run(tmp_path / "valid", "valid")
        if form == "gate-selector":
            args = ["gate", str(valid), "--fail-on", "low", "--expect-manifest-sha256", f"{target}={'0' * 64}"]
            field, label = "expect-manifest-sha256", "run"
        elif form == "drift-baseline":
            args = ["gate-drift", "--baseline", str(target), "--current", str(valid), "--fail-on", "high"]
            field, label = "baseline", "baseline run"
        else:
            args = ["gate-drift", "--baseline", str(valid), f"--current={target}", "--fail-on", "high"]
            field, label = "current", "current run"
    err = _blocked(args, tmp_path, capsys, "unsafe_input", label)
    assert f"Refusing {field}: unsafe input." in err


def test_direct_admission_still_raises_with_the_fixed_message(tmp_path: Path) -> None:
    from auditex.cli import _build_gate_parser
    from auditex.gate import gate_findings
    from azure_tenant_audit.cli_guard import RunArgumentRefusal, parse_guarded
    from azure_tenant_audit.guarded_io import UnsafeRunFileError, guard_session

    run = offline_run(tmp_path / "run", "run")
    alias = tmp_path / "alias"
    alias.symlink_to(run, target_is_directory=True)
    for path, condition in ((tmp_path / "missing", "absent"), (alias, None)):
        with guard_session(), pytest.raises(RunArgumentRefusal) as exc:
            parse_guarded(_build_gate_parser(), [str(path), "--fail-on", "low"])
        assert isinstance(exc.value, UnsafeRunFileError)
        assert exc.value.condition == condition
        assert str(exc.value) == "Refusing run-dir: unsafe input."
    with guard_session(), pytest.raises(UnsafeRunFileError):
        gate_findings(run_dir=str(alias), fail_on="low")


def test_other_commands_keep_the_plain_fixed_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, stdout = _main(["compare", "--run-dir", str(tmp_path / "missing")])
    err = capsys.readouterr().err
    assert rc == 2
    assert stdout == ""
    assert "Refusing run-dir: unsafe input." in err
    assert str(tmp_path) not in err


@pytest.mark.parametrize("form", ["hardlink", "direct"])
def test_private_inputs_never_reach_the_chunk_reader_or_its_consumers(tmp_path: Path, form: str) -> None:
    from azure_tenant_audit.chunk_reader import EndpointEvidenceError, iter_endpoint_records
    from azure_tenant_audit.normalize import build_normalized_snapshot

    root = tmp_path / "run"
    private = root / "operator-inputs"
    private.mkdir(parents=True, mode=0o700)
    (private / "sensitive-users.txt").write_text(json.dumps({"id": SENTINEL}) + "\n", encoding="utf-8")
    (private / "sensitive-users.key").write_bytes(b"k" * 32)
    if form == "hardlink":
        (root / "chunks").mkdir()
        os.link(private / "sensitive-users.txt", root / "chunks" / "users.jsonl")
        relative = "chunks/users.jsonl"
    else:
        relative = "operator-inputs/sensitive-users.txt"
    section = {"value": [{"id": "inline-only"}], "chunk_files": [relative], "item_count": 1, "chunk_count": 1}

    with pytest.raises(EndpointEvidenceError) as exc:
        list(iter_endpoint_records(section, root))
    assert exc.value.issue == {"code": "unsafe_chunk_path", "chunk_index": 0}
    issues: list[dict[str, Any]] = []
    assert list(iter_endpoint_records(section, root, issues=issues)) == []
    assert issues[0] == {"code": "unsafe_chunk_path", "chunk_index": 0}
    snapshot = build_normalized_snapshot(
        tenant_name="synthetic", run_id="run", collector_payloads={"identity": {"users": section}}, run_dir=root
    )
    assert snapshot["snapshot"]["normalization_complete"] is False
    assert snapshot["snapshot"]["normalization_incomplete_sections"] == ["identity.users"]
    rendered = json.dumps(snapshot)
    assert SENTINEL not in rendered and "inline-only" not in rendered and "sensitive-users" not in rendered

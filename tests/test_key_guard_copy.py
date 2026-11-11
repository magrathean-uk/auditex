"""Customer-pack copy and digest boundaries must not disclose private inputs."""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import nullcontext
from pathlib import Path

import pytest
from support import RunBundleBuilder

from auditex.reporting import _copy_source_artifact
from azure_tenant_audit import run_files
from azure_tenant_audit.evidence_refs import file_sha256
from azure_tenant_audit.sensitive_users import SensitiveUsers

KEY = b'{"PRIVATEKEY":0,"PRIVATEKEY":1} '
ADDRESS = "private-copy@example.invalid"


@pytest.fixture
def sealed_run(tmp_path: Path) -> Path:
    run = RunBundleBuilder(tmp_path).manifest(
        operator_inputs={"sensitive_users": SensitiveUsers((ADDRESS,)).manifest(KEY)},
    ).build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "sensitive-users.key").write_bytes(KEY)
    (private / "sensitive-users.txt").write_text(ADDRESS + "\n", encoding="utf-8")
    return run


def _context():
    cls = getattr(run_files, "GuardContext", None)
    return cls() if cls is not None else nullcontext(None)


@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("alias_kind", ["direct", "dot", "symlink", "hardlink", "backslash-hardlink"])
def test_copy_never_exposes_private_bytes_or_hash(
    sealed_run: Path, tmp_path: Path, member: str, alias_kind: str,
) -> None:
    source = sealed_run / "operator-inputs" / member
    with _context() as context:
        if context is not None:
            context.bind_run(sealed_run)
        if alias_kind in {"direct", "dot"}:
            relative = ("./" if alias_kind == "dot" else "") + "operator-inputs/" + member
        else:
            directory = sealed_run / "reports"
            directory.mkdir()
            alias = directory / "apparently-public.json"
            if alias_kind == "symlink":
                alias.symlink_to(source)
            else:
                os.link(source, alias)
            relative = (r"reports\apparently-public.json" if alias_kind == "backslash-hardlink"
                        else "reports/apparently-public.json")
        row = _copy_source_artifact(sealed_run, tmp_path / "pack", relative, "test")
    rendered = json.dumps(row)
    assert row["present"] is False and row["customer_safe"] is False
    assert hashlib.sha256(KEY).hexdigest() not in rendered
    assert hashlib.sha256((ADDRESS + "\n").encode()).hexdigest() not in rendered
    assert "PRIVATEKEY" not in rendered and ADDRESS not in rendered
    assert not (tmp_path / "pack").exists()


def test_evidence_file_sha256_never_hashes_registered_key(sealed_run: Path) -> None:
    with _context() as context:
        if context is not None:
            context.bind_run(sealed_run)
        with pytest.raises(run_files.UnsafeRunFileError):
            file_sha256(sealed_run / "operator-inputs" / "sensitive-users.key")


def test_guarded_text_decode_error_never_contains_input_bytes(tmp_path: Path) -> None:
    import traceback

    from auditex.run_bundle import _read_text

    run = RunBundleBuilder(tmp_path).build()
    selected = run / "bad-text"
    selected.write_bytes(b"\xffPRIVATEKEY")
    with pytest.raises(run_files.UnsafeRunFileError) as error:
        _read_text(run, selected)
    rendered = "".join(traceback.format_exception(error.value))
    assert "PRIVATEKEY" not in rendered and "\\xff" not in rendered
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
def test_copy_refuses_case_alias_when_the_filesystem_resolves_it(sealed_run: Path, tmp_path: Path, member: str) -> None:
    relative = f"operator-inputs/{member}".upper()
    if not (sealed_run / relative).is_file():
        pytest.skip("case-sensitive filesystem has no such alias")
    with _context() as context:
        context.bind_run(sealed_run)
        row = _copy_source_artifact(sealed_run, tmp_path / "pack", relative, "test")
    assert row["present"] is False and row["customer_safe"] is False
    assert KEY.decode() not in json.dumps(row)

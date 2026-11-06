"""Constructed rows only; held-out test and pilot rows excluded.

All vectors here are constructed canaries; no pack rows are used.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.sensitive_users import (
    BUNDLE_PATH, KEY_PATH, MAX_BYTES, SensitiveUsers, SensitiveUsersError,
    load_sensitive_users, sensitive_users_digest, verify_sensitive_users,
)

CANARIES = ("sensitive-canary-a@example.invalid", "sensitive-canary-b@example.invalid")
DISCARDED_NAME = "discarded-display-canary@example.invalid"
KEY_CANARY = b"constructed-private-key-canary-1"
SAMPLE = "examples/sample_audit_bundle/sample_result.json"


@pytest.mark.parametrize("content", [
    " Name;Sensitive-Canary-B@Example.Invalid \n sensitive-canary-a@example.invalid\nSENSITIVE-CANARY-A@EXAMPLE.INVALID\n",
    json.dumps(["Name;Sensitive-Canary-B@Example.Invalid", " sensitive-canary-a@example.invalid ", CANARIES[0]]),
    pytest.param("\ufeff" + "\r\n".join(reversed(CANARIES)), id="constructed-sensitive-bom-text"),
    pytest.param("\ufeff" + json.dumps(list(reversed(CANARIES))), id="constructed-sensitive-bom-json"),
])
def test_normalisation_and_hash(tmp_path, content):
    path = tmp_path / "input.txt"
    path.write_text(content)
    supplied = load_sensitive_users(path)
    assert supplied.addresses == CANARIES
    assert supplied.manifest(KEY_CANARY) == {
        "supplied": True, "count": 2,
        "hmac_sha256": hmac.new(KEY_CANARY, "\n".join(CANARIES).encode(), "sha256").hexdigest(),
    }
    assert all(address not in repr(supplied) for address in CANARIES)


@pytest.mark.parametrize(("content", "line"), [
    (b"", 1), (b" \n\n", 1), (b"[]", 1), (b"[\n]", 1),
    (b"[\n42]", 2), (b"[\nnull]", 2), (b"[\n{}]", 2),
    (b'["ok@example.invalid",\n"bad"]', 2),
    (b'["ok@example.invalid",\n]', 2),
    pytest.param(b'["ok@example.invalid",\n' + b"9" * 5000 + b"]", 2, id="constructed-sensitive-huge-integer"),
    pytest.param(b"\xef\xbb\xbf\xef\xbb\xbfok@example.invalid", 1, id="constructed-sensitive-double-bom"),
    pytest.param(b"ok@example.invalid\n\xef\xbb\xbfother@example.invalid", 2, id="constructed-sensitive-embedded-bom"),
    pytest.param("Name\u2028Display;ok@example.invalid\nbad".encode(), 2, id="constructed-sensitive-physical-line-u2028"),
    pytest.param("Name\u0085Display;ok@example.invalid\nbad".encode(), 2, id="constructed-sensitive-physical-line-u0085"),
    (b'["ok@example.invalid"]\nextra', 2),
    (b"ok@example.invalid\nbad;email;ambiguous", 2),
    (b"ok@example.invalid\nname;", 2),
    (b"ok@example.invalid\na..b@example.invalid", 2),
    (b"ok@example.invalid\n.a@example.invalid", 2),
    (b"ok@example.invalid\na@-example.invalid", 2),
    (b"ok@example.invalid\na@example", 2),
    (b"ok@example.invalid\na b@example.invalid", 2),
    (b"ok@example.invalid\na@@example.invalid", 2),
    (b"ok@example.invalid\n\xff", 2),
    pytest.param(b"\xef\xbb\xbf\n\xff", 2, id="constructed-sensitive-bom-utf8-error-line"),
    (b"ok@example.invalid\n\x00", 2),
    (b'[\n"name\\u0000;ok@example.invalid"]', 2),
    (b"x" * (MAX_BYTES + 1), 1),
    (b"a@b.invalid\n" * 10001, 10001),
])
def test_invalid_file_is_sanitised(tmp_path, content, line):
    path = tmp_path / "input.txt"
    path.write_bytes(content)
    with pytest.raises(SensitiveUsersError, match=f"line {line}:") as caught:
        load_sensitive_users(path)
    assert "@" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_regular_file_only_and_read_once(tmp_path, monkeypatch):
    path = tmp_path / "input.txt"
    path.write_text(CANARIES[0])
    opened = []
    original = os.open

    def open_spy(name, flags, *args, **kwargs):
        if Path(name) == path:
            opened.append(flags)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_spy)
    assert load_sensitive_users(path).addresses == CANARIES[:1]
    assert len(opened) == 1
    assert opened[0] & os.O_ACCMODE == os.O_RDONLY
    for non_file in (tmp_path, tmp_path / "missing"):
        with pytest.raises(SensitiveUsersError):
            load_sensitive_users(non_file)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(SensitiveUsersError):
        load_sensitive_users(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(SensitiveUsersError, match="line 1: expected a regular file"):
        load_sensitive_users(fifo)
    if Path("/dev/zero").exists():
        with pytest.raises(SensitiveUsersError, match="line 1: expected a regular file"):
            load_sensitive_users("/dev/zero")


def test_limits_are_inclusive(tmp_path):
    path = tmp_path / "input.txt"
    path.write_text("a@b.invalid\n" * 10000)
    assert load_sensitive_users(path).manifest(KEY_CANARY)["count"] == 1
    path.write_bytes(b"a@b.invalid\n" + b" " * (MAX_BYTES - 12))
    assert path.stat().st_size == MAX_BYTES
    assert load_sensitive_users(path).manifest(KEY_CANARY)["count"] == 1


def test_env_and_flag_precedence(tmp_path, monkeypatch):
    env = tmp_path / "env.txt"
    flag = tmp_path / "flag.txt"
    env.write_text(CANARIES[0])
    flag.write_text(CANARIES[1])
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", str(env))
    assert load_sensitive_users().addresses == CANARIES[:1]
    assert load_sensitive_users(flag).addresses == CANARIES[1:]
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", str(tmp_path / "absent"))
    assert cli.main(["--offline", "--sample", SAMPLE, "--out", str(tmp_path / "out"),
                     "--sensitive-users", str(flag)]) == 0


def test_empty_environment_is_unset_but_empty_explicit_path_is_invalid(monkeypatch):
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", "")
    assert load_sensitive_users().manifest() == {"supplied": False}
    with pytest.raises(SensitiveUsersError):
        load_sensitive_users("")


@pytest.mark.parametrize("failure", [ValueError, RecursionError])
def test_decoder_failures_are_sanitised(tmp_path, monkeypatch, failure):
    path = tmp_path / "input.txt"
    path.write_text('[\n"' + CANARIES[0] + '"]')

    def fail(*args):
        raise failure(str(path) + CANARIES[0])

    monkeypatch.setattr(json.JSONDecoder, "raw_decode", fail)
    with pytest.raises(SensitiveUsersError) as caught:
        load_sensitive_users(path)
    assert str(caught.value) == "Sensitive-users input: line 2: invalid JSON array."


@pytest.mark.parametrize("equals", [False, True])
def test_sensitive_user_prefix_redaction(equals):
    from azure_tenant_audit.auth_runtime import scrub_command_line
    from azure_tenant_audit.secret_hygiene import collect_sensitive_argv_values, redact_argv

    full = "--sensitive-users"
    canary_path = "/constructed/" + CANARIES[0] + ".txt"
    # Synthetic argv remains redacted even though public parsers reject prefixes.
    for end in range(3, len(full) + 1):
        prefix = full[:end]
        argv = [prefix + "=" + canary_path] if equals else [prefix, canary_path]
        for redactor in (scrub_command_line, redact_argv):
            assert redactor(argv) == ([prefix + "=***redacted***"] if equals else [prefix, "***redacted***"])
        assert collect_sensitive_argv_values(argv) == {canary_path}


@pytest.mark.parametrize("guided", [False, True])
@pytest.mark.parametrize("equals", [False, True])
def test_sensitive_user_prefix_rejected_before_file_open(tmp_path, monkeypatch, guided, equals):
    from auditex.guided import build_guided_parser

    path = tmp_path / (CANARIES[0] + ".txt")
    path.write_text(CANARIES[0])
    out = tmp_path / "runs"
    opened = []
    original = os.open

    def open_spy(name, flags, *args, **kwargs):
        if Path(name) == path:
            opened.append(flags)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_spy)
    parser = build_guided_parser() if guided else cli.build_parser()
    full = "--sensitive-users"
    for end in range(3, len(full)):
        prefix = full[:end]
        argv = [prefix + "=" + str(path)] if equals else [prefix, str(path)]
        with pytest.raises(SystemExit) as caught:
            parser.parse_args(["--out", str(out), *argv])
        assert caught.value.code == 2
        assert opened == []
        assert not out.exists()


def test_recording_private_artifact_never_reads_hashes_or_sizes_it(tmp_path, monkeypatch):
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "test", "record-only")
    private = writer.run_dir / BUNDLE_PATH

    def forbidden(*args, **kwargs):
        pytest.fail("recording an artefact must only record its path")

    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    writer.record_artifact(private)
    assert BUNDLE_PATH in writer.artifact_paths()


@pytest.mark.parametrize("entrypoint", ["engine", "product", "guided", "live-direct"])
def test_invalid_input_stops_before_collection(tmp_path, monkeypatch, capsys, caplog, entrypoint):
    from auditex import cli as product_cli
    from auditex import guided

    path = tmp_path / "input.txt"
    path.write_text(CANARIES[0] + "\nname;" + CANARIES[1] + ";bad")
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", str(path))

    def forbidden(*args, **kwargs):
        pytest.fail("collection/auth/guided flow reached with invalid input")

    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", forbidden)
    monkeypatch.setattr(guided, "_resolve_flow", forbidden)
    if entrypoint == "guided":
        assert guided.run_guided(guided.build_guided_parser().parse_args([])) == 2
    elif entrypoint == "live-direct":
        assert cli.run_live(cli.build_parser().parse_args([])) == 2
    else:
        with pytest.raises(SystemExit) as caught:
            (product_cli.main(["run"]) if entrypoint == "product" else cli.main([]))
        assert caught.value.code == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err + caplog.text
    assert "line 2" in output
    assert all(address not in output for address in CANARIES)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("entrypoint", ["engine", "product"])
def test_canaries_stay_only_in_private_copy(tmp_path, monkeypatch, capsys, caplog, entrypoint):
    from azure_tenant_audit import output
    from auditex import cli as product_cli
    from auditex.explorer import write_explorer
    from auditex.exporters import BUILTIN_EXPORTERS, run_exporter
    from auditex.reporting import (
        _copy_source_artifact, enterprise_handoff, verify_enterprise_handoff_pack,
        write_enterprise_handoff_pack,
    )
    from azure_tenant_audit.auth_runtime import scrub_command_line
    from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
    from azure_tenant_audit.secret_hygiene import redact_argv

    monkeypatch.setattr(output.secrets, "token_bytes", lambda size: KEY_CANARY if size == 32 else pytest.fail("key size"))
    path = tmp_path / (CANARIES[0] + ".txt")
    path.write_text(DISCARDED_NAME + ";" + CANARIES[1].upper() + "\n" + CANARIES[0])
    opened = []
    original = os.open

    def spy(name, flags, *args, **kwargs):
        if Path(name) == path:
            opened.append(flags)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    argv = ["--offline", "--sample", SAMPLE, "--out", str(tmp_path / "runs"),
            "--tenant-name", "test", "--run-name", "canary", "--sensitive-users", str(path)]
    assert (cli.main(argv) if entrypoint == "engine" else product_cli.main(["run", *argv])) == 0
    assert len(opened) == 1
    run = tmp_path / "runs" / "test-canary"
    private = run / BUNDLE_PATH
    key_file = run / KEY_PATH
    assert key_file.read_bytes() == KEY_CANARY
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert private.read_text() == "\n".join(CANARIES) + "\n"
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(private.parent.stat().st_mode) == 0o700
    manifest = json.loads((run / "run-manifest.json").read_text())
    assert manifest["operator_inputs"]["sensitive_users"] == load_sensitive_users(path).manifest(KEY_CANARY)
    assert "sha256" not in manifest["operator_inputs"]["sensitive_users"]
    assert verify_sensitive_users(run)
    assert BUNDLE_PATH in manifest["artifacts"]
    assert BUNDLE_PATH in manifest["redacted_artifacts"]
    assert KEY_PATH in manifest["artifacts"]
    assert KEY_PATH in manifest["redacted_artifacts"]
    assert (run / "operator-inputs/.gitignore").read_text() == "*\n"
    assert "operator-inputs" not in json.loads((run / "ai_context.json").read_text())["artifacts"]
    assert BUNDLE_PATH not in json.loads((run / "ai_context.json").read_text())["artifacts"].get("operator-inputs", [])
    assert verify_bundle_hashes(run)["status"] == "verified"
    pack = tmp_path / "pack"
    write_enterprise_handoff_pack(run, pack)
    for hashes_path in (run / "bundle-hashes.json", pack / "source-artifacts/bundle-hashes.json"):
        hashes = json.loads(hashes_path.read_text())
        assert not any(row["path"].startswith("operator-inputs/") for row in hashes["artifacts"])
        excluded = [row for row in hashes["excluded"] if row["path"].startswith("operator-inputs/")]
        assert sorted(excluded, key=lambda row: row["path"]) == [
            {"path": "operator-inputs/.gitignore", "reason": "redacted_operator_input"},
            {"path": KEY_PATH, "reason": "redacted_operator_input"},
            {"path": BUNDLE_PATH, "reason": "redacted_operator_input"},
        ]
    # Neither private content nor its file fingerprint/size may enter the index.
    private_digest = hashlib.sha256(private.read_bytes()).hexdigest()
    assert private_digest.encode() not in (run / "index/evidence.sqlite").read_bytes()
    key_digest = hashlib.sha256(key_file.read_bytes()).hexdigest()
    assert key_digest.encode() not in (run / "index/evidence.sqlite").read_bytes()
    assert not (pack / "source-artifacts/operator-inputs").exists()
    assert not (pack / "source-artifacts" / BUNDLE_PATH).exists()
    assert verify_enterprise_handoff_pack(pack)["valid"]
    denied = _copy_source_artifact(run, tmp_path / "manual-copy", BUNDLE_PATH, "test")
    assert denied["skipped_reason"] == "redacted_operator_input"
    for relative in (KEY_PATH, "./" + KEY_PATH, "operator-inputs/./sensitive-users.key"):
        denied_key = _copy_source_artifact(run, tmp_path / "manual-copy", relative, "test")
        assert denied_key["skipped_reason"] == "redacted_operator_input"
    for format_name in BUILTIN_EXPORTERS:
        run_exporter(name=format_name, run_dir=str(run), output_path=str(tmp_path / "rendered" / format_name))
    write_explorer([run], tmp_path / "explorer.html")
    handoff = json.dumps(enterprise_handoff(run))
    captured = capsys.readouterr()
    emitted = captured.out + captured.err + caplog.text + handoff
    for redactor in (scrub_command_line, redact_argv):
        emitted += json.dumps(redactor(["--sensitive-users", str(path), "--sensitive-users=" + str(path)]))
    assert all(address not in emitted.lower() for address in (*CANARIES, DISCARDED_NAME))
    assert KEY_CANARY.decode() not in emitted
    assert KEY_CANARY.hex() not in emitted
    # Only the named private inputs are exempt from integrity accounting.
    planted_paths = ("operator-inputs/planted.json", "operator-inputs/sub/x.json")
    for relative in planted_paths:
        planted = run / relative
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text("{}\n")
    integrity = verify_bundle_hashes(run)
    assert set(planted_paths) <= set(integrity["unlisted"])
    assert not {BUNDLE_PATH, KEY_PATH, "operator-inputs/.gitignore"} & set(integrity["unlisted"])
    # Scan every bundle byte (including SQLite, coverage, events and audit logs), pack,
    # export and explorer. Only the source and the explicitly private copy may contain a canary.
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact != key_file:
            data = artifact.read_bytes()
            assert KEY_CANARY not in data, artifact.relative_to(tmp_path)
            assert KEY_CANARY.hex().encode() not in data, artifact.relative_to(tmp_path)
        if artifact.is_file() and artifact not in (path, private, key_file):
            data = artifact.read_bytes().lower()
            assert all(address.encode() not in data for address in (*CANARIES, DISCARDED_NAME)), artifact.relative_to(tmp_path)


@pytest.fixture
def umask_022():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def test_resume_replaces_or_removes_private_copy(tmp_path, umask_022):
    from azure_tenant_audit.output import AuditWriter
    from azure_tenant_audit.sensitive_users import SensitiveUsers

    writer = AuditWriter(tmp_path, "test", "resume")
    writer.write_sensitive_users(SensitiveUsers(CANARIES))
    key = (writer.run_dir / KEY_PATH).read_bytes()
    assert len(key) == 32
    assert stat.S_IMODE((writer.run_dir / KEY_PATH).stat().st_mode) == 0o600
    assert stat.S_IMODE((writer.run_dir / BUNDLE_PATH).stat().st_mode) == 0o600
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_sensitive_users(writer.run_dir)
    original = json.loads((writer.run_dir / "run-manifest.json").read_text())["operator_inputs"]
    resumed = AuditWriter(tmp_path, "test", "resume", run_dir=writer.run_dir)
    resumed.write_sensitive_users(SensitiveUsers(CANARIES))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert json.loads((writer.run_dir / "run-manifest.json").read_text())["operator_inputs"] == original
    assert verify_sensitive_users(writer.run_dir)
    resumed.write_sensitive_users(SensitiveUsers(CANARIES[:1]))
    assert (resumed.run_dir / KEY_PATH).read_bytes() == key
    assert stat.S_IMODE((resumed.run_dir / KEY_PATH).stat().st_mode) == 0o600
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_sensitive_users(resumed.run_dir)
    assert stat.S_IMODE((resumed.run_dir / BUNDLE_PATH).stat().st_mode) == 0o600
    assert (resumed.run_dir / BUNDLE_PATH).read_text() == CANARIES[0] + "\n"
    resumed.write_sensitive_users(SensitiveUsers())
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    manifest = json.loads((resumed.run_dir / "run-manifest.json").read_text())
    assert manifest["operator_inputs"]["sensitive_users"] == {"supplied": False}
    assert BUNDLE_PATH not in manifest["artifacts"]
    assert BUNDLE_PATH not in manifest["redacted_artifacts"]
    assert not (resumed.run_dir / BUNDLE_PATH).exists()
    assert not (resumed.run_dir / "operator-inputs/.gitignore").exists()
    assert KEY_PATH not in manifest["artifacts"]
    assert KEY_PATH not in manifest["redacted_artifacts"]
    assert not (resumed.run_dir / KEY_PATH).exists()
    assert not verify_sensitive_users(resumed.run_dir)
    resumed.write_sensitive_users(SensitiveUsers(CANARIES))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert (resumed.run_dir / KEY_PATH).read_bytes() != key
    assert verify_sensitive_users(resumed.run_dir)


def test_same_list_has_different_hmac_per_run(tmp_path):
    from azure_tenant_audit.output import AuditWriter

    digests, keys = [], []
    for name in ("first", "second"):
        writer = AuditWriter(tmp_path, "test", name)
        writer.write_sensitive_users(SensitiveUsers(CANARIES))
        writer.write_bundle({"collectors": [], "overall_status": "ok"})
        keys.append((writer.run_dir / KEY_PATH).read_bytes())
        digests.append(json.loads((writer.run_dir / "run-manifest.json").read_text())
                       ["operator_inputs"]["sensitive_users"]["hmac_sha256"])
        assert verify_sensitive_users(writer.run_dir)
    assert len(keys[0]) == len(keys[1]) == 32
    assert keys[0] != keys[1]
    assert digests[0] != digests[1]


@pytest.mark.parametrize("tamper", ["list", "key", "missing-key", "short-key", "digest", "count", "supplied"])
def test_verification_rejects_tamper(tmp_path, tamper):
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "test", "tamper")
    writer.write_sensitive_users(SensitiveUsers(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_sensitive_users(writer.run_dir)
    key_file = writer.run_dir / KEY_PATH
    if tamper == "list":
        (writer.run_dir / BUNDLE_PATH).write_text(CANARIES[0] + "\n")
    elif tamper == "key":
        key_file.write_bytes(bytes(byte ^ 1 for byte in key_file.read_bytes()))
    elif tamper == "missing-key":
        key_file.unlink()
    elif tamper == "short-key":
        key_file.write_bytes(b"short")
    else:
        manifest_path = writer.run_dir / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        field, value = {"digest": ("hmac_sha256", "0" * 64), "count": ("count", 1),
                        "supplied": ("supplied", False)}[tamper]
        manifest["operator_inputs"]["sensitive_users"][field] = value
        manifest_path.write_text(json.dumps(manifest))
    assert not verify_sensitive_users(writer.run_dir)


@pytest.mark.parametrize("damage", ["missing", "short", "symlink", "fifo"])
def test_resume_never_silently_replaces_unusable_key(tmp_path, damage):
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "test", "resume-key")
    writer.write_sensitive_users(SensitiveUsers(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    key_file = writer.run_dir / KEY_PATH
    key_file.unlink()
    if damage == "short":
        key_file.write_bytes(b"short")
    elif damage == "symlink":
        key_file.symlink_to(writer.run_dir / BUNDLE_PATH)
    elif damage == "fifo":
        os.mkfifo(key_file)
    resumed = AuditWriter(tmp_path, "test", run_dir=writer.run_dir)
    with pytest.raises(SensitiveUsersError):
        resumed.write_sensitive_users(SensitiveUsers(CANARIES[:1]))
    assert (writer.run_dir / BUNDLE_PATH).read_text() == "\n".join(CANARIES) + "\n"
    assert not verify_sensitive_users(writer.run_dir)


def test_digest_requires_a_32_byte_key():
    with pytest.raises(SensitiveUsersError):
        sensitive_users_digest(CANARIES, b"short")


def test_guided_passes_loaded_input_without_rereading(tmp_path, monkeypatch, capsys):
    from auditex import guided

    path = tmp_path / "input.txt"
    path.write_text(CANARIES[0])
    monkeypatch.setattr(guided, "build_doctor_report", lambda **kwargs: {
        "system": {"os": "test", "machine": "test"}, "auth": {},
        "readiness": {"core_ready": True, "exchange_ready": True},
    })
    monkeypatch.setattr(guided, "_persist_local_defaults", lambda **kwargs: None)
    seen = []

    def engine(argv, event_listener=None, *, sensitive_users):
        path.unlink()
        seen.append(sensitive_users.addresses)
        assert "--sensitive-users" not in argv
        return 0

    monkeypatch.setattr(guided.tenant_cli, "main", engine)
    args = guided.build_guided_parser().parse_args([
        "--flow", "app-audit", "--tenant-id", "tenant.invalid", "--tenant-name", "test",
        "--client-id", "constructed-app", "--client-secret", "constructed-secret",
        "--non-interactive", "--local-mode", "--out", str(tmp_path / "out"),
        "--sensitive-users", str(path),
    ])
    assert guided.run_guided(args) == 0
    assert seen == [CANARIES[:1]]
    output = capsys.readouterr()
    assert CANARIES[0] not in output.out + output.err


@pytest.mark.parametrize("flag", ["--sensitive-users"])
@pytest.mark.parametrize("equals", [False, True])
def test_simulated_live_run_reads_once_before_collection(tmp_path, monkeypatch, capsys, caplog, flag, equals):
    from azure_tenant_audit.collectors.base import CollectorResult

    path = tmp_path / (CANARIES[0] + ".txt")
    path.write_text("Name;" + CANARIES[0].upper())
    events = []

    class Collector:
        name = "identity"

        def run(self, context):
            # The source disappears during collection; finalisation must use the parsed value.
            path.unlink()
            return CollectorResult(name="identity", status="ok", item_count=1, message="ok",
                                   payload={"value": [{"id": "constructed-user"}]},
                                   coverage=[{"collector": "identity", "name": "users", "type": "graph",
                                              "status": "ok", "item_count": 1}])

    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Collector()})
    argv = ["--tenant-name", "test", "--run-name", "live", "--tenant-id", "constructed-tenant",
            "--client-id", "constructed-app", "--client-secret", "constructed-secret",
            "--collectors", "identity", "--out", str(tmp_path / "runs")]
    argv.extend([flag + "=" + str(path)] if equals else [flag, str(path)])
    assert cli.main(argv, event_listener=events.append) == 0
    run = tmp_path / "runs" / "test-live"
    private = run / BUNDLE_PATH
    assert private.read_text() == CANARIES[0] + "\n"
    manifest = json.loads((run / "run-manifest.json").read_text())
    assert manifest["command_line"][-1] == (flag + "=***redacted***" if equals else "***redacted***")
    assert manifest["operator_inputs"]["sensitive_users"]["count"] == 1
    captured = capsys.readouterr()
    assert CANARIES[0] not in (json.dumps(events) + captured.out + captured.err + caplog.text).lower()
    for artifact in run.rglob("*"):
        if artifact.is_file() and artifact != private:
            assert CANARIES[0].encode() not in artifact.read_bytes().lower(), artifact.relative_to(run)


SS21 = "MS.SECURITYSUITE.2.1v1"
SS23 = "MS.SECURITYSUITE.2.3v1"


def rule_input_bundle(tmp_path, addresses=CANARIES):
    """A real private operator copy and constructed Exchange operation envelopes."""
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "mocktenant", "sensitive-rules")
    writer.write_sensitive_users(SensitiveUsers(addresses))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    root = writer.run_dir
    (root / "raw").mkdir(exist_ok=True)
    operations = {
        "acceptedDomains": [], "antiPhishRules": [], "eopProtectionPolicyRules": [],
        "atpProtectionPolicyRules": [], "atpPolicyForO365": [],
        "antiPhishPolicies": [{"Identity": "Default", "Name": "Default", "Enabled": True,
                               "IsDefault": True, "EnableTargetedUserProtection": True,
                               "TargetedUserProtectionAction": "Quarantine",
                               "TargetedUsersToProtect": list(addresses)}],
    }
    (root / "raw/exchange_policy.json").write_text(json.dumps({
        name: {"value": rows, "status": "ok"} for name, rows in operations.items()}))
    return root


def private_config(projection):
    from auditex.scuba_projection import rule_policy_section

    return rule_policy_section(projection, SS21, "scuba_config")


@pytest.mark.parametrize("damage", [
    "missing", "tampered", "count", "bool-count", "hmac", "false", "absent", "bad-shape",
    "bad-metadata", "extra-metadata", "missing-key", "short-key", "directory", "symlink", "parent-symlink",
    "key-symlink", "fifo", "unreadable", "oversize", "entries", "noncanonical",
])
def test_rule_input_rejects_mutation(tmp_path, monkeypatch, damage, capsys, caplog):
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.model_evidence import NOT_COLLECTED
    from azure_tenant_audit.sensitive_users import MAX_ENTRIES

    root = rule_input_bundle(tmp_path)
    target, key_path = root / BUNDLE_PATH, root / KEY_PATH
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    metadata = manifest["operator_inputs"]["sensitive_users"]
    if damage == "missing":
        target.unlink()
    elif damage == "tampered":
        target.write_text(CANARIES[0] + "\n")
    elif damage in {"count", "bool-count", "hmac", "false"}:
        field, value = {"count": ("count", 1), "bool-count": ("count", True),
                        "hmac": ("hmac_sha256", "0" * 64), "false": ("supplied", False)}[damage]
        metadata[field] = value
    elif damage == "absent":
        manifest.pop("operator_inputs")
    elif damage == "bad-shape":
        manifest["operator_inputs"] = []
    elif damage == "bad-metadata":
        manifest["operator_inputs"]["sensitive_users"] = []
    elif damage == "extra-metadata":
        metadata["unexpected"] = True
    elif damage == "missing-key":
        key_path.unlink()
    elif damage == "short-key":
        key_path.write_bytes(b"short")
    elif damage in {"directory", "symlink", "fifo"}:
        target.unlink()
        if damage == "directory":
            target.mkdir()
        elif damage == "fifo":
            os.mkfifo(target)
        else:
            target.symlink_to(root / "run-manifest.json")
    elif damage == "parent-symlink":
        private = root / "operator-inputs"
        moved = tmp_path / "outside-private"
        private.rename(moved)
        private.symlink_to(moved, target_is_directory=True)
    elif damage == "key-symlink":
        key_path.unlink()
        key_path.symlink_to(target)
    elif damage == "unreadable":
        original = os.open

        def denied(path, *args, **kwargs):
            if str(path) == "sensitive-users.txt":
                raise PermissionError("constructed sanitisation canary " + CANARIES[0])
            return original(path, *args, **kwargs)

        monkeypatch.setattr(os, "open", denied)
    elif damage == "oversize":
        target.write_bytes(b"x" * (MAX_BYTES + 1))
    elif damage == "entries":
        target.write_text("a@b.invalid\n" * (MAX_ENTRIES + 1))
    elif damage == "noncanonical":
        target.write_text("\n".join(reversed(CANARIES)) + "\n")
    manifest_path.write_text(json.dumps(manifest))
    projection = project_run(root)
    assert private_config(projection) == NOT_COLLECTED
    outcome = projection.report["sections"]["scuba_config"]["synthesis"]["policies"][SS21]
    assert outcome == ("oversize" if damage in {"oversize", "entries"} else "operator_input_required")
    captured = capsys.readouterr()
    public = json.dumps([projection, projection.views, projection.report]) + captured.out + captured.err + caplog.text
    assert all(address not in public for address in CANARIES)


@pytest.mark.parametrize("entrypoint", ["project", "assess"])
@pytest.mark.parametrize("invalid", ["UPPERCASE@EXAMPLE.INVALID", "not-an-email"])
def test_rule_input_rejects_invalid_captured_snapshot_after_replacement(tmp_path, monkeypatch, entrypoint, invalid):
    from auditex import model_serving, scuba_projection
    from azure_tenant_audit.model_evidence import NOT_COLLECTED
    from azure_tenant_audit.value_rules import assess

    root = rule_input_bundle(tmp_path, (invalid,))
    operations_path = root / "raw/exchange_policy.json"
    operations = json.loads(operations_path.read_text())
    operations["antiPhishPolicies"]["value"][0]["TargetedUserProtectionAction"] = "NoAction"
    operations_path.write_text(json.dumps(operations))
    target = root / BUNDLE_PATH
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    key = (root / KEY_PATH).read_bytes()
    assert manifest["operator_inputs"]["sensitive_users"] == SensitiveUsers((invalid,)).manifest(key)

    replacement_list = tmp_path / "replacement-list"
    replacement_list.write_text(CANARIES[0] + "\n")
    replacement_manifest = tmp_path / "replacement-manifest"
    manifest["operator_inputs"]["sensitive_users"] = SensitiveUsers(CANARIES[:1]).manifest(key)
    replacement_manifest.write_text(json.dumps(manifest))

    # Swap both files only after the projection has captured the original list
    # and key, and after it has already read the original manifest.
    original_open, original_close = os.open, os.close
    private_directory = None
    private_file_opens = []
    swapped = False

    def capture_open(path, flags, *args, **kwargs):
        nonlocal private_directory
        fd = original_open(path, flags, *args, **kwargs)
        if path == root / "operator-inputs":
            private_directory = fd
        if Path(path).name in {"sensitive-users.txt", "sensitive-users.key"}:
            private_file_opens.append(Path(path).name)
        return fd

    def replace_on_close(fd):
        nonlocal swapped
        original_close(fd)
        if fd == private_directory and not swapped:
            os.replace(replacement_list, target)
            os.replace(replacement_manifest, manifest_path)
            swapped = True

    monkeypatch.setattr(os, "open", capture_open)
    monkeypatch.setattr(os, "close", replace_on_close)
    projections = []
    if entrypoint == "project":
        projections.append(scuba_projection.project_run(root))
    else:
        def capture_projection(*args, **kwargs):
            projection = scuba_projection.project_run(*args, **kwargs)
            projections.append(projection)
            return projection

        monkeypatch.setattr(model_serving, "project_run", capture_projection)
        result = model_serving.assess_run(root, policies=[SS21])

    assert swapped
    assert len(projections) == 1
    if entrypoint == "assess":
        assert result["policies"][0]["rule_precheck"]["cell"] == "section_not_collected"
    projection = projections[0]
    assert private_config(projection) == NOT_COLLECTED
    assert projection.report["sections"]["scuba_config"]["synthesis"]["policies"][SS21] == "operator_input_required"
    sections = {**projection.rule_sections, "scuba_config": private_config(projection)}
    assert assess(SS21, sections)["cell"] == "section_not_collected"
    assert private_file_opens == ["sensitive-users.txt", "sensitive-users.key"]
    assert verify_sensitive_users(root)  # The replacement is independently valid.


@pytest.mark.parametrize("data", [
    b" A@example.invalid \n",
    b"Name;a@example.invalid\n",
    b'["a@example.invalid"]\n',
    b"\xef\xbb\xbfa@example.invalid\n",
])
def test_rule_input_rejects_noncanonical_snapshot_with_matching_hmac(tmp_path, data):
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.model_evidence import NOT_COLLECTED

    root = rule_input_bundle(tmp_path, CANARIES[:1])
    (root / BUNDLE_PATH).write_bytes(data)
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    key = (root / KEY_PATH).read_bytes()
    captured = (data.decode("utf-8").removesuffix("\n"),)
    manifest["operator_inputs"]["sensitive_users"] = SensitiveUsers(captured).manifest(key)
    manifest_path.write_text(json.dumps(manifest))

    projection = project_run(root)
    assert private_config(projection) == NOT_COLLECTED
    assert projection.report["sections"]["scuba_config"]["synthesis"]["policies"][SS21] == "operator_input_required"


def test_rule_input_reads_valid_private_files_once(tmp_path, monkeypatch):
    from auditex.scuba_projection import project_run

    root = rule_input_bundle(tmp_path)
    original_open = os.open
    private_file_opens = []

    def capture_open(path, flags, *args, **kwargs):
        if Path(path).name in {"sensitive-users.txt", "sensitive-users.key"}:
            private_file_opens.append(Path(path).name)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", capture_open)
    projection = project_run(root)
    assert private_config(projection) == {"SecuritySuite": {SS21: {"SensitiveUsers": list(CANARIES)}}}
    assert private_file_opens == ["sensitive-users.txt", "sensitive-users.key"]


def test_rule_input_private_capture_ignores_model_budgets_and_never_enters_gate(tmp_path, monkeypatch):
    from auditex import scuba_projection as module
    from azure_tenant_audit.model_evidence import NOT_COLLECTED

    addresses = tuple(f"private-{i:04}@example.invalid" for i in range(100))
    root = rule_input_bundle(tmp_path, addresses)
    for name in ("_seen_shape", "_oversize"):
        original = getattr(module, name)

        def guarded(*args, _original=original, **kwargs):
            assert not any(address in repr(args) for address in addresses)
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, guarded)
    for redact in (True, False):
        # Avoid raw tenant-policy canaries: this check isolates the operator copy.
        (root / "raw/exchange_policy.json").unlink(missing_ok=True)
        projection = module.project_run(root, redact=redact, max_items=1, max_chars=10)
        assert private_config(projection) == {"SecuritySuite": {SS21: {"SensitiveUsers": list(addresses)}}}
        assert module.policy_section(projection, SS21, "scuba_config") == NOT_COLLECTED
        public = json.dumps([projection, projection.views, projection.report, projection.rule_sections])
        assert all(address not in public for address in addresses)
        assert module.rule_policy_section(projection, SS23, "scuba_config") == NOT_COLLECTED


def test_rule_input_does_not_consume_extra_private_files_or_unmanifested_input(tmp_path, monkeypatch):
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.bundle_integrity import build_bundle_hash_manifest, verify_bundle_hashes

    root = rule_input_bundle(tmp_path)
    before = project_run(root)
    (root / "bundle-hashes.json").write_text(json.dumps(build_bundle_hash_manifest(root)))
    extra = root / "operator-inputs/unrelated.txt"
    extra.write_text("unrelated-private-canary@example.invalid\n")
    after = project_run(root)
    assert after == before and after.views == before.views and after.rule_views == before.rule_views
    assert extra.relative_to(root).as_posix() in verify_bundle_hashes(root)["unlisted"]
    manifest_path = root / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("operator_inputs")
    manifest_path.write_text(json.dumps(manifest))
    baseline = project_run(root)
    # False / absent metadata must not open any private file and must preserve
    # all public bytes, including the existing synthesis record and prompt view.
    original = os.open

    def denied(path, *args, **kwargs):
        assert "operator-inputs" not in str(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    manifest["operator_inputs"] = {"sensitive_users": {"supplied": False}}
    manifest_path.write_text(json.dumps(manifest))
    absent = project_run(root)
    assert json.dumps([absent, absent.views, absent.report], sort_keys=True) == json.dumps(
        [baseline, baseline.views, baseline.report], sort_keys=True)


@pytest.mark.parametrize("action,cell", [("Quarantine", "policy_field_unusable"),
                                         ("NoAction", "no_qualifying_policy")])
def test_rule_input_assessment_replay_and_all_public_outputs_are_private(
    tmp_path, monkeypatch, capsys, caplog, action, cell,
):
    from copy import deepcopy
    import shutil
    from auditex import scuba_projection as module
    from auditex.model_serving import ModelClient, assess_run, assess_scubagear_export, policy_catalogue
    from auditex.scubagear_export import load_export, project_export
    from azure_tenant_audit.model_assessment import validate_assessment
    from azure_tenant_audit.value_rules import assess

    caplog.set_level("DEBUG")
    root = rule_input_bundle(tmp_path)
    operations_path = root / "raw/exchange_policy.json"
    operations = json.loads(operations_path.read_text())
    operations["antiPhishPolicies"]["value"][0]["TargetedUserProtectionAction"] = action
    operations_path.write_text(json.dumps(operations))
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("operator input called the model"))
    projection = module.project_run(root)
    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = private_config(projection)
    assert assess(SS21, sections)["cell"] == cell
    public_outputs = [projection, projection.views, projection.report]
    result = assess_run(root, policies=[SS21, SS23])
    validate_assessment(result)
    assert result["policies"][0]["rule_precheck"]["cell"] == cell
    assert result["policies"][1]["rule_precheck"]["cell"] == "section_not_collected"
    public_outputs.append(result)
    public_outputs.append(assess_run(root, policies=[SS21], dry_run=True))
    replay = tmp_path / "offline-replay"
    shutil.copytree(root, replay)
    replay_result = assess_run(replay, policies=[SS21, SS23])
    assert replay_result["policies"] == result["policies"]
    public_outputs.append(replay_result)
    # Export configuration remains provider-owned. Adjacent bundle inputs must
    # never get imported; today's export withholding and public outputs stay intact.
    provider = json.loads(Path("tests/fixtures/scubagear-export/mocktenant-provider-export.json").read_text())
    provider.update({section: deepcopy(value) for section, value in sections.items()
                     if section != "scuba_config"})
    provider["scuba_config"] = private_config(projection)
    export_path = tmp_path / "provider.json"
    export_path.write_text(json.dumps(provider))
    exported, extra = project_export(load_export(export_path), policy_catalogue()["policies"])
    public_outputs.extend([exported, exported.views, exported.report, extra])
    export_result = assess_scubagear_export(export_path, tmp_path / "export-assessment", policies=[SS21])
    validate_assessment(export_result)
    public_outputs.append(export_result)
    public_outputs.append(assess_scubagear_export(
        export_path, tmp_path / "export-dry", policies=[SS21], dry_run=True))
    captured = capsys.readouterr()
    text = json.dumps(public_outputs) + captured.out + captured.err + caplog.text
    assert all(address not in text for address in CANARIES)
    # Synthetic source evidence and the explicitly private copies are the only
    # exemptions; assessment JSON, prompts, adapter sidecars and logs are scanned.
    exemptions = {export_path, operations_path, replay / "raw/exchange_policy.json",
                  root / BUNDLE_PATH, root / KEY_PATH, replay / BUNDLE_PATH, replay / KEY_PATH}
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact not in exemptions:
            assert all(address.encode() not in artifact.read_bytes().lower() for address in CANARIES), artifact


def test_rule_input_verified_configuration_reaches_every_compatible_vector_cell(tmp_path, record_property):
    """Replay existing synthetic/train/validation vectors through the real list loader.

    Raw rule evidence is supplied directly, as in the vector harness. This is
    deliberately distinct from collection: the current collector and adapter
    do not supply TargetedUsersToProtect. Four malformed/empty config cells
    cannot be produced by a verified canonical list; the ordinary s5 harness
    still tests them, together with all other SS 2.1 cells.
    """
    from collections import Counter
    from copy import deepcopy
    import lzma
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.value_rules import assess, cells_for
    from test_value_rules_s4 import _serve_rule

    source = Path("tests/fixtures/value-rules/vectors-s5.jsonl.xz")
    counts = Counter()
    with lzma.open(source, "rt") as handle:
        rows = [row for line in handle if (row := json.loads(line))["policy"] == SS21]
    for index, vector in enumerate(rows):
        config = vector["sections"].get("scuba_config")
        if not isinstance(config, dict):
            continue
        block = config.get("SecuritySuite", {}).get(SS21, {}) if isinstance(config.get("SecuritySuite"), dict) else {}
        if not block and isinstance(config.get("Defender"), dict):
            block = config["Defender"].get("MS.DEFENDER.2.1v1", {})
        values = block.get("SensitiveUsers") if isinstance(block, dict) else None
        if not isinstance(values, list):
            continue
        local = tmp_path / str(index)
        local.mkdir()
        input_path = local / "input.txt"
        input_path.write_text(json.dumps(values))
        try:
            supplied = load_sensitive_users(input_path)
        except SensitiveUsersError:
            continue
        root = rule_input_bundle(local, supplied.addresses)
        sections = deepcopy(vector["sections"])
        sections["scuba_config"] = private_config(project_run(root))
        record = assess(SS21, sections)
        served = _serve_rule(SS21, sections)
        assert (record["cell"], record["verdict"], record["reason_code"], record["reason_text"]) == (
            vector["rule_cell"], vector["rule_verdict"], vector["rule_reason_code"], vector["rule_reason_text"])
        assert served["rule_precheck"]["cell"] == record["cell"]
        counts[record["cell"]] += 1
    assert len(rows) == 264
    assert set(counts) == set(cells_for(SS21)) - {
        "config_shape_unusable", "config_list_unusable", "config_list_empty", "config_entry_unusable"}
    assert {"default_qualifies", "custom_qualifies", "preset_qualifies", "no_qualifying_policy"} <= counts.keys()
    record_property("sensitive_users_vector_counts", json.dumps({
        "total": sum(counts.values()), "by_cell": dict(sorted(counts.items()))}))


def test_rule_input_met_canaries_with_synthetic_private_policy_evidence(tmp_path, monkeypatch, capsys, caplog):
    """Test the downstream privacy boundary without pretending collection supplies targets."""
    from auditex.model_serving import assess_run
    from auditex.scuba_projection import project_run
    from azure_tenant_audit.model_assessment import validate_assessment

    root = rule_input_bundle(tmp_path)
    projection = project_run(root)
    # Only this constructed rule evidence has targets. The production adapter
    # deliberately omits them; the separate replay test pins that limitation.
    projection.rule_sections["anti_phish_policies"][0]["TargetedUsersToProtect"] = list(CANARIES)
    monkeypatch.setattr("auditex.model_serving.project_run", lambda *args, **kwargs: projection)
    result = assess_run(root, policies=[SS21])
    validate_assessment(result)
    assert result["policies"][0]["rule_precheck"]["cell"] == "default_qualifies"
    dry = assess_run(root, policies=[SS21], dry_run=True)
    captured = capsys.readouterr()
    public = json.dumps([result, dry, projection, projection.views, projection.report])
    public += captured.out + captured.err + caplog.text
    assert all(address not in public for address in CANARIES)
    for artifact in root.rglob("*"):
        if artifact.is_file() and artifact.relative_to(root).as_posix() not in {
            BUNDLE_PATH, KEY_PATH, "raw/exchange_policy.json"}:
            assert all(address.encode() not in artifact.read_bytes().lower() for address in CANARIES), artifact

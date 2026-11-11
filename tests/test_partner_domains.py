"""Constructed rows only; held-out test and pilot rows excluded.

Fixture provenance boundary: constructed rows and pack train and validation rows
from v3.9.1; held-out test and pilot rows excluded. All vectors actually used here
are constructed canaries; no pack rows or spec vector rows are copied.
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
from azure_tenant_audit.partner_domains import (
    BUNDLE_PATH,
    KEY_PATH,
    MAX_BYTES,
    PartnerDomains,
    PartnerDomainsError,
    load_partner_domains,
    partner_domains_digest,
    verify_partner_domains,
)

CANARIES = ("partner-canary-a.example.invalid", "partner-canary-b.example.invalid")
KEY_CANARY = b"constructed-private-key-canary-2"
SAMPLE = "examples/sample_audit_bundle/sample_result.json"


@pytest.mark.parametrize("content", [
    " Partner-Canary-B.Example.Invalid. \n partner-canary-a.example.invalid\nPARTNER-CANARY-A.EXAMPLE.INVALID\n",
    json.dumps(["Partner-Canary-B.Example.Invalid.", " partner-canary-a.example.invalid ", CANARIES[0]]),
    pytest.param("\ufeff" + "\r\n".join(reversed(CANARIES)), id="constructed-partner-bom-text"),
    pytest.param("\ufeff" + json.dumps(list(reversed(CANARIES))), id="constructed-partner-bom-json"),
])
def test_normalisation_and_hash(tmp_path, content):
    path = tmp_path / "input.txt"
    path.write_text(content)
    supplied = load_partner_domains(path)
    assert supplied.domains == CANARIES
    assert supplied.manifest(KEY_CANARY) == {
        "supplied": True, "count": 2,
        "hmac_sha256": hmac.new(KEY_CANARY, "\n".join(CANARIES).encode(), "sha256").hexdigest(),
    }
    assert all(domain not in repr(supplied) for domain in CANARIES)


@pytest.mark.parametrize(("content", "line"), [
    (b"", 1), (b" \n\n", 1), (b"[]", 1), (b"[\n]", 1),
    (b"[\n42]", 2), (b"[\nnull]", 2), (b"[\n{}]", 2),
    (b'["ok.example.invalid",\n"bad"]', 2),
    (b'["ok.example.invalid",\n]', 2),
    pytest.param(b'["ok.example.invalid",\n' + b"9" * 5000 + b"]", 2, id="constructed-partner-huge-integer"),
    (b"\xef\xbb\xbf\xef\xbb\xbfok.example.invalid", 1),
    (b"ok.example.invalid\n\xef\xbb\xbfother.example.invalid", 2),
    ("ok.example.invalid\nname\u2028display.example.invalid".encode(), 2),
    ("ok.example.invalid\nname\u0085display.example.invalid".encode(), 2),
    (b'["ok.example.invalid"]\nextra', 2),
    (b"ok.example.invalid\nname;example.invalid", 2),
    (b"ok.example.invalid\n# comment", 2),
    (b"ok.example.invalid\n@example.invalid", 2),
    (b"ok.example.invalid\na@example.invalid", 2),
    (b"ok.example.invalid\nhttps://example.invalid", 2),
    (b"ok.example.invalid\n*.example.invalid", 2),
    (b"ok.example.invalid\nexample.invalid/path", 2),
    (b"ok.example.invalid\nexample.invalid:443", 2),
    (b"ok.example.invalid\nfoo_bar.invalid", 2),
    (b"ok.example.invalid\n-example.invalid", 2),
    (b"ok.example.invalid\nexample-.invalid", 2),
    (b"ok.example.invalid\n.example.invalid", 2),
    (b"ok.example.invalid\nexample..invalid", 2),
    (b"ok.example.invalid\nexample.invalid..", 2),
    (b"ok.example.invalid\n1.2.3.4", 2),
    (b"ok.example.invalid\nexample.123", 2),
    (b"ok.example.invalid\nexample.0.", 2),
    (b"ok.example.invalid\nexample", 2),
    (b"ok.example.invalid\nexample invalid", 2),
    (b"ok.example.invalid\n" + b"a" * 64 + b".invalid", 2),
    (b"ok.example.invalid\n" + b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 62, 2),
    ("ok.example.invalid\nbücher.invalid".encode(), 2),
    (b"ok.example.invalid\n\xff", 2),
    (b"\xef\xbb\xbf\n\xff", 2),
    (b"ok.example.invalid\n\x00", 2),
    (b'[\n"ok.example.invalid\\u0000"]', 2),
    (b"x" * (MAX_BYTES + 1), 1),
    (b"b.invalid\n" * 10001, 10001),
])
def test_invalid_file_is_sanitised(tmp_path, content, line):
    path = tmp_path / "input.txt"
    path.write_bytes(content)
    with pytest.raises(PartnerDomainsError, match=f"line {line}:") as caught:
        load_partner_domains(path)
    assert "ok.example.invalid" not in str(caught.value)
    assert str(path) not in str(caught.value)


@pytest.mark.parametrize("domain", [
    "xn--bcher-kva.invalid", "sub.partner.example.invalid", "0.1a", "1.2.3.example", "a" * 63 + ".invalid",
    ".".join(["a" * 63] * 3 + ["a" * 61]),
])
def test_valid_dns_boundaries(tmp_path, domain):
    path = tmp_path / "input.txt"
    path.write_text(domain.upper() + ".")
    assert load_partner_domains(path).domains == (domain,)


@pytest.mark.parametrize("last_label", ["0x", "0x1", "0xabcd", "0XABC"])
def test_numeric_suffix_and_trailing_dot_ip_are_rejected(tmp_path, last_label):
    path = tmp_path / "input.txt"
    for domain in (f"example.{last_label}", "1.2.3.4."):
        path.write_text(domain)
        with pytest.raises(PartnerDomainsError, match="invalid DNS domain name"):
            load_partner_domains(path)
    for domain in ("0x1.example",):
        path.write_text(domain)
        assert load_partner_domains(path).domains == (domain,)


def test_regular_file_only_and_read_once(tmp_path, monkeypatch):
    path = tmp_path / "input.txt"
    path.write_text(CANARIES[0])
    opened = []
    original = os.open

    def open_spy(name, flags, *args, **kwargs):
        if str(name) == path.name and kwargs.get("dir_fd") is not None:
            opened.append(flags)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_spy)
    assert load_partner_domains(path).domains == CANARIES[:1]
    assert len(opened) == 1
    assert opened[0] & os.O_ACCMODE == os.O_RDONLY
    for non_file in (tmp_path, tmp_path / "missing"):
        with pytest.raises(PartnerDomainsError):
            load_partner_domains(non_file)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(PartnerDomainsError):
        load_partner_domains(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(PartnerDomainsError, match="line 1: expected a regular file"):
        load_partner_domains(fifo)
    if Path("/dev/zero").exists():
        with pytest.raises(PartnerDomainsError, match="line 1: expected a regular file"):
            load_partner_domains("/dev/zero")


def test_limits_are_inclusive(tmp_path):
    path = tmp_path / "input.txt"
    path.write_text("b.invalid\n" * 10000)
    assert load_partner_domains(path).manifest(KEY_CANARY)["count"] == 1
    path.write_bytes(b"b.invalid\n" + b" " * (MAX_BYTES - 10))
    assert path.stat().st_size == MAX_BYTES
    assert load_partner_domains(path).manifest(KEY_CANARY)["count"] == 1


def test_env_and_flag_precedence(tmp_path, monkeypatch):
    env = tmp_path / "env.txt"
    flag = tmp_path / "flag.txt"
    env.write_text(CANARIES[0])
    flag.write_text(CANARIES[1])
    monkeypatch.setenv("AUDITEX_PARTNER_DOMAINS_FILE", str(env))
    assert load_partner_domains().domains == CANARIES[:1]
    assert load_partner_domains(flag).domains == CANARIES[1:]
    monkeypatch.setenv("AUDITEX_PARTNER_DOMAINS_FILE", str(tmp_path / "absent"))
    assert cli.main(["--offline", "--sample", SAMPLE, "--out", str(tmp_path / "out"),
                     "--partner-domains", str(flag)]) == 0


def test_empty_environment_is_unset_but_empty_explicit_path_is_invalid(monkeypatch):
    monkeypatch.setenv("AUDITEX_PARTNER_DOMAINS_FILE", "")
    assert load_partner_domains().manifest() == {"supplied": False}
    with pytest.raises(PartnerDomainsError):
        load_partner_domains("")


@pytest.mark.parametrize("failure", [ValueError, RecursionError])
def test_decoder_failures_are_sanitised(tmp_path, monkeypatch, failure):
    path = tmp_path / "input.txt"
    path.write_text('[\n"' + CANARIES[0] + '"]')

    def fail(*args):
        raise failure(str(path) + CANARIES[0])

    monkeypatch.setattr(json.JSONDecoder, "raw_decode", fail)
    with pytest.raises(PartnerDomainsError) as caught:
        load_partner_domains(path)
    assert str(caught.value) == "Partner-domains input: line 2: invalid JSON array."


@pytest.mark.parametrize("equals", [False, True])
def test_partner_domain_prefix_redaction(equals):
    from azure_tenant_audit.auth_runtime import scrub_command_line
    from azure_tenant_audit.secret_hygiene import (
        collect_sensitive_argv_values,
        redact_argv,
    )

    full = "--partner-domains"
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
def test_partner_domain_prefix_rejected_before_file_open(tmp_path, monkeypatch, capsys, caplog, guided, equals):
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
    full = "--partner-domains"
    for end in range(3, len(full)):
        prefix = full[:end]
        argv = [prefix + "=" + str(path)] if equals else [prefix, str(path)]
        with pytest.raises(SystemExit) as caught:
            parser.parse_args(["--out", str(out), *argv])
        assert caught.value.code == 2
        diagnostic = capsys.readouterr().err + caplog.text
        assert "error: invalid arguments" in diagnostic
        assert str(path) not in diagnostic
        assert path.name not in diagnostic
        assert opened == []
        assert not out.exists()


@pytest.mark.parametrize("entrypoint", ["engine", "product", "product-run", "guided"])
@pytest.mark.parametrize("equals", [False, True])
def test_partner_domain_rejected_prefix_keeps_stderr_private(tmp_path, capsys, caplog, entrypoint, equals):
    from auditex.cli import main as product_main

    path = tmp_path / "confidential partner.example.invalid.json"
    option = "--partner-domain"
    argv = [option + "=" + str(path)] if equals else [option, str(path)]
    command = cli.main if entrypoint == "engine" else product_main
    if entrypoint == "product-run":
        argv = ["run", *argv]
    elif entrypoint == "guided":
        argv = ["guided-run", *argv]
    with pytest.raises(SystemExit) as caught:
        command(argv)
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err + caplog.text
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic


def test_partner_domain_parser_redacts_escaped_value_in_other_diagnostics(tmp_path, capsys):
    from auditex.guided import build_guided_parser

    path = tmp_path / "confidential\npartner.example.invalid.json"
    with pytest.raises(SystemExit) as caught:
        build_guided_parser().parse_args(["--partner-domain", str(path), "--flow", str(path)])
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic
    assert repr(path.name)[1:-1] not in diagnostic


@pytest.mark.parametrize("entrypoint", ["engine", "guided"])
@pytest.mark.parametrize("equals", [False, True])
@pytest.mark.parametrize("option", [
    "--partner-domian", "--partner-domains-file", "--Partner-Domains",
    "--partner\u2010domains", "-partner-domains",
])
def test_misspelled_partner_domain_option_hides_path(tmp_path, capsys, entrypoint, equals, option):
    from auditex.cli import main as product_main

    path = tmp_path / "confidential partner domain list.json"
    argv = [f"{option}={path}"] if equals else [option, str(path)]
    command = cli.main if entrypoint == "engine" else product_main
    if entrypoint == "guided":
        argv = ["guided-run", *argv]
    with pytest.raises(SystemExit) as caught:
        command(argv)
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic


@pytest.mark.parametrize("entrypoint", ["engine", "guided"])
@pytest.mark.parametrize("equals", [False, True])
@pytest.mark.parametrize("placement", ["after-option", "after-double-dash", "repeated"])
def test_rejected_partner_domain_path_is_hidden_in_any_position(tmp_path, capsys, entrypoint, equals, placement):
    from auditex.cli import main as product_main

    path = tmp_path / "confidential partner domain list.json"
    extra = [f"--partner-domian={path}"] if equals else ["--partner-domian", str(path)]
    prefixes = {
        "after-option": ["--tenant-name", "constructed"],
        "after-double-dash": ["--"],
        "repeated": extra,
    }
    argv = [*prefixes[placement], *extra]
    command = cli.main if entrypoint == "engine" else product_main
    if entrypoint == "guided":
        argv = ["guided-run", *argv]
    with pytest.raises(SystemExit) as caught:
        command(argv)
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic


@pytest.mark.parametrize("entrypoint", ["engine", "guided"])
def test_short_partner_domain_value_does_not_corrupt_error(capsys, entrypoint):
    from auditex.cli import main as product_main

    command = cli.main if entrypoint == "engine" else product_main
    prefix = [] if entrypoint == "engine" else ["guided-run"]
    with pytest.raises(SystemExit) as caught:
        command([*prefix, "--partner-dom", "r", "--bogus"])
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert "--bogus" not in diagnostic


@pytest.mark.parametrize("entrypoint", ["probe", "google"])
@pytest.mark.parametrize("equals", [False, True])
def test_other_product_parsers_hide_rejected_partner_domain_path(tmp_path, capsys, entrypoint, equals):
    from auditex.cli import main as product_main

    path = tmp_path / "confidential partner domain list.json"
    prefix = ["probe", "live", "--tenant-name", "t"] if entrypoint == "probe" else ["google", "run"]
    extra = [f"--partner-domains={path}"] if equals else ["--partner-domains", str(path)]
    with pytest.raises(SystemExit) as caught:
        product_main([*prefix, *extra])
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic


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

    path = tmp_path / "PRIVATE-PARTNER-FILENAME-1234.txt"
    path.write_text(CANARIES[0] + "\nname;" + CANARIES[1] + ";bad")
    monkeypatch.setenv("AUDITEX_PARTNER_DOMAINS_FILE", str(path))

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
    if entrypoint in {"engine", "product"}:
        assert "usage:" in captured.err
        assert "error: Partner-domains input: line 2:" in captured.err
    assert all(domain not in output for domain in CANARIES)
    assert str(path) not in output and path.name not in output
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("entrypoint", ["engine", "product"])
@pytest.mark.parametrize("input_kind", ["sensitive-users", "partner-domains"])
@pytest.mark.parametrize("case,reason", [
    ("value", "line 2:"),
    ("json", "line 2: invalid JSON array"),
    ("utf8", "line 2: expected UTF-8"),
    ("missing", "line 1: unable to read a regular local file"),
])
def test_operator_validation_diagnostics_hide_source_values_and_path(
    tmp_path, monkeypatch, capsys, entrypoint, input_kind, case, reason
):
    from auditex import cli as product_cli

    path = tmp_path / "PRIVATE-SOURCE-FILENAME-1234.txt"
    secret = "PRIVATE-SOURCE-VALUE-1234"
    if case == "value":
        first = "valid@example.invalid" if input_kind == "sensitive-users" else "valid.example.invalid"
        path.write_text(f"{first}\n{secret};invalid;entry")
    elif case == "json":
        path.write_text(f'["{secret}",\n]')
    elif case == "utf8":
        path.write_bytes(secret.encode() + b"\n\xff")

    def forbidden(*args, **kwargs):
        pytest.fail("collection reached after invalid input")

    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", forbidden)
    argv = [f"--{input_kind}", str(path)]
    with pytest.raises(SystemExit) as caught:
        cli.main(argv) if entrypoint == "engine" else product_cli.main(["run", *argv])
    captured = capsys.readouterr()
    diagnostic = captured.out + captured.err
    assert caught.value.code == 2
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert "usage:" in captured.err and f"error: {input_kind.capitalize()} input: {reason}" in captured.err
    assert secret not in diagnostic and str(path) not in diagnostic and path.name not in diagnostic


@pytest.mark.parametrize("entrypoint", ["engine", "product"])
def test_canaries_stay_only_in_private_copy(tmp_path, monkeypatch, capsys, caplog, entrypoint):
    from auditex import cli as product_cli
    from auditex.explorer import write_explorer
    from auditex.exporters import BUILTIN_EXPORTERS, run_exporter
    from auditex.reporting import (
        _copy_source_artifact,
        enterprise_handoff,
        verify_enterprise_handoff_pack,
        write_enterprise_handoff_pack,
    )
    from azure_tenant_audit import output
    from azure_tenant_audit.auth_runtime import scrub_command_line
    from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
    from azure_tenant_audit.secret_hygiene import redact_argv

    monkeypatch.setattr(output.secrets, "token_bytes", lambda size: KEY_CANARY if size == 32 else pytest.fail("key size"))
    path = tmp_path / (CANARIES[0] + ".txt")
    path.write_text(CANARIES[1].upper() + ".\n" + CANARIES[0])
    opened = []
    original = os.open

    def spy(name, flags, *args, **kwargs):
        fd = original(name, flags, *args, **kwargs)
        info = os.fstat(fd)
        target = path.stat()
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            opened.append(flags)
        return fd

    monkeypatch.setattr(os, "open", spy)
    argv = ["--offline", "--sample", SAMPLE, "--out", str(tmp_path / "runs"),
            "--tenant-name", "test", "--run-name", "canary", "--partner-domains", str(path)]
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
    assert manifest["operator_inputs"]["partner_domains"] == load_partner_domains(path).manifest(KEY_CANARY)
    assert "sha256" not in manifest["operator_inputs"]["partner_domains"]
    assert verify_partner_domains(run)
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
    for relative in (KEY_PATH, "./" + KEY_PATH, "operator-inputs/./partner-domains.key"):
        denied_key = _copy_source_artifact(run, tmp_path / "manual-copy", relative, "test")
        assert denied_key["skipped_reason"] == "redacted_operator_input"
    for format_name in BUILTIN_EXPORTERS:
        run_exporter(name=format_name, run_dir=str(run), output_path=str(tmp_path / "rendered" / format_name))
    write_explorer([run], tmp_path / "explorer.html")
    handoff = json.dumps(enterprise_handoff(run))
    captured = capsys.readouterr()
    emitted = captured.out + captured.err + caplog.text + handoff
    for redactor in (scrub_command_line, redact_argv):
        emitted += json.dumps(redactor(["--partner-domains", str(path), "--partner-domains=" + str(path)]))
    assert all(domain not in emitted.lower() for domain in CANARIES)
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
            assert all(domain.encode() not in data for domain in CANARIES), artifact.relative_to(tmp_path)


@pytest.fixture
def umask_022():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def test_resume_replaces_or_removes_private_copy(tmp_path, umask_022):
    from azure_tenant_audit.output import AuditWriter
    from azure_tenant_audit.partner_domains import PartnerDomains

    writer = AuditWriter(tmp_path, "test", "resume")
    writer.write_partner_domains(PartnerDomains(CANARIES))
    key = (writer.run_dir / KEY_PATH).read_bytes()
    assert len(key) == 32
    assert stat.S_IMODE((writer.run_dir / KEY_PATH).stat().st_mode) == 0o600
    assert stat.S_IMODE((writer.run_dir / BUNDLE_PATH).stat().st_mode) == 0o600
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_partner_domains(writer.run_dir)
    original = json.loads((writer.run_dir / "run-manifest.json").read_text())["operator_inputs"]
    resumed = AuditWriter(tmp_path, "test", "resume", run_dir=writer.run_dir)
    resumed.write_partner_domains(PartnerDomains(CANARIES))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert json.loads((writer.run_dir / "run-manifest.json").read_text())["operator_inputs"] == original
    assert verify_partner_domains(writer.run_dir)
    resumed.write_partner_domains(PartnerDomains(CANARIES[:1]))
    assert (resumed.run_dir / KEY_PATH).read_bytes() == key
    assert stat.S_IMODE((resumed.run_dir / KEY_PATH).stat().st_mode) == 0o600
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_partner_domains(resumed.run_dir)
    assert stat.S_IMODE((resumed.run_dir / BUNDLE_PATH).stat().st_mode) == 0o600
    assert (resumed.run_dir / BUNDLE_PATH).read_text() == CANARIES[0] + "\n"
    resumed.write_partner_domains(PartnerDomains())
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    manifest = json.loads((resumed.run_dir / "run-manifest.json").read_text())
    assert manifest["operator_inputs"]["partner_domains"] == {"supplied": False}
    assert BUNDLE_PATH not in manifest["artifacts"]
    assert BUNDLE_PATH not in manifest["redacted_artifacts"]
    assert not (resumed.run_dir / BUNDLE_PATH).exists()
    assert not (resumed.run_dir / "operator-inputs/.gitignore").exists()
    assert KEY_PATH not in manifest["artifacts"]
    assert KEY_PATH not in manifest["redacted_artifacts"]
    assert not (resumed.run_dir / KEY_PATH).exists()
    assert not verify_partner_domains(resumed.run_dir)
    resumed.write_partner_domains(PartnerDomains(CANARIES))
    resumed.write_bundle({"collectors": [], "overall_status": "ok"})
    assert (resumed.run_dir / KEY_PATH).read_bytes() != key
    assert verify_partner_domains(resumed.run_dir)


def test_same_list_has_different_hmac_per_run(tmp_path):
    from azure_tenant_audit.output import AuditWriter

    digests, keys = [], []
    for name in ("first", "second"):
        writer = AuditWriter(tmp_path, "test", name)
        writer.write_partner_domains(PartnerDomains(CANARIES))
        writer.write_bundle({"collectors": [], "overall_status": "ok"})
        keys.append((writer.run_dir / KEY_PATH).read_bytes())
        digests.append(json.loads((writer.run_dir / "run-manifest.json").read_text())
                       ["operator_inputs"]["partner_domains"]["hmac_sha256"])
        assert verify_partner_domains(writer.run_dir)
    assert len(keys[0]) == len(keys[1]) == 32
    assert keys[0] != keys[1]
    assert digests[0] != digests[1]


@pytest.mark.parametrize("tamper", ["list", "key", "missing-key", "short-key", "digest", "count", "supplied"])
def test_verification_rejects_tamper(tmp_path, tamper):
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "test", "tamper")
    writer.write_partner_domains(PartnerDomains(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_partner_domains(writer.run_dir)
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
        manifest["operator_inputs"]["partner_domains"][field] = value
        manifest_path.write_text(json.dumps(manifest))
    assert not verify_partner_domains(writer.run_dir)


@pytest.mark.parametrize("damage", ["missing", "short", "symlink", "fifo"])
def test_resume_never_silently_replaces_unusable_key(tmp_path, damage):
    from azure_tenant_audit.guarded_io import UnsafeRunFileError
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "test", "resume-key")
    writer.write_partner_domains(PartnerDomains(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    key_file = writer.run_dir / KEY_PATH
    key_file.unlink()
    if damage == "short":
        key_file.write_bytes(b"short")
    elif damage == "symlink":
        key_file.symlink_to(writer.run_dir / BUNDLE_PATH)
    elif damage == "fifo":
        os.mkfifo(key_file)
    with pytest.raises((UnsafeRunFileError, PartnerDomainsError)):
        resumed = AuditWriter(tmp_path, "test", run_dir=writer.run_dir)
        resumed.write_partner_domains(PartnerDomains(CANARIES[:1]))
    assert (writer.run_dir / BUNDLE_PATH).read_text() == "\n".join(CANARIES) + "\n"
    assert not verify_partner_domains(writer.run_dir)


def test_digest_requires_a_32_byte_key():
    with pytest.raises(PartnerDomainsError):
        partner_domains_digest(CANARIES, b"short")


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

    def engine(argv, event_listener=None, *, partner_domains):
        path.unlink()
        seen.append(partner_domains.domains)
        assert "--partner-domains" not in argv
        return 0

    monkeypatch.setattr(guided.tenant_cli, "main", engine)
    args = guided.build_guided_parser().parse_args([
        "--flow", "app-audit", "--tenant-id", "tenant.invalid", "--tenant-name", "test",
        "--client-id", "constructed-app", "--client-secret", "constructed-secret",
        "--non-interactive", "--local-mode", "--out", str(tmp_path / "out"),
        "--partner-domains", str(path),
    ])
    assert guided.run_guided(args) == 0
    assert seen == [CANARIES[:1]]
    output = capsys.readouterr()
    assert CANARIES[0] not in output.out + output.err


@pytest.mark.parametrize("flag", ["--partner-domains"])
@pytest.mark.parametrize("equals", [False, True])
def test_simulated_live_run_reads_once_before_collection(tmp_path, monkeypatch, capsys, caplog, flag, equals):
    from azure_tenant_audit.collectors.base import CollectorResult

    path = tmp_path / (CANARIES[0] + ".txt")
    path.write_text(CANARIES[0].upper() + ".")
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
    assert manifest["operator_inputs"]["partner_domains"]["count"] == 1
    captured = capsys.readouterr()
    assert CANARIES[0] not in (json.dumps(events) + captured.out + captured.err + caplog.text).lower()
    for artifact in run.rglob("*"):
        if artifact.is_file() and artifact != private:
            assert CANARIES[0].encode() not in artifact.read_bytes().lower(), artifact.relative_to(run)


@pytest.mark.parametrize("equals", [False, True])
def test_every_sensitive_flag_set_redacts_the_path(equals):
    from auditex.command_runner import redact_command
    from auditex.google_workspace.run import scrub_google_command_line
    from azure_tenant_audit.auth_runtime import scrub_command_line
    from azure_tenant_audit.response import _scrub_command_line as redact_response
    from azure_tenant_audit.secret_hygiene import redact_argv

    path = "/constructed/" + CANARIES[0] + ".txt"
    argv = ["--partner-domains=" + path] if equals else ["--partner-domains", path]
    for redactor in (redact_command, scrub_google_command_line, scrub_command_line, redact_response, redact_argv):
        assert path not in json.dumps(redactor(argv))
        assert "***redacted***" in json.dumps(redactor(argv))


def test_demo_never_loads_partner_domains(tmp_path, monkeypatch, capsys):
    from auditex.cli import main
    from azure_tenant_audit import partner_domains

    source = tmp_path / "operator.txt"
    source.write_text(CANARIES[0])
    monkeypatch.setenv("AUDITEX_PARTNER_DOMAINS_FILE", str(source))

    def forbidden(*args, **kwargs):
        pytest.fail("demo must not resolve operator inputs")

    monkeypatch.setattr(partner_domains, "load_partner_domains", forbidden)
    monkeypatch.setattr(cli, "load_partner_domains", forbidden)
    out = tmp_path / "demo"
    assert main(["demo", "--no-pause", "--no-html", "--out", str(out)]) == 0
    manifests = list((out / "runs").glob("*/run-manifest.json"))
    assert len(manifests) == 2
    for path in manifests:
        assert json.loads(path.read_text())["operator_inputs"]["partner_domains"] == {"supplied": False}
        assert not (path.parent / BUNDLE_PATH).exists()
        assert not (path.parent / KEY_PATH).exists()
    for path in out.rglob("*"):
        if path.is_file():
            assert CANARIES[0].encode() not in path.read_bytes()
    captured = capsys.readouterr()
    assert CANARIES[0] not in captured.out + captured.err


@pytest.mark.parametrize("clear_first", ["users", "domains"])
def test_inputs_use_separate_keys_and_clear_independently(tmp_path, clear_first):
    from azure_tenant_audit.output import AuditWriter
    from azure_tenant_audit.sensitive_users import (
        BUNDLE_PATH as USERS_PATH,
    )
    from azure_tenant_audit.sensitive_users import (
        KEY_PATH as USERS_KEY_PATH,
    )
    from azure_tenant_audit.sensitive_users import (
        SensitiveUsers,
        verify_sensitive_users,
    )

    writer = AuditWriter(tmp_path, "test", "both")
    writer.write_sensitive_users(SensitiveUsers(("constructed-user@example.invalid",)))
    writer.write_partner_domains(PartnerDomains(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    users_key = (writer.run_dir / USERS_KEY_PATH).read_bytes()
    domains_key = (writer.run_dir / KEY_PATH).read_bytes()
    assert len(users_key) == len(domains_key) == 32
    assert users_key != domains_key
    assert verify_sensitive_users(writer.run_dir)
    assert verify_partner_domains(writer.run_dir)
    if clear_first == "users":
        writer.write_sensitive_users(SensitiveUsers())
        remaining, removed = (BUNDLE_PATH, KEY_PATH), (USERS_PATH, USERS_KEY_PATH)
    else:
        writer.write_partner_domains(PartnerDomains())
        remaining, removed = (USERS_PATH, USERS_KEY_PATH), (BUNDLE_PATH, KEY_PATH)
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert all((writer.run_dir / name).exists() for name in remaining)
    assert not any((writer.run_dir / name).exists() for name in removed)
    assert (writer.run_dir / "operator-inputs/.gitignore").read_text() == "*\n"
    assert ((writer.run_dir / USERS_KEY_PATH).read_bytes() == users_key if clear_first == "domains"
            else (writer.run_dir / KEY_PATH).read_bytes() == domains_key)
    assert verify_sensitive_users(writer.run_dir) == (clear_first == "domains")
    assert verify_partner_domains(writer.run_dir) == (clear_first == "users")
    writer.write_sensitive_users(SensitiveUsers())
    writer.write_partner_domains(PartnerDomains())
    assert not (writer.run_dir / "operator-inputs/.gitignore").exists()


@pytest.mark.parametrize("member", ["partner-domains.key", "partner-domains.txt"])
@pytest.mark.parametrize("reader", ["run", "standalone", "selected-alias"])
def test_partner_pair_identity_is_refused_by_guarded_readers(tmp_path, monkeypatch, member, reader):
    from support import RunBundleBuilder

    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )
    from azure_tenant_audit.run_files import read_run_file

    run = RunBundleBuilder(tmp_path).summary_md().manifest(
        operator_inputs={"partner_domains": PartnerDomains(CANARIES).manifest(KEY_CANARY)},
    ).build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "partner-domains.key").write_bytes(KEY_CANARY)
    (private / "partner-domains.txt").write_text("\n".join(CANARIES) + "\n")
    source = private / member
    with GuardContext() as context:
        context.bind_run(run)
        if reader == "selected-alias":
            original_open = os.open
            private_fd = original_open(source, os.O_RDONLY)

            def open_selected(name, flags, *args, **kwargs):
                if str(name) == "summary.md":
                    return os.dup(private_fd)
                return original_open(name, flags, *args, **kwargs)

            monkeypatch.setattr(os, "open", open_selected)
        try:
            with pytest.raises(UnsafeRunFileError):
                if reader == "run":
                    read_run_file(run, "operator-inputs/" + member)
                else:
                    selected = source if reader == "standalone" else run / "summary.md"
                    with open_guarded_file(selected, field="input", context=context):
                        pytest.fail("a private partner-domain identity was admitted")
        finally:
            if reader == "selected-alias":
                os.close(private_fd)


@pytest.mark.parametrize("damage", ["missing-key", "missing-list", "bad-hmac"])
def test_partner_pair_must_match_its_manifest_before_admission(tmp_path, damage):
    from support import RunBundleBuilder

    from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError

    metadata = PartnerDomains(CANARIES).manifest(KEY_CANARY)
    if damage == "bad-hmac":
        metadata["hmac_sha256"] = "0" * 64
    run = RunBundleBuilder(tmp_path).manifest(operator_inputs={"partner_domains": metadata}).build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    if damage != "missing-key":
        (private / "partner-domains.key").write_bytes(KEY_CANARY)
    if damage != "missing-list":
        (private / "partner-domains.txt").write_text("\n".join(CANARIES) + "\n")
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        context.bind_run(run)


def test_clearing_users_keeps_partner_files_ignored_by_git(tmp_path):
    import subprocess

    from azure_tenant_audit.output import AuditWriter
    from azure_tenant_audit.sensitive_users import SensitiveUsers

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    writer = AuditWriter(repo, "test", "both")
    writer.write_sensitive_users(SensitiveUsers(("constructed-user@example.invalid",)))
    writer.write_partner_domains(PartnerDomains(CANARIES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    writer.write_sensitive_users(SensitiveUsers())
    for path in (BUNDLE_PATH, KEY_PATH):
        relative = (writer.run_dir / path).relative_to(repo)
        assert subprocess.run(["git", "check-ignore", "--no-index", "-q", str(relative)], cwd=repo).returncode == 0
    assert (writer.run_dir / "operator-inputs/.gitignore").read_text() == "*\n"


@pytest.fixture
def partner_manifest_schema():
    schema = json.loads(Path("schemas/run_manifest.schema.json").read_text())
    return schema["properties"]["operator_inputs"]["properties"]["partner_domains"]


@pytest.mark.parametrize("metadata", [
    {"supplied": False}, {"supplied": True, "count": 1, "hmac_sha256": "a" * 64},
])
def test_manifest_schema_accepts_partner_domains(partner_manifest_schema, metadata):
    import jsonschema

    jsonschema.Draft202012Validator(partner_manifest_schema).validate(metadata)


@pytest.mark.parametrize("metadata", [
    {}, {"supplied": "true"}, {"supplied": True},
    {"supplied": True, "count": 0, "hmac_sha256": "a" * 64},
    {"supplied": True, "count": -1, "hmac_sha256": "a" * 64},
    {"supplied": True, "count": 1.5, "hmac_sha256": "a" * 64},
    {"supplied": True, "count": True, "hmac_sha256": "a" * 64},
    {"supplied": True, "count": 1, "hmac_sha256": "A" * 64},
    {"supplied": True, "count": 1, "hmac_sha256": "g" * 64},
    {"supplied": True, "count": 1, "hmac_sha256": "a" * 63},
    {"supplied": True, "count": 1, "hmac_sha256": "a" * 65},
    {"supplied": True, "count": 1, "hmac_sha256": 123},
    {"supplied": True, "count": 1, "sha256": "a" * 64},
    {"supplied": False, "count": 1}, {"supplied": False, "hmac_sha256": "a" * 64},
    {"supplied": False, "count": 2, "hmac_sha256": "a" * 64},
    {"supplied": False, "extra": "constructed"},
])
def test_manifest_schema_rejects_malformed_partner_domains(partner_manifest_schema, metadata):
    import jsonschema

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(partner_manifest_schema).validate(metadata)


def test_manifest_schema_defines_partner_domains_hmac(partner_manifest_schema):
    schema = json.loads(Path("schemas/run_manifest.schema.json").read_text())
    assert partner_manifest_schema == schema["properties"]["operator_inputs"]["properties"]["sensitive_users"]


def test_json_entry_cap_uses_physical_line_before_deduplication(tmp_path):
    path = tmp_path / "input.json"
    path.write_text("[\n" + ",\n".join('"b.invalid"' for _ in range(10001)) + "\n]")
    with pytest.raises(PartnerDomainsError, match="line 10002: too many entries"):
        load_partner_domains(path)


def test_json_escaped_newline_does_not_shift_physical_error_line(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('[\n"example.invalid\\ninvalid"]')
    with pytest.raises(PartnerDomainsError, match="line 2: invalid DNS domain name"):
        load_partner_domains(path)

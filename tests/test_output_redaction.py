"""The report-output redaction boundary: planted identifiers, idempotency and the writer inventory.

Every identifier below is synthetic. The shareable outputs must not carry the planted values; policy ids,
verdicts, reason codes and the public baseline addresses must survive.
"""
from __future__ import annotations

import ast
import csv
import hashlib
import io
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from auditex.cli import _emit_report_payload
from auditex.notify import send_notification
from auditex.reporting import (
    FORMAT_EXTENSIONS,
    preview_report,
    render_report,
    verify_enterprise_handoff_pack,
    write_enterprise_handoff_pack,
)
from auditex.output_writers import WRITER_INVENTORY, WriterEntry
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.output_redaction import (
    PENDING_PRODUCT_POLICY,
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    PROFILES,
    PUBLIC_GUIDS,
    RedactionContext,
    context_for_run,
    pseudonym,
    redact_output,
    run_salt,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

EMAIL = "jane.doe@plantedcorp.example"
EMAIL_LOCAL = "jane.doe"
DOMAIN = "plantedcorp.example"
NAME = "Priya Nairplanted"
IMMUTABLE = "Zm9vYmFyLXBsYW50ZWQtaWQ="
GUID = "3f2b8c1e-5a6d-4e7f-9a1b-2c3d4e5f6a7b"
BEARER = "Bearer abcdefghijklmnopqrstuvwx0123456789"
# Built from parts so no token-shaped literal sits in the repository.
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJwbGFudGVkIn0", "c2lnbmF0dXJlcGxhbnRlZA"])
KEYVALUE = "client_secret=planted-s3cr3t-value"
SECRET_VALUE = "planted-s3cr3t-value"
PUBLIC = "reports@dmarc.cyber.dhs.gov"
POLICY_ID = "MS.EXO.4.1v1"


def _planted_values(run: Path) -> list[str]:
    return [EMAIL, EMAIL_LOCAL, NAME, IMMUTABLE, GUID, BEARER.split()[1], JWT, SECRET_VALUE, str(run)]


@pytest.fixture
def planted_run(tmp_path: Path) -> Path:
    """A hand-made run with every planted identifier class in its evidence (not a validated bundle)."""
    run = tmp_path / "planted-tenant-run"
    (run / "reports").mkdir(parents=True)
    (run / "normalized").mkdir()
    (run / "run-manifest.json").write_text(
        json.dumps({"run_id": "run", "tenant_name": "planted", "run_dir": str(run), "tenant_id": GUID}), encoding="utf-8"
    )
    (run / "summary.json").write_text(json.dumps({"tenant_name": "planted", "overall_status": "ok"}), encoding="utf-8")
    finding = {
        "id": POLICY_ID,
        "title": f"DMARC is weak for {DOMAIN}",
        "severity": "high",
        "status": "open",
        "rule_id": POLICY_ID,
        "collector": "dns_posture",
        "verdict": "fail",
        "reason_code": "not_collected",
        "affected_objects": [EMAIL, GUID, f"{NAME} ({IMMUTABLE})"],
        "impact": f"{NAME} can send as {EMAIL}; {BEARER}",
        "remediation": f"Publish rua=mailto:{PUBLIC}. Ask {EMAIL}. {KEYVALUE}",
        "expected_value": "p=reject",
        "evidence": {"client_secret": SECRET_VALUE, "token": JWT, "path": f"{run}/raw/x.json", "setting": "DmarcPolicy"},
    }
    pack = {
        "findings": [finding],
        "summary": {"tenant_name": "planted", "overall_status": "ok", "finding_count": 1},
        "action_plan": [{"id": "a1", "title": f"Fix DMARC for {EMAIL}", "priority": "high", "status": "open"}],
        "proof_table": [],
    }
    (run / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    (run / "normalized" / "effective_admin_set.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "key": f"effective_admin:{GUID}",
                        "principal_type": "user",
                        "is_user": True,
                        "counted": True,
                        "display_name": NAME,
                        "principal_name": EMAIL,
                        "role_names": ["Global Administrator"],
                        "roles": [{"role": "Global Administrator", "role_definition_id": "62e90394-69f5-4237-9190-012177145e10"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (run / "normalized" / "identity_users.json").write_text(
        json.dumps({"records": [{"id": GUID, "display_name": NAME, "OnPremisesImmutableId": IMMUTABLE}]}), encoding="utf-8"
    )
    return run


# -- the function ---------------------------------------------------------------------------------------------------


def test_the_planted_classes_are_redacted_and_the_public_and_decision_values_survive(tmp_path: Path) -> None:
    run = tmp_path / "run"
    context = RedactionContext(salt="s", run_paths=(str(run),))
    value = {
        "policy_id": POLICY_ID,
        "verdict": "fail",
        "reason_code": "not_collected",
        "setting": "DmarcPolicy",
        "rua": f"mailto:{PUBLIC}, mailto:{EMAIL}",
        "domain": DOMAIN,
        "guid": GUID,
        "ms": "00000003-0000-0000-c000-000000000000",
        "role_template": "62e90394-69f5-4237-9190-012177145e10",
        "labelled": "Trace ID: 11111111-2222-3333-4444-555555555555",
        "path": f"{run}/raw/x.json",
        "secret_text": f"{BEARER} {JWT} {KEYVALUE}",
        "client_secret": SECRET_VALUE,
        "admin": {"principal_type": "user", "roles": ["x"], "display_name": NAME, "OnPremisesImmutableId": IMMUTABLE},
        "count": 3,
        "flag": True,
        "none": None,
    }
    out = redact_output(value, profile=PROFILE_SHAREABLE, context=context)
    dumped = json.dumps(out)
    for planted in (EMAIL_LOCAL, GUID, BEARER.split()[1], JWT, SECRET_VALUE, NAME, IMMUTABLE, str(run)):
        assert planted not in dumped, planted
    assert out["policy_id"] == POLICY_ID and out["verdict"] == "fail" and out["reason_code"] == "not_collected"
    assert out["setting"] == "DmarcPolicy"
    assert PUBLIC in out["rua"] and f"***@{DOMAIN}" in out["rua"]
    assert out["domain"] == DOMAIN  # decision pending product: domains are kept
    assert out["guid"].startswith("00000000-0000-4000-8000-")
    assert out["ms"] == value["ms"] and out["role_template"] == value["role_template"]
    assert out["labelled"] == value["labelled"]
    assert out["path"] == "raw/x.json"
    assert out["admin"]["display_name"] == "User " + pseudonym("s", NAME)
    assert out["admin"]["OnPremisesImmutableId"] == "Id " + pseudonym("s", IMMUTABLE)
    assert (out["count"], out["flag"], out["none"]) == (3, True, None)


def test_idempotent_deterministic_and_shape_preserving(tmp_path: Path) -> None:
    context = RedactionContext(salt="s", run_paths=(str(tmp_path),))
    samples = [
        f"{EMAIL} {GUID} {BEARER} {KEYVALUE} {tmp_path}/a {NAME}",
        {"a": [EMAIL, {"b": GUID}], "admin": {"is_user": True, "roles": [1], "display_name": NAME}, "n": 1.5},
        [EMAIL, (GUID, 2), {"k": None}],
        {EMAIL: 1, "x@plantedcorp.example": 2},
        "***@d.example User 0123456789abcdef <run-dir>/x 00000000-0000-4000-8000-0123456789ab",
        "",
        7,
        None,
        b"raw bytes",
    ]
    for sample in samples:
        for profile in PROFILES:
            first = redact_output(sample, profile=profile, context=context)
            assert redact_output(first, profile=profile, context=context) == first, (profile, sample)
            assert redact_output(sample, profile=profile, context=context) == first
            assert type(first) is type(sample)
    nested = redact_output([EMAIL, (GUID,), {"k": [EMAIL]}], context=context)
    assert isinstance(nested, list) and isinstance(nested[1], tuple) and isinstance(nested[2]["k"], list)
    assert redact_output({1, 2}) == {1, 2} and redact_output(b"x") == b"x" and redact_output(2.5) == 2.5


def test_keys_are_untouched_unless_they_are_identifiers_and_collisions_keep_every_value() -> None:
    out = redact_output({"verdict": "pass", GUID: 1, "a@x.example": 2, "b@x.example": 3})
    assert out["verdict"] == "pass"
    assert len(out) == 4 and sorted(map(str, out.values())) == ["1", "2", "3", "pass"]
    assert "***@x.example" in out and "***@x.example#2" in out
    assert redact_output(out) == out


def test_a_typo_in_a_profile_name_raises_instead_of_publishing() -> None:
    with pytest.raises(KeyError):
        redact_output("x@y.example", profile="sharable")


def test_the_pseudonyms_and_the_salt_are_the_projections() -> None:
    from auditex.scuba_projection import Projection, _redact

    projection = Projection()
    projection["privileged_users"] = {"User1": {"DisplayName": NAME, "OnPremisesImmutableId": IMMUTABLE}}
    projection["x"] = f"mail {EMAIL}"
    _redact(projection, "salt-1", True)
    mine = redact_output(
        {"DisplayName": NAME, "OnPremisesImmutableId": IMMUTABLE, "text": f"mail {EMAIL}"},
        profile=PROFILE_SHAREABLE,
        context=RedactionContext(salt="salt-1"),
    )
    assert mine["DisplayName"] == projection["privileged_users"]["User1"]["DisplayName"]
    assert mine["OnPremisesImmutableId"] == projection["privileged_users"]["User1"]["OnPremisesImmutableId"]
    assert mine["text"] == projection["x"]


def test_run_salt_is_the_digest_of_the_canonical_manifest(tmp_path: Path) -> None:
    manifest = {"b": 1, "a": ["é", {"c": None}]}
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    assert run_salt(tmp_path) == hashlib.sha256(canonical.encode()).hexdigest()
    assert run_salt(tmp_path / "missing") == hashlib.sha256(b"{}").hexdigest()


def test_the_pending_product_decisions_each_flip_with_one_field() -> None:
    value = {"guid": GUID, "mail": EMAIL, "text": f"see {DOMAIN} and mail.{DOMAIN}", "owner": "Planted Owner",
             "g": {"principal_type": "group", "display_name": "Planted Finance Group"}}
    default = redact_output(value)
    assert DOMAIN in json.dumps(default) and "Planted Owner" in json.dumps(default) and "Planted Finance Group" in json.dumps(default)
    assert GUID not in json.dumps(default)
    flipped = redact_output(
        value,
        context=RedactionContext(policy=replace(PENDING_PRODUCT_POLICY, redact_guids=False, redact_domains=True,
                                                redact_group_names=True, redact_free_text=True)),
    )
    dumped = json.dumps(flipped)
    assert GUID in dumped and DOMAIN not in dumped and "Planted Owner" not in dumped and "Planted Finance Group" not in dumped
    assert re.search(r"\*\*\*@domain-[0-9a-f]{12}\.invalid", dumped)
    assert redact_output(flipped, context=RedactionContext(policy=replace(
        PENDING_PRODUCT_POLICY, redact_guids=False, redact_domains=True, redact_group_names=True, redact_free_text=True,
    ))) == flipped
    # The public baseline address stays whole even when domains are redacted.
    domains_on = RedactionContext(policy=replace(PENDING_PRODUCT_POLICY, redact_domains=True))
    assert redact_output({"a": PUBLIC, "b": EMAIL}, context=domains_on)["a"] == PUBLIC


def test_the_report_pack_profile_redacts_secrets_only() -> None:
    out = redact_output({"t": BEARER, "e": EMAIL, "g": GUID, "client_secret": SECRET_VALUE}, profile=PROFILE_REPORT_PACK)
    assert out == {"t": "Bearer ***redacted***", "e": EMAIL, "g": GUID, "client_secret": orx.SECRET_PLACEHOLDER}


def test_public_guids_cover_every_guid_literal_the_product_ships() -> None:
    pattern = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    shipped: set[str] = set()
    for root in (SRC, REPO_ROOT / "configs", REPO_ROOT / "profiles"):
        for path in root.rglob("*"):
            if path.suffix in {".py", ".json", ".yaml", ".yml"} and path.is_file():
                shipped.update(pattern.findall(path.read_text(encoding="utf-8", errors="ignore")))
    missing = sorted(guid for guid in shipped if guid not in PUBLIC_GUIDS)
    assert not missing, f"decide whether these shipped GUIDs are public (add them to PUBLIC_GUIDS): {missing}"


# -- the output classes ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("format_name", sorted(FORMAT_EXTENSIONS))
def test_reports_and_exports_carry_no_planted_identifier(planted_run: Path, tmp_path: Path, format_name: str) -> None:
    preview = preview_report(run_dir=str(planted_run), format_name=format_name)
    target = tmp_path / f"out{FORMAT_EXTENSIONS[format_name]}"
    render_report(run_dir=str(planted_run), format_name=format_name, output_path=str(target))
    written = target.read_text(encoding="utf-8")
    for text in (preview["content"], written, json.dumps(preview["citations"])):
        for planted in _planted_values(planted_run):
            assert planted not in text, (format_name, planted)
    assert POLICY_ID in written
    assert (target.stat().st_mode & 0o777) == 0o600
    if format_name in {"json", "md", "html"}:
        assert PUBLIC in written
    if format_name == "json":
        document = json.loads(written)
        finding = document["sections"]["findings"][0]
        assert (finding["id"], finding["verdict"], finding["reason_code"], finding["status"]) == (POLICY_ID, "fail", "not_collected", "open")
        assert finding["evidence"]["setting"] == "DmarcPolicy"
        users = document["sections"]["normalized"]["identity_users"]["records"][0]
        assert users["display_name"] == "User " + pseudonym(run_salt(planted_run), NAME)
        assert users["OnPremisesImmutableId"] == "Id " + pseudonym(run_salt(planted_run), IMMUTABLE)
        assert f"***@{DOMAIN}" in written
    if format_name == "csv":
        rows = list(csv.DictReader(io.StringIO(written)))
        assert rows[0]["id"] == POLICY_ID and rows[0]["status"] == "open"


def test_the_report_pack_writer_redacts_secrets_and_keeps_references_exact(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, "planted", "w")
    payload = {
        "findings": [{"id": f"x:{EMAIL}:{GUID}", "evidence": f"{BEARER} {KEYVALUE}", "verdict": "fail"}],
        "action_plan": [{"id": "a", "title": f"{JWT}"}],
    }
    pack_path = writer.write_report_pack(payload)
    written = pack_path.read_text(encoding="utf-8") + (pack_path.parent / "action-plan.json").read_text(encoding="utf-8")
    for secret in (BEARER.split()[1], SECRET_VALUE, JWT):
        assert secret not in written
    assert f"x:{EMAIL}:{GUID}" in written and '"verdict": "fail"' in written
    again = json.loads(pack_path.read_text(encoding="utf-8"))
    assert writer.write_report_pack(again) == pack_path
    assert json.loads(pack_path.read_text(encoding="utf-8")) == again  # a rewrite of a redacted pack changes nothing


def test_report_payload_files_and_stdout_are_redacted_and_the_setup_guide_is_not(
    planted_run: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    content = json.dumps({"verdict": "fail", "who": EMAIL, "guid": GUID, "path": f"{planted_run}/x", "t": BEARER}, indent=2) + "\n"
    target = tmp_path / "payload.json"
    _emit_report_payload(content=content, format_name="json", output_path=str(target), run_dir=str(planted_run))
    written = target.read_text(encoding="utf-8")
    for planted in (EMAIL_LOCAL, GUID, BEARER.split()[1], str(planted_run)):
        assert planted not in written
    assert json.loads(written)["verdict"] == "fail"
    _emit_report_payload(content=f"# Report\n\n{EMAIL} {BEARER}\n", format_name="md", output_path=None, run_dir=str(planted_run))
    printed = capsys.readouterr().out
    assert EMAIL_LOCAL not in printed and BEARER.split()[1] not in printed
    _emit_report_payload(content="--subject admin@example.com\n", format_name="md", output_path=None, redact=False)
    assert "admin@example.com" in capsys.readouterr().out


def test_notifications_carry_no_planted_identifier_for_any_sink(planted_run: Path) -> None:
    result = send_notification(run_dir=str(planted_run), sink="slack", dry_run=True)
    text = json.dumps(result)
    for planted in _planted_values(planted_run):
        assert planted not in text, planted
    assert result["payload"]["overall_status"] == "ok" and result["payload"]["finding_count"] == 1


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("redaction-demo")
    rc = run_offline(
        REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json", root, "halcyon", "demo",
        auditor_profile="global-reader", plane="inventory",
    )
    assert rc in (0, 1)
    return root / "halcyon-demo"


def test_a_customer_pack_redacts_what_it_generates_and_still_verifies(demo_run: Path, tmp_path: Path) -> None:
    pack = tmp_path / "pack"
    write_enterprise_handoff_pack(demo_run, pack)
    assert verify_enterprise_handoff_pack(pack)["valid"] is True
    # Not vacuous: the run's own evidence holds real-looking addresses and GUIDs that the pack must not repeat.
    raw = (demo_run / "reports" / "report-pack.json").read_text(encoding="utf-8")
    assert re.search(r"[\w.]+@halcyonfreight\.example", raw) and re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-", raw)
    guid = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])", re.IGNORECASE)
    address = re.compile(r"(?<![*\w.-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    for path in sorted(pack.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(pack).as_posix()
        text = path.read_text(encoding="utf-8")
        assert str(demo_run) not in text and str(demo_run.resolve()) not in text, relative
        if relative.startswith("source-artifacts/") and relative != "source-artifacts/run-manifest.json":
            continue  # verbatim, integrity-bound copies (decision pending product)
        leaked = [m for m in address.findall(text) if m.lower() not in orx.PUBLIC_ADDRESSES]
        assert not leaked, (relative, leaked[:3])
        loose = [
            g for g in guid.findall(text)
            if g.lower() not in PUBLIC_GUIDS and not g.startswith("00000000-0000-4000-8000-") and not orx._is_microsoft_app_id(g.lower())
        ]
        assert not [g for g in loose if f"ID: {g}" not in text and f"id: {g}" not in text], (relative, loose[:3])
    handoff = json.loads((pack / "handoff.json").read_text(encoding="utf-8"))
    assert handoff["handoff_status"]
    manifest = json.loads((pack / "pack-manifest.json").read_text(encoding="utf-8"))
    assert manifest["kind"] == "auditex_enterprise_handoff_pack"


def test_the_explainer_profile_is_the_report_profile_for_text(tmp_path: Path) -> None:
    """The documented call point for the explainer: its text passes the same function as a report."""
    text = f"{NAME} ({EMAIL}) holds {GUID}; see {PUBLIC} and {POLICY_ID}."
    context = RedactionContext(salt="s", protected_names=frozenset({NAME}))
    explained = redact_output(text, profile=PROFILE_EXPLAINER, context=context)
    assert explained == redact_output(text, profile=PROFILE_SHAREABLE, context=context)
    assert NAME not in explained and EMAIL_LOCAL not in explained and GUID not in explained
    assert PUBLIC in explained and POLICY_ID in explained


# -- the writer inventory is checked against the source ---------------------------------------------------------------

_WRITE_CALLS = {
    "write_private_text", "write_private_bytes", "copy_private_file", "write_text", "write_bytes",
    "_write_json_atomic", "_write_text_atomic", "secure_write_text", "secure_write_json",
}
_REDACTION_CALLS = {"redact_output", "redact_for_run", "_final_pass", "_redact_report_content"}
_SCANNED_MODULES = (
    "auditex.reporting", "auditex.cli", "auditex.exporters", "auditex.notify", "auditex.explorer",
    "auditex.model_serving", "azure_tenant_audit.output", "azure_tenant_audit.cli",
)


def _functions(module: str) -> dict[str, ast.AST]:
    tree = ast.parse((SRC / (module.replace(".", "/") + ".py")).read_text(encoding="utf-8"))
    found: dict[str, ast.AST] = {}

    def visit(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[".".join([*stack, child.name])] = child
                visit(child, [*stack, child.name])
            elif isinstance(child, ast.ClassDef):
                visit(child, [*stack, child.name])
            else:
                visit(child, stack)

    visit(tree, [])
    return found


def _call_names(function: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
                if target.attr == "write" and isinstance(target.value, ast.Name) and target.value.id in {"handle", "fh"}:
                    names.add("write_text")
    return names


def _covered(module: str, qualname: str) -> WriterEntry | None:
    for entry in WRITER_INVENTORY:
        if entry.module != module:
            continue
        if entry.qualname == qualname or (entry.qualname.endswith(".*") and qualname.startswith(entry.qualname[:-1])):
            return entry
    return None


def test_every_inventoried_writer_exists_and_every_shareable_one_calls_the_redaction() -> None:
    for entry in WRITER_INVENTORY:
        functions = _functions(entry.module)
        if entry.qualname.endswith(".*"):
            assert any(name.startswith(entry.qualname[:-1]) for name in functions), entry
            continue
        assert entry.qualname in functions, f"inventory names a function that does not exist: {entry}"
        if entry.kind == "shareable":
            assert entry.profile in PROFILES
            assert _call_names(functions[entry.qualname]) & _REDACTION_CALLS, f"{entry.qualname} does not redact"
        else:
            assert entry.kind == "private" and entry.profile is None
    # The helpers the writers delegate to must themselves reach the shared function.
    assert "redact_output" in _call_names(_functions("auditex.reporting")["_final_pass"])
    assert "redact_output" in _call_names(_functions("auditex.cli")["_redact_report_content"])


def test_no_writer_outside_the_inventory_writes_a_file_directly() -> None:
    unregistered = []
    for module in _SCANNED_MODULES:
        for qualname, function in _functions(module).items():
            if _call_names(function) & _WRITE_CALLS and _covered(module, qualname) is None:
                unregistered.append(f"{module}:{qualname}")
    assert not unregistered, (
        "these functions write files but are not in WRITER_INVENTORY (src/auditex/output_writers.py); "
        f"classify each as shareable (and redact) or private: {unregistered}"
    )


def test_the_emit_functions_that_print_or_write_reports_go_through_the_inventory() -> None:
    # The CLI branches that hand a report payload to a file or stdout all call the one inventoried emitter.
    source = (SRC / "auditex" / "cli.py").read_text(encoding="utf-8")
    assert source.count("_emit_report_payload(content=content, format_name=args.format, output_path=args.output, run_dir=args.run_dir)") == 4
    # The only opt-out is the setup guide's emitter call (the definition's own default is ``redact: bool = True``).
    assert source.count("output_path=output_path, redact=False)") == 1

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
from auditex.output_writers import MCP_TOOL_INVENTORY, SINK_INVENTORY, WRITER_INVENTORY, SinkEntry, sink_entry
from sink_expansions import WILDCARD_EXPANSIONS
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.output_redaction import (
    PROFILE_POLICY,
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
        context=RedactionContext(policy=replace(PROFILE_POLICY[PROFILE_SHAREABLE], redact_guids=False, redact_domains=True,
                                                redact_group_names=True, redact_free_text_keys=True)),
    )
    dumped = json.dumps(flipped)
    assert GUID in dumped and DOMAIN not in dumped and "Planted Owner" not in dumped and "Planted Finance Group" not in dumped
    assert re.search(r"\*\*\*@domain-[0-9a-f]{12}\.invalid", dumped)
    assert redact_output(flipped, context=RedactionContext(policy=replace(
        PROFILE_POLICY[PROFILE_SHAREABLE], redact_guids=False, redact_domains=True, redact_group_names=True, redact_free_text_keys=True,
    ))) == flipped
    # The public baseline address stays whole even when domains are redacted.
    domains_on = RedactionContext(policy=replace(PROFILE_POLICY[PROFILE_SHAREABLE], redact_domains=True))
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


def test_a_customer_pack_redacts_everything_it_carries_and_still_verifies(demo_run: Path, tmp_path: Path) -> None:
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
#
# R15. The scan is an AST scan over every module under ``src/``. It finds the usual shapes of writing, printing and
# sending (``output_writers.SCAN_LIMITS`` lists what it cannot see) and every hit must be classified in
# ``SINK_INVENTORY``. It checks that a "routed" function reaches the redaction; it does not follow data.

_REDACTION_CALLS = {
    "redact_output", "redact_for_run", "redact_payload", "_final_pass", "_redact_report_content",
    "_redacted_report_payload", "_redact_envelope",
}
_WRITE_NAMES = {
    "write_text", "write_bytes", "copy_private_file", "secure_write_text", "secure_write_json", "copyfile",
    "copyfileobj", "copy2", "copytree", "writelines", "write",
}
_NET_VERBS = {"get", "post", "put", "patch", "delete", "request", "head", "send", "sendmail", "send_message", "starttls"}
_NET_RECEIVER = re.compile(r"(^|\.)(requests|session|_session|opener|_opener|smtp|server|client|_client|conn|http|urllib|fetcher)$")
_MODE = re.compile(r"^[rwaxbt+U]{1,4}$")
_NET_CONSTRUCTORS = {"SMTP", "SMTP_SSL", "urlopen", "HTTPConnection", "HTTPSConnection"}


def _sink_kinds(call: ast.Call) -> set[str]:
    function = call.func
    name = function.id if isinstance(function, ast.Name) else function.attr if isinstance(function, ast.Attribute) else None
    receiver = ast.unparse(function.value) if isinstance(function, ast.Attribute) else ""
    kinds: set[str] = set()
    if name in {"open", "fdopen"}:
        modes = [a.value for a in call.args[:2] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        modes += [k.value.value for k in call.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)]
        if any(_MODE.match(m) and re.search(r"[wax+]", m) for m in modes):
            kinds.add("open-write")
        elif name == "open" and receiver in {"", "os"} and re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND|flags", ast.unparse(call)):
            kinds.add("os.open-write")
        elif name == "fdopen" and not modes:
            kinds.add("fdopen-dynamic-mode")
        elif name == "open" and receiver == "" and len(call.args) >= 2 and not modes:
            kinds.add("open-dynamic-mode")
        if name == "open" and re.search(r"opener|urllib", receiver):
            kinds.add("net:open")
    if name in _WRITE_NAMES and (isinstance(function, ast.Attribute) or name not in {"write"}):
        kinds.add(f"write:{name}")
    if name in {"copy", "move"} and "shutil" in receiver:
        kinds.add(f"write:shutil.{name}")
    if name and name.startswith("write_private_"):
        kinds.add(f"write:{name}")
    if name == "dump" and receiver in {"json", "pickle", "yaml"}:
        kinds.add(f"dump:{receiver}")
    if name == "print" and not all(isinstance(a, ast.Constant) for a in call.args):
        kinds.add("print")
    if isinstance(function, ast.Attribute) and name in _NET_VERBS and _NET_RECEIVER.search(receiver):
        kinds.add(f"net:{name}")
    if name in _NET_CONSTRUCTORS:
        kinds.add(f"net:{name}")
    return kinds


def _scan_source(source: str) -> dict[str, set[str]]:
    """Every function (and the module body) of ``source`` that contains a sink call, with the kinds found."""
    found: dict[str, set[str]] = {}

    def visit(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, [*stack, child.name])
                continue
            if isinstance(child, ast.Call):
                kinds = _sink_kinds(child)
                if kinds:
                    found.setdefault(".".join(stack) or "<module>", set()).update(kinds)
            visit(child, stack)

    visit(ast.parse(source), [])
    return found


def _scan_tree() -> dict[tuple[str, str], set[str]]:
    hits: dict[tuple[str, str], set[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        module = ".".join(path.relative_to(SRC).with_suffix("").parts)
        for qualname, kinds in _scan_source(path.read_text(encoding="utf-8")).items():
            hits[(module, qualname)] = kinds
    return hits


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
    return names


def _function(spec: str) -> ast.AST:
    module, qualname = spec.split(":")
    return _functions(module)[qualname]


def test_the_scan_finds_the_sink_shapes_the_review_named() -> None:
    """R15: a writer through ``with open(..., "w")`` and the other shapes the first test missed are all seen."""
    shapes = {
        "def a(p, x):\n    with open(p, 'w') as stream:\n        stream.write(x)\n": {"open-write", "write:write"},
        "def b(p, x):\n    p.write_bytes(x)\n": {"write:write_bytes"},
        "def c(x):\n    print(x)\n": {"print"},
        "def d(x):\n    print('literal only')\n": set(),
        "def e(session, x):\n    session.post('u', json=x)\n": {"net:post"},
        "import smtplib\ndef f(x):\n    smtp = smtplib.SMTP('h')\n    smtp.send_message(x)\n": {"net:SMTP", "net:send_message"},
        "import json\ndef g(x, h):\n    json.dump(x, h)\n": {"dump:json"},
        "import urllib.request\ndef h(u):\n    urllib.request.urlopen(u)\n": {"net:urlopen"},
        "import os\ndef i(p):\n    return os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT), 'wb')\n": {"open-write", "os.open-write"},
        "class K:\n    def m(self, x):\n        self.session.get(x)\n": {"net:get"},
        "import requests\nrequests.post('u')\n": {"net:post"},
    }
    for source, expected in shapes.items():
        found = _scan_source(source)
        kinds = set().union(*found.values()) if found else set()
        assert kinds == expected, (source, kinds)
    assert "<module>" in _scan_source(list(shapes)[-1])
    assert "K.m" in _scan_source(list(shapes)[-2])


def test_every_sink_the_scan_finds_in_src_is_classified_and_every_entry_is_live() -> None:
    hits = _scan_tree()
    assert hits, "the scan found nothing: it is broken"
    unknown = sorted(f"{module}:{qualname} {sorted(kinds)}" for (module, qualname), kinds in hits.items() if sink_entry(module, qualname) is None)
    assert not unknown, (
        "these functions write, print or send but are not in SINK_INVENTORY (src/auditex/output_writers.py); "
        f"classify each as routed (and redact) or private (with the reason): {unknown}"
    )
    stale = [e.pattern for e in SINK_INVENTORY if not any(e.matches(m, q) for (m, q) in hits)]
    assert not stale, f"inventory entries that match no scanned function: {stale}"
    for entry in SINK_INVENTORY:
        assert entry.classification in {"routed", "private"} and entry.reason, entry


def _is_wildcard(entry: SinkEntry) -> bool:
    return any(char in entry.pattern for char in "*?[")


def _unreviewed_wildcard_matches(
    functions: "set[tuple[str, str]] | list[tuple[str, str]]",
    inventory: "tuple[SinkEntry, ...]" = SINK_INVENTORY,
    expansions: "dict[str, tuple[str, ...]]" = WILDCARD_EXPANSIONS,
) -> list[str]:
    """Scanned functions classified only by a wildcard that nobody has listed in the frozen expansion (S9)."""
    unreviewed = []
    for module, qualname in sorted(functions):
        matching = [entry for entry in inventory if entry.matches(module, qualname)]
        if not matching or any(not _is_wildcard(entry) for entry in matching):
            continue  # unknown (reported by the classification test) or named explicitly
        spec = f"{module}:{qualname}"
        if not any(spec in expansions.get(entry.pattern, ()) for entry in matching):
            unreviewed.append(spec)
    return unreviewed


def test_a_wildcard_never_classifies_a_new_sink_function_silently() -> None:
    """S9: every function a wildcard pattern matches is listed in ``tests/sink_expansions.py``; the list is exact."""
    hits = set(_scan_tree())
    unreviewed = _unreviewed_wildcard_matches(hits)
    assert not unreviewed, (
        "these functions write, print or send and are matched only by a wildcard in SINK_INVENTORY that has not "
        "reviewed them: read each one, then add it to WILDCARD_EXPANSIONS in tests/sink_expansions.py (it is private, "
        "with the wildcard's reason) or give it its own explicit SinkEntry (routed or private, with a reason): "
        f"{unreviewed}"
    )
    wildcards = {entry.pattern: entry for entry in SINK_INVENTORY if _is_wildcard(entry)}
    assert set(WILDCARD_EXPANSIONS) == set(wildcards), (sorted(set(WILDCARD_EXPANSIONS) ^ set(wildcards)))
    for pattern, listed in WILDCARD_EXPANSIONS.items():
        assert list(listed) == sorted(listed), f"{pattern}: keep the expansion sorted"
        current = sorted(f"{m}:{q}" for (m, q) in hits if wildcards[pattern].matches(m, q))
        assert list(listed) == current, f"{pattern}: stale expansion (removed or renamed function): {sorted(set(listed) ^ set(current))}"


def test_the_wildcard_check_catches_the_review_s9_example() -> None:
    new = ("azure_tenant_audit.output", "new_customer_export")
    source = "from pathlib import Path\ndef new_customer_export(p, payload):\n    p.write_text(payload)\n"
    assert "write:write_text" in _scan_source(source)["new_customer_export"]
    assert sink_entry(*new) is not None  # the broad wildcard does match it...
    assert _unreviewed_wildcard_matches({new}) == ["azure_tenant_audit.output:new_customer_export"]  # ...but the check refuses
    explicit = (*SINK_INVENTORY, SinkEntry("azure_tenant_audit.output:new_customer_export", "private", "reviewed: test only"))
    assert _unreviewed_wildcard_matches({new}, explicit) == []
    listed = {**WILDCARD_EXPANSIONS, "azure_tenant_audit.output:*": (*WILDCARD_EXPANSIONS["azure_tenant_audit.output:*"], "azure_tenant_audit.output:new_customer_export")}
    assert _unreviewed_wildcard_matches({new}, expansions=listed) == []


def test_every_routed_entry_reaches_the_redaction() -> None:
    for entry in SINK_INVENTORY:
        if entry.classification != "routed":
            continue
        assert entry.via, entry
        via = _function(entry.via)
        assert _call_names(via) & _REDACTION_CALLS, f"{entry.via} does not call the redaction"
        module, qualname = entry.pattern.split(":")
        if entry.via != entry.pattern:
            # Reached only through ``via``: the sink function is called from the function that redacts.
            assert qualname.split(".")[-1] in _call_names(via), f"{entry.via} does not call {qualname}"
    # The helpers the routed writers delegate to must themselves reach the shared function.
    for helper in ("auditex.reporting:_final_pass", "auditex.cli:_redact_report_content", "auditex.cli:_redacted_report_payload", "auditex.notify:_redact_envelope"):
        assert _call_names(_function(helper)) & {"redact_output", "redact_payload"}, helper


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


def test_every_mcp_tool_is_classified_and_every_routed_one_redacts_its_response() -> None:
    from auditex import mcp_server

    handlers = set(mcp_server.tool_handlers())
    inventory = {entry.tool: entry for entry in MCP_TOOL_INVENTORY}
    assert len(inventory) == len(MCP_TOOL_INVENTORY)
    assert handlers == set(inventory), (sorted(handlers - set(inventory)), sorted(set(inventory) - handlers))
    functions = _functions("auditex.mcp_server")
    for entry in MCP_TOOL_INVENTORY:
        assert entry.classification in {"routed", "no_evidence", "operator_config", "diagnostic"}, entry
        if entry.classification != "routed":
            assert entry.reason, entry
            continue
        function = functions[entry.function]
        if entry.via:
            assert entry.via.split(":")[1].split(".")[-1] in _call_names(function) or "send_notification" in _call_names(function) or "_preview_report" in _call_names(function), entry
            assert _call_names(_function(entry.via)) & _REDACTION_CALLS, entry
        else:
            assert "redact_payload" in _call_names(function) or _delegates_to_a_redacting_function(function, functions), entry


def _delegates_to_a_redacting_function(function: ast.AST, functions: dict[str, ast.AST]) -> bool:
    return any(
        name in functions and name != getattr(function, "name", "") and "redact_payload" in _call_names(functions[name])
        for name in _call_names(function)
    )


def test_the_report_commands_that_print_or_write_payloads_go_through_the_one_emitter() -> None:
    source = (SRC / "auditex" / "cli.py").read_text(encoding="utf-8")
    assert source.count("_emit_report_payload(") == 7  # the definition, analyze, api-calls, permissions, proof-table, handoff and the setup guide
    # The only opt-out is the setup guide's emitter call (the definition's own default is ``redact: bool = True``).
    assert source.count("output_path=output_path, redact=False)") == 1

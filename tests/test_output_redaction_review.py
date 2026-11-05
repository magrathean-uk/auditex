"""Regression tests for the independent review of the report-output redaction boundary (R1 to R14).

Each test reproduces one review finding; every identifier is synthetic. R15 (the structural writer scan) is in
``tests/test_output_redaction.py``.
"""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

import pytest

from auditex import mcp_server
from auditex.cli import _emit_report_payload
from auditex import cli as auditex_cli
from auditex.notify import _run_fingerprint, send_notification
from auditex.reporting import preview_report
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.citations import build_citation_summary
from azure_tenant_audit.output_redaction import (
    PROFILE_EXPLAINER,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    RedactionContext,
    context_for_run,
    pseudonym,
    redact_output,
    scrub_run_paths,
)

EMAIL = "jane.doe@plantedcorp.example"
LOCAL = "jane.doe"
NAME = "Priya Nairplanted"
IMMUTABLE = "Zm9vYmFyLXBsYW50ZWQtaWQ="
GUID = "3f2b8c1e-5a6d-4e7f-9a1b-2c3d4e5f6a7b"
SECRET = "planted-s3cr3t-value"
PLACEHOLDER = orx.SECRET_PLACEHOLDER


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A hand-made run: the evidence holds an e-mail, a GUID, a privileged name and an immutable id."""
    run = tmp_path / "tenant-run-a"
    (run / "reports").mkdir(parents=True)
    (run / "normalized").mkdir()
    (run / "run-manifest.json").write_text(
        json.dumps({"run_id": "a", "tenant_name": "planted", "run_dir": str(run), "tenant_id": GUID}), encoding="utf-8"
    )
    (run / "summary.json").write_text(json.dumps({"tenant_name": "planted", "overall_status": "ok"}), encoding="utf-8")
    finding = {
        "id": "MS.EXO.4.1v1", "title": "DMARC is weak", "severity": "high", "status": "open", "verdict": "fail",
        "affected_objects": [EMAIL, GUID, f"{NAME} ({IMMUTABLE})"],
        "impact": f"{NAME} can send as {EMAIL} from {run}/raw/x.json",
    }
    pack = {
        "findings": [finding],
        "summary": {"tenant_name": "planted", "overall_status": "ok", "finding_count": 1},
        "action_plan": [{"id": "a1", "title": f"Fix DMARC for {EMAIL}", "priority": "high", "status": "open"}],
        "proof_table": [{"finding_id": "MS.EXO.4.1v1", "artifact_path": "normalized/identity_users.json", "record_key": f"user:{EMAIL}"}],
    }
    (run / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    (run / "normalized" / "identity_users.json").write_text(
        json.dumps({"records": [{"id": GUID, "display_name": NAME, "OnPremisesImmutableId": IMMUTABLE}]}), encoding="utf-8"
    )
    return run


def _clean(text: str, run: Path | None = None, *planted: str) -> None:
    for value in (LOCAL, GUID, IMMUTABLE, NAME, *planted, *( [str(run)] if run else [])):
        assert value not in text, value


# -- R3 -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", [PROFILE_SHAREABLE, PROFILE_REPORT_PACK, PROFILE_EXPLAINER])
def test_r3_credential_keys_replace_a_value_of_any_type(profile: str) -> None:
    value = {
        "client_secret": ["planted-secret"],
        "password": {"value": "planted-password"},
        "api_key": 12345,
        "Access-Token": ["a", {"b": "c"}],
        "clientSecret": ["x"],
        "password_policy": {"min_length": 8},
        "token_count": 3,
        "empty": {"password": ""},
        "none": {"password": None},
        "list": {"private_key": []},
    }
    out = redact_output(value, profile=profile)
    assert out["client_secret"] == PLACEHOLDER and out["password"] == PLACEHOLDER and out["api_key"] == PLACEHOLDER
    assert out["Access-Token"] == PLACEHOLDER and out["clientSecret"] == PLACEHOLDER
    assert out["password_policy"] == {"min_length": 8} and out["token_count"] == 3
    assert out["empty"] == {"password": ""} and out["none"] == {"password": None} and out["list"] == {"private_key": []}
    assert redact_output(out, profile=profile) == out


# -- R4 -----------------------------------------------------------------------------------------------------------


def test_r4_escaped_quotes_in_embedded_json_are_parsed_not_corrupted() -> None:
    embedded = '{"password": "plant\\"tail"}'
    out = redact_output(embedded)
    assert "plant" not in out and "tail" not in out
    assert json.loads(out) == {"password": PLACEHOLDER}
    nested = '{"a": "jane@plantedcorp.example", "n": [1, {"client_secret": "x\\"y"}], "s": "it\\"s"}'
    out = redact_output(nested)
    parsed = json.loads(out)
    assert parsed == {"a": "***@plantedcorp.example", "n": [1, {"client_secret": PLACEHOLDER}], "s": 'it"s'}
    assert out == json.dumps(parsed)  # the original's separators survive
    assert redact_output(out) == out
    # A fragment that is not JSON still loses the whole quoted value, escapes included.
    fragment = 'log: {"password": "plant\\"tail"} and more'
    assert "plant" not in redact_output(fragment) and "tail" not in redact_output(fragment)
    assert redact_output(fragment).endswith('} and more')


def test_r4_embedded_json_values_use_the_structure_rules() -> None:
    admin = json.dumps({"principal_type": "user", "roles": ["x"], "display_name": NAME})
    out = redact_output(admin, context=RedactionContext(salt="s"))
    assert json.loads(out)["display_name"] == "User " + pseudonym("s", NAME)


# -- R5 -----------------------------------------------------------------------------------------------------------


def test_r5_percent_encoded_and_unicode_escaped_addresses_are_masked() -> None:
    url = "https://graph.microsoft.com/v1.0/users/jane%40plantedcorp.example?x=1"
    out = redact_output(url)
    assert "jane" not in out and out.startswith("https://graph.microsoft.com/v1.0/users/") and out.endswith("plantedcorp.example?x=1")
    assert redact_output(out) == out
    escaped = '{"Email":"jane\\u0040plantedcorp.example"}'
    out = redact_output(escaped)
    assert "jane" not in out and json.loads(out)["Email"].endswith("plantedcorp.example")
    for form in ("jane\\u0040plantedcorp.example sent", "jane&#64;plantedcorp.example", "see jane%40plantedcorp.example."):
        masked = redact_output(form)
        assert "jane" not in masked and "plantedcorp.example" in masked, form
        assert redact_output(masked) == masked
    public = "mailto:reports%40dmarc.cyber.dhs.gov"
    assert redact_output(public) == public


# -- R6 -----------------------------------------------------------------------------------------------------------


def test_r6_google_privileged_records_are_pseudonymised(run_dir: Path) -> None:
    name = "Planted Google Admin"
    record = {"display_name": name, "is_admin": True, "is_privileged": True}
    context = RedactionContext(salt="s")
    assert redact_output(record, context=context)["display_name"] == "User " + pseudonym("s", name)
    delegated = {"display_name": name, "is_delegated_admin": True}
    assert redact_output(delegated, context=context)["display_name"] == "User " + pseudonym("s", name)
    ordinary = {"display_name": "Planted Plain Person", "is_admin": False, "is_privileged": False}
    assert redact_output(ordinary, context=context)["display_name"] == "Planted Plain Person"
    (run_dir / "normalized" / "google_users.json").write_text(
        json.dumps({"records": [{"primary_email": EMAIL, **record}]}), encoding="utf-8"
    )
    rendered = preview_report(run_dir=str(run_dir), format_name="json")["content"]
    assert name not in rendered
    text_only = preview_report(run_dir=str(run_dir), format_name="md", include_sections=["findings"])["content"]
    assert name not in text_only
    assert name not in redact_output(f"{name} signed in", context=context_for_run(run_dir))


# -- R7 -----------------------------------------------------------------------------------------------------------


def test_r7_immutable_ids_are_protected_from_the_context_whatever_sections_are_selected(run_dir: Path) -> None:
    for format_name in ("md", "json", "html", "csv"):
        content = preview_report(run_dir=str(run_dir), format_name=format_name, include_sections=["findings"])["content"]
        assert IMMUTABLE not in content and NAME not in content, format_name
    explained = redact_output(
        f"The account {NAME} (id {IMMUTABLE}) is an administrator.", profile=PROFILE_EXPLAINER, context=context_for_run(run_dir)
    )
    assert IMMUTABLE not in explained and NAME not in explained
    context = context_for_run(run_dir)
    assert IMMUTABLE in context.protected_ids and NAME in context.protected_names


# -- R8 -----------------------------------------------------------------------------------------------------------


def test_r8_structural_keys_and_controlled_vocabulary_are_not_name_substituted() -> None:
    context = RedactionContext(salt="s", protected_names=frozenset({"status", "Global Administrator", "Planted Person"}))
    value = {
        "status": "open",
        "role": "Global Administrator",
        "role_names": ["Global Administrator"],
        "note": "Planted Person holds Global Administrator and status is open",
        "user": {"principal_type": "user", "roles": ["Global Administrator"], "display_name": "Global Administrator"},
    }
    out = redact_output(value, context=context)
    assert set(out) == set(value)
    assert out["status"] == "open" and out["role"] == "Global Administrator" and out["role_names"] == ["Global Administrator"]
    assert out["note"] == "User " + pseudonym("s", "Planted Person") + " holds Global Administrator and status is open"
    assert out["user"]["roles"] == ["Global Administrator"]
    assert out["user"]["display_name"] == "User " + pseudonym("s", "Global Administrator")
    assert redact_output(out, context=context) == out
    keyed = redact_output({"Planted Person": 1, "status": 2}, context=context)
    assert keyed == {"Planted Person": 1, "status": 2}  # a key is rewritten only when it is an identifier


# -- R9 -----------------------------------------------------------------------------------------------------------


def test_r9_key_collisions_keep_every_value_and_run_in_linear_time() -> None:
    out = redact_output({"a@x.example": 1, "***@x.example": 2})
    assert sorted(out.values()) == [1, 2] and len(out) == 2
    assert redact_output(out) == out
    reversed_out = redact_output({"***@x.example": 2, "a@x.example": 1, "b@x.example": 3, "c@x.example#2": 4})
    assert sorted(reversed_out.values()) == [1, 2, 3, 4] and reversed_out["***@x.example"] == 2
    many = {f"u{i}@x.example": i for i in range(16000)}
    started = time.perf_counter()
    result = redact_output(many)
    elapsed = time.perf_counter() - started
    assert len(result) == 16000 and sorted(result.values()) == list(range(16000))
    assert elapsed < 6.0, elapsed  # quadratic suffix allocation took 16 s here
    assert redact_output({"a@x.example": 1, "b@x.example": 2, "***@x.example#2": 3}) == {
        "***@x.example": 1, "***@x.example#3": 2, "***@x.example#2": 3,
    }


# -- R10 and R11 --------------------------------------------------------------------------------------------------


def test_r10_two_runs_of_one_tenant_get_different_fingerprints(run_dir: Path, tmp_path: Path) -> None:
    other = tmp_path / "tenant-run-b"
    shutil.copytree(run_dir, other)
    first = send_notification(run_dir=str(run_dir), sink="slack", dry_run=True)
    second = send_notification(run_dir=str(other), sink="slack", dry_run=True)
    assert _run_fingerprint(first["payload"]) != _run_fingerprint(second["payload"])
    assert _run_fingerprint(first["payload"]) == _run_fingerprint(send_notification(run_dir=str(run_dir), sink="slack", dry_run=True)["payload"])
    assert _run_fingerprint(first["payload"]) == _run_fingerprint({"tenant_name": "planted", "run_dir": str(run_dir)})
    assert str(run_dir) not in json.dumps(first) and tmp_path.name not in json.dumps(first["payload"].get("run_fingerprint", ""))


def test_r11_the_notification_envelope_is_redacted_including_citations(run_dir: Path) -> None:
    named = run_dir / f"summary-{EMAIL}.json"
    named.write_text(json.dumps({"tenant_name": "planted"}), encoding="utf-8")
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["summary_path"] = str(named)
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=True)
    text = json.dumps(result)
    assert LOCAL not in text and EMAIL not in text and str(run_dir) not in text
    assert any("plantedcorp.example" in row["artifact_path"] for row in result["citations"])
    assert result["citation_summary"] == build_citation_summary(result["citations"])
    assert mcp_server.preview_notification(str(run_dir), "teams")["citation_summary"] == result["citation_summary"]


# -- R12 and R13 --------------------------------------------------------------------------------------------------


def test_r12_every_run_path_occurrence_is_scrubbed_and_the_result_is_stable() -> None:
    text = "/tmp/run/raw/a; see /tmp/run/raw/b and (/tmp/run) /tmp/run/c"
    once = scrub_run_paths(text, ["/tmp/run"])
    assert "/tmp/run" not in once and once.startswith("raw/a; see ")
    assert scrub_run_paths(once, ["/tmp/run"]) == once
    assert scrub_run_paths("/tmp/run", ["/tmp/run"]) == "<run-dir>"
    assert scrub_run_paths("/tmp/run2/x", ["/tmp/run"]) == "/tmp/run2/x"
    redacted = redact_output(text, context=RedactionContext(run_paths=("/tmp/run",)))
    assert "/tmp/run" not in redacted and redact_output(redacted, context=RedactionContext(run_paths=("/tmp/run",))) == redacted


def test_r13_generated_pseudonyms_are_never_matched_as_names() -> None:
    context = RedactionContext(salt="s", protected_names=frozenset({"User", "Group", "Planted Person"}))
    for text in ("User", "Alice User Smith", "Planted Person and User", f"Id 0123456789abcdef {IMMUTABLE}"):
        once = redact_output(text, context=context)
        assert redact_output(once, context=context) == once, text
    assert redact_output("User", context=context) == "User " + pseudonym("s", "User")
    ids = RedactionContext(salt="s", protected_ids=frozenset({"Id 0123456", IMMUTABLE}))
    once = redact_output(f"x {IMMUTABLE} y", context=ids)
    assert redact_output(once, context=ids) == once


# -- R14 ----------------------------------------------------------------------------------------------------------


def test_r14_very_deep_values_fail_closed_with_a_controlled_error() -> None:
    deep: Any = EMAIL
    for _ in range(600):
        deep = {"x": deep}
    with pytest.raises(orx.RedactionDepthError):
        redact_output(deep)
    assert issubclass(orx.RedactionDepthError, ValueError)
    cycle: list[Any] = []
    cycle.append(cycle)
    with pytest.raises(orx.RedactionDepthError):
        redact_output(cycle)
    nested_text = '{"x":' * 600 + '"' + EMAIL + '"' + "}" * 600  # valid JSON, 600 deep, written without re-escaping
    with pytest.raises(orx.RedactionDepthError):
        redact_output(nested_text)
    ok: Any = EMAIL
    for _ in range(40):
        ok = {"x": [ok]}
    assert LOCAL not in json.dumps(redact_output(ok))


# -- R2 -----------------------------------------------------------------------------------------------------------


def test_r2_markdown_payloads_are_redacted_before_rendering(capsys: pytest.CaptureFixture[str]) -> None:
    _emit_report_payload(content="client_secret=planted-secret\n", format_name="md", output_path=None)
    assert "planted-secret" not in capsys.readouterr().out
    seen: list[Any] = []

    def render(payload: Any) -> str:
        seen.append(payload)
        return f"# Report\n\n| who | secret |\n| --- | --- |\n| {payload['who']} | {payload['client_secret']} |\n"

    _emit_report_payload(
        payload={"who": EMAIL, "client_secret": SECRET}, renderer=render, format_name="md", output_path=None
    )
    printed = capsys.readouterr().out
    assert seen == [{"who": f"***@plantedcorp.example", "client_secret": PLACEHOLDER}]
    assert LOCAL not in printed and SECRET not in printed and "| --- | --- |" in printed
    json_out = _emit_report_payload(payload={"who": EMAIL}, renderer=None, format_name="json", output_path=None)
    assert LOCAL not in capsys.readouterr().out and json_out is None


# -- R1 -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["summarize_run", "proof_table", "enterprise_handoff", "analyze_report", "api_inventory", "permissions_ledger", "list_blockers"])
def test_r1_mcp_run_tools_return_redacted_payloads(run_dir: Path, tool: str) -> None:
    result = getattr(mcp_server, tool)(str(run_dir))
    _clean(json.dumps(result, default=str), run_dir)
    handler = mcp_server.tool_handlers()
    registered = {"summarize_run": "auditex_summarize_run", "proof_table": "auditex_proof_table", "enterprise_handoff": "auditex_enterprise_handoff",
                  "analyze_report": "auditex_report_analyze", "api_inventory": "auditex_api_inventory",
                  "permissions_ledger": "auditex_permissions_ledger", "list_blockers": "auditex_list_blockers"}[tool]
    _clean(json.dumps(handler[registered](str(run_dir)), default=str), run_dir)


def test_r1_summarize_keeps_decision_fields_and_a_consistent_citation_summary(run_dir: Path) -> None:
    result = mcp_server.summarize_run(str(run_dir))
    assert result["citation_summary"] == build_citation_summary(result["citations"])
    assert result["report_pack"]["findings"][0]["verdict"] == "fail"
    assert result["report_pack"]["findings"][0]["id"] == "MS.EXO.4.1v1"


def test_r1_comparison_assessment_and_pack_tools_are_redacted(run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    planted = {"who": EMAIL, "guid": GUID, "path": f"{run_dir}/raw/x.json", "t": f"client_secret={SECRET}", "verdict": "fail"}
    monkeypatch.setattr(mcp_server, "diff_run_directories", lambda a, b, classic=False: dict(planted))
    import auditex.compare as compare
    import auditex.external_assessments as external
    import auditex.assessment_review as review
    import auditex.reporting as reporting

    monkeypatch.setattr(compare, "compare_runs", lambda dirs, allow_cross_tenant=False, classic=False: dict(planted))
    monkeypatch.setattr(external, "import_assessment", lambda source, path, tenant_id=None: dict(planted))
    monkeypatch.setattr(review, "compare_external_assessments", lambda paths, expected_tenant_id=None, run_dir=None: dict(planted))
    monkeypatch.setattr(reporting, "verify_enterprise_handoff_pack", lambda pack, **kw: dict(planted))
    # The external-assessment tools take no run: there is no run path to scrub, everything else still applies.
    results = [
        (mcp_server.diff_runs(str(run_dir), str(run_dir)), run_dir),
        (mcp_server.compare_many_runs([str(run_dir), str(run_dir)]), run_dir),
        (mcp_server.normalize_external_assessment("scuba", "x.json"), None),
        (mcp_server.compare_external_assessment_files(["x.json"], run_dir=str(run_dir)), run_dir),
        (mcp_server.verify_customer_pack(str(run_dir)), run_dir),
    ]
    for result, run in results:
        _clean(json.dumps(result), run, SECRET)
        assert result["verdict"] == "fail"


def test_r1_report_analyze_cli_prints_a_redacted_payload(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert auditex_cli.main(["report", "analyze", str(run_dir)]) == 0
    _clean(capsys.readouterr().out, run_dir)


def test_free_text_flip_covers_container_values_and_the_inert_role_flag_is_gone() -> None:
    from dataclasses import fields, replace

    assert "redact_role_names" not in {f.name for f in fields(orx.ProfilePolicy)}
    context = RedactionContext(policy=replace(orx.PROFILE_POLICY[orx.PROFILE_SHAREABLE], redact_free_text_keys=True))
    out = redact_output({"comments": ["Planted comment", {"by": "Planted Person"}], "owner": "Planted Owner", "notes": []}, context=context)
    text = json.dumps(out)
    assert "Planted" not in text and out["notes"] == [] and redact_output(out, context=context) == out

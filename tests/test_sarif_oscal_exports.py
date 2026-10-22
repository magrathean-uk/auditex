from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from auditex.reporting import preview_report
from auditex.exporters import run_exporter, list_exporters

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def offline_run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "sarif-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-sarif-test"


def test_list_exporters_includes_sarif_and_oscal() -> None:
    names = {row["name"] for row in list_exporters()}
    assert "sarif" in names
    assert "oscal" in names


def test_preview_report_supports_sarif_format(offline_run_dir: Path) -> None:
    preview = preview_report(run_dir=str(offline_run_dir), format_name="sarif")

    document = json.loads(preview["content"])
    assert document["version"] == "2.1.0"
    assert document["$schema"].startswith("https://json.schemastore.org/sarif")
    assert document["runs"][0]["tool"]["driver"]["name"] == "auditex"
    assert isinstance(document["runs"][0]["results"], list)


def test_sarif_severity_maps_to_levels() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.crit", "severity": "critical", "title": "Crit", "category": "x"},
        {"id": "f2", "rule_id": "rule.high", "severity": "high", "title": "High", "category": "x"},
        {"id": "f3", "rule_id": "rule.med", "severity": "medium", "title": "Med", "category": "x"},
        {"id": "f4", "rule_id": "rule.low", "severity": "low", "title": "Low", "category": "x"},
    ]
    summary = {"tenant_name": "acme", "schema_version": "2026-04-21"}

    document = render_sarif(findings=findings, summary=summary, manifest={})

    levels = {result["ruleId"]: result["level"] for result in document["runs"][0]["results"]}
    assert levels["rule.crit"] == "error"
    assert levels["rule.high"] == "error"
    assert levels["rule.med"] == "warning"
    assert levels["rule.low"] == "note"


def test_sarif_uses_provider_label_from_manifest() -> None:
    from auditex.reporting import render_sarif

    document = render_sarif(
        findings=[],
        summary={"tenant_name": "acme"},
        manifest={"platform": "google_workspace", "run_id": "run-1"},
    )

    run = document["runs"][0]
    description = run["automationDetails"]["description"]["text"]
    assert "Google Workspace" in description
    assert "Microsoft 365" not in description
    assert run["properties"]["auditex.platform"] == "google_workspace"


def test_sarif_rule_index_aligns_results_to_rules() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.alpha", "severity": "high", "title": "Alpha", "category": "x"},
        {"id": "f2", "rule_id": "rule.beta", "severity": "medium", "title": "Beta", "category": "x"},
        {"id": "f3", "rule_id": "rule.alpha", "severity": "high", "title": "Alpha 2", "category": "x"},
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})

    rules = document["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]
    assert rule_ids == ["rule.alpha", "rule.beta"]
    indexes = {result["ruleId"]: result["ruleIndex"] for result in document["runs"][0]["results"]}
    assert indexes["rule.alpha"] == 0
    assert indexes["rule.beta"] == 1


def test_sarif_includes_framework_mappings_in_properties() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "category": "x",
            "framework_mappings": {
                "cis_m365_v3": ["1.1.1"],
                "mitre_attack": ["T1078"],
            },
        }
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})

    rule_props = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert "tags" in rule_props
    assert "cis_m365_v3:1.1.1" in rule_props["tags"]
    assert "mitre_attack:T1078" in rule_props["tags"]


def test_sarif_rule_help_markdown_contains_template_sections() -> None:
    """D1: every SARIF rule must carry help.text + help.markdown + helpUri so
    GitHub Code Scanning's UI surfaces actionable rule docs inline."""
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha finding",
            "description": "Alpha desc",
            "impact": "Alpha impact",
            "remediation": "Alpha remediation",
            "category": "test",
            "framework_mappings": {
                "cis_m365_v3": ["1.1.1"],
                "mitre_attack": ["T1078"],
            },
            "references": ["RFC 1234", "Microsoft Learn page"],
        }
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["help"]["text"] == "Alpha remediation"
    md = rule["help"]["markdown"]
    assert "## Alpha finding" in md
    assert "**Description:** Alpha desc" in md
    assert "**Impact:** Alpha impact" in md
    assert "**Remediation:** Alpha remediation" in md
    assert "**Severity:** high" in md
    assert "cis_m365_v3" in md and "1.1.1" in md
    assert "mitre_attack" in md and "T1078" in md
    assert "RFC 1234" in md
    assert rule["helpUri"].endswith("configs/finding-templates.json#rule.alpha")
    assert rule["helpUri"].startswith("https://")


def test_sarif_rule_help_markdown_minimal_when_template_missing() -> None:
    """A finding with only a rule_id and severity must still produce a
    valid help.markdown — no KeyError, no empty string."""
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.bare", "severity": "low"},
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"]["markdown"]  # not empty
    assert rule["helpUri"].endswith("configs/finding-templates.json#rule.bare")


def test_sarif_help_fields_populated_for_every_rule_under_diverse_input() -> None:
    """Regression guard: every rule emitted by render_sarif must have the
    three help fields populated regardless of how complete the source
    finding is. Synthetic batch covers the realistic spread of finding
    shapes (full template, partial, minimal)."""
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.full",
            "severity": "high",
            "title": "Full",
            "description": "d",
            "impact": "i",
            "remediation": "r",
            "category": "x",
            "framework_mappings": {"cis_m365_v3": ["1.1"]},
            "references": ["doc"],
        },
        {
            "id": "f2",
            "rule_id": "rule.no_template",
            "severity": "medium",
            "title": "No template",
            "category": "x",
        },
        {
            "id": "f3",
            "rule_id": "rule.bare",
            "severity": "low",
        },
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 3
    for rule in rules:
        rule_id = rule["id"]
        assert rule.get("help", {}).get("text"), f"rule={rule_id} missing help.text"
        assert rule.get("help", {}).get("markdown"), f"rule={rule_id} missing help.markdown"
        assert rule.get("helpUri"), f"rule={rule_id} missing helpUri"
        assert rule_id in rule["helpUri"], (
            f"rule={rule_id} helpUri does not deep-link to its template entry"
        )


def test_sarif_google_rules_link_to_google_rule_catalog() -> None:
    from auditex.reporting import render_sarif

    document = render_sarif(
        findings=[
            {
                "id": "google.admin_2sv_not_enforced:user-1",
                "rule_id": "google.admin_2sv_not_enforced",
                "severity": "high",
                "title": "Admin account does not enforce 2-step verification",
                "category": "identity",
                "framework_mappings": {"google_workspace_baseline": ["identity.2sv"]},
            }
        ],
        summary={},
        manifest={"platform": "google_workspace", "run_id": "run-1"},
    )

    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert "src/auditex/google_workspace/findings.py" in rule["helpUri"]
    assert "configs/finding-templates.json" not in rule["helpUri"]
    assert "google.admin_2sv_not_enforced" in rule["helpUri"]


def test_sarif_fingerprint_is_stable_across_renders() -> None:
    """D2: rendering the same finding twice must produce the same
    fingerprint so GitHub Code Scanning dedupes its alert tracking
    across runs."""
    from auditex.reporting import render_sarif

    finding = {
        "id": "app_credentials:app-1:secret_expired",
        "rule_id": "app_credentials.secret_expired",
        "severity": "critical",
        "title": "Application secret is expired",
        "category": "application",
        "evidence_refs": [
            {
                "artifact_path": "normalized/application_credential_objects.json",
                "artifact_kind": "normalized_section",
                "collector": "app_credentials",
                "record_key": "application_credentials:app-1",
            }
        ],
    }
    first = render_sarif(findings=[finding], summary={}, manifest={})
    second = render_sarif(findings=[finding], summary={}, manifest={})

    fp1 = first["runs"][0]["results"][0]["fingerprints"]
    fp2 = second["runs"][0]["results"][0]["fingerprints"]
    assert fp1 == fp2
    assert "auditex/v1" in fp1
    # Sanity: SHA-256 hex is 64 chars.
    assert len(fp1["auditex/v1"]) == 64


def test_sarif_fingerprint_differs_for_distinct_findings() -> None:
    """Two findings under the same rule against different objects must
    produce different fingerprints."""
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "app_credentials:app-1:secret_expired",
            "rule_id": "app_credentials.secret_expired",
            "severity": "critical",
            "title": "Secret expired (app 1)",
            "evidence_refs": [
                {
                    "artifact_path": "normalized/x.json",
                    "artifact_kind": "normalized_section",
                    "collector": "app_credentials",
                    "record_key": "application_credentials:app-1",
                }
            ],
        },
        {
            "id": "app_credentials:app-2:secret_expired",
            "rule_id": "app_credentials.secret_expired",
            "severity": "critical",
            "title": "Secret expired (app 2)",
            "evidence_refs": [
                {
                    "artifact_path": "normalized/x.json",
                    "artifact_kind": "normalized_section",
                    "collector": "app_credentials",
                    "record_key": "application_credentials:app-2",
                }
            ],
        },
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    fps = [r["fingerprints"]["auditex/v1"] for r in document["runs"][0]["results"]]
    assert len(set(fps)) == 2, f"distinct findings produced colliding fingerprints: {fps}"


def test_sarif_fingerprint_independent_of_run_metadata() -> None:
    """A re-run of the same audit must keep fingerprints stable even when
    run_id / created_utc / tenant context changes — the dedup contract
    breaks otherwise."""
    from auditex.reporting import render_sarif

    finding = {
        "id": "rule.example:obj-1",
        "rule_id": "rule.example",
        "severity": "high",
        "evidence_refs": [
            {"record_key": "section:obj-1", "artifact_path": "x", "artifact_kind": "y", "collector": "c"}
        ],
    }
    a = render_sarif(findings=[finding], summary={"tenant_name": "old", "schema_version": "old"}, manifest={"run_id": "run-A"})
    b = render_sarif(findings=[finding], summary={"tenant_name": "new", "schema_version": "new"}, manifest={"run_id": "run-B"})
    assert (
        a["runs"][0]["results"][0]["fingerprints"]
        == b["runs"][0]["results"][0]["fingerprints"]
    )


def test_run_exporter_writes_sarif_to_disk(offline_run_dir: Path) -> None:
    result = run_exporter(name="sarif", run_dir=str(offline_run_dir))
    artifact = Path(result["artifacts"][0]["path"])
    assert artifact.exists()
    assert artifact.suffix in {".json", ".sarif"} or artifact.name.endswith(".sarif.json")
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"


UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_oscal_assessment_results(document: dict) -> list[str]:
    """Lightweight structural validator for OSCAL Assessment Results 1.1.2.

    Asserts the invariants that GitHub Code Scanning, Defender for Cloud
    consumers, and the OSCAL reference parser all rely on. NOT a full
    schema check (the OSCAL JSON schema cross-references multiple
    documents); intentionally focuses on the must-have fields per the
    OSCAL spec § Assessment Results.
    """
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["root: not a dict"]
    ar = document.get("assessment-results")
    if not isinstance(ar, dict):
        return ["assessment-results: missing or not a dict"]
    if not UUID_PATTERN.match(str(ar.get("uuid") or "")):
        errors.append("assessment-results.uuid: missing or not a valid UUID")
    metadata = ar.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("assessment-results.metadata: missing or not a dict")
    else:
        for required in ("title", "last-modified", "version", "oscal-version"):
            if not metadata.get(required):
                errors.append(f"assessment-results.metadata.{required}: missing")
    if "import-ap" not in ar or not isinstance(ar["import-ap"], dict) or not ar["import-ap"].get("href"):
        errors.append("assessment-results.import-ap.href: missing")
    results = ar.get("results")
    if not isinstance(results, list) or not results:
        errors.append("assessment-results.results: missing or empty")
    else:
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                errors.append(f"results[{index}]: not a dict")
                continue
            for required in ("uuid", "title", "description", "start"):
                if not result.get(required):
                    errors.append(f"results[{index}].{required}: missing")
            if not UUID_PATTERN.match(str(result.get("uuid") or "")):
                errors.append(f"results[{index}].uuid: not a valid UUID")
            reviewed = result.get("reviewed-controls")
            if not isinstance(reviewed, dict):
                errors.append(f"results[{index}].reviewed-controls: missing or not a dict")
            else:
                selections = reviewed.get("control-selections")
                if not isinstance(selections, list) or not selections:
                    errors.append(f"results[{index}].reviewed-controls.control-selections: empty")
                else:
                    for sindex, selection in enumerate(selections):
                        if not isinstance(selection, dict):
                            errors.append(
                                f"results[{index}].reviewed-controls.control-selections[{sindex}]: not a dict"
                            )
                            continue
                        # Each selection needs at least one selector — include-all,
                        # include-controls, or exclude-controls.
                        if not any(
                            key in selection
                            for key in ("include-all", "include-controls", "exclude-controls")
                        ):
                            errors.append(
                                f"results[{index}].reviewed-controls.control-selections[{sindex}]:"
                                " no include-all/include-controls/exclude-controls selector"
                            )
            for collection in ("observations", "findings"):
                items = result.get(collection)
                if items is None:
                    continue
                if not isinstance(items, list):
                    errors.append(f"results[{index}].{collection}: not a list")
                    continue
                for iindex, item in enumerate(items):
                    if not isinstance(item, dict):
                        errors.append(f"results[{index}].{collection}[{iindex}]: not a dict")
                        continue
                    if not UUID_PATTERN.match(str(item.get("uuid") or "")):
                        errors.append(
                            f"results[{index}].{collection}[{iindex}].uuid: not a valid UUID"
                        )
    return errors


def test_oscal_assessment_results_passes_structural_validator() -> None:
    """D3: the auditex OSCAL output must satisfy the OSCAL Assessment
    Results 1.1.2 minimum-viable invariants on a synthetic finding."""
    from auditex.reporting import render_oscal

    findings = [
        {
            "id": "rule.alpha:obj-1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "description": "alpha",
            "framework_mappings": {"nist_800_53": ["AC-3"]},
            "remediation": "fix",
        }
    ]
    document = render_oscal(
        findings=findings,
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )
    errors = _validate_oscal_assessment_results(document)
    assert not errors, f"OSCAL structural validation failed: {errors}"


def test_oscal_metadata_uses_provider_label_from_manifest() -> None:
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[],
        summary={"tenant_name": "acme"},
        manifest={"platform": "google_workspace", "run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )

    metadata = document["assessment-results"]["metadata"]
    assert "Google Workspace" in metadata["title"]
    assert metadata["props"] == [{"name": "auditex.platform", "value": "google_workspace"}]


def test_oscal_includes_google_workspace_baseline_targets() -> None:
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[
            {
                "id": "google.admin_2sv_not_enforced:user-1",
                "rule_id": "google.admin_2sv_not_enforced",
                "severity": "high",
                "title": "Admin 2SV not enforced",
                "framework_mappings": {"google_workspace_baseline": ["identity.2sv"]},
            }
        ],
        summary={"tenant_name": "acme"},
        manifest={"platform": "google_workspace", "run_id": "run-1"},
    )

    finding = document["assessment-results"]["results"][0]["findings"][0]
    controls = {(prop["class"], prop["value"]) for prop in finding["props"] if prop["name"] == "framework-control"}
    assert ("google_workspace_baseline", "identity.2sv") in controls
    assert finding["target"]["type"] == "objective-id"
    assert finding["target"]["target-id"] == "google.admin_2sv_not_enforced"


def test_oscal_assessment_results_passes_validator_with_zero_findings() -> None:
    """OSCAL output must remain valid even when no findings exist —
    consumers (CMS, Defender for Cloud) reject results with empty or
    malformed envelopes."""
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[],
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )
    errors = _validate_oscal_assessment_results(document)
    assert not errors, errors


def test_oscal_assessment_results_includes_reviewed_controls_per_result() -> None:
    """Regression guard for the reviewed-controls field — OSCAL 1.1.2
    requires it on every result, but auditex didn't emit it before D3.
    Ensures the field never disappears in a future refactor."""
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[],
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )
    result = document["assessment-results"]["results"][0]
    reviewed = result.get("reviewed-controls")
    assert isinstance(reviewed, dict)
    selections = reviewed.get("control-selections")
    assert isinstance(selections, list) and selections
    # ``include-all: {}`` is the canonical "all controls in scope" selector.
    assert "include-all" in selections[0]


def test_oscal_export_has_assessment_results_shape(offline_run_dir: Path) -> None:
    result = run_exporter(name="oscal", run_dir=str(offline_run_dir))
    artifact = Path(result["artifacts"][0]["path"])
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert "assessment-results" in document
    assessment = document["assessment-results"]
    assert "uuid" in assessment
    assert "metadata" in assessment
    assert isinstance(assessment["results"], list)
    assert assessment["results"][0]["uuid"]


def test_oscal_findings_include_related_observations() -> None:
    from auditex.reporting import render_oscal

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "category": "x",
            "framework_mappings": {"nist_800_53": ["AC-3", "AC-6"]},
            "remediation": "Do the thing",
        }
    ]
    document = render_oscal(
        findings=findings,
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )
    result = document["assessment-results"]["results"][0]
    assert result["findings"][0]["title"] == "Alpha"
    related = result["findings"][0]["related-observations"]
    assert related and related[0]["observation-uuid"]
    # The mapped controls are ``framework-control`` properties, classed by framework.
    controls = {
        (prop["class"], prop["value"])
        for finding in result["findings"]
        for prop in finding["props"]
        if prop["name"] == "framework-control"
    }
    assert {("nist_800_53", "AC-3"), ("nist_800_53", "AC-6")} <= controls


# --- Validation against the official schemas -------------------------------------------------
#
# The schemas are vendored under tests/schemas (see the README there), so the run needs no network.

SCHEMA_DIR = REPO_ROOT / "tests" / "schemas"


def _load_jsonschema():
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - a missing dev dependency must fail, not skip
        pytest.fail(
            "jsonschema is required to validate exports against the official schemas: "
            "python -m pip install -e '.[test]'",
            pytrace=False,
        )
    return jsonschema


def _python_patterns(node):
    """The OSCAL token pattern uses Unicode property escapes that Python's ``re`` lacks.

    Only ``\\p{L}`` and ``\\p{N}`` are translated, in memory; every other rule is the published one.
    """
    if isinstance(node, dict):
        return {
            key: (
                value.replace("\\p{L}", "[^\\W\\d_]").replace("\\p{N}", "\\d")
                if key == "pattern" and isinstance(value, str)
                else _python_patterns(value)
            )
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_python_patterns(item) for item in node]
    return node


@pytest.fixture(scope="module")
def oscal_validator():
    jsonschema = _load_jsonschema()
    schema = _python_patterns(
        json.loads((SCHEMA_DIR / "oscal_assessment-results_schema-1.1.2.json").read_text(encoding="utf-8"))
    )
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(schema)


@pytest.fixture(scope="module")
def sarif_validator():
    jsonschema = _load_jsonschema()
    schema = json.loads((SCHEMA_DIR / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    jsonschema.Draft4Validator.check_schema(schema)
    return jsonschema.Draft4Validator(schema)


def _schema_errors(validator, document) -> list[str]:
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message[:160]}"
        for error in sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    ]


def _offline_bundle(root: Path, sample: str, label: str) -> Path:
    from azure_tenant_audit.cli import run_offline

    assert run_offline(
        REPO_ROOT / "examples" / sample, root, "halcyon", label, auditor_profile="global-reader", plane="inventory"
    ) in (0, 1)
    return root / f"halcyon-{label}"


@pytest.fixture(scope="module")
def demo_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _offline_bundle(tmp_path_factory.mktemp("demo-bundle"), "demo_tenant/demo_tenant.json", "demo")


@pytest.fixture(scope="module")
def google_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from auditex.google_workspace.run import run_google_offline

    out = tmp_path_factory.mktemp("google-bundle")
    rc = run_google_offline(
        sample_path=REPO_ROOT / "examples" / "google_workspace_sample.json",
        out=out,
        tenant_name="acme",
        run_name="google",
        domain="example.com",
        customer_id=None,
    )
    assert rc in (0, 1)
    return out / "acme-google"


def _export(run_dir: Path, name: str) -> dict:
    preview = preview_report(run_dir=str(run_dir), format_name=name)
    return json.loads(preview["content"])


def test_oscal_export_of_the_demo_bundle_is_valid_assessment_results(oscal_validator, demo_bundle: Path) -> None:
    document = _export(demo_bundle, "oscal")

    assert len(document["assessment-results"]["results"][0]["findings"]) > 10
    assert _schema_errors(oscal_validator, document) == []


def test_oscal_export_of_the_google_bundle_is_valid_assessment_results(oscal_validator, google_bundle: Path) -> None:
    document = _export(google_bundle, "oscal")

    assert document["assessment-results"]["results"][0]["findings"]
    assert _schema_errors(oscal_validator, document) == []


def test_oscal_export_with_no_findings_is_valid_assessment_results(oscal_validator) -> None:
    from auditex.reporting import render_oscal

    document = render_oscal(findings=[], summary={"tenant_name": "acme"}, manifest={"run_id": "run-1"})

    assert _schema_errors(oscal_validator, document) == []


def test_oscal_export_of_awkward_findings_is_valid_assessment_results(oscal_validator) -> None:
    """Rule ids that are not tokens, empty fields and unusual objects still give a schema-valid document."""
    from auditex.reporting import render_oscal

    findings = [
        {"id": "9 odd id/with:chars", "rule_id": "9.odd rule", "severity": "high", "title": "T", "affected_objects": ["a", "", "b c"]},
        {"id": "bare", "severity": "low"},
        {
            "id": "rich",
            "rule_id": "rule.rich",
            "title": "Rich",
            "description": "d",
            "remediation": "fix it",
            "framework_mappings": {"nist_800_53": ["AC-3", " ", "AC-3"], "cis_m365_v7": ["1.1.1"]},
            "evidence_refs": [
                {
                    "artifact_path": "normalized/users.json",
                    "artifact_kind": "normalized_json",
                    "record_key": "user:1",
                    "json_pointer": "/records/0",
                    "content_hash": "ab" * 32,
                    "collected_at": "2026-10-22T10:00:00Z",
                    "resolved": True,
                },
                {"artifact_path": "raw/a b.json", "record_key": "k", "resolved": False},
            ],
        },
    ]
    document = render_oscal(
        findings=findings,
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "created_utc": "2026-10-22T09:00:00.123456Z", "duration_seconds": 12.5},
    )

    assert _schema_errors(oscal_validator, document) == []
    rich = next(obs for obs in document["assessment-results"]["results"][0]["observations"] if obs["title"] == "Rich")
    assert rich["collected"] == "2026-10-22T10:00:00Z"
    assert rich["relevant-evidence"][0]["href"] == "normalized/users.json#/records/0"
    assert {"name": "sha256", "value": "ab" * 32} in rich["relevant-evidence"][0]["props"]
    assert rich["relevant-evidence"][1]["href"] == "raw/a%20b.json"


def test_oscal_validator_rejects_a_document_that_breaks_the_schema(oscal_validator, demo_bundle: Path) -> None:
    """The check is live: a finding without its required target is reported."""
    document = _export(demo_bundle, "oscal")
    del document["assessment-results"]["results"][0]["findings"][0]["target"]

    errors = _schema_errors(oscal_validator, document)

    assert errors and any("target" in error for error in errors)

    # Patterns are checked too, including the token pattern that needed translating for Python.
    document = _export(demo_bundle, "oscal")
    document["assessment-results"]["results"][0]["observations"][0]["uuid"] = "not-a-uuid"
    document["assessment-results"]["results"][0]["findings"][0]["target"]["target-id"] = "9 not a token"

    errors = _schema_errors(oscal_validator, document)

    assert any("uuid" in error for error in errors)
    assert any("target-id" in error for error in errors)


def test_oscal_collection_time_is_the_manifest_created_utc(demo_bundle: Path) -> None:
    from auditex.reporting import render_oscal

    manifest = json.loads((demo_bundle / "run-manifest.json").read_text(encoding="utf-8"))
    findings = json.loads((demo_bundle / "findings" / "findings.json").read_text(encoding="utf-8"))
    expected = manifest["created_utc"][:19] + "Z"

    document = render_oscal(findings=findings, summary={}, manifest=manifest)

    result = document["assessment-results"]["results"][0]
    assert result["start"] == expected
    assert result["end"] == expected  # an offline replay has no duration
    assert {"name": "auditex.collection_time_basis", "value": "run_manifest_created_utc"} in result["props"]
    # Every observation's evidence was collected in that run, so each carries the run's time.
    assert {item["collected"] for item in result["observations"]} == {expected}


def test_oscal_collection_time_falls_back_to_export_time_and_says_so() -> None:
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[{"id": "f", "rule_id": "r", "title": "t"}],
        summary={},
        manifest={"run_id": "run-1", "created_utc": "not a time"},
    )

    result = document["assessment-results"]["results"][0]
    assert {"name": "auditex.collection_time_basis", "value": "export_time"} in result["props"]
    assert result["start"] == document["assessment-results"]["metadata"]["last-modified"]


def test_oscal_end_is_start_plus_run_duration() -> None:
    from auditex.reporting import render_oscal

    document = render_oscal(
        findings=[],
        summary={},
        manifest={"run_id": "run-1", "created_utc": "2026-10-22T09:00:00.000000Z", "duration_seconds": 90},
    )

    result = document["assessment-results"]["results"][0]
    assert (result["start"], result["end"]) == ("2026-10-22T09:00:00Z", "2026-10-22T09:01:30Z")


def test_sarif_export_of_the_demo_bundle_is_valid_sarif(sarif_validator, demo_bundle: Path) -> None:
    document = _export(demo_bundle, "sarif")

    assert len(document["runs"][0]["results"]) > 10
    assert _schema_errors(sarif_validator, document) == []


def test_sarif_export_of_the_google_bundle_is_valid_sarif(sarif_validator, google_bundle: Path) -> None:
    document = _export(google_bundle, "sarif")

    assert document["runs"][0]["results"]
    assert _schema_errors(sarif_validator, document) == []


def test_sarif_export_of_synthetic_findings_is_valid_sarif(sarif_validator) -> None:
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.alpha", "severity": "critical", "title": "Alpha", "affected_objects": ["x", "y"]},
        {"id": "f2", "rule_id": "rule.bare", "severity": "info"},
        {
            "id": "f3",
            "rule_id": "rule.evidence",
            "severity": "medium",
            "confidence": "high",
            "framework_mappings": {"nist_800_53": ["AC-3"]},
            "evidence_refs": [
                {"artifact_path": "normalized/users.json", "record_key": "user:1", "content_hash": "cd" * 32, "resolved": True}
            ],
        },
    ]

    document = render_sarif(findings=findings, summary={"tenant_name": "acme"}, manifest={"run_id": "run-1"})

    assert _schema_errors(sarif_validator, document) == []
    evidence = document["runs"][0]["results"][2]["properties"]["auditex.evidence"]
    assert evidence == [
        {"artifact_path": "normalized/users.json", "record_key": "user:1", "content_hash": "cd" * 32, "resolved": True}
    ]


def test_sarif_export_with_no_findings_is_valid_sarif(sarif_validator) -> None:
    from auditex.reporting import render_sarif

    assert _schema_errors(sarif_validator, render_sarif(findings=[], summary={}, manifest={})) == []


def test_sarif_validator_rejects_a_document_that_breaks_the_schema(sarif_validator, demo_bundle: Path) -> None:
    document = _export(demo_bundle, "sarif")
    document["runs"][0]["results"][0]["level"] = "catastrophic"

    errors = _schema_errors(sarif_validator, document)

    assert errors and any("level" in error for error in errors)

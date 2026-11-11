"""Optional synthetic differential replay against pinned OPA and ScubaGear Rego."""
from __future__ import annotations

import json
import lzma
import os
import subprocess
from collections import defaultdict
from hashlib import sha256
from pathlib import Path

import pytest

from auditex.scubagear_prune_proof import REGO_SHA256
from azure_tenant_audit.value_rules import assess

OPA = Path(os.environ["AUDITEX_TEST_OPA"]) if os.environ.get("AUDITEX_TEST_OPA") else None
SCUBA = Path(os.environ["AUDITEX_TEST_SCUBAGEAR"]) if os.environ.get("AUDITEX_TEST_SCUBAGEAR") else None
pytestmark = pytest.mark.skipif(not (OPA and OPA.is_file() and SCUBA and (SCUBA / "Rego").is_dir()),
                                reason="set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-v2.jsonl.xz"
UNAVAILABLE = {"No License", "Access Denied", "Setting Not Found in JSON"}


@pytest.fixture(scope="module")
def pinned():
    version = subprocess.run([str(OPA), "version"], capture_output=True, text=True, timeout=30)
    if version.returncode or "Version: 1.20.2" not in version.stdout.splitlines():
        pytest.skip("OPA is not pinned version 1.20.2")
    rego = SCUBA / "Rego"
    for name, digest in REGO_SHA256.items():
        if not (rego / name).is_file() or sha256((rego / name).read_bytes()).hexdigest() != digest:
            pytest.skip("ScubaGear Rego differs from pinned revision 2446ad72")
    return rego


def _input(row):
    sections = dict(row["sections"])
    if row["policy"].startswith("MS.POWERBI."):
        if row["source_kind"] != "constructed" and sections.get("powerbi_access_denied_reason") is None:
            sections.pop("powerbi_access_denied_reason", None)
        return sections
    return {"authentication_method": sections["authentication_method"]}


def _outcome(row, result):
    if result.get("errors"):
        return "error"
    if not result.get("result"):
        return "no_result"
    tests = result["result"][0].get("expressions", [{}])[0].get("value", [])
    matches = [item for item in tests if item.get("PolicyId") == row["policy"]]
    if not matches:
        return "no_result"
    if len(matches) != 1:
        return "error"
    item = matches[0]
    if isinstance(item.get("ActualValue"), str) and item["ActualValue"] in UNAVAILABLE:
        return "not_assessed"
    return "met" if item.get("RequirementMet") is True else "not_met"


def test_stratified_v2_cells_against_rego(pinned, tmp_path):
    groups = defaultdict(list)
    with lzma.open(FIXTURE, "rt") as source:
        for line in source:
            row = json.loads(line)
            if any(isinstance(v, dict) and v.get("collection_status") == "not_collected"
                   for v in row["sections"].values()):
                continue
            groups[(row["policy"], row["rule_cell"])].append(row)
    ordered = [sorted(rows, key=lambda r: r["vector_id"]) for rows in groups.values()]
    selected = [rows[0] for rows in ordered]
    extra = int(os.getenv("AUDITEX_TEST_VALUE_RULE_SAMPLE", "0"))
    if extra > 0:
        remaining = sorted((row for rows in ordered for row in rows[1:]), key=lambda r: r["vector_id"])
        selected.extend(remaining[:extra])
    for row in selected:
        package, config = (("powerbi", "PowerBIConfig.rego") if row["policy"].startswith("MS.POWERBI.")
                           else ("aad", "AADConfig.rego"))
        path = tmp_path / "input.json"
        path.write_text(json.dumps(_input(row), ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run([str(OPA), "eval", "-f", "json", "-d", str(pinned / config),
                               "-d", str(pinned / "Utils"), "-i", str(path), f"data.{package}.tests"],
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            result = {"errors": [proc.stderr[:200]]}
        assert _outcome(row, result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert actual == row["rule_verdict"], row["vector_id"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]


FIXTURE_V39 = Path(__file__).parent / "fixtures/value-rules/vectors-v39.jsonl.xz"
PACKAGES = {"MS.TEAMS.": ("teams", "TeamsConfig.rego"), "MS.EXO.": ("exo", "EXOConfig.rego"),
            "MS.SECURITYSUITE.": ("securitysuite", "SecuritySuiteConfig.rego")}
# The SS 1.4 Rego prints nothing without a licence flag; the kit's replay supplies it as the pack oracle did.
EXTRA_INPUT = {"MS.SECURITYSUITE.1.4v1": {"defender_license": True}}


def _outcome_v3(policy, result):
    """The kit's v3 reading of the Rego (replay.py): no row, an error, two differing rows, a GCC-style
    not-applicable report, a PowerShell Error (not assessed), else RequirementMet."""
    if result.get("errors"):
        return "error"
    tests = result["result"][0].get("expressions", [{}])[0].get("value", []) if result.get("result") else []
    mine = [item for item in tests if item.get("PolicyId") == policy]
    if not mine:
        return "no_result"

    def one(item):
        details = item.get("ReportDetails")
        if isinstance(details, str) and ("not applicable to GCC" in details or "only applicable if" in details):
            return "not_applicable"
        if item.get("ActualValue") == "PowerShell Error":
            return "not_assessed"
        return "met" if item.get("RequirementMet") is True else "not_met"
    outcomes = {one(item) for item in mine}
    return "double_verdict" if len(outcomes) > 1 else outcomes.pop()


def test_stratified_v39_cells_against_rego(pinned, tmp_path):
    """One constructed vector per (policy, cell) whose gold is an OPA replay, plus the optional extra sample."""
    groups = defaultdict(list)
    with lzma.open(FIXTURE_V39, "rt") as source:
        for line in source:
            row = json.loads(line)
            if row.get("gold_source") == "opa-replay":
                groups[(row["policy"], row["rule_cell"])].append(row)
    assert len({policy for policy, _ in groups}) == 25
    ordered = [sorted(rows, key=lambda r: r["vector_id"]) for _, rows in sorted(groups.items())]
    selected = [rows[0] for rows in ordered]
    extra = int(os.getenv("AUDITEX_TEST_VALUE_RULE_SAMPLE", "0"))
    if extra > 0:
        remaining = sorted((row for rows in ordered for row in rows[1:]), key=lambda r: r["vector_id"])
        selected.extend(remaining[:extra])
    for row in selected:
        package, config = next(value for prefix, value in PACKAGES.items() if row["policy"].startswith(prefix))
        path = tmp_path / "input.json"
        path.write_text(json.dumps({**row["sections"], **EXTRA_INPUT.get(row["policy"], {})}, ensure_ascii=False),
                        encoding="utf-8")
        proc = subprocess.run([str(OPA), "eval", "-f", "json", "-d", str(pinned / config),
                               "-d", str(pinned / "Utils"), "-i", str(path), f"data.{package}.tests"],
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            result = {"errors": [proc.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert actual == row["rule_verdict"], row["vector_id"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]

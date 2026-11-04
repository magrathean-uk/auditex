"""Offline differential verdict check against pinned OPA and ScubaGear Rego.

Export AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR; there are no machine-specific defaults.
Only synthetic inputs are evaluated. Neither tool is downloaded or invoked during collection.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import re
import stat
import subprocess

import pytest

from auditex.model_serving import policy_catalogue
from auditex.scuba_projection import PACK_ENUM_DOMAINS, PACK_SHAPE_DIGESTS, _json
from auditex.scubagear_export import canonicalise_privileged_users, prune_section
from auditex.scubagear_prune_proof import PRUNE_PROOF, REGO_SHA256


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


OPA = _env_path("AUDITEX_TEST_OPA")
SCUBA = _env_path("AUDITEX_TEST_SCUBAGEAR")
pytestmark = pytest.mark.skipif(
    not (OPA and OPA.is_file() and SCUBA and (SCUBA / "Rego").is_dir()),
    reason="export AUDITEX_TEST_OPA (OPA 1.20.2) and AUDITEX_TEST_SCUBAGEAR (PowerShell/ScubaGear at the pinned commit)")

PACKAGES = {"aad": "AADConfig", "exo": "EXOConfig", "sharepoint": "SharepointConfig",
            "teams": "TeamsConfig", "securitysuite": "SecuritySuiteConfig"}
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/scubagear-export"
RUN_COUNTS = {"opa": 0, "rows": 0, "reachable_rows": 0, "vocabulary": 0, "vocabulary_runs": 0}


@pytest.fixture(scope="module")
def pinned():
    mode = OPA.stat().st_mode
    if not stat.S_ISREG(mode) or not os.access(OPA, os.X_OK):
        pytest.skip("AUDITEX_TEST_OPA is not OPA 1.20.2")
    proc = subprocess.run([str(OPA), "version"], capture_output=True, text=True, timeout=30,
                          env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")})
    if proc.returncode or "Version: 1.20.2" not in proc.stdout.splitlines():
        pytest.skip("AUDITEX_TEST_OPA is not OPA 1.20.2")
    rego = SCUBA / "Rego"
    if any(not (rego / name).is_file() or sha256((rego / name).read_bytes()).hexdigest() != digest
           for name, digest in REGO_SHA256.items()):
        pytest.skip("AUDITEX_TEST_SCUBAGEAR/Rego is not the pinned revision 2446ad72")
    return OPA, rego


def _eval(opa: Path, rego_dir: Path, package: str, input_value: dict, workdir: Path) -> dict[str, str]:
    workdir.mkdir(parents=True, exist_ok=True)
    path = workdir / "input.json"
    path.write_text(json.dumps(input_value, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    command = [str(opa), "eval", f"data.{package}.tests", "-i", str(path), "-d",
               str(rego_dir / (PACKAGES[package] + ".rego")), "-d", str(rego_dir / "Utils"), "-f", "values"]
    proc = subprocess.run(command, cwd=workdir, capture_output=True, text=True, timeout=120,
                          env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")})
    RUN_COUNTS["opa"] += 1
    if proc.returncode:
        pytest.fail(f"{package} OPA eval failed: {proc.stderr[:200]}")
    try:
        payload = json.loads(proc.stdout)
        rows = payload[0]
        assert isinstance(rows, list)
        verdicts = {}
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("PolicyId"), str) and type(row.get("RequirementMet")) is bool:
                verdicts.setdefault(row["PolicyId"], set()).add(
                    "pass" if row["RequirementMet"] is True else "fail")
        verdicts = {policy_id: tuple(sorted(values)) for policy_id, values in verdicts.items()}
    except (ValueError, TypeError, KeyError, IndexError, AssertionError):
        pytest.fail(f"{package} OPA output is invalid: {proc.stderr[:200]}")
    return verdicts


def evaluate_pair(opa: Path, rego_dir: Path, full_input: dict, pruned_input: dict,
                  workdir: Path) -> list[tuple[str, str, str, str]]:
    """Return only verdict differences; this function intentionally does not check the pin."""
    differences = []
    catalogue = policy_catalogue()["policies"]
    reachable = {pid for pid, item in catalogue.items() if all(s in PACK_SHAPE_DIGESTS for s in item["sections"])}
    for package in PACKAGES:
        full = _eval(opa, rego_dir, package, full_input, workdir / (package + "-full"))
        pruned = _eval(opa, rego_dir, package, pruned_input, workdir / (package + "-pruned"))
        for pid in sorted(set(full) | set(pruned)):
            RUN_COUNTS["rows"] += 1
            RUN_COUNTS["reachable_rows"] += pid in reachable
            a, b = full.get(pid, "not_evaluated"), pruned.get(pid, "not_evaluated")
            if a != b:
                differences.append((package, pid, a, b))
    return differences


def _pair(export: dict) -> tuple[dict, dict]:
    full, pruned = deepcopy(export), deepcopy(export)
    for section in PRUNE_PROOF:
        if section in pruned:
            pruned[section] = prune_section(section, pruned[section])[0]
    if "privileged_users" in pruned:
        pruned["privileged_users"] = canonicalise_privileged_users(pruned["privileged_users"])[0]
    return full, pruned


def _descriptor_value(node, section: str, path: str = "", mode: int = 0):
    if isinstance(node, str) and node[:1] in '{["':
        try:
            return _descriptor_value(json.loads(node), section, path, mode)
        except json.JSONDecodeError:
            pass
    if isinstance(node, dict) and set(node) == {"object"}:
        return {key: _descriptor_value(child, section, path + "." + key, mode)
                for key, child in node["object"].items()}
    if isinstance(node, dict) and set(node) == {"array"}:
        return [_descriptor_value(child, section, path + "[]", mode) for child in node["array"]]
    if node == "NoneType":
        return None
    domain = PACK_ENUM_DOMAINS.get(section, {}).get(path.removesuffix("[]"), [])
    candidates = [json.loads(item) for item in domain]
    for candidate in candidates[mode % max(1, len(candidates)):] + candidates[:mode % max(1, len(candidates))]:
        if node == "str" and isinstance(candidate, str) or node == "bool" and type(candidate) is bool or \
                node == "int" and type(candidate) is int:
            return candidate
    return {"str": "mocktenant.invalid", "bool": bool(mode % 2), "int": mode, "float": float(mode)}[node]


def _inject_all(node, names: set[str], value) -> None:
    if isinstance(node, list):
        for child in node:
            _inject_all(child, names, value)
    elif isinstance(node, dict):
        for child in list(node.values()):
            _inject_all(child, names, value)
        for name in names:
            node.setdefault(name, deepcopy(value))


def _vocabulary(rego_dir: Path) -> set[str]:
    names = set()
    for path in rego_dir.rglob("*.rego"):
        for line in path.read_text(encoding="utf-8").splitlines():
            quote, escaped, clean = False, False, []
            for char in line:
                if escaped:
                    escaped = False
                elif char == "\\" and quote:
                    escaped = True
                elif char == '"':
                    quote = not quote
                elif char == "#" and not quote:
                    break
                clean.append(char)
            code = "".join(clean)
            names.update(re.findall(r'\.([A-Za-z][A-Za-z0-9_]*)', code))
            names.update(re.findall(r'"([A-Za-z][A-Za-z0-9_]*)"', code))
    return names


def run_vocabulary_case(opa: Path, rego_dir: Path, workdir: Path) -> tuple[list, int, int]:
    """Exercise vocabulary from the directory under test; no pin or environment read."""
    vocabulary = _vocabulary(rego_dir)
    shapes = json.loads((ROOT / "tests/fixtures/scuba-projection-shapes-v7.json").read_text())["sections"]
    clean = json.loads((FIXTURES / "mocktenant-provider-export.json").read_text())
    randomizer = random.Random(20261104)
    differences, runs = [], 0
    for draw in range(4):
        full = deepcopy(clean)
        if draw:
            for section in PRUNE_PROOF:
                descriptors = [d for d in shapes[section]
                               if sha256(_json(d).encode()).hexdigest() in PACK_SHAPE_DIGESTS[section]]
                full[section] = _descriptor_value(randomizer.choice(descriptors), section, mode=draw)
        full["privileged_users"] = canonicalise_privileged_users(full["privileged_users"])[0]
        for mode in (["All"], "All", True, "enabled", False, None, 0, [], "", {}):
            injected = deepcopy(full)
            for section in PRUNE_PROOF:
                _inject_all(injected[section], vocabulary, mode)
            pruned = deepcopy(injected)
            removed = 0
            for section in PRUNE_PROOF:
                pruned[section], count = prune_section(section, pruned[section])[:2]
                removed += count
            assert removed > 0, (draw, mode)
            differences.extend(evaluate_pair(opa, rego_dir, injected, pruned, workdir / f"draw-{draw}-{runs}"))
            runs += 10
    return differences, len(vocabulary), runs


def test_fixture_verdicts_and_nonvacuity(pinned, tmp_path):
    opa, rego = pinned
    clean = json.loads((FIXTURES / "mocktenant-provider-export.json").read_text())
    real = json.loads((FIXTURES / "mocktenant-realformat-export.json").read_text())
    for index, export in enumerate((clean, real)):
        full, pruned = _pair(export)
        assert not evaluate_pair(opa, rego, full, pruned, tmp_path / f"fixture-{index}")
    empty = {k: v for k, v in clean.items() if k == "scuba_config" or k.endswith("_commands")}
    catalogue = policy_catalogue()["policies"]
    reachable = {pid for pid, item in catalogue.items() if all(s in PACK_SHAPE_DIGESTS for s in item["sections"])}
    assert len(reachable) == 44
    nonvacuity = {}
    for package in ("aad", "exo", "sharepoint", "teams"):
        baseline = _eval(opa, rego, package, empty, tmp_path / (package + "-empty"))
        verdicts = [_eval(opa, rego, package, export, tmp_path / f"{package}-{i}") for i, export in enumerate((clean, real))]
        members = {pid for pid in reachable if pid.split(".")[1].lower() == package}
        changes = sum(verdicts[0].get(pid, "not_evaluated") != baseline.get(pid, "not_evaluated") for pid in members)
        assert changes > 0
        statuses = {status for v in verdicts for pid in members for status in v.get(pid, ())}
        assert {"pass", "fail"} <= statuses
        nonvacuity[package] = {"reachable": len(members), "changed_from_empty": changes,
                                "pass": sum("pass" in v.get(pid, ()) for v in verdicts for pid in members),
                                "fail": sum("fail" in v.get(pid, ()) for v in verdicts for pid in members)}
    print("nonvacuity", json.dumps(nonvacuity, sort_keys=True))


def test_witness_sweep(pinned, tmp_path):
    opa, rego = pinned
    shapes = json.loads((ROOT / "tests/fixtures/scuba-projection-shapes-v7.json").read_text())["sections"]
    clean = json.loads((FIXTURES / "mocktenant-provider-export.json").read_text())
    randomizer = random.Random(20261104)
    choices_by_section = {}
    for section in PRUNE_PROOF:
        descriptors = [d for d in shapes[section] if sha256(_json(d).encode()).hexdigest() in PACK_SHAPE_DIGESTS[section]]
        choices_by_section[section] = descriptors if len(descriptors) <= 6 else [descriptors[0], descriptors[-1]] + [
            descriptors[i] for i in randomizer.sample(range(len(descriptors)), 4)]
    for index in range(12):
        export = deepcopy(clean)
        for section in PRUNE_PROOF:
            choices = choices_by_section[section]
            export[section] = _descriptor_value(choices[index % len(choices)], section, mode=index % 2)
            _inject_all(export[section], {"ExtraScalar"}, "mock")
            _inject_all(export[section], {"ExtraObject"}, {"Nested": "mock"})
        full, pruned = _pair(export)
        assert not evaluate_pair(opa, rego, full, pruned, tmp_path / f"sweep-{index}")


def test_users_and_negative_control(pinned, tmp_path):
    opa, rego = pinned
    base = json.loads((FIXTURES / "mocktenant-provider-export.json").read_text())
    for count in range(2, 8):
        full = deepcopy(base)
        full["privileged_users"] = dict(list(base["privileged_users"].items())[:count])
        for index in range(len(base["privileged_users"]), count):
            guid = f"00000000-0000-4000-8000-{index + 1:012d}"
            full["privileged_users"][guid] = {"id": guid, "DisplayName": f"Mock {index}",
                                                 "OnPremisesImmutableId": None,
                                                 "roles": ["Global Administrator"]}
        pruned = deepcopy(full)
        pruned["privileged_users"] = canonicalise_privileged_users(pruned["privileged_users"])[0]
        assert not evaluate_pair(opa, rego, full, pruned, tmp_path / f"users-{count}")
    full = deepcopy(base)
    full["meeting_policies"][0]["AllowExternalParticipantGiveRequestControl"] = True
    pruned = deepcopy(full)
    del pruned["meeting_policies"][0]["AllowExternalParticipantGiveRequestControl"]
    differences = evaluate_pair(opa, rego, full, pruned, tmp_path / "negative")
    assert ("teams", "MS.TEAMS.1.1v1", ("fail",), ("pass",)) in differences


def test_vocabulary_injection(pinned, tmp_path):
    opa, rego = pinned
    differences, size, runs = run_vocabulary_case(opa, rego, tmp_path)
    RUN_COUNTS["vocabulary"], RUN_COUNTS["vocabulary_runs"] = size, runs
    assert size > 300
    assert runs == 400
    assert not differences, differences
    print("differential_counts", json.dumps(RUN_COUNTS, sort_keys=True))

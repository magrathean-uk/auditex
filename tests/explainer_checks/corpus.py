"""Generated corpus: base pairs, shared pairs, mutation rows, canary-twin inputs and red-team pairs, all in memory.

Nothing here is read from a stored pair, prompt, selection or mutation file. Every pair is what the product pipeline
produces for an allowed pool vector: the engine's rule record (``value_rules.assess``), the runtime view
(``explainer.build_view``) and the runtime renderer (``explainer.explain``). The mutation stream applies the
operators of ``mutants.py`` to the base pairs, seeded only by base id and mutant name. The small manifest under
``tests/fixtures/explainer/corpus-manifest.json`` pins counts and the sha256 of each canonical byte stream, so any
drift in the pool, the engine, the template or the generators is detected without storing the expanded data.
"""
import copy
import json
import random
import re
from functools import lru_cache

from azure_tenant_audit import explainer, value_rules
from azure_tenant_audit.explainer.adapter import adapt_record
from azure_tenant_audit.explainer.textkit import shared_exceptions

from . import mutants, pool
from .context import Context
from .driver import run_pair
from .support import ROOT, config, corpus_resources, read_json
from .textnorm import norm

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")
MANIFEST = ROOT / "tests" / "fixtures" / "explainer" / "corpus-manifest.json"
CHUNKS = 4
ORDINARY = {"enabled", "disabled", "true", "false", "none", "unknown", "default", "allowed", "blocked", "global",
            "users", "groups", "roles", "admin", "member", "guest"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stream_sha256(items):
    """sha256 of the canonical JSON lines of ``items`` (one line each, trailing newline)."""
    import hashlib
    digest = hashlib.sha256()
    for item in items:
        digest.update((canonical(item) + "\n").encode("utf-8"))
    return digest.hexdigest()


def _leaves(value, acc):
    if isinstance(value, dict):
        for item in value.values():
            _leaves(item, acc)
    elif isinstance(value, list):
        for item in value:
            _leaves(item, acc)
    elif isinstance(value, str):
        acc.append(value)


def _common_words(resources):
    """Ordinary vocabulary (baseline text, template phrases, collection wording): never a leak candidate."""
    common = set(ORDINARY)
    for policy in resources.bl["policies"].values():
        common |= set(re.findall(r"[a-z0-9]+", norm(policy["statement"] + " " + " ".join(policy["lines"]))))
    for cell in resources.template["cells"]:
        common |= set(re.findall(r"[a-z0-9]+", norm(cell.get("explanation_template", "") + " "
                                                      + " ".join(cell.get("reason_patterns", [])))))
    common |= set(re.findall(r"[a-z0-9]+", norm(" ".join(c["text"] for c in resources.collection["cells"]
                                                         if c.get("applies")))))
    return common


def record_terms(raw_sections, prompt_text, common):
    """Terms of the full raw record that the view omits (check d's leak candidates), at most 200, sorted."""
    leaves = []
    _leaves(raw_sections, leaves)
    candidates = set()
    for text in leaves:
        candidates.add(text)
        for match in EMAIL.finditer(text):
            candidates.add(match.group(0))
            candidates.add(match.group(0).split("@")[0])
    prompt = norm(prompt_text)
    terms = []
    for term in sorted(candidates):
        n = norm(term)
        if len(n) < 5 or n.isdigit() or n in prompt:
            continue
        words = re.findall(r"[a-z0-9]+", n)
        if words and all(w in common for w in words):
            continue
        terms.append(term)
    return terms[:200]


def policy_kinds():
    return {pid: policy["kind"] for pid, policy in config("scuba-value-rules.json")["policies"].items()}


@lru_cache(maxsize=1)
def testset():
    return pool.build_testset(kinds=policy_kinds())


def _record(vector, templates):
    detail = value_rules.assess(vector["policy"], vector["sections"])
    assert (detail["cell"], detail["verdict"]) == (vector["cell"], vector["verdict"]), (
        "engine and fixture label disagree for " + vector["vector_id"])
    return adapt_record({"policy_id": vector["policy"], "verdict": detail["verdict"], "cell": detail["cell"],
                         "reason_code": detail["reason_code"], "reason_text": detail["reason_text"],
                         "cited_sections": detail["cited_sections"]}, templates=templates)


def section_order(record, sections, templates):
    """The supplied full section order: the policy read set first, then any other supplied sections."""
    return list(dict.fromkeys([*templates["policies"][record["policy_id"]]["sections"], *sections]))


def build_pair(row, vector, resources, common):
    baselines, collection, templates = explainer._resources()
    record = _record(vector, templates)
    sections = vector["sections"]
    order = section_order(record, sections, templates)
    view = explainer.build_view(record, sections, order, baselines=baselines, collection=collection)
    output = explainer.explain(record, sections, order)
    terms = record_terms(sections, json.dumps(view, ensure_ascii=False), common)
    return {"id": row["test_id"], "vector_id": row["vector_id"], "origin": row["kind"], "area": row["area"],
            "part": row["part"], "stage_pilot": row["stage_pilot"], "stage_B": row["stage_B"],
            "prompt": {"data": view, "record": record, "full_record_terms": terms}, "output": output}


@lru_cache(maxsize=1)
def _base_pairs_master():
    resources = corpus_resources()
    common = _common_words(resources)
    by_id = {v["vector_id"]: v for v in pool.pool()}
    return tuple(build_pair(row, by_id[row["vector_id"]], resources, common) for row in testset()["rows"])


def base_pairs():
    """All base pairs in test-id order (fresh copies: callers may edit them)."""
    return copy.deepcopy(list(_base_pairs_master()))


def vector_for(pair):
    return next(v for v in pool.pool() if v["vector_id"] == pair["vector_id"])


def shared_pairs():
    """The two A1 shared reasons as pairs, with every fixed policy section supplied and collected."""
    baselines, collection, templates = explainer._resources()
    resources = corpus_resources()
    pairs = []
    for code, entry in shared_exceptions().items():
        pid = "MS.AAD.1.1v1"
        required = templates["policies"][pid]["sections"]
        record = {"policy_id": pid, "verdict": entry["verdict"], "cell": entry["cell"], "reason_code": code,
                  "reason_text": entry["reason_text"], "cited_sections": list(required)}
        sections = {name: ([] if name != "scuba_config" else {"M365Environment": "commercial",
                                                                "collection_status": "collected"})
                    for name in required}
        order = list(required)
        view = explainer.build_view(record, sections, order, baselines=baselines, collection=collection)
        output = explainer.explain(record, sections, order)
        pairs.append({"id": "SHARED-" + code, "vector_id": "constructed:shared:" + code, "origin": "constructed",
                      "area": "AAD", "part": "shared", "stage_pilot": False, "stage_B": False,
                      "prompt": {"data": view, "record": record,
                                 "full_record_terms": ["SYNTHETIC_FAULT_INPUT_DO_NOT_ECHO"]},
                      "output": output})
    assert resources  # shared pairs use the same resources as every other pair
    return pairs


SHARED_MUTANTS = []
for _code in shared_exceptions():
    for _name, _group, _expect in [
            ("alter_explanation", "a", ["a", "c"]), ("assert_compliance", "a", ["a", "c"]),
            ("claim_missing_evidence", "c", ["a", "c"]), ("collect_evidence", "c", ["c", "e", "e2"]),
            ("baseline_change", "e", ["c", "e", "e2"]), ("drop_step", "e2", ["c", "e", "e2"]),
            ("append_step", "e", ["c", "e", "e2"]), ("wrong_product_step", "e", ["c", "e", "e2"]),
            ("benign", "benign", [])]:
        def _make(code, name):
            def fn(pair, ctx, rng, env):
                if ctx.reason_code != code:
                    return None
                out = copy.deepcopy(pair["output"])
                if name == "alter_explanation":
                    out["explanation"] = out["explanation"].replace("Auditex", "The tenant")
                elif name == "assert_compliance":
                    out["explanation"] += " The tenant complies."
                elif name == "claim_missing_evidence":
                    out["explanation"] = "Evidence is missing; no conclusion was reached, so this policy was not assessed."
                elif name == "collect_evidence":
                    out["remediation_steps"] = ["Collect the evidence again."]
                elif name == "baseline_change":
                    out["remediation_steps"] = ["Disable the policy."]
                elif name == "drop_step":
                    out["remediation_steps"] = []
                elif name == "append_step":
                    out["remediation_steps"].append("Check the evidence.")
                elif name == "wrong_product_step":
                    other = "rule_evaluation_failed" if code == "rule_not_implemented" else "rule_not_implemented"
                    out["remediation_steps"] = list(shared_exceptions()[other]["remediation_steps"])
                return {"output": out}
            return fn
        SHARED_MUTANTS.append({"name": _code + "_" + _name, "group": _group, "expect": _expect,
                               "benign": _group == "benign", "fn": _make(_code, _name)})


def mutation_environment(pairs, resources):
    return {"train_idents": sorted(i for i in resources.train_idents if i),
            "not_met_pairs": [p for p in pairs if p["prompt"]["record"]["verdict"] == "not_met"]}


def mutation_rows(pairs=None, resources=None):
    """Yield every mutation row for the stage-B bases plus the shared pairs, in a fixed order.

    Row: {id, base_id, mutant, group, expect, benign, pilot, output | output_text}. The base pairs are the
    stage-B list (pilot is a subset); each mutant's RNG is seeded only by base id and mutant name.
    """
    resources = resources or corpus_resources()
    pairs = [p for p in (pairs or base_pairs()) if p["stage_B"]] + shared_pairs()
    env = mutation_environment(pairs, resources)
    for pair in pairs:
        ctx = Context(pair, resources)
        for m in (SHARED_MUTANTS if ctx.shared else mutants.REG):
            rng = random.Random(f"{pair['id']}|{m['name']}")
            out = m["fn"](pair, ctx, rng, env)
            if out is None:
                continue
            yield {"id": pair["id"] + "/" + m["name"], "base_id": pair["id"], "mutant": m["name"], "group": m["group"],
                   "expect": list(m["expect"]), "benign": m["benign"], "pilot": pair["stage_pilot"], **out}


def resolve_base(selector, *, test_id="RT"):
    """Resolve a (policy, verdict, cell) selector to a base pair over the allowed pool, at test time.

    Candidates are the pool vectors of that policy and cell: the test set's core vector first, then the rest by
    kind, size and vector id. Optional filters pick the first whose pair satisfies them: ``reason_contains`` (a
    substring of the rule's reason text) and ``evidence_contains`` (substrings of the view's evidence JSON) and ``sections_contain`` (case-folded substrings
    of the vector's full raw sections, for terms the view omits).
    A selector that resolves to nothing raises, so a pool or catalogue change cannot silently re-bind a case.
    """
    resources = corpus_resources()
    common = _common_words(resources)
    core = {r["vector_id"] for r in testset()["rows"] if r["part"] == "core"}
    vectors = [v for v in pool.pool() if v["policy"] == selector["policy"] and v["cell"] == selector["cell"]
               and v["verdict"] == selector["verdict"]]
    vectors.sort(key=lambda v: (v["vector_id"] not in core, pool.RANK[v["kind"]], len(pool.canon(v["sections"])),
                                v["vector_id"]))
    for vector in vectors:
        row = {"test_id": test_id, "vector_id": vector["vector_id"], "kind": vector["kind"],
               "area": pool.area(vector["policy"]), "part": "redteam", "stage_pilot": False, "stage_B": False}
        pair = build_pair(row, vector, resources, common)
        evidence = json.dumps(pair["prompt"]["data"]["evidence"], ensure_ascii=False)
        if selector.get("reason_contains") and selector["reason_contains"] not in pair["prompt"]["record"]["reason_text"]:
            continue
        if any(s not in evidence for s in selector.get("evidence_contains", [])):
            continue
        raw = json.dumps(vector["sections"], ensure_ascii=False).casefold()
        if any(s.casefold() not in raw for s in selector.get("sections_contain", [])):
            continue
        return pair
    raise LookupError("selector resolves to no allowed pool vector: " + json.dumps(selector, sort_keys=True))


def all_pairs_by_id():
    pairs = {p["id"]: p for p in base_pairs()}
    for pair in shared_pairs():
        pairs[pair["id"]] = pair
    return pairs


def load_manifest():
    return read_json(MANIFEST)


def pair_rows_for_manifest():
    return [{"id": p["id"], "vector_id": p["vector_id"], "prompt": p["prompt"], "output": p["output"]}
            for p in base_pairs()]


def check_all(pairs, resources=None):
    """Run the eight checks over pairs; return (failures, skips) as lists of (id, check)."""
    resources = resources or corpus_resources()
    failures, skips = [], []
    for pair in pairs:
        for check, result in run_pair(pair, resources).items():
            if result["pass"] is False:
                failures.append((pair["id"], check, [f["code"] for f in result["failures"]]))
            elif result["pass"] is None:
                skips.append((pair["id"], check))
    return failures, skips


"""The allowed vector pool and the deterministic test-set builder (no stored pairs, selections or prompts).

Fixture rule for this public repository: explainer test material may be derived only from constructed rows and
model-pack TRAIN and VALIDATION rows, each with a vector id and an origin. Held-out test-split rows (pack or pilot),
sealed pilot rows and diagnostic rows are never read, stored or derived from. ``normal_kind`` fails closed on any
other source kind and on any ``split == "test"``.

The pool is the union of the value-rule vector fixtures under ``tests/fixtures/value-rules`` (already reviewed
against this rule by the value-rule suites) plus the A2 constructed vectors. ``build_testset`` ports the explainer
plan's strata (core: one vector per policy and cell; depth: extra vectors by verdict and area; nested stage lists)
as pure functions of the pool and a seed.
"""
import collections
import hashlib
import json
import lzma
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "tests" / "fixtures" / "value-rules"

ALLOWED_KINDS = ("constructed", "pack-train", "pack-validation")
# Source-kind spellings that are the same allowed kind (carried-forward v2 files and licensed twins of train rows).
KIND_ALIASES = {"packlic-train": "pack-train", "aad-pack-train": "pack-train", "pbi-pack-train": "pack-train",
                "pbi-pack-validation": "pack-validation"}
SEED = "explainer-testset-20261105"
CAP = 6000
AREAS = ["AAD", "SECURITYSUITE", "TEAMS", "EXO", "POWERBI", "SHAREPOINT", "POWERPLATFORM"]
VERDICTS = ["met", "not_met", "not_assessed", "not_applicable"]
PILOT_V = {"met": 20, "not_met": 30, "not_assessed": 38, "not_applicable": 8}
PILOT_A = {"AAD": 20, "SECURITYSUITE": 20, "TEAMS": 14, "EXO": 14, "POWERBI": 12, "SHAREPOINT": 8, "POWERPLATFORM": 8}
B_V = {"met": 63, "not_met": 94, "not_assessed": 118, "not_applicable": 25}
B_A = {"AAD": 63, "SECURITYSUITE": 62, "TEAMS": 44, "EXO": 44, "POWERBI": 37, "SHAREPOINT": 25, "POWERPLATFORM": 25}
DEPTH_V = {"met": 80, "not_met": 100, "not_assessed": 90, "not_applicable": 30}
DEPTH_FLOOR = 5
BIG = 2000
RANK = {"pack-validation": 0, "pack-train": 1, "constructed": 2}


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def normal_kind(row):
    """The allowlisted kind of a vector row; anything else (including a test split) is a hard error."""
    if row.get("split") == "test":
        raise ValueError("held-out test row in the pool: " + str(row.get("vector_id")))
    kind = KIND_ALIASES.get(row.get("source_kind"), row.get("source_kind"))
    if kind not in ALLOWED_KINDS:
        raise ValueError("source kind outside the allowlist: " + repr(row.get("source_kind")))
    return kind


def area(policy):
    return policy.split(".")[1]


def _lines(path):
    opener = lzma.open if path.suffix == ".xz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


@lru_cache(maxsize=1)
def pool():
    """Allowed vectors, deduplicated by vector id in file order, each annotated with its allowlisted kind."""
    files = sorted(VECTORS.glob("vectors-*.jsonl.xz")) + sorted(VECTORS.glob("vectors-*.jsonl"))
    rows, seen = [], set()
    for path in files:
        for row in _lines(path):
            kind = normal_kind(row)
            if row["vector_id"] in seen:
                continue
            seen.add(row["vector_id"])
            rows.append({"vector_id": row["vector_id"], "policy": row["policy"], "cell": row["rule_cell"],
                         "verdict": row["rule_verdict"], "kind": kind, "origin": row["vector_id"].split(":")[0],
                         "sections": row["sections"], "criticality": row.get("criticality"),
                         "cited": row.get("rule_cited_sections")})
    return tuple(rows)


def h(seed, *parts):
    """Seeded deterministic tie-break key (never Python's hash())."""
    return sha("|".join([seed, *map(str, parts)]))


def _ipf(counts, row_margin, col_margin):
    t = {k: float(v) for k, v in counts.items()}
    for _ in range(300):
        for i in VERDICTS:
            s = sum(t[(i, j)] for j in AREAS)
            if s:
                for j in AREAS:
                    t[(i, j)] *= row_margin[i] / s
        for j in AREAS:
            s = sum(t[(i, j)] for i in VERDICTS)
            if s:
                for i in VERDICTS:
                    t[(i, j)] *= col_margin[j] / s
    return t


def _mincost_alloc(target, caps, rm, cm):
    """Integer matrix with margins rm, cm, 0 <= x <= caps, minimising sum (x - target)^2 (convex min-cost flow)."""
    source, sink = "S", "T"
    nodes = [source, sink] + [("v", i) for i in VERDICTS] + [("a", j) for j in AREAS]
    edges = []  # [u, v, cap, cost, flow]

    def add(u, v, cap, cost):
        edges.append([u, v, cap, cost, 0])
        edges.append([v, u, 0, -cost, 0])
        return len(edges) - 2

    for i in VERDICTS:
        add(source, ("v", i), rm[i], 0)
    for j in AREAS:
        add(("a", j), sink, cm[j], 0)
    cell_edges = {}
    for i in VERDICTS:
        for j in AREAS:
            cell_edges[(i, j)] = [add(("v", i), ("a", j), 1, round(1000 * (2 * k + 1 - 2 * target[(i, j)])))
                                  for k in range(caps.get((i, j), 0))]
    need = sum(rm.values())
    assert need == sum(cm.values()), (need, sum(cm.values()))
    for _ in range(need):
        dist = {n: None for n in nodes}
        dist[source] = 0
        prev = {}
        changed = True
        while changed:
            changed = False
            for index, (u, v, cap, cost, flow) in enumerate(edges):
                if cap - flow > 0 and dist[u] is not None and (dist[v] is None or dist[u] + cost < dist[v]):
                    dist[v] = dist[u] + cost
                    prev[v] = index
                    changed = True
        if dist[sink] is None:
            raise RuntimeError("infeasible margins")
        node = sink
        while node != source:
            index = prev[node]
            edges[index][4] += 1
            edges[index ^ 1][4] -= 1
            node = edges[index][0]
    return {key: sum(edges[e][4] for e in es) for key, es in cell_edges.items()}


def build_testset(vectors=None, *, kinds, seed=SEED):
    """Core, depth and nested stage lists over the allowed pool; ``kinds`` maps policy id to its rule kind.

    Returns {"rows": [...], "core": n, "depth": n, "counts": {...}}; every row has a stable test id X0001... and the
    flags stage_pilot / stage_B. A pure function of its inputs: no file, clock or randomness beyond ``seed``.
    """
    vecs = []
    for v in (pool() if vectors is None else vectors):
        v = dict(v)
        v["_sec_sha"] = sha(canon(v["sections"]))
        v["_chars"] = len(canon(v["sections"]))
        v["_over"] = any(len(canon(x)) > CAP for x in v["sections"].values())
        vecs.append(v)

    def key(r, *parts):
        return h(seed, *parts)

    by_cell = collections.defaultdict(list)
    for r in vecs:
        by_cell[(r["policy"], r["cell"])].append(r)
    core = []
    for cell in sorted(by_cell):
        ordered = sorted(by_cell[cell], key=lambda r: (RANK[r["kind"]], r["_over"], key(r, "core", r["vector_id"])))
        core.append(ordered[0])
    core_ids = {r["vector_id"] for r in core}
    core_keys = {(r["policy"], r["_sec_sha"]) for r in core}

    pool_rows = [r for r in vecs if r["vector_id"] not in core_ids and (r["policy"], r["_sec_sha"]) not in core_keys]
    sizes = sorted(r["_chars"] for r in vecs)
    tercile_cut = sizes[(2 * len(sizes)) // 3]
    core_cnt = collections.Counter((r["verdict"], area(r["policy"])) for r in core)

    def alloc_by_area(total, verdict):
        cnt = {a: core_cnt[(verdict, a)] for a in AREAS if core_cnt[(verdict, a)] > 0}
        out = {a: min(DEPTH_FLOOR, total // max(1, len(cnt))) for a in cnt}
        rest = total - sum(out.values())
        base = sum(cnt.values())
        exact = {a: rest * cnt[a] / base for a in cnt}
        for a in cnt:
            out[a] += int(exact[a])
        left = total - sum(out.values())
        for a in sorted(cnt, key=lambda a: (-(exact[a] - int(exact[a])), a))[:left]:
            out[a] += 1
        return out

    depth, short = [], {}
    seen_keys = set(core_keys)
    for verdict in VERDICTS:
        quota = alloc_by_area(DEPTH_V[verdict], verdict)
        for a in sorted(quota):
            cand = [r for r in pool_rows if r["verdict"] == verdict and area(r["policy"]) == a]
            percell = collections.defaultdict(list)
            for r in cand:
                tier = 0 if r["_chars"] >= BIG else (1 if r["_chars"] >= tercile_cut else 2)
                percell[(r["policy"], r["cell"], tier)].append(r)
            order = []
            for cell, lst in percell.items():
                lst.sort(key=lambda r: (r["_over"], key(r, "depth", r["vector_id"])))
                order += [((cell[2], i, lst[i]["_over"], key(lst[i], "depthord", lst[i]["vector_id"])), lst[i])
                          for i in range(len(lst))]
            order.sort(key=lambda t: t[0])
            got = 0
            for _, r in order:
                if got >= quota[a]:
                    break
                k = (r["policy"], r["_sec_sha"])
                if k in seen_keys:
                    continue
                seen_keys.add(k)
                depth.append(r)
                got += 1
            if got < quota[a]:
                short[f"{verdict}|{a}"] = f"{quota[a]} wanted, {got} available"
    selected = core + depth

    def kind_of(r):
        return kinds.get(r["policy"], "?")

    def pick(items, q, kind_ct, pol_ct, tag):
        items = list(items)
        chosen = []
        for _ in range(q):
            items.sort(key=lambda r: (kind_ct[kind_of(r)], pol_ct[r["policy"]], key(r, tag, r["vector_id"])))
            r = items.pop(0)
            chosen.append(r)
            kind_ct[kind_of(r)] += 1
            pol_ct[r["policy"]] += 1
        return chosen

    def stage(base, universe, rm, cm, tag):
        ucnt = collections.Counter((r["verdict"], area(r["policy"])) for r in universe)
        bcnt = collections.Counter((r["verdict"], area(r["policy"])) for r in base)
        rrm = {i: rm[i] - sum(bcnt[(i, j)] for j in AREAS) for i in VERDICTS}
        rcm = {j: cm[j] - sum(bcnt[(i, j)] for i in VERDICTS) for j in AREAS}
        assert min(rrm.values()) >= 0 and min(rcm.values()) >= 0, (rrm, rcm)
        full = _ipf({(i, j): ucnt[(i, j)] for i in VERDICTS for j in AREAS}, rm, cm)
        target = {k: full[k] - bcnt[k] for k in full}
        caps = {(i, j): ucnt[(i, j)] - bcnt[(i, j)] for i in VERDICTS for j in AREAS}
        x = _mincost_alloc(target, caps, rrm, rcm)
        have = {r["vector_id"] for r in base}
        kind_ct = collections.Counter(kind_of(r) for r in base)
        pol_ct = collections.Counter(r["policy"] for r in base)
        out = list(base)
        for i in VERDICTS:
            for j in AREAS:
                cand = [r for r in universe if r["vector_id"] not in have and r["verdict"] == i and area(r["policy"]) == j]
                out += pick(cand, x[(i, j)], kind_ct, pol_ct, tag)
        return out

    pilot = stage([], core, PILOT_V, PILOT_A, "pilot")
    stage_b = stage(pilot, selected, B_V, B_A, "B")
    pilot_ids = {r["vector_id"] for r in pilot}
    b_ids = {r["vector_id"] for r in stage_b}
    assert pilot_ids <= b_ids <= {r["vector_id"] for r in selected}

    rows = []
    ordered = [(r, "core") for r in sorted(core, key=lambda r: (r["policy"], r["cell"]))]
    ordered += [(r, "depth") for r in sorted(depth, key=lambda r: (r["policy"], r["cell"], r["vector_id"]))]
    for n, (r, part) in enumerate(ordered, start=1):
        rows.append({"test_id": f"X{n:04d}", "part": part, "vector_id": r["vector_id"], "policy": r["policy"],
                     "area": area(r["policy"]), "cell": r["cell"], "verdict": r["verdict"], "kind": r["kind"],
                     "rule_kind": kind_of(r), "sections_sha256": r["_sec_sha"], "sections_chars": r["_chars"],
                     "over_cap": r["_over"], "stage_pilot": r["vector_id"] in pilot_ids, "stage_B": r["vector_id"] in b_ids})

    def tab(items, fn):
        return dict(sorted(collections.Counter(fn(x) for x in items).items(), key=lambda kv: str(kv[0])))

    counts = {
        "pool": len(vecs), "pool_by_kind": tab(vecs, lambda r: r["kind"]),
        "cells_in_pool": len(by_cell), "policies_in_pool": len({r["policy"] for r in vecs}),
        "core": len(core), "depth": len(depth), "total": len(rows), "pilot": len(pilot), "stage_B": len(stage_b),
        "core_by_verdict": tab(core, lambda r: r["verdict"]), "core_by_area": tab(core, lambda r: area(r["policy"])),
        "depth_by_verdict": tab(depth, lambda r: r["verdict"]), "depth_shortfall": short,
        "by_kind": tab(rows, lambda r: r["kind"]), "stage_pilot_by_verdict": tab(pilot, lambda r: r["verdict"]),
        "stage_B_by_verdict": tab(stage_b, lambda r: r["verdict"]), "distinct_rule_kinds": len({kind_of(r) for r in selected}),
        "policies_covered": len({r["policy"] for r in selected}), "over_cap_rows": sum(r["_over"] for r in selected),
    }
    return {"rows": rows, "counts": counts}

"""One complete replay of the generated base pairs; no stored pair, prompt or result is read."""
import copy
import hashlib
import json
from time import perf_counter

from . import CHECKS, corpus
from .driver import run_pair
from .support import corpus_resources, integration_result


def assert_result_schema(results):
    assert tuple(results) == CHECKS
    for result in results.values():
        assert set(result) == {"pass", "klass", "failures", "notes"}
        assert result["pass"] is None or isinstance(result["pass"], bool)
        assert isinstance(result["notes"], list)
        assert isinstance(result["failures"], list)
        for failure in result["failures"]:
            assert set(failure) == {"code", "klass", "text", "detail"}


def replay_all(root):
    resources = corpus_resources()
    seen, failures, skipped = set(), [], []
    replay = []
    start = perf_counter()
    for pair in corpus.base_pairs():
        assert pair["id"] not in seen
        seen.add(pair["id"])
        original = copy.deepcopy(pair)
        results = run_pair(pair, resources)
        assert_result_schema(results)
        replay.append(json.dumps({"id": pair["id"], "checks": results}, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        assert pair == original, pair["id"]
        failures.extend((pair["id"], check, result["failures"]) for check, result in results.items() if result["pass"] is False)
        skipped.extend((pair["id"], check) for check, result in results.items() if result["pass"] is None)
    elapsed = perf_counter() - start
    integration_result("replay", "\n".join(replay) + "\n", root=root)
    integration_result("replay-timing", {"seconds": elapsed, "pairs": len(seen)}, root=root)
    assert len(seen) == corpus.load_manifest()["pairs"]["base"]
    assert not skipped, skipped[:10]
    assert not failures, failures[:10]
    print(f"{len(seen)} pairs, {8 * len(seen)} check results; {elapsed:.3f} s; SHA256="
          + hashlib.sha256(("\n".join(replay) + "\n").encode()).hexdigest())


def test_pair_determinism_and_nonmutation():
    resources = corpus_resources()
    pair = corpus.base_pairs()[0]
    original = copy.deepcopy(pair)
    first = json.dumps(run_pair(pair, resources), sort_keys=True)
    assert first == json.dumps(run_pair(pair, resources), sort_keys=True)
    assert pair == original


def test_all_generated_pairs(tmp_path):
    """Two fresh interpreters share only this test's scratch directory."""
    import subprocess
    import sys
    from pathlib import Path
    outputs = []
    for attempt in ("first", "second"):
        root = tmp_path / attempt
        code = ("import sys; from pathlib import Path; sys.path[:0] = "
                + repr([str(Path(__file__).resolve().parents[2] / "src"), str(Path(__file__).resolve().parents[1])])
                + "; from explainer_checks.test_suite import replay_all; replay_all(Path("
                + repr(str(root)) + "))")
        result = subprocess.run([sys.executable, "-B", "-I", "-c", code],
                                capture_output=True, text=True, timeout=240)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout)
        outputs.append((root / "replay.jsonl").read_bytes())
    assert outputs[0] == outputs[1], "fresh-process replay bytes changed"

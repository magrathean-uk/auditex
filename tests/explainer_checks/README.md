# Explainer checks

The eight independent hard checks (S, a, b, c, d, e, e2, e3) and the generators that feed them. Nothing the checks
consume is stored as expanded data: the test set, base pairs, mutants and twins are generated in memory, deterministically,
from the allowed vector pool (constructed rows and pack train/validation rows under `tests/fixtures/value-rules`; the
fixture rule is in `tests/fixtures/explainer/README.md` and enforced by `tests/test_explainer_fixtures.py`).

| Module | Role |
| --- | --- |
| `pool.py` | The allowed pool (fails closed on any other source kind or a test split) and `build_testset`: core (one vector per policy and cell), depth, nested stage lists, as pure functions of the pool and a seed. |
| `corpus.py` | Base pairs through the product pipeline (engine record, `build_view`, `explain`), the two shared-reason pairs, the mutation stream, selector resolution (`resolve_base`), stream hashes. |
| `mutants.py` | The mutation operators (the S/C logic), seeded only by base id and mutant name. |
| `redteam.py` | The 50 red-team candidates re-bound to allowed bases by selector. |
| `build_manifest.py` | Regenerates `tests/fixtures/explainer/corpus-manifest.json` (counts and sha256 of each generated stream). |
| `support.py` | Gzip-aware fixture readers; the checker resources assembled from the pinned raw baselines (parsed by this package's own reader) and the shipped configs. |

Default pytest excludes `explainer_acceptance` via pytest.ini. The default mutation sample takes the first four rows per
harmful type and six per benign type in generated order (all 160 types). The generated base pairs replay by default,
twice in fresh interpreters within one tmp_path; persistent output files are never test expectations.

`make acceptance` runs these jobs after the v3.9.1 value-rule replay (it needs `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`; see the runbook). To run only the explainer jobs, use the recipe below, serially from the repository root (no network), each under a 300 s cap:

```sh
for chunk in 00 01 02 03; do
  PYTHONPATH="$PWD/src" perl -e 'alarm 300; exec @ARGV' .venv/bin/python -B -I -m pytest tests/explainer_checks/test_mutation.py -m explainer_acceptance -k "chunk-$chunk" -p no:cacheprovider -q -s -o addopts= || exit
done
PYTHONPATH="$PWD/src" perl -e 'alarm 300; exec @ARGV' .venv/bin/python -B -I -m pytest tests/test_explainer_integration.py -m explainer_acceptance -k twins -p no:cacheprovider -q -s -o addopts=
PYTHONPATH="$PWD/src" perl -e 'alarm 300; exec @ARGV' .venv/bin/python -B -I -m pytest tests/test_explainer_integration.py -m explainer_acceptance -k byte_identical -p no:cacheprovider -q -s -o addopts=
```

The four mutation chunks partition rows by index modulo four. A harmful mutant counts as detected only when an expected check
fails; any benign failure or skip is a false positive. The manifest pins 19,354 harmful and 2,522 benign rows and lists the four
known misses (19,350 detected, 99.979%); the acceptance run requires zero false positives and no miss outside that list. The twins
job runs five twins per base pair with the real builder (a twin that cites a section outside the policy's read set must be rejected).
The byte-identical job replays every base pair through the runtime in two fresh processes. Expected red-team and product
migration/redaction gaps keep their strict xfails.

Executable pre blocks are indivisible approved command units. Only exact whole units present in both fixed policy metadata and
the prompt are exempt from the 30-word step cap in S; e and e3 reject partial command blocks. Whole-command checker matching
permits the existing dash/quote/whitespace normalisation within lines, retaining line boundaries so comments cannot swallow
subsequent code. The six-step cap and all prose limits remain in force. Portal navigation pre blocks are prose. PowerShell
syntax regression tests use its read-only Parser API to compare raw source and rendered ASTs for all executable blocks across
compact/full cells; commands are never executed. If pwsh is absent, syntax parsing is explicitly skipped after the source-identity
checks.

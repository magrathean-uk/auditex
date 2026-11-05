# Explainer test fixtures

Runtime resources live under `configs/`; this directory holds only small, pinned test inputs. The explainer's test
set, base pairs, prompts and mutation corpus are **not stored**: `tests/explainer_checks` generates them in memory,
deterministically, from the value-rule vector fixtures under `tests/fixtures/value-rules` plus constructed rows, and
`corpus-manifest.json` pins their counts and the sha256 of each canonical byte stream, so any drift is detected.

## The fixture rule (binding for this repository)

Fixtures may contain **only constructed rows and model-pack TRAIN and VALIDATION rows**, each with a vector id and an
origin. They never contain held-out test-split rows (pack or pilot), sealed pilot rows or diagnostic rows, any machine
path (no home, volume or workspace path), or a file over 1 MB; this directory stays under 1 MB in total.
`tests/test_explainer_fixtures.py` enforces it over every file here (decompressing `.gz`), with planted negative
controls, and checks that the generated test set uses only the allowlisted kinds (`constructed`, `pack-train`,
`pack-validation`; carried-forward spellings such as `packlic-train` are the same kinds).

## Contents

| Path | What it is |
| --- | --- |
| `corpus-manifest.json` | Counts and sha256 of the generated pool, test set, base pairs and mutation stream; input pins; the four known mutation misses. Regenerate with `tests/explainer_checks/build_manifest.py --write` (a reviewed change, not a test repair). |
| `baselines/` | The eight pinned CISA ScubaGear baseline files and licence (gzip, original bytes after decompression), a frozen independent extraction of them and its manifest. |
| `checks/` | Ordinary-word list and notice, independent baseline expectations, the synthetic training-identifier tokens for check d, upstream pins. |
| `collection/` | The reconciliation record of the 919 inherited collection-wording entries and notes. |
| `renderer/` | The spec's byte-exact v3.9.1 cell catalogue (the independent pin), the frozen shown/full step digests of every cell, two constructed fault vectors, provenance. |
| `integration/` | Reviewed command-step changes, executable command units, the pre-migration catalogue measure. |
| `controls/` | Constructed controls: the 18 changed text pairs, injected exceptions, fault adapter records. |
| `redteam/` | The 50 independent red-team candidates (W01 to W40, B01 to B10): texts, intents, expected checks, and a selector per candidate that binds it to an allowed pool base at test time. |
| `SHA256SUMS` | Stored-byte digests of every other file here. |

## Generated test material

* Pool: the allowed vector fixtures, deduplicated by vector id: 16,986 vectors (12,146 constructed, 4,313 pack-train,
  527 pack-validation) covering all 102 policies and 1,084 cells.
* Test set (`pool.build_testset`, seed in the manifest): core (one vector per policy and cell, preferring validation,
  then train, then constructed rows), depth (300 more by verdict and area) and the nested stage lists (pilot 96, stage B
  300, all). The plan's 1,335 was core 1,035 plus 300 depth, where 49 cells had only excluded rows; the allowed pool
  reaches every cell, so the full set is 1,084 plus 300 = 1,384 and the stage lists keep 96 and 300.
* Base pairs: for each selected vector the engine's rule record, the runtime `build_view` and `explain`; mutants are the
  operators of `tests/explainer_checks/mutants.py` applied to the stage-B pairs plus the two shared-reason pairs.

Baseline requirement and Instructions excerpts derive from CISA SCuBA / ScubaGear commit
`2446ad723b7f55031cc02c8aca244d731d468cba`, whose repository licence is CC0 1.0 Universal. The Entra ID, Power Platform
and Security Suite baseline headers attribute portions to Microsoft documentation under CC BY 4.0; credit CISA and
Microsoft. See `baselines/README.md` and `docs/provenance/explainer-baselines.md`. Synthetic project data is
Apache-2.0 and contains no tenant evidence.

Literal dash bytes: authored Python uses Unicode escapes. The original dash bytes are preserved only in the pinned
baseline markdown and in the independently parsed baseline expectations.

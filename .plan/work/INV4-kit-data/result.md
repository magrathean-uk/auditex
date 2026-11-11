## RESULT INV4-kit-data
status: done
summary: The v10 pack of record has train 4294, validation 531, test 435 and quarantine 0 (ministral3-8b split). Its test set is byte-identical to frozen test-v7. By my longest-text heuristic 318/435 test rows (73.1%) have a train twin, against 137 in V11-DATA-PLAN. No test-v8 file exists, only a plan. The sealed AAD v2.1 pilot is present and frozen. Full notes: .plan/work/INV4-kit-data/notes.md
changes: none in the repository. Notes written to .plan/work/INV4-kit-data/notes.md and .plan/work/INV4-kit-data/twin-by-family-v7.txt
verification: 9 read-only shell commands (listing, wc -l, shasum on three test.jsonl files, python3 -I counting twins with counts only, grep/rg, test -x for OPA). No row content quoted; no secret-like files read; no builds, tests or network.
risks: The twin figure (318) uses my own heuristic and disagrees with the project's 137 strict-key figure, so the two are not reconciled. The ScubaGear pin 2446ad7 is cited in DATASET-CARD but not verified against the pinned tree in kit/20261027-ship-plan. The 20 quarantined vocabulary-ambiguous cases were not found as a file in the kit.
questions_for_g: The SessionStart hook asked to run `clean-development doctor`. I did not run it, because this brief says not to run it unless explicitly authorised. Say if you want it run (diagnosis only).

### Findings

**1. exists**
- Pack of record: kit/20261030-oracle-pack-v10/training-pack-oracle-v10-ministral3-8b/ holds train.jsonl 4294, validation.jsonl 531, test.jsonl 435, quarantine.jsonl 0, approved-cases.jsonl 5260. Same layout for ministral3-14b.
- Generators for v10: kit/20261030-oracle-pack-v10/mine_v10.py, curate_v10.py, balance_v10.py, finalise_v10.py, verify_v10.py, check_regen_parity_v10.py.
- Frozen test-v7: kit/20261026-oracle-pack-v7/training-pack-oracle-v7/test.jsonl (435 rows); train.jsonl 3263; validation.jsonl 348.
- Sealed AAD pilot v2.1: kit/20261104-aad-section-pilot-v2.1/ (FREEZE-NOTE.md:1 "re-sealed 4 November 2026"; rows-all.jsonl 487; rows-dropped.jsonl 403; manifest.json).
- Older packs: kit/20261019-oracle-cases/, kit/20261029-oracle-pack-v8/, kit/20261029-oracle-pack-v9/, kit/20261026-oracle-pack-v7/ (build_v7.py).
- Plan for test-v8: kit/20261031-v11-plan/V11-DATA-PLAN.md:8, :13, :55.
- Other: kit/auditex-jupiter-deploy-20261023.tar.gz (6.2 MB) with .sha256; kit/wheels/ (three auditex wheels).

**2. works**
- Row counts: `wc -l` on the v10 and v7 split files (identical 435-row test counts).
- Test identity: `shasum -a 256` on kit/20261026-oracle-pack-v7/training-pack-oracle-v7/test.jsonl and both kit/20261030-oracle-pack-v10/training-pack-oracle-v10-ministral3-{8b,14b}/test.jsonl all give prefix 2e521987902ec2d9.
- Twin counts: python3 -I counting exact longest-text matches of test rows against train rows (counts only). Result: 318/435 for v7 and for v10-8b. Per-family shares min 0.18, max 1.00; 5 families fully twinned; 0 families untwinned.
- OPA 1.20.2 binary present at the path mine_v10.py:21 uses (`test -x`).
- Rego pin and OPA version stated at kit/20261030-oracle-pack-v10/DATASET-CARD.md:74.

**3. broken**
- none found in the commands run. Not checked: kit completeness or any integrity manifest.
- Referenced but unverified: ScubaGear commit 2446ad7 (DATASET-CARD.md:74); no checkout of that exact commit confirmed.

**4. dead candidates**
- kit/20261027-ship-plan/ (10.6 GB, 202,314 files). rg shows it holds the scratch tree (`tree/run/kit/*`) and copies of the ScubaGear Rego. Inferred dead; not confirmed by rg.
- kit/20261104-civo-pull/ (12.2 GB). Not in this slice; no reference check done.
- Superseded v10 round folders: kit/20261030-oracle-pack-v10/superseded-round1/ and superseded-round2/.
- Stray kit/.DS_Store (14 KB).
- TODO/FIXME: only one per copy in make_fixture.py and test_dns_lookup_parsers.py (kit/20261031-dummy-tenant/tools/coverage-fixtures/, kit/20261018-phase2-validated/source/tests/). Not in the slice's scripts.

**5. contradictions**
- kit/20261031-v11-plan/V11-DATA-PLAN.md:12-13 says 137 test rows share a strict key with a train row. My heuristic gives 318 twins. The definitions differ (inferred), not reconciled.
- kit/20261031-v11-plan/V11-DATA-PLAN.md:12 gives 171/435 rows for MS.AAD.9.1v1 (39%). Per-family counts from the kit were not re-checked against that figure.

**6. open questions**
- Which twin definition the project uses for 137: `rg -n "strict_key|near_key" kit/20261030-oracle-pack-v10/curate_v10.py`.
- Where the 20 quarantined vocabulary-ambiguous cases live: `rg -n -i "vocabulary|ambig" kit/20261030-oracle-pack-v10 kit/20261031-v11-plan` (not run).
- Whether the ScubaGear checkout under kit/20261027-ship-plan/tree/run/kit/*/scuba-pin is at 2446ad7: `git -C <scuba-pin> rev-parse HEAD` (read-only).
- Whether a twin-free test-v8 can be regenerated offline: needs the Rego at 2446ad7 and kit/20261019-oracle-cases/cases*.jsonl; not attempted (no builds or runs).
- Neighbouring area (one line): kit/jupiter-results/ (250 MB) and kit/20261104-civo-pull/ are outside this slice.

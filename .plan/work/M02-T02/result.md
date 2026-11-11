## RESULT M02-T02
status: done
summary: Item 3 closed. The twin key now covers fail-closed branches that read only availability inputs, taken from the pinned Rego, for 27 policies in Power BI, SharePoint, Power Platform and Teams. A not_assessed row that fires one is keyed on the policy, the branch and the presence of the inputs the branch reads. The build checks each such candidate by evaluation (same Rego result on its deciding inputs alone): 1,096/1,096. The reviewer's probe finds 10 matches on the old set and 0 on the new one, also by their own script in all three modes. Soundness holds (0/3,435 keys on the pack), and the test-v7 recount is restated with earlier figures kept.
summary: Item 7 closed with one named limit. `kit-check twins` holds engine pins, Rego and seed hashes, v10 seed counts and caps to pinned values, recomputed from sources where present. It recomputes every coverage reason from a per-cell evidence record. A cell recorded as having no generated input cannot be re-checked without regenerating; this limit is in heldout/README.md.
summary: Resealed set: 501 rows, 102/102 policies, 188/314 cells. not_assessed rows fell from 33 to 10, because most fail-closed candidates are now twins of training rows. Two defects found and fixed on the way: a JSON null denial reason fired no branch, and Power Platform 2.2 compares environment names (its values are now exact, via repair_reads.py).
changes: kit/20261111-airr-v4/heldout/{twin_definition.py,heldout_lib.py,build_heldout.py,README.md,tests/test_twins_check.py,heldout.jsonl,reproduction.json,consumed-splits.json,manifest.json,measures.json,policy-states.json,SHA256SUMS}; heldout/notes/{availability_gates.py (new),field-reads.json,field-reads-v3.json (round-1 copy),repair_reads.py,recount-result.json,recount-result-v3.json (round-1 copy),selftest.py,twin-reconciliation.md}; kit/20261111-airr-v4/checks/twins.py; checks/SHA256SUMS (twins.py line only); .plan/work/M02-T02/notes.md
verification: `grep -qx 'heldout-twins: 0' <scratch result.md> && "$AIRR_KIT/bin/kit-check" twins --result <scratch result.md>` PASS. The scratch file (`$TMPDIR/m02t02-r3/work/M02-T02/result.md`) holds these Findings lines. Also PASS with AIRR_OPA and AIRR_SCUBAGEAR set (501/501 labels re-run).
verification: heldout/tests 24 pass with the engine (8 new: false rule hash, coverage reason, seed count, changed v10 seed, forged twin evidence, inconsistent counts, false availability probe, availability twin in later data). checks/tests 54 pass. kit-check selftest PASS. notes/selftest.py 43/43. Second build for byte-identity skipped (15 to 20 CPU minutes).
risks: Uncovered cells rose from 118 to 126 (92 not_assessed), each with a reason in manifest.json. A false "no generated input" record cannot be detected without regenerating. Its effect on a score is a narrower but visible coverage, never a leak.
risks: A different random stream exposed a SecuritySuite 3.1 abstraction gap (it compares sensitive-information names). The sealed streams do not hit it, and the build's soundness gate stops on it if they do. Follow-up: exact values for 3.1 before any regeneration with new streams.
risks: Every build started with load below 12, but load rose above 20 during the runs because other projects keep the machine busy. Run logs are in .plan/work/M02-T02/job-4 to job-9; job-9 is the sealed set.
questions_for_g: none
### Findings
heldout-twins: 0
heldout-sha256: 20484ddc34fe8cc9876fdae96d308fae572a5097ab6a5afb04d4b99cf1b15a10
heldout-rows: 501
heldout-policies: 102/102
heldout-cells: 188/314
heldout-share-cap: 3 per cent
heldout-max-share: 1.80 per cent
heldout-soundness: pass
heldout-unknown-policies: none
heldout-label-reproduction: 501/501
heldout-nn-copy-decisive: 216/501
heldout-nn-copy-full: 205/501
heldout-nn-copy-policy-majority: 189/501
heldout-availability-matches: 0
gpu-hours: heldout 0

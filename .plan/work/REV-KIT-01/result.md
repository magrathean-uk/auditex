## RESULT REV-KIT-01
status: done
summary:
verdict: changes-required
reviewed: fd568fabc6e1
The four original findings are closed. Two new accounting false passes block GPU work.
changes: none
verification: PASS - repeated bypass probes, complete manifest checks, 21 twin tests, 10,454 repetition probes, byte-identical recount, 8 trainer tests and syntax checks. FAIL - four accounting inconsistency probes.
risks: Filesystem suites and CPU training self-test skipped because scratch writes are denied; no GPU/Slurm execution; clean-development doctor failed lifecycle ownership validation, no repairs attempted.
questions_for_g: none
### Findings
1. closed - kit/20261111-airr-v4/checks/usage.py:252 - A later RUNNING start now fails until a terminal record closes that start; both declared-attempt variants reject.
11. closed - kit/20261111-airr-v4/checks/usage.py:112 - Unknown, malformed, missing and zero GPU allocations reject; explicit CPU allocation passes and typed GPU allocation counts correctly.
12. closed - kit/20261111-airr-v4/bin/kitcheck.py:434 - Both missing-directory probes return 1; unreadable-directory validation rejects.
13. closed - kit/20261111-airr-v4/heldout/twin_definition.py:222 - Fresh-reference repetitions preserve both interfaces' keys; recount remains unchanged with zero conflicts.
14. new [blocking GPU work] - kit/20261111-airr-v4/checks/usage.py:239 - Open rows discard elapsed/allocation observations. For the same start, RUNNING evidence of 8 GPU-hours followed by a terminal row reporting 4 passes a claim of 4. Allocation regression also passes. Neither gap is named in kit documents.
15. new [blocking GPU work] - kit/20261111-airr-v4/checks/usage.py:133 - Generic GPU count overrides contradictory typed counts. Generic 1 plus typed 4 passes as 1; generic 0 plus typed 4 with a CPU declaration passes as zero. Complete manifests verify. This gap is undocumented.
Limit [non-blocking] - kit/20261111-airr-v4/bin/README.md:39 names omitted-export trust, scheduler reconciliation and same-cluster timestamps.
Limit [non-blocking] - kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md:12 and :50 name exact-value policies and representation distinctions; relaxing empty/absent sections adds no twins in the frozen pack. Future labelled-row soundness checks are required by kit/20261111-airr-v4/heldout/twin_definition.py:29.
Limit [non-blocking, documentation gap] - kit/20261111-airr-v4/trainer/score_checkpoints.py:398 retains resolved paths in selection.json. The authors' private-or-strip mitigation is absent from the kit's own documents.

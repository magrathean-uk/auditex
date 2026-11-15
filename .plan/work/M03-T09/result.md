## RESULT M03-T09
status: done
summary: Repaired exemplars 08 and 09 to name Global; added the pilot-2-pass rejection test; refreshed prompt, provenance and manifests. No commits.
changes: AIRR kit checks/{dataround.py,SHA256SUMS,tests/test_check_dataround_pilot3.py}; runs/data-round/pilot-3/{exemplars.jsonl,teacher_prompt.py,exemplars-provenance.md,SHA256SUMS}; .plan/work/M03-T09/ evidence and result.
verification: Requested hostload-gated dataround suite PASS: 76 tests, exit 0. All eleven frozen checks PASS on all nine references. Preparation/result verification, attribution probes and manifest checks PASS.
risks: kit-check selftest not run: no Python with torch; nothing installed. Cross-vendor recheck remains with the orchestrator.
questions_for_g: none
### Findings
pilot-3-prompt: ready
exemplars: Four added sentences name Global; seven other rows unchanged.
heldout-reads: 0

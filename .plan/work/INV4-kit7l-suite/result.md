## RESULT INV4-kit7l-suite
status: done
summary: Inventory of the dummy-tenant kit's offline suite and round gate is complete; no suite, PowerShell, sign-in or tenant contact was run.
summary: The last full-run numbers on record (orch-numbers.txt) were all green, but the record later shows a full run exiting 7; the outcome of the last run (chk-r7l5) is not in the record.
summary: check-suite.sh exits 0 whatever its steps return, so its exit code is not a pass/fail signal.
summary: The tooling docs describe round 7k while the kit has moved on to 7l5 and 7m.
summary: The SessionStart hook asked for `clean-development doctor`; I did not run it because the brief forbids it. G to decide.
changes: none (notes written to .plan/work/INV4-kit7l-suite/notes.md)
verification: shasum -a 256 of kit/20261027-ship-plan/pwsh-guarded matches pwsh-guarded.sha256 (pass); ls of tooling, kit, mock-harness and tools folders (pass); no suite, no PowerShell run
risks: check-suite.sh's own exit status is 0 regardless of failures (check-suite.sh:15); latest full-run outcome unknown from this slice; hard-coded the external volume paths in the scripts
questions_for_g: Should `clean-development doctor` be run for the SessionStart hook's request? It is diagnosis only, and the brief forbids it.
### Findings
1. exists
- kit/20261027-ship-plan/tooling/check-suite.sh (15 lines): the offline suite driver.
- kit/20261027-ship-plan/tooling/make-briefs.py (37 lines): builds lens briefs from env vars; K path hard-coded at line 10.
- kit/20261027-ship-plan/tooling/codex-review-prompt.tmpl.md (30 lines): the gate-review prompt, worded as review 16; placeholders `{ORCH}` (line 21) and `{GUARD}` (line 28).
- kit/20261027-ship-plan/tooling/brief-common-template.md, brief-worker-a-example.md, brief-worker-b-example.md: round-7k worker briefs.
- kit/20261027-ship-plan/tooling/README.md (21 lines), lens-items-{behaviour,closure,live,oracle}.md, round.txt, known.txt, orch-numbers.txt, q.py, learn-md/ (121 files).
- kit/20261027-ship-plan/pwsh-guarded (475 B, read-only) and pwsh-guarded.sha256.
- kit/20261031-dummy-tenant/populate/: 00-identity through 99-rollback, _common.ps1, _schema.ps1, 90-verify.ps1, README.md (327 lines).
- kit/20261031-dummy-tenant/compare.py (2594 lines); tools/test_compare.py (4014); tools/Test-KitConstructs.ps1 (740); tools/Test-ShapeLint.ps1 (582); tools/derive_rego_dependencies.py (555, `--check` at line 536); tools/pins.json.
- kit/20261031-dummy-tenant/tools/mock-harness/: Run-Mock.ps1 (~70 KB), MockTenant.ps1, OpaExport.ps1, OpaCompare.ps1, about 40 Cases-Round7*.ps1 files.
- kit/20261031-dummy-tenant/tools/scubagear-opa-smoke/Test-ScubaOpaPath.ps1.
- Absent: no top-level README.md (the brief's "README" is populate/README.md); no tests/ or mock/ folder.
2. works
- shasum -a 256 of pwsh-guarded = 24a5555182ab6646c78b60f1d54f8e11cac1cebbe7a48c0a1689e484b250aa24, equal to pwsh-guarded.sha256:1 (command run).
- pwsh-guarded:6-9 sets XDG_DATA_HOME=/var/empty, PSModulePath="", DT_NO_SIGNIN_GUARD=1, then `exec pwsh -NoProfile "$@"` (read).
- Test-KitConstructs.ps1:209 allowlists the guard path as a call-target (Grep).
- DT_NO_SIGNIN_GUARD is set by the wrapper but read by no tools/ or populate/ file; Grep hits only review logs (inferred unread).
- Run-Mock.ps1:4: exit code = number of failed assertions (read).
- Run-Mock.ps1:154-169 (-OnlyR7 branch) and 594-618 (default path) load the Cases files (Grep).
- Last full-run numbers on record, orch-numbers.txt:1 (round unnamed, inferred 7k): test_compare 269/269; Run-Mock -Opa rc 0 "all assertions passed" (R7 + R7b 463/463); verify 95 MATCH / 6 FROZEN / 1 UNKNOWN; OPA 99 of 99 compared rows agree, 1 fail-closed, 1 reporter Error (PP 3.1), 1 skipped; W5 373/373 over 105 states; W6b 114/114; rollback PLAN 117 then CHANGED 117; Test-ScubaOpaPath rc 0 (30 OK); Test-KitConstructs rc 0; shape lint rc 0 (241 allowlisted findings). Not re-run.
- Later counts in the record: Python 321/321 (tree/auditex-kit-status.md:30), 298 (:43) (inferred growth).
3. broken
- check-suite.sh:15 is the last statement; the script's exit status is tail's (0) regardless of failures.
- check-suite.sh:2 falls back to $TMPDIR for logs when LOGDIR is unset (tooling/README.md:4 says $TMPDIR is deleted at session end).
- check-suite.sh:10 `find / -maxdepth 4 -name .scubagear` walks the root filesystem each run (inferred slow).
- check-suite.sh:7, 9 and 12 hard-code the OPA path, the ScubaGear checkout and the kit path.
- tree/main-status.md:51: a later full Run-Mock "exited 7 (7 real assertion failures)" on 5 Nov (chk-r7l4).
- No missing file among the targets check-suite.sh names (checked against the listings).
4. dead candidates
- Round-7k briefs (tooling/brief-common-template.md, brief-worker-a/b-example.md): tooling/README.md:16-17 says "all to be replaced".
- kit/20261031-dummy-tenant/run/kit/protocol/before/tools/... and protocol/repair-r2-before/tools/...: duplicate tool copies (Grep); not on the Run-Mock path (inferred).
- kit/20261031-dummy-tenant/tools/mock-harness/Cases-Round7l5-W20a.ps1: referenced only at Cases-Round7l4-W19a.ps1:340 (inferred loaded through the chain).
- tooling/known.txt: holds "a session deadline" (tooling/README.md:12).
5. contradictions
- tooling/README.md:4 says never put job output in $TMPDIR; check-suite.sh:2 does.
- tooling/README.md:1 "state after round 7k" versus the 7l5/7m record (tree/auditex-kit-status.md:43-63) and Run-Mock.ps1:594-618 loading up to Cases-Round7l4-W19b.
- brief-common-template.md:32 tells workers to "check every few minutes, up to 30 minutes": polling, which the operator's AGENTS.md forbids ("No polling loops").
6. open questions
- Outcome of chk-r7l5 / chk-r7l6 (7 Nov): read the check-mock.log in the job outdir named in tree/auditex-kit-status.md (outside this slice).
- Round label of orch-numbers.txt: check tooling/round.txt or the run folder name.
- Whether the W-a chain (Cases-Round7b.ps1:589-599 to W20a) runs on the default path: read the context of Cases-Round7l4-W19a.ps1:340.
- Which code reads DT_NO_SIGNIN_GUARD: read Test-KitConstructs.ps1 guard units (about lines 200-300) and populate/_common.ps1.
- Whether kit/20261031-dummy-tenant/run/kit/protocol/ is meant to stay in the live kit.
- Scripts hard-code the external volume path; this worktree uses ~/dev/machine/work/auditex-data/... (assumed a link, not verified).
- Neighbouring area: tree/ (orchestrator relay, subhost.sh) is outside this slice.

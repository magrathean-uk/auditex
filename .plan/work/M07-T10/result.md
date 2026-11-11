## RESULT M07-T10
status: done
summary: Built kit/20261111-kit-7q/dt-r7q from a copy of dt-r7l6-ro, then brought over items 1, 2, 3 and 5 of round 7p file by file from dt-r7p-ro2 (whole files or selected hunks). Nothing of item 4 remains.
Added the README replication sentence. Replaced workstation paths in changed files where they were only text; working paths are kept and listed.
Wrote kit/20261111-kit-7q/ROUND-7Q.md: both file tables, the _common.ps1 function analysis, case lists and checks. Froze dt-r7q-ro with MANIFEST.sha256; copied check-suite-7l.sh and pwsh-guarded beside them unchanged.
Evidence: .plan/work/M07-T10/notes.md; logs under kit/20261111-kit-7q (quick-1, quick-2, runs/).
changes: kit/20261111-kit-7q/ (dt-r7q, dt-r7q-ro, MANIFEST.sha256, ROUND-7Q.md, check-suite-7l.sh, pwsh-guarded, runner/, build/, old-proof/, quick-1/, quick-2/, runs/); .plan/work/M07-T10/notes.md; repository unchanged
verification: driver --quick on dt-r7q: pass (7 steps; test_compare 332 tests OK; shape lint 0 not allowlisted, 0 stale; constructs 0 findings, 0 stale, no wildcard); driver --quick with --snapshot dt-r7q-ro and --manifest: pass (kit equals snapshot, 366 of 366); kept round cases on dt-r7q: 28 of 28 pass, protocol ok; same cases on old-proof (dt-r7l6-ro plus the 7q harness): 23 fail, 4 controls pass, W7p-r1-dehydrated-timeout-keeps-intent passes (in 7p it failed against the pre-repair copy, not the baseline); round-7p comparison test: OK on dt-r7q, FAILED on old compare.py; regression with 7p's 249-id filter: 140 of 144 pass, 4 Get-JournalEntries runner artefacts (same ids as 7p); 7b regression: 15 of 15 run pass, stopped for time; W14b-L7 check on its own: pass; dt-r7l6-ro, dt-r7p-ro and dt-r7p-ro2 match their manifests; live kit unchanged
risks: Workstation paths remain in changed files where they are working paths: the guard path in the W11a, W12a, W13a and W14a cases, OPA and Rego paths in test_compare.py, constructs entries tied to the unchanged Test-ScubaOpaPath.ps1, and README line 54, which baseline case W10a checks verbatim (all also in the baseline); The 7b regression was partial (15 cases), and runs used 7p's development runner, not the full mock run; Re-reviewed constructs hash for 99-rollback.ps1 (item 2 lines only) needs the gate review's confirmation
questions_for_g: none
### Findings
quick-checks: pass
files-differing-from-baseline: 23
files-differing-from-7p: 20
session-code-equals-baseline: yes - populate/05 to 90 scripts, MockTenant.ps1, Run-Mock.ps1 and shape-lint-allowlist.txt are byte-identical; 99-rollback.ps1 differs only in 4 item-2 lines; _common.ps1 differs only in Test-DtDehydratedRefusal, Import-DtTeamsModule, Read-DtConfig, Get-DtCreateFailureKind, Initialize-DtIntents, Invoke-DtChange, Test-DtLicencePlans and Connect-DtTeams (only its two loader lines replaced by the Import-DtTeamsModule call); no connect, disconnect, session or guard function changed apart from the Teams module loader
cases-kept: 28
cases-removed: 17
shared-names-grep: 0 (43 names that round 7p introduced for item 4; the bare prefix DtShared matches only the baseline's DtSharedSessionCommands, which appears identically in dt-r7l6-ro)
frozen: kit/20261111-kit-7q/dt-r7q-ro c3e3e85acdfd 366
full-suite-command: cd 20261111-kit-7q && bash check-suite-7l.sh --snapshot dt-r7q-ro --manifest MANIFEST.sha256 --repo <auditex checkout> dt-r7q full-1 <OPA 1.20.2 binary> <ScubaGear 2446ad7 checkout>

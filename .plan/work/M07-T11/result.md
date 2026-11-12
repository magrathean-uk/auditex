## RESULT M07-T11
status: partial
summary: Repair after confirmation done in dt-r7r and refrozen. Session fields count only when Ok and not blank, and a missing, null or blank required field on either side refuses. Any exception inside Set-DtGraphRequestContext now sets the sticky refusal flag first. A GRAPH SESSION REFUSED raised after the send is ambiguous.
8 new mock cases, each failing on the 96ad252db64c code where a defect existed. Docs now promise only what a MaxRetry mismatch actually does, and README notes that a silent sign-in can fall back to a browser.
verify deferred: heavy slot busy. The filtered driver mock step was deferred twice (hostload exit 75) and never ran. It is ready as kit/20261111-kit-7r/runs/drv-filtered-2/run.sh.
changes: none in the repository. Kit: dt-r7r and dt-r7r-ro (populate/_common.ps1, LIMITS.md, TRIAL-FACTS.md, populate/README.md, tools/mock-harness/MockTenant.ps1, tools/mock-harness/Cases-Round7r.ps1), kit/20261111-kit-7r/MANIFEST.sha256, kit/20261111-kit-7r/ROUND-7R.md, proof copies proof-7r-ro and proof-7q, runs/repair-*, quick-3, quick-4. Plan: .plan/work/M07-T11/evidence.md, progress.md
verification: parse 90 files 0 errors: pass. New cases on dt-r7r (runs/repair-new-2): 8/8 pass. On the 96ad252db64c code: 6 fail; auth-type and added-scopes pass, as they cover gaps where no defect existed. On 7q: 8/8 fail. Kept 7q plus all 23 7r cases (runs/repair-kept-1): 51/51 pass, protocol 61/43/43. Driver quick steps on dt-r7r (quick-3) and against snapshot, manifest and repo worktree (quick-4): pass, 7 steps; shape lint 271 all allowlisted, 0 stale; constructs 0 findings. All 32 construct reviewed-unit hashes are identical before and after. Hygiene of the 57 added lines: clean. dt-r7q-ro, dt-r7l6-ro, dt-r7p-ro and dt-r7p-ro2 match their manifests; driver, guard and runner equal 7q's; live kit untouched. Filtered driver mock step: NOT RUN (slot deferred twice). Full mock run: not started (brief).
risks: 1) The filtered driver step and the full offline suite are still to run on dt-r7r-ro. 2) Retries on non-create writes stay at the SDK default of 3 (inherited, DEC-014; listed in ROUND-7R.md). 3) A browser sign-in as the same operator on reconnect is still not detected.
questions_for_g: none
### Findings
quick-checks: pass quick-4 (parse, py_compile, test_compare, shape_lint, constructs, rego_dependencies, hygiene against dt-r7r-ro and MANIFEST.sha256)
design: a One helper, Set-DtGraphRequestContext, re-runs the same Connect-MgGraph after every Set and proves the session and MaxRetry; any refusal or exception inside it sets the sticky refusal flag, which blocks every later Graph request in the run.
set-request-context-call-sites: 1 all through the helper yes
new-cases: 23 (15 earlier, 8 in this repair)
new-cases-fail-on-7q: 22 (the harness self-test cannot fail on kit code)
not-provable-offline: a reconnect never opening a browser while the auth record exists; the cause of the client reset inside the SDK; the auth-record path on operating systems other than macOS; MaxRetry 0 on the wire
frozen: kit/20261111-kit-7r/dt-r7r-ro 510f26e348fd 367
full-suite-command: cd 20261111-kit-7r && bash check-suite-7l.sh --mock-timeout 28800 --snapshot dt-r7r-ro --manifest MANIFEST.sha256 --repo <auditex checkout> dt-r7r full-1 <OPA 1.20.2 binary> <ScubaGear 2446ad7 checkout>
item 1: closed kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:1966 and :1975-1984 W7r-unit-blank-session-field-refused W7r-unit-null-session-field-refused W7r-blank-or-null-session-field-on-both-sides-refused
item 2: closed kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:2021-2047 (sets the flag at :2045) W7r-context-read-throws-after-set-before-create-is-sticky W7r-context-read-throws-after-set-in-restore-is-sticky
item 3: closed kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:1239 W7r-refusal-after-send-with-refusal-text-is-ambiguous
item 4: closed kit/20261111-kit-7r/dt-r7r-ro/tools/mock-harness/Cases-Round7r.ps1:230-394 (knobs in MockTenant.ps1:257-260) all eight cases above plus W7r-reconnect-other-auth-type-refused W7r-reconnect-added-scopes-refused
item 5: closed kit/20261111-kit-7r/dt-r7r-ro/LIMITS.md:224, TRIAL-FACTS.md:11, populate/README.md:96 W7r-docs-round-7r (still passes; the wording was checked by hand against the helper's read-back in _common.ps1:2038-2042)

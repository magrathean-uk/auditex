---
id: M07
name: dummy-tenant-kit
weight: 12
status: planned
---
# M07 dummy-tenant-kit
The dummy-tenant kit and the trial-tenant work G put ahead of everything (DEC-006), scoped by DEC-008, DEC-010 and DEC-014. The kit lives in the development kit, outside this repository (`$DT_KIT`, the dummy-tenant-kit row of ARCHITECTURE.md); its tasks write only `.plan/work/<id>/result.md` here, and every predicate below works from recorded evidence: manifest hashes of frozen kit copies, the suite driver's logs and the review records. Live steps (phase D and the rollback) are run by the tenant chat on G's sign-ins, one fresh sign-in per script and service (DEC-010); this plan records their gates and findings and no task of this plan contacts a tenant. Rounds 7m, 7n and 7o and the shared sign-in opener stay out of scope. The population scripts the tenant chat uses were reviewed separately (`REV-M07-populator`, approve on the last diff) and are not kit source.

## Goal
The trial tenant is seeded only from a kit round that passed its tier A gate (confirmation by both providers on the frozen copy and the full offline suite), the tenant chat runs phase D from exactly that frozen copy, the live kit folder holds the accepted round with the previous state kept, phase D's gates and findings are recorded here, and the trial tenant is rolled back before the trial ends.

## Definition of Done
- [x] The accepted kit 7l6 is frozen read-only with its manifest (365 files, sha256 109679e6...), and the full-suite driver is repaired and self-tested: `grep -qx 'status: done' .plan/work/M07-T01/result.md && grep -q 'dt-r7l6-ro (365 files) with MANIFEST.sha256' .plan/work/M07-T01/result.md && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7l-gate/MANIFEST.sha256" | cut -d' ' -f1)" = 109679e67da549ddc6c72bd751f1217fb146f31962a5bd5e2392c80958b1cb8c && (cd "$DT_KIT/20261111-kit-7l-gate/dt-r7l6-ro" && shasum -a 256 -c --quiet ../MANIFEST.sha256)` (evidence: .plan/work/M07-T01/result.md and the DEC-006 amendment 1 manifest hash, command passed)
- [x] The trial tenant's read-only live facts (licences, Exchange, Teams module, sign-ins, outside objects, population, replication) are checked against the kit: `for t in 03 04 05 07 08 09; do grep -qx 'status: done' .plan/work/M07-T$t/result.md || exit 1; done` (evidence: .plan/work/M07-T03/result.md to .plan/work/M07-T09/result.md, command passed)
- [x] Round 7q, the DEC-008 change round without the shared sign-in (DEC-010), is confirmed ship by both providers on its frozen copy and passes the full offline suite 9 of 9 on that copy: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7q\/dt-r7q-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T10/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7q/MANIFEST.sha256" | cut -c1-12)" = "$h" && (cd "$DT_KIT/20261111-kit-7q/dt-r7q-ro" && shasum -a 256 -c --quiet ../MANIFEST.sha256) && for r in codex opus; do f=.plan/work/REV-M07-T10-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done && grep -q -- '--snapshot dt-r7q-ro --manifest MANIFEST.sha256' "$DT_KIT/20261111-kit-7q/full-1-job/cmd.txt" && grep -qx 'OVERALL: PASS (9 steps)' "$DT_KIT/20261111-kit-7q/full-1-job/log.txt"` (evidence: .plan/work/REV-M07-T10-codex/result.md, .plan/work/REV-M07-T10-opus/result.md and the 7q full-suite log, command passed)
- [x] Round 7r (DEC-014) is frozen with its manifest and confirmed ship by both providers, diff-scoped against 7q, on that frozen copy: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7r\/dt-r7r-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T11/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7r/MANIFEST.sha256" | cut -c1-12)" = "$h" && (cd "$DT_KIT/20261111-kit-7r/dt-r7r-ro" && shasum -a 256 -c --quiet ../MANIFEST.sha256) && for r in codex opus; do f=.plan/work/REV-M07-T11-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done` (evidence: REV-M07-T11-codex and REV-M07-T11-opus, both ship at 510f26e348fd on 12 Nov 2026; command exit 0)
- [x] The full offline suite passes 9 of 9 on the confirmed 7r frozen copy: `grep -qx 'full-suite: pass 9 of 9' .plan/work/M07-T13/result.md && grep -q -- '--snapshot dt-r7r-ro --manifest MANIFEST.sha256' "$DT_KIT/20261111-kit-7r/full-1-job/cmd.txt" && grep -qx 'OVERALL: PASS (9 steps)' "$DT_KIT/20261111-kit-7r/full-1-job/log.txt" && test "$DT_KIT/20261111-kit-7r/full-1-job/log.txt" -nt "$DT_KIT/20261111-kit-7r/MANIFEST.sha256"` (evidence: .plan/work/M07-T13/result.md, OVERALL PASS 9 steps, mock 580 throws of 580 expected, 12 Nov 2026; command exit 0)
- [ ] Round 7s (DEC-054, DEC-058) is frozen with its manifest, confirmed ship by both providers, diff-scoped against 7r, on that frozen copy, and passes the full offline suite 9 of 9 on it: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T18/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7s/MANIFEST.sha256" | cut -c1-12)" = "$h" && (cd "$DT_KIT/20261111-kit-7s/dt-r7s-ro" && shasum -a 256 -c --quiet ../MANIFEST.sha256) && for r in codex opus; do f=.plan/work/REV-M07-T18-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done && grep -qx 'full-suite: pass 9 of 9' .plan/work/M07-T20/result.md && grep -q -- '--snapshot dt-r7s-ro --manifest MANIFEST.sha256' "$DT_KIT/20261111-kit-7s/full-1-job/cmd.txt" && grep -qx 'OVERALL: PASS (9 steps)' "$DT_KIT/20261111-kit-7s/full-1-job/log.txt" && test "$DT_KIT/20261111-kit-7s/full-1-job/log.txt" -nt "$DT_KIT/20261111-kit-7s/MANIFEST.sha256"`
- [ ] The tenant chat has the accepted 7s folder and its manifest hash, and the live kit folder holds round 7s with the previous state kept: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T18/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7s/MANIFEST.sha256" | cut -c1-12)" = "$h" && grep -qx "handover: kit/20261111-kit-7s/dt-r7s-ro $h" .plan/work/M07-T21/result.md && (cd "$DT_KIT/20261031-dummy-tenant" && shasum -a 256 -c --quiet "$DT_KIT/20261111-kit-7s/MANIFEST.sha256") && p=$(sed -n 's/^previous-state: kit\/\([A-Za-z0-9._-]*\)$/\1/p' .plan/work/M07-T15/result.md) && test -n "$p" && (cd "$DT_KIT/$p" && shasum -a 256 -c --quiet "$DT_KIT/20261111-kit-7l-gate/MANIFEST.sha256")`
- [ ] The lab Fabric operator app (DEC-066) is applied before 60-powerbi, phase D on the trial tenant ran from the handed-over 7s copy only, its gates and findings are recorded, and no intent is left open: `h=$(sed -n 's/^handover: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\)$/\1/p' .plan/work/M07-T21/result.md) && test -n "$h" && grep -qx 'applied: complete' .plan/work/M07-T22/result.md && grep -qx "phase-d-kit: $h" .plan/work/M07-T16/result.md && grep -qx 'phase-d: complete' .plan/work/M07-T16/result.md && grep -qx 'open-intents: 0' .plan/work/M07-T16/result.md && grep -qx 'writes-outside-kit: 0' .plan/work/M07-T16/result.md`
- [ ] The trial tenant is rolled back before the trial ends, with every kit object removed or a G-accepted manual stop: `grep -qx 'rollback: complete' .plan/work/M07-T17/result.md && grep -qx 'open-intents: 0' .plan/work/M07-T17/result.md && grep -qE '^manual-stops-unaccepted: 0$' .plan/work/M07-T17/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M07-T01 | Freeze the kit at round 7l6 and repair the offline suite driver | sol | M | risk:low | done |
| M07-T02 | Confirmation run of the full offline suite on 7l6 | orchestrator | S | risk:low | dropped |
| M07-T03 | Check the accepted kit against the day-one licence facts | sol | S | risk:low | done |
| M07-T04 | Check the accepted kit against the Exchange, Teams-module and sign-in facts | sol | S | risk:low | done |
| M07-T05 | Find the cause of the Teams sign-in blocker on macOS | sol | S | risk:low | done |
| M07-T07 | Check the kit against objects added outside the kit | sol | S | risk:low | done |
| M07-T08 | Assess the impact of tenant content on the kit's run and expectations | sol | S | risk:low | done |
| M07-T09 | Assess two live licence facts (analysis only) | terra | S | risk:low | done |
| M07-T06 | Kit round 7p from the live facts (DEC-008) | sol | L | risk:high | done |
| M07-T10 | Kit round 7q: round 7p without the shared sign-in (DEC-010) | sol | M | risk:high | done |
| M07-T11 | Kit round 7r: the Graph request-context defect (DEC-014) | sol | M | risk:high | done |
| M07-T12 | Confirm round 7r by both providers, diff-scoped | codex, sol | S | gate risk:high | done |
| M07-T13 | Run the full offline suite on the confirmed round 7r | orchestrator | S | risk:low | done |
| M07-T14 | Hand the accepted folder and manifest hash to the tenant chat | orchestrator | S | risk:low | done |
| M07-T18 | Kit round 7s: the Graph 404 shape, compare.py and the dry-run findings (DEC-054, DEC-058) | sol | M | risk:high | done |
| M07-T19 | Confirm round 7s by both providers, diff-scoped | codex, sol | S | gate risk:high | todo |
| M07-T20 | Run the full offline suite on the confirmed round 7s | orchestrator | S | risk:low | todo |
| M07-T21 | Hand the 7s folder and manifest hash to the tenant chat | orchestrator | S | risk:low | todo |
| M07-T22 | The lab Fabric operator app for phase D's Power BI step (DEC-066) | sol | M | gate risk:high | todo |
| M07-T15 | Bring the live kit folder to the accepted round, previous state kept | terra | S | risk:high | todo |
| M07-T16 | Record phase D on the trial tenant (run by the tenant chat) | orchestrator | M | risk:high | todo |
| M07-T17 | Record the rollback of the trial tenant before the trial ends | orchestrator | M | risk:high | todo |

## Acceptance criteria
### M07-T01 Freeze the kit at round 7l6 and repair the offline suite driver
- The live kit is frozen as `dt-r7l6` and a read-only twin `dt-r7l6-ro` (365 files) with `MANIFEST.sha256`; every file differing from 7l5 is explained; the driver `check-suite-7l.sh` checks the guard's sha256, one log and summary line per step and a final PASS or FAIL line, and its self-test passes 42 of 42.
- verify: `grep -qx 'status: done' .plan/work/M07-T01/result.md && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7l-gate/MANIFEST.sha256" | cut -d' ' -f1)" = 109679e67da549ddc6c72bd751f1217fb146f31962a5bd5e2392c80958b1cb8c`
- files: `kit/20261111-kit-7l-gate/**` in the development kit; `.plan/work/M07-T01/result.md`

### M07-T02 Confirmation run of the full offline suite on 7l6
- Dropped: the one run through the repaired driver ended `OVERALL: FAIL (2 of 9 steps failed)` (the mock step hit its alarm, and hygiene saw the repository change during the run), and DEC-008 replaced the 7l6 confirmation with a change round before a fix was rerun; the 7q full suite (DoD item 3) is the passing run. No result file was written.
- verify: `grep -q '^OVERALL: FAIL' "$DT_KIT/20261111-kit-7l-gate/full-1-job/log.txt"`
- files: `kit/20261111-kit-7l-gate/full-1/**` and `kit/20261111-kit-7l-gate/full-1-job/**` in the development kit

### M07-T03 Check the accepted kit against the day-one licence facts
- Read-only analysis: which trial licences the kit needs; finds the Agent 365 gate as the day-one blocker (input to DEC-008 item 1).
- verify: `grep -qx 'status: done' .plan/work/M07-T03/result.md`
- files: `.plan/work/M07-T03/result.md`

### M07-T04 Check the accepted kit against the Exchange, Teams-module and sign-in facts
- Read-only analysis with kit file and line references; names what cannot be proven offline (dehydrated-organisation refusals, silent re-sign-in inside one process).
- verify: `grep -qx 'status: done' .plan/work/M07-T04/result.md`
- files: `.plan/work/M07-T04/result.md`

### M07-T05 Find the cause of the Teams sign-in blocker on macOS
- Read-only: the MicrosoftTeams module from 7.9.0 passes a Windows-only console callback to MSAL; 7.8.0 is the stated workaround (input to DEC-008's version setting).
- verify: `grep -qx 'status: done' .plan/work/M07-T05/result.md`
- files: `.plan/work/M07-T05/result.md`

### M07-T07 Check the kit against objects added outside the kit
- Read-only: none of the four additions trips a kit guard or changes an expected verdict; operator checks that matter are listed.
- verify: `grep -qx 'status: done' .plan/work/M07-T07/result.md`
- files: `.plan/work/M07-T07/result.md`

### M07-T08 Assess the impact of tenant content on the kit's run and expectations
- Read-only: no verify row, expectation, comparison check or pinned-rule input depends on content or on population counts; the rows that can move are named.
- verify: `grep -qx 'status: done' .plan/work/M07-T08/result.md`
- files: `.plan/work/M07-T08/result.md`

### M07-T09 Assess two live licence facts (analysis only)
- Read-only: neither fact can make the kit record a wrong state; the one costly case (a role create refused just after a user create) is named.
- verify: `grep -qx 'status: done' .plan/work/M07-T09/result.md`
- files: `.plan/work/M07-T09/result.md`

### M07-T06 Kit round 7p from the live facts (DEC-008)
- The four DEC-008 items plus the shared sign-in, one repair round, frozen as `dt-r7p-ro2`; the gate split (Opus ship, Codex do-not-ship on session ownership) led to DEC-010, which cut the shared sign-in. Round 7p is not an accepted round.
- verify: `grep -qx 'status: done' .plan/work/M07-T06/result.md && grep -q 'verdict: do-not-ship' .plan/work/REV-M07-T06-codex/result.md`
- files: `kit/20261111-kit-7p/**` in the development kit; `.plan/work/M07-T06/result.md`

### M07-T10 Kit round 7q: round 7p without the shared sign-in (DEC-010)
- Built from `dt-r7l6-ro` plus 7p items 1, 2, 3 and 5; all sign-in and session code equals the baseline apart from the Teams module loader; frozen as `dt-r7q-ro` (366 files); confirmed ship by both providers (`REV-M07-T10-codex`, `REV-M07-T10-opus`) and passed the full offline suite 9 of 9. Stopped on its first live dry run by the Graph request-context defect (DEC-014).
- verify: `grep -qx 'frozen: kit/20261111-kit-7q/dt-r7q-ro c3e3e85acdfd 366' .plan/work/M07-T10/result.md`
- files: `kit/20261111-kit-7q/**` in the development kit; `.plan/work/M07-T10/result.md`

### M07-T11 Kit round 7r: the Graph request-context defect (DEC-014)
- Every Graph request-context change goes through one helper that reconnects and proves the same account, tenant, auth type and scopes, or the retry count is set once before sign-in (the choice justified in `ROUND-7R.md`); no bare `Set-MgRequestContext` outside the helper, enforced by the construct check; a mock model of the SDK behaviour with new cases that fail on 7q where possible; all 7q cases still pass; documents state the silent Graph sign-in from the SDK's auth record. Nothing else changes (no session sharing, no Exchange, Security and Compliance or Teams connect change, no expected-verdict change).
- Frozen as `dt-r7r-ro` with `MANIFEST.sha256`; writes `frozen: kit/20261111-kit-7r/dt-r7r-ro <12 hex> <file count>` and `full-suite-command: <one line>` under `### Findings`. Status taken from its result file; none exists yet.
- verify: `grep -qx 'status: done' .plan/work/M07-T11/result.md && h=$(sed -n 's/^frozen: kit\/20261111-kit-7r\/dt-r7r-ro \([0-9a-f]\{12\}\) [0-9][0-9]*$/\1/p' .plan/work/M07-T11/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7r/MANIFEST.sha256" | cut -c1-12)" = "$h"`
- files: `kit/20261111-kit-7r/**` in the development kit; `.plan/work/M07-T11/result.md`

### M07-T12 Confirm round 7r by both providers, diff-scoped
- Precondition: M07-T11 done. Tier A: one Codex and one Opus reviewer, each in a fresh context on the frozen `dt-r7r-ro`, manifest checked first, the diff against `dt-r7q-ro` only; each writes `verdict: ship` or `verdict: do-not-ship` and `reviewed: <12 hex of the manifest sha256>, manifest check pass`.
- Checks that the two wording advisories of the 7q confirmation (BACKLOG) are cleared; if not, they stay in BACKLOG and do not block.
- A do-not-ship gets one repair round by the author and one re-confirmation (review loop limits), then the question goes to G.
- verify: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7r\/dt-r7r-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T11/result.md) && test -n "$h" && for r in codex opus; do f=.plan/work/REV-M07-T11-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done`
- files: `.plan/work/REV-M07-T11-codex/result.md`, `.plan/work/REV-M07-T11-opus/result.md` (read-only on the kit)

### M07-T13 Run the full offline suite on the confirmed round 7r
- Precondition: M07-T12 done. The orchestrator starts the `full-suite-command` of M07-T11 as the one heavy job, with output in `kit/20261111-kit-7r/full-1` and `full-1-job`, against `--snapshot dt-r7r-ro --manifest MANIFEST.sha256`; the mock step's throw count equals its expected count.
- Writes `full-suite: pass 9 of 9` (or `full-suite: fail <steps>`) under `### Findings`; a failure goes back to the M07-T11 author as one repair, then M07-T12 confirms again.
- verify: `grep -qx 'full-suite: pass 9 of 9' .plan/work/M07-T13/result.md && grep -qx 'OVERALL: PASS (9 steps)' "$DT_KIT/20261111-kit-7r/full-1-job/log.txt" && test "$DT_KIT/20261111-kit-7r/full-1-job/log.txt" -nt "$DT_KIT/20261111-kit-7r/MANIFEST.sha256"`
- files: `kit/20261111-kit-7r/full-1/**` and `kit/20261111-kit-7r/full-1-job/**` in the development kit; `.plan/work/M07-T13/result.md`

### M07-T14 Hand the accepted folder and manifest hash to the tenant chat
- Precondition: M07-T13 passed. The orchestrator gives the tenant chat the folder `kit/20261111-kit-7r/dt-r7r-ro` and the first 12 hex of its manifest sha256, with the DEC-010 sign-in rule (one fresh sign-in per script and service) and the trial facts the round recorded; nothing else is sent.
- Writes `handover: kit/20261111-kit-7r/dt-r7r-ro <12 hex>` under `### Findings`; the hash equals M07-T11's `frozen:` value.
- verify: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7r\/dt-r7r-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T11/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7r/MANIFEST.sha256" | cut -c1-12)" = "$h" && grep -qx "handover: kit/20261111-kit-7r/dt-r7r-ro $h" .plan/work/M07-T14/result.md`
- Superseded by M07-T21 (DEC-054): phase D stopped on 7r at its first look-up with no tenant write, and round 7s replaces this hand-over.
- files: `.plan/work/M07-T14/result.md`; the tenant chat's inbox note (outside the repository)

### M07-T18 Kit round 7s: the Graph 404 shape, compare.py and the dry-run findings (DEC-054, DEC-058)
- Part 1: `Test-DtNotFoundError` classifies through `Get-DtHttpStatus`, so a live Graph 404 with a null `StatusCode` and the status only in `Response.StatusCode` reads as not found; every status read off an exception uses the same value logic; the mock throws the live 404 shape (the old one on request); new cases fail on 7r where `ROUND-7S.md` claims. An un-gated candidate `dt-r7s-cand` with `CANDIDATE.sha256` went to the tenant chat's read-only dry runs (DEC-064).
- Part 2a: `compare.py` reads the released product's assessment (schema 2026-11-05, class `value_rule`), 2026-10-29 still accepted, any other schema refused. Part 2b: the dry runs found no kit defect; the Fabric operator client (F1) is recorded as README wording only and answered by M07-T22.
- Frozen as `dt-r7s-ro` (369 files) with `MANIFEST.sha256`; writes `frozen: kit/20261111-kit-7s/dt-r7s-ro <12 hex> <file count>` and `full-suite-command: <one line>` under `### Findings`.
- verify: `grep -qx 'status: done' .plan/work/M07-T18/result.md && h=$(sed -n 's/^frozen: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\) [0-9][0-9]*$/\1/p' .plan/work/M07-T18/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7s/MANIFEST.sha256" | cut -c1-12)" = "$h"`
- files: `kit/20261111-kit-7s/**` in the development kit; `.plan/work/M07-T18/result-1.md`, `result-2a.md`, `result.md`

### M07-T19 Confirm round 7s by both providers, diff-scoped
- Precondition: M07-T18 done. Tier A: one Codex and one Opus reviewer (`REV-M07-T18-codex`, `REV-M07-T18-opus`), each in a fresh context on the frozen `dt-r7s-ro`, manifest checked first, the diff against `dt-r7r-ro` only (brief `.plan/work/REV-M07-T18/brief-src.md`); each writes `verdict: ship` or `verdict: do-not-ship` and `reviewed: <12 hex of the manifest sha256>, manifest check pass`.
- A do-not-ship gets one repair round by the author and one re-confirmation (review loop limits), then the question goes to G.
- verify: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T18/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7s/MANIFEST.sha256" | cut -c1-12)" = "$h" && for r in codex opus; do f=.plan/work/REV-M07-T18-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done`
- files: `.plan/work/REV-M07-T18-codex/result.md`, `.plan/work/REV-M07-T18-opus/result.md` (read-only on the kit)

### M07-T20 Run the full offline suite on the confirmed round 7s
- Precondition: M07-T19 done. The orchestrator starts the `full-suite-command` of M07-T18 as the one heavy job, with output in `kit/20261111-kit-7s/full-1` and `full-1-job`, against `--snapshot dt-r7s-ro --manifest MANIFEST.sha256`; the mock step's throw count equals its expected count.
- Writes `full-suite: pass 9 of 9` (or `full-suite: fail <steps>`) under `### Findings`; a failure goes back to the M07-T18 author as one repair, then M07-T19 confirms again.
- verify: `grep -qx 'full-suite: pass 9 of 9' .plan/work/M07-T20/result.md && grep -q -- '--snapshot dt-r7s-ro --manifest MANIFEST.sha256' "$DT_KIT/20261111-kit-7s/full-1-job/cmd.txt" && grep -qx 'OVERALL: PASS (9 steps)' "$DT_KIT/20261111-kit-7s/full-1-job/log.txt" && test "$DT_KIT/20261111-kit-7s/full-1-job/log.txt" -nt "$DT_KIT/20261111-kit-7s/MANIFEST.sha256"`
- files: `kit/20261111-kit-7s/full-1/**` and `kit/20261111-kit-7s/full-1-job/**` in the development kit; `.plan/work/M07-T20/result.md`

### M07-T21 Hand the 7s folder and manifest hash to the tenant chat
- Precondition: M07-T20 passed. The orchestrator gives the tenant chat the folder `kit/20261111-kit-7s/dt-r7s-ro` and the first 12 hex of its manifest sha256, with the DEC-010 sign-in rule (one fresh sign-in per script and service), the trial facts the round recorded and the M07-T22 order (the Fabric app before 60-powerbi); nothing else is sent. Supersedes the 7r hand-over of M07-T14.
- Writes `handover: kit/20261111-kit-7s/dt-r7s-ro <12 hex>` under `### Findings`; the hash equals M07-T18's `frozen:` value.
- verify: `h=$(sed -n 's/^frozen: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\) .*$/\1/p' .plan/work/M07-T18/result.md) && test -n "$h" && test "$(shasum -a 256 "$DT_KIT/20261111-kit-7s/MANIFEST.sha256" | cut -c1-12)" = "$h" && grep -qx "handover: kit/20261111-kit-7s/dt-r7s-ro $h" .plan/work/M07-T21/result.md`
- files: `.plan/work/M07-T21/result.md`; the tenant chat's inbox note (outside the repository)

### M07-T22 The lab Fabric operator app for phase D's Power BI step (DEC-066)
- An operator script pair in the records folder (`dt-live`, outside the repository and the kit; author run `FAPP`, brief `.plan/work/FAPP/brief-src.md`): one public-client app registration with the kit's localhost redirect, the one delegated `Tenant.ReadWrite.All` on the Fabric service plus sign-in scopes, and admin consent for exactly that grant; no secret, certificate, application permission or directory role. Sign-in with no scopes and the Cancel line first, refusal before any write, a journal with intent before the first write, bounded read-backs and a journalled, ID-checked removal script. The author writes `frozen: <12 hex of the sha256 of its MANIFEST.sha256>` under `### Findings`.
- Tier A: one Codex and one Opus reviewer (`REV-FAPP-codex`, `REV-FAPP-opus`), each on the frozen copy, manifest checked first; each writes `verdict: ship` or `verdict: do-not-ship` and `reviewed: <12 hex>`; one repair round and one re-check, then the question goes to G.
- The tenant chat creates the app on G's sign-in from the frozen copy, before phase D's 60-powerbi, and appends its `OUT-OF-KIT-WRITES.md` row (app, service principal, the delegated grant and its consent, the undo) and its rollback line for M07-T17. M08 Part B's Power BI step may reuse it. Writes `fabric-app: <12 hex>`, `applied: complete`, `out-of-kit-row: written` and `rollback-line: written` under `### Findings` in `.plan/work/M07-T22/result.md`.
- verify: `h=$(sed -n 's/^frozen: \([0-9a-f]\{12\}\)$/\1/p' .plan/work/FAPP/result.md) && test -n "$h" && for r in codex opus; do f=.plan/work/REV-FAPP-$r/result.md; grep -qE '^[[:space:]]*(summary: )?verdict: ship$' "$f" && grep -qE "^[[:space:]]*(summary: )?reviewed: $h" "$f" || exit 1; done && grep -qx "fabric-app: $h" .plan/work/M07-T22/result.md && grep -qx 'applied: complete' .plan/work/M07-T22/result.md && grep -qx 'out-of-kit-row: written' .plan/work/M07-T22/result.md && grep -qx 'rollback-line: written' .plan/work/M07-T22/result.md`
- files: the Fabric app scripts, `FABRIC-APP-RECORD.md`, their `MANIFEST.sha256`, journal and `OUT-OF-KIT-WRITES.md` row in the records folder; `.plan/work/FAPP/result.md`, `.plan/work/REV-FAPP-codex/result.md`, `.plan/work/REV-FAPP-opus/result.md`, `.plan/work/M07-T22/result.md`

### M07-T15 Bring the live kit folder to the accepted round, previous state kept
- Precondition: M07-T21 done, and the tenant chat confirms no kit script is running. Copies the live folder `kit/20261031-dummy-tenant` first to a kept folder whose files check against the 7l6 manifest (`previous-state: kit/<folder>`), then makes every manifest entry of the live folder equal to `dt-r7s-ro`; files not in the manifest (runtime records written by earlier runs) stay in place and are counted, never deleted.
- Writes `previous-state: kit/<folder>`, `live-manifest-check: pass` and `live-extra-files: <n>` under `### Findings`.
- verify: `(cd "$DT_KIT/20261031-dummy-tenant" && shasum -a 256 -c --quiet "$DT_KIT/20261111-kit-7s/MANIFEST.sha256") && p=$(sed -n 's/^previous-state: kit\/\([A-Za-z0-9._-]*\)$/\1/p' .plan/work/M07-T15/result.md) && test -n "$p" && (cd "$DT_KIT/$p" && shasum -a 256 -c --quiet "$DT_KIT/20261111-kit-7l-gate/MANIFEST.sha256")`
- files: `kit/20261031-dummy-tenant/**` and the kept folder in the development kit; `.plan/work/M07-T15/result.md`

### M07-T16 Record phase D on the trial tenant (run by the tenant chat)
- Precondition: M07-T21 done and M07-T22 applied. The tenant chat runs phase D from the 7s copy handed over by M07-T21 on G's sign-ins (the organisation enable step by hand first, DEC-008 item 3; the Fabric operator app of M07-T22 in `FabricClientId` before 60-powerbi); this task records each script's gate (dry run, write, verify) and every finding from the tenant chat's report, with no tenant name, credential or workstation path.
- Writes `phase-d-kit: <12 hex>`, `phase-d: complete` (or `phase-d: stopped <script> <reason>`), `open-intents: <n>`, `writes-outside-kit: <n>` and one `finding:` line per finding under `### Findings`. A kit defect found live stops phase D and goes to G as a change-round decision (DEC-014 precedent).
- verify: `h=$(sed -n 's/^handover: kit\/20261111-kit-7s\/dt-r7s-ro \([0-9a-f]\{12\}\)$/\1/p' .plan/work/M07-T21/result.md) && test -n "$h" && grep -qx 'applied: complete' .plan/work/M07-T22/result.md && grep -qx "phase-d-kit: $h" .plan/work/M07-T16/result.md && grep -qx 'phase-d: complete' .plan/work/M07-T16/result.md && grep -qx 'open-intents: 0' .plan/work/M07-T16/result.md`
- files: `.plan/work/M07-T16/result.md`

### M07-T17 Record the rollback of the trial tenant before the trial ends
- Precondition: M07-T16 done or stopped. The tenant chat runs the kit's rollback from the same frozen copy before the trial ends (about 10 Dec 2026, DEC-008); every kit-created object is removed, or a manual stop is listed and accepted by G.
- Writes `rollback: complete`, `open-intents: 0`, `manual-stops: <n>` and `manual-stops-unaccepted: 0` under `### Findings`.
- verify: `grep -qx 'rollback: complete' .plan/work/M07-T17/result.md && grep -qx 'open-intents: 0' .plan/work/M07-T17/result.md && grep -qE '^manual-stops-unaccepted: 0$' .plan/work/M07-T17/result.md`
- files: `.plan/work/M07-T17/result.md`

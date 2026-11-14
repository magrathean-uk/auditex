# Master plan - Auditex 1.5.0 and the explainer model research
<!-- Hub document, max 150 lines. sol-architect writes it, the orchestrator makes small edits, G approves scope. -->

## Vision
Auditex 1.5.0 is the release in which an IT administrator or consultant can hand a shareable report to a third
party without that party being able to confirm a guessed name from the run folder name: pseudonyms come from a
private per-run key, and names written with middle initials or titles are masked too. The boundary scanners that
prove the tool never writes to a tenant or reads content close the limits plan v3 named, the codebase is held to a
wider lint rule set, and the release stays read-only, deterministic and byte-reproducible. Beside it, the Isambard-AI
allocation is put to use on the job G chose for a model: writing fuller explanations and remediation for verdicts
the value rules already gave. That track ends with a judged build, a measured comparison of bases and a written
recommendation, so G can decide on evidence whether a model explainer ever reaches the product.

## Target user
IT administrators and consultants auditing their own or a customer's Microsoft 365 or Google Workspace tenant
who need defensible, reproducible evidence without write access (wording confirmed by G for 1.3.0).

## Success criteria
Track A, product release 1.5.0:
- `make lint` enforces Ruff E4, E7, E9, F, W, I, B and UP over the whole repository, and `make lint`, `make test`,
  `make contract-smoke`, `make acceptance` (full v3.9.1 replay, no skips, the value-rule contract test included),
  `make release-check` and `make audit-deps` exit 0 on the release commit; two plain `make dist` builds are
  byte-identical; the contract-smoke digest comparison passes and no digest depends on the run date (`--as-of` on
  every offline smoke run, DEC-005); M04-T03 changes only DEC-004's two label-only digest entries.
- Shareable output pseudonyms come from a private per-run key made at collection (older runs are masked with a
  temporary key until `auditex report prepare-key`): knowing the run path reproduces no pseudonym, no read path
  writes a run, and the key appears in no report, pack, export, notification, MCP output or log; G approved the
  design (DEC-004) and its six amendments are tested; privacy reviews by both providers approve the merged heads;
  `CONTRACT_VERSION`, schemas and the output contract change together and the notes say what it means for 1.4.0
  bundles.
- Names with middle initials or titles and name-equal mapping keys are masked or counted, with probes at most
  tokens x 6 and the 90,000-record HTML peak within the baseline plus 15 percent.
- The v3 DEC-008 and DEC-009 scanner limits are closed for planted cases under the fail-closed rule; any other class
  is a named limit in the privacy reference.
- The plan v3 review follow-ups are closed and the vendored microsoft-skills entries are settled by G's deletion gate.
- astra's release gate returns ready on the gated candidate commit and G's yes names 1.5.0 and that commit; the signed
  tag `v1.5.0` on `origin` has the local tag's object and commit; the GitHub release's wheel and sdist, downloaded
  fresh, match the gated hashes. No PyPI.
Track B, explainer model research on Isambard-AI (outside the repository):
- A runbook with the system's checked facts, a standalone trainer that imports nothing from the product, and a v10
  reproduction scoring at least 400 of 435 strict with at most 5 applicability errors. (Not met: mean 386 of 435 over four runs; G accepted the pipeline as qualified, DEC-011.)
- A clean held-out set with zero twins under one written definition, sealed outside git, re-expressed in the product's
  collected form before any M03 scoring or scored per verdict state (M02-T06, DEC-013).
- A judging method for free text calibrated on planted defects, and an acceptance bar recorded before large runs.
- Bases compared with a noise band and picked by the EU-first rule; one data round whose validation pilot passes
  before any training target is regenerated (DEC-037); one judged build scored once on the held-out set; a recommendation with the product-integration options; G's pick recorded.
- Every Track B result is reproduced by the kit's `kit-check` from hashed artefacts, and an other-vendor review
  reruns it at each milestone close.
- No model decides or changes a verdict; no paid API runs; GPU-hours per stage, every job included (failed and
  retried ones too), stay within the caps G approved in the table below.
Dummy-tenant kit and trial tenant (M07, outside the repository; DEC-006, DEC-008, DEC-010, DEC-014):
- The trial tenant is written only from a kit round confirmed ship by both providers on its frozen copy and passing
  the full offline suite 9 of 9; the live kit folder holds that round with the previous state kept; phase D's gates
  and findings are recorded; the tenant is rolled back before the trial ends (DEC-008).

## Scope of 100 percent
Track A: the 1.5.0 release from G's gate answers - the wider Ruff set, the contract-test and gate-doc
fixes, keyed per-run D5 pseudonyms with the middle-initial and title follow-up, the scanner follow-ups, the small
review follow-ups and the release, which stops at the approved candidate until G's yes names 1.5.0. Track B: the
explainer model research from bring-up to G's pick of a judged build (or of none), one data round included (DEC-037). M07: the kit gate, the hand-over,
phase D's record and the rollback. 100 percent means every DoD item in M00-M07 is ticked; the release waits for
neither Track B nor M07.

## Non-goals
- Shipping a model explainer, a model download or any model code in 1.5.0; product integration is a later G gate.
- Any verdict from a model; widening the rules' scope beyond the 102 SCuBA policies.
- Training code in the product repository (v3 DEC-005); a new repository; the Hugging Face upload (parked until a
  build passes its bar and G says yes); paid API runs; base snapshots on the workstation (they are fetched straight onto Isambard-AI).
- Live-tenant work outside M07 (phase D and the rollback are run by the tenant chat on G's sign-ins and only recorded
  here); kit rounds 7m, 7n and 7o and the shared sign-in opener; answering the SCuBA Google Workspace baselines.
- Hosted CI; merging `wt/github-build-tags-20261108`; PyPI or any registry upload; any tenant write path.
- A Ruff format hook; deleting kit folders, `wt/*` branches or worktrees; workstation tooling (clean-development).
- Edits to G-owned legal files except text G approves verbatim.

## Track B GPU-hour budget (caps, for G's approval)
1 node-hour on Isambard-AI is 4 GPU-hours. A stage that reaches its cap stops and reports. G made the whole
allocation available to this project (DEC-002), so the total below is the allocation itself (20,000 GPU-hours, read on the awards portal; it ends 31 Jan 2027) and the
unassigned hours sit in the reserve: the orchestrator resizes stage caps within it, writing an amendment line under
DEC-002 first and then changing that row's cap and its set-by DEC, and shows G the table. The budget look before M03-T01 is the planned point. No hours before DEC-001 is approved.
Stages: bringup (bring-up and qualification), repro (v10 reproduction), heldout (twins and held-out set, CPU only),
prose (teacher-written training data), judging (judging method and bar), basecmp (base comparison), large (large
runs), build (judged build), dataround (prompt v2, the pilot and data v2, DEC-037). Tasks write `gpu-hours: <stage> <used>`; DoD predicates read the cap from this table and sum exactly (`bc`).
The dataround tasks write `round-gpu-hours: dataround <used>`, recomputed by `kit-check dataround`, because the frozen usage check binds stages to the tasks of the table's first rows.

| stage | tasks | cap | set by |
|---|---|---|---|
| bringup | M01-T02, M01-T04 | 32 | DEC-001 |
| repro | M01-T05 | 64 | DEC-001 |
| heldout | M02-T01, M02-T02 | 0 | DEC-001 |
| prose | M02-T03 | 256 | DEC-001 |
| judging | M02-T04, M02-T05 | 128 | DEC-001 |
| basecmp | M03-T01 | 1,024 | DEC-001 |
| large | M03-T02 | 2,048 | DEC-001 |
| build | M03-T03 | 64 | DEC-001 |
| dataround | M03-T06, M03-T07 | 160 | DEC-037 |
| reserve | - | 16,224 | DEC-037 |
| total | - | 20,000 | DEC-002 |

## Architecture
See ARCHITECTURE.md. Parallel work only across modules with different owners; sol agrees interfaces before any parallel dispatch.

## Milestones
<!-- milestones:begin -->
| id | name | weight | % | status |
|---|---|---|---|---|
| M00 | foundation | 7 | 100 | done |
| M01 | airr-bring-up | 13 | 100 | done |
| M02 | explainer-data-and-judging | 14 | 100 | done |
| M03 | explainer-training | 15 | 20 | active |
| M04 | d5-keyed-pseudonyms | 16 | 100 | done |
| M05 | scanners-and-hygiene | 10 | 100 | done |
| M06 | release-1-5-0 | 13 | 70 | planned |
| M07 | dummy-tenant-kit | 12 | 63 | planned |
<!-- milestones:end -->

Priority (G): Track B gets worker seats first; Track A runs beside it as seats allow. Nothing starts before DEC-001.
Track B: M01-T01 and M01-T03 in parallel; M01-T02 after G's login; then M01-T04 -> M01-T05. M02-T01 (CPU) may run
beside M01; M02-T02 (CPU) after M02-T01 and M01-T03 (it needs `kit-check`); M01-T04 -> M02-T04 (freezes the checks)
-> M02-T05; M02-T06 (CPU) after M02-T02 and M02-T05; M02-T03 after M02-T04, M02-T02 and M02-T06 (DEC-026); M03-T01 after M01-T05,
M02-T03, M02-T06, the bar and the budget look; M03-T08 (CPU) -> M03-T06 (pilot; on `pilot: fail` the round stops and G decides under DEC-013) -> M03-T07 -> M03-T02 -> M03-T03 (also after M02-T06) -> M03-T04 (DEC-037).
Track A: M00-T05, then M00-T01 alone, then M00-T02 and M00-T03 in parallel, M00-T06 after M00-T02 (shared
`Makefile`) beside M00-T03, then M00-T04. M04-T01 (read-only design) may run during M00. After M00: M04-T02 ->
M04-T03 (after G's design DEC) -> M04-T04 -> M04-T05; M05-T01 and M05-T02 in parallel beside M04; M05-T05 at any
time after M00; M05-T03 after M05-T01, M05-T02 and M04-T05; M05-T04 after M04-T05 and M05-T03. M06 after M00, M04
and M05.
M07 (kit; the trial end bounds it, DEC-008): M07-T11 -> M07-T12 -> M07-T13 -> M07-T14 -> M07-T16 (phase D, tenant
chat); M07-T15 after M07-T14 when no kit script runs; M07-T17 before the trial ends.

## Top risks
1. Isambard-AI is aarch64 with unknown compute-node internet, wheel support for PEFT and bitsandbytes, and driver
   versus CUDA wheel fit; M01-T02 checks all eight unknowns before any training, with containers as the fallback.
2. Workers cannot log in; every run phase needs G's login. M01-T02 records how long a login lasts and the route
   workers use, and run tasks are batched so one login covers a phase.
3. The allocation has a fixed end and unused hours are lost; Track B has priority, and the caps keep the large runs
   from eating the comparison.
4. Judging free text is easy to get wrong: deterministic checks gate first, the judge is a different model family
   from the candidate, calibrated on planted defects with position swap, and the bar is fixed before large runs; the data round may still miss the bar (EXP-m03-losses), so a validation pilot gates it and a second miss ends it (DEC-037).
5. The keyed scheme is a bundle and contract change touching engine, product, schemas and docs; the design gate,
   the digest gate (failing today on a date-derived field, fixed by M00-T05), both privacy reviews, the
   1.4.0-bundle compatibility test and the current-version test edits in M04-T03 contain it.
6. The wider Ruff set touches files in every module; M00-T01 runs alone before any other Track A writer.
7. Task ids repeat plan v2 and v3 ids; predicates bind to merges after `v1.4.0` and plan v4 DEC entries, the old
   work folders are archived, and milestone tags are `v4-Mxx`. The repository is public: result lines carry no
   workstation paths, credentials, held-out rows or infrastructure names.
8. The trial tenant cannot be reset and its trial ends (DEC-008): writes come only from a frozen copy that
   passed both confirmations and the full suite, a live defect stops phase D for a G change-round decision
   (DEC-014), and the rollback is planned before the trial ends (DEC-008), not after phase D finishes.

## Links
STATE.md, ARCHITECTURE.md, milestones/, BACKLOG.md, DECISIONS.md, CLEANUP.md, RETRO.md

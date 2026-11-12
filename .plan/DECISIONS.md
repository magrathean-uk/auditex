# Decisions
<!-- ADR-lite. One entry per decision, newest last. Approver is G or auto (within the orchestrator's authority). -->

## DEC-001 Plan v4 adopted
- date: 2026-11-11
- status: approved
- decision: plan v4 runs two tracks. Track A is release 1.5.0: the wider Ruff set, the contract-test and gate-doc fixes (including the contract-smoke digest comparison, which fails on the unchanged 1.4.0 tree on a date-derived field), keyed per-run D5 pseudonyms with the middle-initial and title follow-up (a bundle and `CONTRACT_VERSION` change, design to G first), the v3 DEC-008 and DEC-009 scanner follow-ups, the small review follow-ups, the microsoft-skills deletion gate and the release, stopping at the approved candidate until G's yes names 1.5.0. Track B is explainer model research on Isambard-AI (G's pick "Richer explanations"): bring-up and runbook, a standalone trainer in the kit, one v10 reproduction, a clean held-out set, prose data written by Mistral Small 4 run on the allocation, a judging method and bar, a base comparison (Ministral 3 8B and 14B, Gemma 4 31B, Qwen3.8-27B, Qwen 4 if released), large runs and a judged build with a recommendation, within a 4,000 GPU-hour budget split by stage (master-plan.md). Track B results count only when the kit's `kit-check` reproduces them from hashed artefacts and an other-vendor review reruns it; stage caps change only through a DEC G approves, written into the budget table's set-by column.
- options: approve as written | approve with a different GPU-hour total or stage caps | approve Track A only | hold
- why: G's gate answers (`.plan/work/PLAN-v4/answers.md`) set the model's job, the bases, the D5 milestone and AIRR-first priority; the assessment (`.plan/work/assessment-v4.md`) corrected the hygiene premises.
- consequences: progress re-baselines from 100% (plan v3 closed) to 4% under the plan v4 scope and weights; plan v2 and v3 decisions stay binding, cited as "v2 DEC-nnn" and "v3 DEC-nnn"; verdicts come only from value rules and no model explainer enters 1.5.0; Track B writes only `.plan/work/<id>/result.md` in this repository; approving the plan does not approve a release, a new repository or hours beyond the stage caps (downloads of any size need no telling or asking first, G's later ruling; storage routing is unchanged); where the D5 key lives and the contract-smoke digest strategy are settled at the M04 design gate, and how a model explainer could reach the product at the build pick; G is asked at the login, the D5 design, the deletion gate, the budget look, the build pick and the 1.5.0 yes.
- approver: G ("Approved", 11 Nov 2026, after the gate answers in `.plan/work/PLAN-v4/answers.md`)

## DEC-002 The whole allocation is Track B's budget
- date: 2026-11-11
- status: approved
- decision: the whole AIRR allocation on Isambard-AI may be used for this project. The 4,000 GPU-hour total in the master-plan budget table is the starting plan, not a ceiling. Stage caps stay as stop-and-report controls. Once M01-T02 has read the allocation balance, the orchestrator may raise or move stage caps within that balance: each resize is one amendment line under this entry (stage, old cap, new cap, balance read), written before the row's cap and set-by change, and G is shown the resized table. The reserve row needs no separate release.
- options: keep the 4,000 total and the G-only reserve (DEC-001 as drafted) | the whole allocation with orchestrator-resized stage caps (chosen)
- why: G, 11 Nov 2026: "The whole AIRR we have can be used for this project." Hours are not the limit; the allocation's end date is.
- consequences: no change to scope, weights or percentage; the sum of the stage caps never exceeds the balance read on the system; a stage that reaches its cap still stops and reports; the budget look before M03-T01 stays as planned. This supersedes DEC-001's "hours beyond the stage caps" limit and the reserve's G-only release, nothing else.
- approver: G
- amendment 1 (2026-11-11): balance read by G on the awards portal: 20,000 GPU-hours allocated, 0 used, allocation ends 31 Jan 2027. reserve 384 -> 16,384 and total 4,000 -> 20,000. The working stage caps stay as they are until M01-T05 has measured what a run costs on the system; the budget look before M03-T01 then moves hours from the reserve into the prose, judging, basecmp and large stages.

## DEC-003 Kit verifier: merge bar after two repair rounds
- date: 2026-11-11
- status: approved
- decision: after two repair rounds the kit review (REV-KIT-01, kit interface hash fd568fabc6e1) has closed every finding on the trainer, the scorer, the verifier's discovery and the twin definition; each round still found new ways for the `usage` accounting check to pass on contradictory scheduler rows. The open-ended review stops here. `usage` gets one last change with a fixed bar: any export whose rows for one job or one start disagree with each other (elapsed time, allocation, generic against typed GPU counts) fails, and what it still cannot see is named in the kit's `bin/README.md`. The reviewer repeats only its recorded probes for items 14 and 15. From now on the GPU-hours of every Track B stage are also compared with the awards portal's used figure at each milestone close (`REV-M01-kit`, `REV-M02-kit`, `REV-M03-kit`), which is independent of the kit. M01-T04 starts now on the reviewed trainer; its usage is checked with the repaired verifier before M01 closes.
- options: a third open review round before any GPU job | stop at a fixed bar, add the portal comparison and start the qualification job (chosen)
- why: plan v3's lesson for adversarial checker work (two repair rounds, then a written merge bar); the portal figure is a check the kit cannot influence; the allocation has a fixed end.
- consequences: the kit files' `SHA256SUMS` change once more with the `usage` fix; M02-T02, M02-T04 and M02-T05 also own `checks/SHA256SUMS` in the kit, because the verifier now refuses a check module the manifest does not list (files-line amendment, recorded here); run tasks keep `selection.json` out of public places or strip its paths, and the runbook says so.
- approver: auto; confirmed by G on 12 Nov 2026 ("Confirm all five")

## DEC-004 D5 keyed pseudonym design
- date: 2026-11-11
- status: approved
- approver: G
- digest-strategy: seed
- digest-exception: ci-projection-demo model_assessment.json and projection:project_run.report, for projection.redaction.strategy only
- assessment-schema: enum in place, no dated copy
- key-timing: at collection (design Q2 option A)
- keyless-runs: masked with a key held in memory until `auditex report prepare-key` is run once (design Q3 option d)
- test-update-rule: M04-T03 may change a test outside its files line only where the sole failure is (i) a pseudonym pinned from the run-path salt, (ii) an expected file set, tree or hash-manifest row gaining operator-inputs/, .gitignore, pseudonym.key or a key temporary, or (iii) the keyless-run behaviour chosen here; result.md lists each file and line with its reason; any other failure stops M04-T03 for a design note
- decision: G approved the design in `.plan/work/M04-T01/design.md` at revision 3 (sha256 8b18c94ba27c), reviewed three times by both providers (`REV-M04-T01`, `REV-M04-T01-sol`). G's words were the option picks "Approve (Recommended)", "At collection (Recommended)", "Temporary key (Recommended)". Each run sealed by 1.5.0 gets a random 32-byte private key in `operator-inputs/pseudonym.key`; pseudonyms are HMAC-SHA256 of that key, cut to 16 hex, labelled keyed-hmac-sha256-v1; `CONTRACT_VERSION` becomes 2026-11-11.
- amendments from the last review round, binding on M04-T03 and checked by its privacy reviews: (1) every lock error except "would block", "try again" and "interrupted" means storage without locking, raised before anything is written, with tests for the two errors Linux network storage returns, and that storage is named in the limits; (2) the key's temporary file is registered as private before its bytes are written and cannot be read through an ordinary guarded read or standard input by another process, tested with a paused creator; (3) a context keeps the first key it resolved for each run for the whole operation; (4) the durability limit covers every case where the folder cannot be flushed, and the run folder is flushed after `operator-inputs/` is created where the storage supports it; (5) descriptions and documentation cover every keyless run (made by 1.4.0 or earlier, copied without its private folder, or sealed on storage without locking) and make no claim about when MCP clients ask for approval; (6) orchestrator's product default: output made with a temporary key says that its pseudonyms are not stable across sessions and names `auditex report prepare-key`.
- options: approve | one more design round; key at collection | on first shareable use; for keyless runs: temporary key | refuse until prepared | write the key silently | mark the tools as writing
- why: the run-path salt lets someone who knows where an audit was saved confirm a guessed name; both reviewers found the function, the label and the seed strategy sound and recommended the key at collection; they split between refusing keyless runs and the temporary key, and the temporary key is the only option that never writes from a read-only tool and still reports runs on read-only or network storage.
- consequences: the files lines of M04-T03 and M04-T05 widen as design section 13 lists for these answers (plan amendment 1); a new `auditex report prepare-key` command; pseudonyms made by 1.4.0 do not match those of 1.5.0; a 1.4.0 reader loses the explanations of a 1.5.0 run; the named limits of design section 17 stand.

## DEC-005 An as-of date for offline runs
- date: 2026-11-11
- status: approved
- decision: 1.5.0 adds a visible `--as-of <date>` option to offline runs. It fixes the date used for end-of-support, lifecycle, expiry and stale-sync findings, and `make contract-smoke` passes it, so the recorded digests stop depending on the day the check runs (the comparison broke on 10 Nov 2026 when a product passed its end-of-support date; M00-T05, `.plan/work/EXP-clock/result.md`). G's words were the option pick "Yes, add it (Recommended)".
- options: add the option | keep refreshing the digests by hand at each lifecycle date
- why: a release gate that fails on a calendar date is not a regression gate; the demo already fixes its date the same way.
- consequences: one new task in M00 (plan amendment 1) with parser tests under the CLI rules; one refresh of the digest fixture; a small scope growth approved by G.
- approver: G

## DEC-006 Dummy-tenant kit round 7l comes into scope, ahead of everything
- date: 2026-11-11
- status: approved
- decision: G created the trial tenant for the dummy-tenant kit; its trial period is short, and G holds every tenant write until kit round 7l is green. Round 7l to green (its remaining fixes, the full offline suite and the gate review) joins plan v4 as its own track and gets worker seats ahead of every new Isambard-AI and release task; tasks already running keep running. G's words were the option pick "Yes, ahead of everything".
- options: alongside the AIRR track | ahead of everything (chosen) | keep the kit parked
- why: the trial tenant expires before the allocation does, and nothing may be written to it until the kit's create and rollback paths pass their gate.
- consequences: plan v4's non-goal "the dummy-tenant kit" is reversed for round 7l and its gate only; rounds 7m, 7n and 7o, and every live-tenant step, stay outside this plan (the tenant session runs the read-only checks and, after green, the writes, on G's login); kit code stays in the development kit, outside this repository, and its tasks write only `.plan/work/<id>/result.md` here; milestones and weights follow in plan amendment 2 after an inventory of the kit's real state; no tenant is contacted by any task of this plan.
- approver: G
- amendment 1 (2026-11-11): the inventory and M07-T01 found round 7l already accepted. The kit was accepted offline on 8 Nov 2026 after a full offline run with exit 0 and a gate 22 SHIP from both providers with no high or medium finding, and the live kit is byte-identical to that accepted state today (365 files, frozen as `dt-r7l6-ro` in the kit, manifest sha256 109679e67da549ddc6c72bd751f1217fb146f31962a5bd5e2392c80958b1cb8c). The backlog line that listed "the 7l6 full offline suite and gate" as open was stale. What remains under this decision is one confirmation run of the full suite through the repaired driver (`M07-T02`, started by the orchestrator as the one heavy job) and the report to G and the tenant session. No milestone and no weight change are needed, and the seat priority this decision gave the kit ends when that run is started.

## DEC-007 The held-out set's repair may change the twin definition
- date: 2026-11-11
- status: approved
- decision: the review of the clean held-out set (REV-M02-T02) found four blocking defects: labels that the pinned rules do not reproduce from the row's own evidence, "not assessed" labels assigned without evaluating the masked input, rows that share their seed tenants and their missing-section gate with training rows although the twin count is zero, and conflicting labels removed instead of the key being repaired. The repair of M02-T02 may therefore also change `heldout/twin_definition.py` and `heldout/notes/**` in the AIRR kit (M02-T01's files), provided it states the recount of the old test set under the changed key and keeps the soundness check; the set is regenerated from seed tenants disjoint from the training pack's.
- options: reopen M02-T01 as its own task first | let the one repair own both (chosen: the two are sequential, in one module, and the key and the set must agree)
- why: every later score rests on this set; a key that is repaired separately from the set it guards would need a third pass.
- consequences: M02-T01's recorded twin counts may change and are restated by the repair; the set's sha256 changes; M02-T03 and M03 read the definition only after the repaired set passes its review.
- approver: auto; confirmed by G on 12 Nov 2026 ("Confirm all five")

## DEC-008 One kit change round from the trial tenant's live facts
- date: 2026-11-11
- status: approved
- decision: the read-only checks on the trial tenant showed what the accepted kit needs before writes start. G decided three things. (1) MS.AAD.9.1 is the one named gap: the kit's Agent 365 licence requirement is removed (no licence in the tenant carries it and no expected result depends on it). (2) One kit change round now, through the offline gate: that removal; reuse of an already signed-in Exchange, Security and Compliance or Teams session so day one needs far fewer sign-ins; a refusal on an organisation not yet enabled for customisation treated as a definite refusal with mock cases; and a setting that names the Teams module version (the module fails to sign in on macOS from 7.9.0 on; 7.8.0 was observed to connect). (3) The tenant session may run the one-way organisation enable step by hand before the kit's Exchange and Defender scripts. G's words were the option picks "Name 9.1 the gap (Recommended)", "Yes, one round now (Recommended)" and "Yes, run it (Recommended)".
- options: obtain Agent 365 | name 9.1 the gap; one round now | only what is unavoidable; run the enable step | not yet
- why: nothing may be written to the tenant from kit source that has not passed its gate, and the trial ends about 10 Dec 2026, so the changes are gated once, together.
- consequences: tasks M07-T06 onwards (the round, the full offline suite, a gate review by both providers, then the install of the accepted copy with the previous state kept); until that gate passes, the kit accepted on 8 Nov is the only state the tenant session may use; the kit stays outside this repository; a milestone and weights for this work follow in plan amendment 2; rounds 7m, 7n and 7o stay out of scope.
- approver: G


## DEC-009 The v10 reproduction is read as a four-run mean
- date: 2026-11-11
- status: approved
- decision: M01-T05's first run on the system scored 393 of 435 quantised (bar 400, recorded 403), while the original v10 checkpoint scored 402 through the same scorer and the pack is byte-identical, so the scorer and environment reproduce and the shortfall sits in the trained weights. One run cannot separate a real shortfall from run-to-run spread (about 6 rows standard error at this score). Set before any further run is scored: four runs of the unchanged recipe count (run 1, a second run on the same seed, two more on the next two seeds); `reproduction: pass` is written only when the mean quantised strict of the four is at least 400, every run has at most 5 applicability errors and the parity rule passes on the run nearest the mean, whose build is the one recorded. Otherwise `reproduction: fail` with every run's figures. No further run is added after scores are seen.
- options: keep the single-run reading and fail on 393 | re-run until one run passes (rejected: picks on the test set) | a fixed four-run mean (chosen)
- why: the reproduction qualifies the pipeline before large hours are spent; a single draw against a bar 3 rows under the recorded score answers that badly, and the spread is needed anyway for the noise band of the base comparison.
- consequences: about 12 more GPU-hours inside the 48 GPU-hour stage cap; the measured spread goes to M02-T05's bar; a fail does not stop Track B by itself (the model's job is explanation text, verdicts come from rules) but is reported to G with the cause analysis.
- approver: auto

## DEC-010 The shared sign-in leaves the gated kit round
- date: 2026-11-11
- status: approved
- decision: kit round 7p's item 4 (one sign-in per window reused by several scripts, DEC-008) is removed from this round. After one repair the two gate reviews of the frozen copy split: one ship, one do-not-ship on session ownership and cleanup in error paths (a failed census can make a script close a session it did not open; unreadable session ids can be left connected while cleanup reports complete). Both agree the other four items are sound and that no finding can write to the wrong tenant or lock the operator out. A new author builds round 7q from the accepted baseline plus items 1, 2, 3 and 5 only, with all sign-in and session code byte-identical to the accepted kit; then one diff-scoped confirmation by both providers and the full offline suite.
- options: a second repair of the opener by another author (rejected for this round: each review round found new defects in the same new code, and a tier A gate needs both providers) | accept on the split verdict with the findings as stated limits (rejected: a stated property would be false) | cut the feature from the gated round (chosen; announced to G as the fallback before the re-review)
- why: the live run needs the Agent 365 removal, the refusal handling and the Teams version pin; the shared sign-in is a convenience. New session code is the riskiest part of a kit that writes to a tenant that cannot be reset.
- consequences: on the live run G signs in once per script and service, as with the accepted kit. The opener's code and its reviews stay in the 7p folder; bringing it back is its own task with its own gate, only if G asks.
- approver: G (confirmed on 12 Nov 2026, "Confirm all five")

## DEC-011 The training pipeline is accepted although v10's score did not reproduce
- date: 2026-11-11
- status: approved
- decision: M01-T05 failed by the DEC-009 rule: four runs of the unchanged v10 recipe on the system scored 393, 393, 387 and 372 of 435 quantised (mean 386.25, sample sd 9.91; run 4 with 14 applicability errors) against a bar of 400 and the recorded 403. The archived v10 checkpoint scores 402 through the same scorer on a byte-identical pack, and effective batch, step count and training loss match the recorded run, so data, scorer and training dynamics are sound. G accepts the pipeline as qualified and moves on. The recorded 403 is recorded as not reproduced. From here on every model score the plan reports comes from at least three seeds per configuration, read against the measured seed spread; a single run decides nothing.
- options: accept and move on (chosen; G: "Accept, move on") | a bounded investigation first (about 24 GPU-hours; unlikely to change the next step, because only one run exists from the earlier system)
- why: the model's job in this plan is explanation text, and rules decide every verdict; the reproduction was a pipeline qualification, and its real finding is the size of the run-to-run spread.
- consequences: the M01 done item for the reproduction is amended to "measured and accepted"; M03's three-seed rule now covers every reported score; any public statement about v10's accuracy must quote the spread (372 to 393 in four fresh runs), not the single 403; the Hugging Face upload stays parked. DEC-009's four-run reading stands as the rule this was judged by.
- approver: G

## DEC-012 Scanner tasks: Opus authors, Codex reviews
- date: 2026-11-11
- status: approved
- decision: for the two tier A scanner tasks (M05-T01, M05-T02) the provider lanes are swapped: Opus authors on a pool account and Codex reviews. The plan's task lines named Codex as author with a Claude reviewer. The rule that matters is unchanged and still checked at milestone close: the author and the reviewer are of different vendors, and the merge carries the review trailer for the exact commit.
- options: keep Codex as author and wait for its capacity (both Codex accounts are near their working limit until 14 Nov 2026) | swap the lanes so the other provider still sees every tier A change (chosen)
- why: Codex capacity left this week covers reviews, not authoring; waiting would idle the release path for three days.
- consequences: the two task lines are amended; REV-M05-T01, whose only required change was this lane conflict, is refreshed against the amended line. Routing only: no acceptance bar, scope or product behaviour changes.
- approver: auto (routing by capacity, the orchestrator's remit)

## DEC-013 Explainer acceptance bar
- date: 2026-11-11
- status: approved
- decision: a trained explainer model is accepted only when all five rules hold on the clean held-out set (bar file sha256 ee64099a4b745e49668ad21147977cf639f6d17eec0542f58970f3103fcbe4fc, frozen checks 3241cf2ccd79...): (1) floor: on every seed no output states the verdict, a value, the policy or the references wrongly or leaves out a required template step, and at least 99 per cent pass every frozen check; (2) wins: the judge compares each output with the template in both orders, only a win in both orders is a win, everything else is a tie worth half, and every seed's preference band sits wholly above 72.9 per cent (the top of the band mechanical fuller text reaches); (3) judge flags only screen: at most 14.3 per cent of outputs flagged per seed; (4) G reads 24 outputs from the frame frozen in the bar (3 seeds, 4 verdict states, one judge win and one not) with the four-question rubric; pass when none has a factual error and at least 22 are right on all four; (5) at least three seeds per configuration, figures as mean with minimum and maximum.
- options: the plan's default bar with a judge preference whose lower band is above 50 per cent (rejected: mechanical fuller text clears it at 55.7 to 72.9 and the judge's preference for clean fuller text is weak) | the five-rule bar (chosen; G: "Approve the bar")
- why: the calibration showed the judge is reliable on planted defects in near-identical text and weak at ranking fuller text, so acceptance rests on the frozen checks, both-order wins above the mechanical band, and a human read.
- consequences: if no model's band clears 72.9 per cent the question returns to G; the orchestrator does not loosen the rule. Not validatable before a trained model exists: reachability of rule 2, the seed spread, the human read. Before any M03 scoring the held-out inputs are re-expressed in the product's collected form or scores are reported per verdict state (through the 1.4.0 rules only 209 of 501 rows keep their sealed label).
- approver: G

## DEC-014 A second kit change round (7r) for the live Graph defect
- date: 2026-11-12
- status: approved
- decision: the accepted kit 7q stops on its first live dry run on the operator's Mac: any change to the Graph request context after sign-in resets the SDK's client and the next request fails (Microsoft.Graph.Authentication 2.25.0); the kit changes the retry count around every create. No tenant write was made. A narrow change round 7r fixes this (every such change through one helper that reconnects and proves the same account, tenant and scopes, or the retry count set once before sign-in; both proven read-only against the real SDK), adds a mock model of the SDK behaviour, and states in the documents that later processes sign in to Graph silently from the SDK's auth record. Tier A gate as before: one strong author, confirmation by both providers on the frozen copy, the full offline suite at night.
- options: fix round 7r (chosen; G: "Yes, fix it") | park the kit for this trial
- why: without it the kit cannot seed the trial tenant; DEC-008 approved one change round only, so a second is G's call.
- consequences: phase D stays paused until 7r is accepted; earliest the morning of 13 Nov. Nothing else enters the round.
- approver: G

## DEC-015 M00 close and the M04-T02 dispatch: three mechanical calls
- date: 2026-11-12
- status: approved
- decision: (1) the plan v4 close of M00 is tagged `v4-M00` (local), because the local tag `M00` already exists from plan v2 (8 Nov 2026) and tags are not moved; later plan v4 milestone tags take the same prefix. (2) M04-T02 (one data file, no behaviour change, tag `mechanical`) runs on terra as `risk:low`: its verify is the gate and it gets no review. Codex is above the quota threshold and Codex 2 is kept for tier A reviews until the reset on 14 Nov (DEC-012). (3) The dispatcher refused M04-T02 on the round cap ("4 in all"): the four rounds it counted are plan v3's task of the same id (`task/M04-T02-read-boundary-limits`, 9 Nov 2026, merged in 1.4.0); the plan v4 task has had no author round. It is dispatched with `--rounds-ok` naming this entry.
- options: move the old `M00` tag (rejected: tags are not rewritten) | an other-vendor review of a baseline file (rejected: spends the tier A review quota on a file the verify already checks) | renumber the task (rejected: a plan change for a counter artefact)
- why: none of the three changes scope, an acceptance bar or a gate; the round rule exists to stop repair loops and no repair has happened.
- consequences: plan v4 tasks whose ids plan v3 also used (M04, M05, M06 ids) will meet the same refusal; each needs the same flag until the plan skill counts rounds from the current plan tag (reported to G for the plan-skill owner).
- approver: auto

## DEC-016 M04-T02: the baseline is recorded on main, with one test assertion changed
- date: 2026-11-12
- status: approved
- decision: M04-T02's criteria contradicted each other. They ask for the HTML peak baseline to be recorded on the current `main` and for `tests/test_html_peak_harness.py` to pass with no other change, but that test requires the committed baseline to show unmasked names, and `main` has masked every name in the shareable report since 1.4.0 (first author run: blocked, 0 unmasked hits; EXP-peakbase). The task keeps the plan's intent, a baseline on the current `main`, and its files line gains the test for one assertion: the baseline must carry person names (`person_names > 0`) instead of unmasked hits. Both files belong to one module (misc-scripts).
- options: keep the old baseline of 8 Nov, recorded before masking (peak 607,862,784 bytes; M04 limit 699,042,201) | record on `main` as the plan says (first measurement 650,166,272 bytes; M04 limit about 747,691,212) (chosen). Recorded at the merge (18275e0): 626,393,088 bytes, so the M04 limit is 720,352,051
- why: the M04 limit is there to bound what the keyed scheme adds, so it is measured from the code just before that change; the old figure would charge M04 for the 7 percent that 1.4.0's masking already added. Another test still proves the workload carries names (`test_require_masked_fails_on_local_report`).
- consequences: the M04 peak limit is 720,352,051 bytes, about 21 MB above the 699,042,201 of the old baseline (two runs on `main` gave 650 and 626 MB, so one run varies by about 4 percent). The "no workload person name" half of that done item already holds on `main` and acts as a regression guard. The task is no longer `risk:low`: it gets one review, by another Claude account because both Codex seats are held back (DEC-012).
- approver: auto; kept (reported: G's team-manager chat, 12 Nov 2026, under G's "You lead")

## DEC-017 M05 deletion gate
- date: 2026-11-12
- status: approved
- decision: the eight unused vendored files under `tenant-bootstrap/vendor/microsoft-skills` (the catalogue, the microsoft-foundry entry and the entra-agent-id entry; list in `.plan/work/M05-T05/result.md`) stay. No path is approved for removal, so CLEANUP.md gets no row and no removal task is dispatched.
- options: remove them and change the "Retained scope" line of `docs/legal/third-party-notices.md` with wording from G | keep them (chosen)
- why: nothing ships or runs from them, and removal would make a legal line untrue until G rewrote it.
- consequences: the legal text and the vendored manifest stay as they are; the M05 done item for the gate is met with an empty removal list.
- approver: G ("Confirm all five", 12 Nov 2026)

## DEC-018 Plan amendment 2 is drafted
- date: 2026-11-12
- status: approved; merged as c0edff9
- decision: the kit and tenant work (rounds 7l to 7r, the tenant hand-over and phase D), run so far as M07 tasks under `.plan/work` only, becomes milestone M07 with its own weight, and a task to re-express the clean held-out inputs in the product's collected form before any M03 scoring is promoted from the backlog into M02 (DEC-013). The architect drafts it from `.plan/work/PLAN-v4/amend-2.md`.
- options: leave the kit outside the plan and its percentage (rejected: it is the work G put ahead of everything, DEC-006, and the figure hides it) | amend (chosen)
- why: the one public progress figure should count the work actually in scope; M03 scores are not comparable until the held-out inputs match what the product collects.
- consequences: milestone weights change and the overall percentage is re-baselined once G approves the weights.
- approver: G for the draft ("Confirm all five", 12 Nov 2026); the weights: reported (G's team-manager chat, 12:15 GMT on 12 Nov 2026, quoting G: "You lead , AIRR i will try to sign in but all it's needed is in 1pw and use my SSH key", and ruling the weights approved)
- progress (12 Nov 2026): drafted at 77b7f17; one review and one repair (d7619ea) closed five loose pass conditions; the re-check then found the new held-out check under-specified, a new author applied the reviewer's fix (dabe352, a third author round allowed for one narrow gap, auto) and the final re-check approved dabe352. Proposed weights: M00 7, M01 13, M02 14, M03 15, M04 16, M05 10, M06 13, M07 12; overall 36% to 35%. Waiting for G's approval of the weights before the merge.

## DEC-019 M04-T03 design note: the legacy test's fixture carries the legacy label
- date: 2026-11-12
- status: approved
- decision: the first author run of M04-T03 stopped, as its criteria require, on one test outside its files line: `tests/test_explainer_wire.py::test_legacy_assessment_still_validates_before_and_after_upgrade` relabels a freshly made assessment as schema 2026-10-29, and a fresh assessment now carries the new strategy label, which the unchanged dated schema refuses. The test sets the relabelled document's `projection.redaction.strategy` to `run-salted-sha256-v1`, the same edit the task already makes in the owned legacy test of `tests/test_scuba_projection.py`. The files line gains that one place in a file the task already owns in part.
- options: change the dated schema to accept the new label (rejected: the approved design keeps the dated schema unchanged) | leave the test failing or skip it (rejected) | make the fixture a faithful legacy document (chosen)
- why: the criterion is that a 1.4.0 bundle, which carries the old label, validates under both validators; a legacy fixture with the new label tests nothing real. It is a fixture correction inside the approved design, not a change to it.
- consequences: the author continues on its branch for this one edit (a second sol round that is not a repair; a later repair after the review passes the round cap under this entry). Both tier A reviews see the edit. The author's noted risk goes to the reviewers: the CLI `auditex report analyze`, `api-calls`, `permissions`, `proof-table` and `handoff` commands print without the temporary-key notice that DEC-004 amendment 6 asks of reports.
- approver: auto

## DEC-020 Kit gate tasks take worker seats first until phase D starts
- date: 2026-11-12
- status: approved
- decision: M07's remaining gate tasks (the round 7r finish, its confirmation by both providers, the full offline suite and the hand-over) get worker seats and the tier A review quota ahead of new Track A and Track B work until phase D starts on the tenant. Work already running continues.
- options: seats in plan order (rejected: the trial end is the only fixed end in the plan) | kit first (chosen; the architect's recommendation in amendment 2)
- why: phase D cannot start before round 7r is accepted, and the trial tenant ends on a fixed day (DEC-008).
- consequences: M02-T03 and M04-T04 start only when no kit gate task is waiting for a seat; M04-T03, already running, continues. Codex 2's remaining review quota goes to the 7r confirmation first, then to M04-T03.
- approver: reported (G's team-manager chat, 12 Nov 2026, under G's "You lead")

## DEC-021 M04-T03: the test-update rule gains two classes, and the CLI notice joins the files line
- date: 2026-11-12
- status: approved
- decision: the DEC-004 test-update rule is extended with exactly two classes. (iv) Legacy relabel, the DEC-019 class: in `tests/test_model_rules_only.py`, `tests/test_optional_collection_reason.py`, `tests/test_scope_postcheck.py` and `tests/test_value_rules_contract.py` the fixture that relabels a fresh assessment as the old dated schema carries `run-salted-sha256-v1`; the assertions stay as they are. (v) `tests/test_scuba_projection_area_hook.py`: both pinned hashes are refreshed, with a seeded test key for the keyless fixture. Conditions: `result.md` lists every file and line with its reason and shows the before-and-after difference for the two pins; any failure outside these classes stops the run again; one finish run, then the single re-check, the executing check and the privacy review; a failed re-check comes back as a choice, with no further author run on the orchestrator's own call. Recorded with it (orchestrator, same module): `src/auditex/cli.py` may carry the temporary-key notice in `_redacted_report_payload`, which the first review required for the five CLI report commands.
- options: leave the 11 full-suite failures (rejected) | change the old dated schema (rejected: the approved design keeps it unchanged) | extend the rule to these two classes in five named files (chosen)
- why: the repair fixed all three review items and stopped, as its criteria require, on 11 failures the rule did not cover (22,901 pass); the fixtures can only pass by being made faithful, and the pins moved only by the label and the pseudonyms the design changes on purpose.
- consequences: the files line and the rule in the milestone file are amended. Open for G, not blocking: on keyless runs the notice is one extra non-finding row (`pseudonym_notice`) in the findings CSV and a top-level key in JSON; the manager chat puts that design choice to G.
- approver: reported (G's team-manager chat, 12 Nov 2026, quoting G on who rules: "You lead" and "You herd, go!")

## DEC-022 Codex 2 may pass its working limit for two tier A re-checks
- date: 2026-11-12
- status: approved
- decision: Codex 2 only may be dispatched up to 88 percent of its weekly window (working limit 85) until its reset on 14 Nov 2026 22:41 UTC, for two runs only, one each: the kit round 7r re-confirmation and the M04-T03 re-check. The limit is passed on those two dispatches and on nothing else; Codex 1 stays as it is. If either returns do-not-ship or changes-required, the choice goes to G or the team-manager chat; no further Codex run on the orchestrator's own call. Both runs and the Codex 2 figure before and after are named in the next report.
- options: hold the 85 percent line, so M04-T03's re-check waits for the reset (rejected: about two days on the release track for a three-point margin) | a bounded exception for the two gates (chosen)
- why: both are tier A gates that need the other vendor and each costs about a point; Codex 2 stood at 84 percent with two such runs due.
- consequences: Codex 2 ends at about 86 percent; nothing else may use it before the reset.
- approver: reported (G's team-manager chat, 12 Nov 2026, quoting G on who rules: "You lead" and "You herd, go!")

## DEC-023 M04-T03: one last repair for the privacy review's findings
- date: 2026-11-12
- status: approved
- decision: the gates on head 9f38936 split: the Codex 2 re-check approved, the Opus privacy review required changes (REV-M04-T03-privacy), the executing check did not get a heavy slot. One repair by the same author closes B1 (keyless customer pack: manifest, README and JSON source-artefact copies without the temporary-key notice), A1 (a guarded read can return the key bytes when the key is published between discovery and open) and A3 (a keyless run's memory key indexed by device and inode only), each with its test, and A4 (a rename). Nothing else enters. On the new head: the Opus privacy re-check and a Codex 2 re-check, both bounded to that diff and to whether B1, A1 and A3 are closed, then the executing check once. Codex 2: a third named run under DEC-022, same ceiling of 88 percent; the kit 7r re-confirmation keeps its run. Merge only on all three gates. If any fails, stop and bring it to G: no sixth author run, no further Codex run.
- options: repair B1 only and leave A1 and A3 to M04-T04 (rejected: A1 is a path to the key itself) | stop and wait for G | one last repair for all three (chosen)
- why: B1 breaks the output contract and A1 reaches the key, so 1.5.0 should carry neither; a second repair after a second, different gate is not a loop as long as it is the last.
- consequences: the criteria and the files line of M04-T03 are amended in the milestone file. A2 (the CSV notice row) stays G's design choice.
- approver: G ("Yes, one repair", in this chat on 12 Nov 2026), after the same ruling was relayed by his team-manager chat

## DEC-024 M04-T03: one more author run that closes the class, with run_files.py allowed
- date: 2026-11-12
- status: approved
- decision: on head 1f0348d the Codex 2 re-check required changes and the Opus privacy re-check approved (B1 and the rename closed for both). Codex's two blocking points: the key-read race is still open through a read rooted at the key folder, which goes through `src/azure_tenant_audit/run_files.py`, a file the task's verify command barred; and keyless runs with a missing or empty run id share one memory-key index. Because a second review round found another instance of the same race, the approach changes: one more bounded author run lists every guarded entry point in a table and closes each one, `run_files.py` may change for the re-discovery only, and a missing run id refuses or gets a non-reusable identity. Then the two bounded re-checks (a fourth Codex 2 run, ceiling 88 percent as DEC-022) and the executing check; merge only on all three.
- options: park M04-T03 until G is back (offered) | carry both points into M04-T04 (not offered: the merge needs both providers' approval of the exact head) | one more run that closes the class (chosen)
- why: the release should not carry a path to the key; fixing instances one at a time has cost two rounds.
- consequences: the verify command no longer bars `run_files.py`, and the files line and criteria of M04-T03 are amended. If either re-check or the executing check fails after this run, the task stops again and returns to G.
- approver: G ("Yes, one more", in this chat on 12 Nov 2026; the same question put by his team-manager chat got "Yes, one run"). The manager chat recommended a fresh author: every dispatch is a new worker context with no memory of earlier runs, and this one was told to build the entry-point table from the code, so the run already out (claude-1) was not restarted.

## DEC-025 M03 is scored on the collected-form held-out set
- date: 2026-11-12
- status: approved
- decision: M02-T06 takes its first choice. The clean held-out inputs are re-expressed in the form the product collects; the prototype kept 228 of the 501 sealed rows (209 unchanged, 19 by value-preserving transforms the pinned rules reproduce), 78 of 102 policies and 122 of 188 cells, with every verdict state still present, and dropped 273 (126 because the product does not collect that section). M03 is scored on that set. The kit's twins check may change in three bounded ways so a derived set can be checked truthfully: a coverage reason for a cell whose sealed rows were all dropped by re-expression, the measures task id read from the folder, and cap-trim drops with their own reason. The M02-T02 seal stays untouched.
- options: A, the collected form with a reviewed change to the twins check (chosen; the orchestrator's recommendation) | B, keep the sealed 501 in export form and report every bar figure per verdict state (rejected: 291 of 501 rows are inputs the released rules mark not assessed, a form the product never hands the explainer)
- why: the bar should judge the explainer on what the product will really feed it.
- consequences: every M03 report states the coverage lost (24 policies, 66 cells). The M02 kit review confirms the DEC-013 bar is still usable on the smaller set with three seeds; if the wins rule becomes unreachable it returns to G, as DEC-013 says. The 126 "section not collected" drops go to the backlog as a product collection gap. The twins check was accepted on a fixed bar (DEC-003): its change is reviewed with the set by the other vendor (REV-M02-kit). M02-T06 never runs while M02-T03 does (its files line).
- approver: G ("A, collected form", in this chat on 12 Nov 2026)

## DEC-026 How the prose rows and the collected held-out set are registered and compared
- date: 2026-11-12
- status: acted on; listed for G
- decision: from the read-only design note EXP-m02-data. M02-T06 runs first and seals the collected set; M02-T03 then places its rows. The prose files are listed in the kit's `data/splits.json` (owned by M02-T03) under the roles `explainer-train` and `explainer-validation`, never `train` or `validation`, because the M02-T02 seal pins its compared splits. The proof that no explainer row is a twin of a row M03 is scored on, against both the collected and the sealed set, lives in M02-T06's new `checks/collected.py`; `checks/twins.py` gets no change beyond DEC-025's three. Re-expressed rows that become twins of a compared split row, or of another kept row, are dropped and counted (the prototype has 6, so the collected set is about 221 rows, 77 policies, 120 cells). M02-T03 filters its rows against both sets, fills an uncovered template cell from the fixtures' constructed vectors before listing it as missing, and its verify also runs the `twins` and `collected` checks.
- options: list the prose rows as `train` and `validation` (rejected: fails the sealed set's check whatever the rows are) | pin the prose files in the collected set's own manifest (rejected: a reseal whenever the prose data changes) | explainer roles plus the comparison in `checks/collected.py` (chosen)
- why: M02-T03 stopped on exactly this, with 785 checked rows staged; the 82 conflicting evidence keys it found are prose rows (1.4.0 rule verdicts) against the older oracle training rows (Rego labels), not against any held-out row, so they are a property of two labellers and not a leak.
- consequences: the criteria, verify and files lines of M02-T03 and M02-T06 are amended in the milestone file; every change adds a check or a counted drop, none loosens one. Open for G: whether the soundness rule should also hold among the explainer rows themselves (6 keys, 16 rows; recommendation no). The 785 staged rows stay valid and are re-filtered after the seal.
- approver: auto; listed for G

## DEC-027 M02-T06: the collected set gets its own kit-root folder, and no GPU-hours line
- date: 2026-11-12
- status: acted on; listed for G
- decision: the build run of M02-T06 built and checked the whole collected set in a scratch copy of the kit (221 of 501 rows kept: 209 unchanged and 19 transformed, less 6 twins and 1 cap trim; 77 of 102 policies; twins 0; rule agreement 221 of 221; all transformed rows reproduced by the pinned Rego) and stopped on two conflicts with the frozen kit. (1) Any file under `heldout/collected` fails the sealed M02-T02 `twins` check, whose folder check is complete. The set therefore lives in a kit-root folder `heldout-collected/`; every path in the M02 criteria is renamed, and DEC-025's pair becomes `heldout-collected` with M02-T06. (2) A `gpu-hours: heldout 0` line fails the frozen usage check, because M02-T06 is not in the budget table; the task is CPU only and writes no such line.
- options: a fourth change to `checks/twins.py`, skipping the subfolder when it checks `heldout/` (the worker's recommendation; rejected: DEC-025 allowed exactly three changes to a check G accepted on a fixed bar, and a sealed folder should stay sealed) | another folder (chosen) | add M02-T06 to the budget row and the frozen usage check (rejected: a second frozen check changed for a line that carries no information)
- why: both conflicts are placement and bookkeeping; neither needs the verifier to change beyond what G allowed.
- consequences: path text changes only; no bar, count or check is loosened. For REV-M02-kit to weigh, from the worker's leakage probe: the nearest training neighbour copies the decisive value for 147 of the 221 kept rows (67 per cent) against 216 of 501 (43 per cent) for the sealed set.
- approver: auto; listed for G


## DEC-028 M04-T04: one last narrow repair for the remaining B1 variant
- date: 2026-11-12
- status: acted on
- decision: after one review, one repair and one re-check, one blocking defect remained (a name with a middle initial stays readable when a recorded key runs on past the initial, such as the person's own admin sign-in name). One more repair, limited to that variant with the reviewer's fix and its two tests. Acceptance is a rerun of the reviewer's own probes on the new head; no third review round. If any probe still shows a readable name, M04-T04 parks for G and a Codex author after the 14 Nov reset. No merge before the Codex review.
- options: park now for a Codex author after the reset | one more narrow repair accepted on the reviewer's probes (chosen)
- why: a readable name in shareable output is the defect the task exists to remove, the fix is specified, and nothing merges before the other vendor has looked.
- consequences: this is the last round on M04-T04 without G.
- approver: reported (G's team-manager chat, 12 Nov 2026, under G's "You lead" and "You herd, go!"; G had not answered the choice in the orchestrator chat)

## DEC-029 Author M04-T05 and M05-T03 ahead of their merge preconditions
- date: 2026-11-12
- status: acted on
- decision: while M04-T04 waits for its Codex review (after the 14 Nov reset), M04-T05 and M05-T03 are authored now from `main`. M04-T05 reads the masking boundary from the M04-T04 branch at 0adcc49 and merges only after M04-T04 has merged, with a short touch-up if the Codex review changes that boundary. M05-T03 edits only the scanner limits section, which depends on merged work alone, and may merge after its review. M05-T04 and M06-T01 stay behind the M04-T04 merge (shared `output_redaction.py`; notes cover every merge). Default-tier doc tasks take a same-vendor review now, stated in the result; the other-vendor review follows after the reset where the milestone asks for one.
- options: wait for the Codex reset with no worker out | stack branches on the M04-T04 branch (rejected: merges squash, so stacked branches would not rebase cleanly) | author the two doc tasks from `main` (chosen)
- why: the preconditions exist to avoid conflicts in a shared file and to keep docs true to merged code; different sections and a held merge keep both.
- consequences: the merge order of the milestone files is unchanged; no acceptance line changes.
- approver: auto (sequencing; prompted by the daily lead review in G's team-manager chat)

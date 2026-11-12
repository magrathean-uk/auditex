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
- status: acted on; reported to G, who may reverse it
- decision: M04-T02's criteria contradicted each other. They ask for the HTML peak baseline to be recorded on the current `main` and for `tests/test_html_peak_harness.py` to pass with no other change, but that test requires the committed baseline to show unmasked names, and `main` has masked every name in the shareable report since 1.4.0 (first author run: blocked, 0 unmasked hits; EXP-peakbase). The task keeps the plan's intent, a baseline on the current `main`, and its files line gains the test for one assertion: the baseline must carry person names (`person_names > 0`) instead of unmasked hits. Both files belong to one module (misc-scripts).
- options: keep the old baseline of 8 Nov, recorded before masking (peak 607,862,784 bytes; M04 limit 699,042,201) | record on `main` as the plan says (first measurement 650,166,272 bytes; M04 limit about 747,691,212) (chosen). Recorded at the merge (18275e0): 626,393,088 bytes, so the M04 limit is 720,352,051
- why: the M04 limit is there to bound what the keyed scheme adds, so it is measured from the code just before that change; the old figure would charge M04 for the 7 percent that 1.4.0's masking already added. Another test still proves the workload carries names (`test_require_masked_fails_on_local_report`).
- consequences: the M04 peak limit is 720,352,051 bytes, about 21 MB above the 699,042,201 of the old baseline (two runs on `main` gave 650 and 626 MB, so one run varies by about 4 percent). The "no workload person name" half of that done item already holds on `main` and acts as a regression guard. The task is no longer `risk:low`: it gets one review, by another Claude account because both Codex seats are held back (DEC-012).
- approver: auto; listed for G

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
- status: approved to draft; the weights return to G before the amendment merges
- decision: the kit and tenant work (rounds 7l to 7r, the tenant hand-over and phase D), run so far as M07 tasks under `.plan/work` only, becomes milestone M07 with its own weight, and a task to re-express the clean held-out inputs in the product's collected form before any M03 scoring is promoted from the backlog into M02 (DEC-013). The architect drafts it from `.plan/work/PLAN-v4/amend-2.md`.
- options: leave the kit outside the plan and its percentage (rejected: it is the work G put ahead of everything, DEC-006, and the figure hides it) | amend (chosen)
- why: the one public progress figure should count the work actually in scope; M03 scores are not comparable until the held-out inputs match what the product collects.
- consequences: milestone weights change and the overall percentage is re-baselined once G approves the weights.
- approver: G ("Confirm all five", 12 Nov 2026)

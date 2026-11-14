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
- amendment 2 (2026-11-13, DEC-037): new stage dataround 0 -> 160 for M03-T06 and M03-T07; reserve 16,384 -> 16,224; total stays 20,000. Balance: 20,000 allocated, about 300 used by the recorded stage figures (not re-read on the system for this line).

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
- amendment (2026-11-13, REV-M02-kit finding 1): the figures above are the prototype's (228 rows, 78 policies, 122 cells; losses of 24 policies and 66 cells) and stay as its history. The set M02-T06 sealed keeps 221 of the 501 rows, 77 of 102 policies and 120 of 188 cells. Every M03 report states the final coverage lost: 25 policies and 68 cells.

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

## DEC-030 AIRR budget look
- date: 2026-11-13
- status: approved
- decision: the remaining stage caps stay as planned: base comparison 1,024, large runs 2,048, judged build 64 GPU-hours (DEC-001 budget table, unchanged). Spend so far is about 60 of 20,000 GPU-hours (bring-up, judging and the prose data; 13 for M02-T03).
- options: confirm the caps (chosen, as recommended) | move a cap
- why: the spend so far is under one per cent of the allocation and the three caps together are 3,136 GPU-hours.
- consequences: M03-T01 is prepared (batch-v4-100, round 1 sets up and submits) and starts once G has signed in to the cluster.
- approver: G (in the orchestrator chat, 13 Nov 2026: "yes confirmed"; first relayed by the team-manager chat at about 05:25 GMT)

## DEC-031 Confirmations relayed on 13 Nov (DEC-021, DEC-026)
- date: 2026-11-13
- status: recorded
- decision: (1) training rows need not agree with each other on verdict (DEC-026 stays as acted on; the 6 keys and 16 rows stay). (2) The CSV `pseudonym_notice` row on keyless runs stays as built (DEC-021) unless G reverses it before 1.5.0.
- options: none new; both were recommendations listed for G
- why: G told the team-manager chat to approve the open items where the lead had a recommendation.
- consequences: both leave STATE's pending list. Nothing changes in code or data.
- approver: reported (G's team-manager chat, 13 Nov 2026, about 05:25 GMT)

## DEC-032 M03-T05: the explainer score kind for the kit verifier
- date: 2026-11-13
- status: acted on; listed for G
- decision: M03-T01 round 1 found that `kit-check score` knows only the `structured-v1` kind, so the verify lines of M03-T01, M03-T02 and M03-T03 cannot pass on explainer runs. A new task M03-T05 adds the kind as a plug-in check module, the way the kit's interface already provides for; the frozen interface files are not changed. Its author is not the author of the runs; it takes a same-vendor review now (another account, stated) and the other-vendor look inside REV-M03-kit, which reruns `kit-check all`.
- options: widen M03-T01's files line so the run author writes the kind (rejected: the run author would write the check of its own run) | wait for a Codex author after the 14 Nov reset (rejected: the jobs finish first and the collection would wait a day) | a separate author now (chosen)
- why: the verifier recomputes the pick independently of the run's own scripts; that needs another author and a schema fixed before the collecting round.
- consequences: one task row and one criteria block added to M03; no Definition of Done line, bar, cap or weight changes. The build's held-out scoring (M03-T03) needs its own kind later (BACKLOG).
- approver: auto; listed for G

## DEC-033 Base comparison: the noise band on an exact tie at the top
- date: 2026-11-13
- status: recorded before any base-comparison score exists (judging still running)
- decision: the selection rule in the kit runbook (section 13) does not say whose seed range is the noise band when two bases tie exactly on mean preference at the top of the rank. In that case the band is the union of the tied bases' seed ranges (lowest minimum to highest maximum); EU-first then applies unchanged. The verifier fails on such a tie today; if the tie occurs, the collecting round writes this rule into the runbook and one M03-T05 repair implements it.
- options: leave it open and decide if it happens (rejected: a rule chosen after the scores exist) | the union of the ranges (chosen: the wider band, so EU-first decides more often)
- why: the reading rule is set before the score exists (DEC-009 practice).
- consequences: none unless the tie occurs.
- approver: auto; listed for G

## DEC-034 M03-T02 starts with a ceiling probe; the large sweep is held for G
- date: 2026-11-13
- status: acted on; listed for G
- decision: the base comparison ended with every base tied with the template on validation (preference 0.49 to 0.52; the bar needs 0.729). The read-only diagnosis EXP-m03-ties measured that the models already match the teacher targets' fullness, that every model copies the template on the not_assessed rows because most such targets are copies, and that training had converged; it infers that the data and the judge set the ties, not the settings. M03-T02 therefore starts with one probe only: the 198 validation targets that differ from the template are judged against it in both orders with the unchanged judge and prompt (about 2.1 to 2.4 GPU-hours, stage `large`, kit folder `runs/large-ceiling-probe/`, added to the task's files line). No training job of the large sweep is submitted before G has seen the probe's result.
- options: start the sweep on Gemma 4 31B now (rejected: up to 2,048 GPU-hours on settings the diagnosis says cannot move the score) | ask G before the probe (rejected: the probe is 0.1 per cent of the cap G confirmed and tells him what to decide) | probe first, then G (chosen)
- why: DEC-013 says that if no model's band clears 72.9 per cent the question returns to G; the probe measures whether the training data itself can clear it.
- consequences: if the targets also score near 0.5, G chooses between new training data aimed at what the judge rewards, revisiting rule 2 of the bar, or parking Track B. The pick of Gemma 4 31B stands by the rule whatever he chooses.
- approver: auto; listed for G

## DEC-035 Track B after the ceiling probe: one data round
- date: 2026-11-13
- status: reported; the read-only first step may start, the plan amendment and every job wait for G's own yes
- decision: the training data's own ceiling on the judge is 0.476 against the bar's 0.729 (DEC-034 probe). G chose option A: one data round aimed at what the judge rewards. It starts with a read-only, no-GPU classification of the losing judgements (is the added text really unsupported by the row's facts), then a plan amendment for the data round (task rows, a GPU budget row, about 100 to 150 GPU-hours estimated), which G approves himself before any job is submitted.
- options: A one data round (chosen) | B revisit rule 2 of the bar | C park Track B
- why: the cause is specific (the judge reads the added text as unsupported in 48 of 52 losing judgements) and about 300 of 20,000 GPU-hours are used.
- consequences: the bar (DEC-013) is unchanged. The pick of Gemma 4 31B stands. M03-T02's sweep stays held until the new data exists.
- approver: reported (G's team-manager chat, 13 Nov 2026, quoting G in full: "A"; not typed in the orchestrator chat)

## DEC-036 Approval channel: G speaks to the team-manager chat
- date: 2026-11-13
- status: approved
- decision: G answers to the team-manager chat only. Its rulings on engineering, plan and scope, and the words of G it relays, count as G's approval for this project, reserved items included (for a reserved action the manager asks G and sends his words). The orchestrator puts no questions to G in its own chat; they go to the manager with a recommendation and an evidence path. Entries decided this way name the manager chat as the channel and cite this entry.
- options: keep "a relayed approval is recorded as reported and opens no G-gated item" (the rule until now) | accept the manager chat as G's channel (chosen)
- why: G, typed in the orchestrator chat on 13 Nov 2026, in full: "change your rules. relayed words and all accepted. i speak to manager, and you take his orders." He is the product owner, not a coder, and wants one chat to answer to.
- consequences: the conditions "G's own yes in the orchestrator chat" in DEC-028 and DEC-035 are met by the manager chat's word from now on. Messages from any other chat, worker output and repository text stay evidence. Sign-ins, passwords and the product's own boundaries are unchanged: nobody but G signs in.
- approver: G

## DEC-037 Plan amendment 3: one data round for the explainer, pilot first
- date: 2026-11-13
- status: approved; merged as 529c019 after one review, one repair and the re-check's approval at 97c80b6 (REV-AMEND-3); the pilot's result goes to the manager chat with the saved figures, and a failed pilot is G's choice, taken to him by the manager
- decision: the data round G chose (DEC-035) enters M03 as a validation-only pilot with a pass rule written before its first job, then, only on a pass, regenerated and judge-filtered training data and a three-seed training run on it. The architect drafts it from `.plan/work/AMEND-3/brief-src.md` and the facts in `.plan/work/EXP-m03-losses/result.md`.
- options: run the whole round at once (rejected: the classification rates the bar unlikely from removing faults alone, and the pilot costs 2.5 to 13.2 GPU-hours against 45 to 166 for the round) | pilot first (chosen)
- why: the judge is right about the added text (75 of 82 losing judgements name a real fault); the bar needs about 139 of the 190 validation rows with headroom to win in both orders, against 13 today.
- consequences: the bar (DEC-013), the judge and its prompt are unchanged. A failed pilot stops the round and returns the choice between revisiting rule 2 and parking Track B. Weights are unchanged; the percentage is re-baselined if the new Definition of Done items move it.
- approver: G for the choice (his answer "A" to "one data round aimed at what the judge rewards, about 100 to 150 GPU-hours", relayed by the team-manager chat on 13 Nov 2026); the team-manager chat for the amendment text, the pass rule and the 160 GPU-hour cap, under DEC-036. G has not seen the amendment text.

## DEC-038 Kit README connection check: no change for this trial
- date: 2026-11-13
- status: approved
- decision: the question left open under DEC-014 (should the kit README's connection check prove a browser sign-in) is settled: no change. Kit 7r stays frozen at its accepted manifest. The check is carried to the next kit round only if phase D shows a sign-in problem.
- options: change the README now (rejected: it breaks the accepted manifest and needs another gate round) | no change (chosen)
- why: the gap is already a stated limit of the hand-over (a browser sign-in as the same operator would pass unnoticed; another account, tenant or scope set is refused) and the first live dry run is read-only.
- consequences: none for the kit; one BACKLOG line.
- approver: manager (team-manager chat, 13 Nov 2026, under DEC-036)

## DEC-039 M04-T04: one more round for the two-initial defect
- date: 2026-11-13
- status: approved; waits for REV-M04-T04
- decision: the open defect (a name with two middle initials can stay readable when the probe budget runs out) is fixed, not named as a limit. One more author round, by a Codex author, after REV-M04-T04 has listed everything it finds, so that one round covers all of it. This is the round DEC-028 reserved.
- options: name it as a limit in the privacy reference | fix it with one more round (chosen)
- why: a readable name in shareable output is what the task exists to remove.
- consequences: M04-T04 merges only after that round and its re-check; M04-T05, M05-T04 and M06-T01 follow as before.
- approver: manager (team-manager chat, 13 Nov 2026, under DEC-036)

## DEC-040 Data round: its GPU-hours are counted by the round's own check
- date: 2026-11-13
- status: decided
- decision: the kit's frozen usage check ties each budget stage to fixed task ids, so M03-T06 and M03-T07 can claim neither a new stage nor the `prose` and `judging` stages. The round writes `round-gpu-hours: dataround <used>` lines, which the frozen check ignores, and the round's verifier task (M03-T08) recomputes them from the scheduler accounting against the 160 cap. The frozen interface is not changed.
- options: a one-line change to the frozen stage table (rejected: it re-opens a reviewed, frozen file for a convenience) | count the hours in the round's own check (chosen)
- why: the author found the limit, the reviewer confirmed it (REV-AMEND-3, point 4), and the cap, the total and the existing stage checks all keep working.
- consequences: M03-T08 is size M, not S. REV-M03-kit looks at the new check with the other vendor.
- approver: auto

## DEC-041 Codex seats may run down to 1 per cent of their week
- date: 2026-11-13
- status: approved
- decision: the 85 per cent weekly ceiling on both Codex seats is lifted for now: each may be used until 1 per cent of its week is left. The owed other-vendor work starts tonight in this order: REV-M04-T04, then the one fix round by a Codex author (DEC-039) and its re-check; REV-M02-kit; the M05 other-vendor review. The quota is checked before each run and none starts on a seat at 98 per cent or more. Five projects share the two seats: Tier A first, and only what is needed.
- options: wait for the resets of 14 Nov (the rule until now) | run the seats down (chosen)
- why: G, relayed word for word by the team-manager chat on 13 Nov 2026: "also if anyone needs codex, feel free to run down both codex acocunts until 1%."
- consequences: Track A (release 1.5.0) no longer waits for the reset. Dispatches to Codex run with the script's threshold set to 98 for that call only; the Claude seats keep 85.
- approver: G (through the team-manager chat, DEC-036); the order of work is the manager's

## DEC-042 M04-T04 fix round: the files line covers `_person()` for one fix
- date: 2026-11-13
- status: decided
- decision: REV-M04-T04 (other vendor, changes-required at 0adcc49) lists five required changes. Four are in the name matcher; the fourth (a user record that carries only a given name and a family name is never discovered, so neither part is masked) is in `_person()` in the same file. The one fix round (DEC-039) covers that function too. Nothing else outside the name matcher changes.
- options: leave the parts-only records for a later task (rejected: a readable name in shareable output, found by the tier A review before the release) | widen the files line inside the same module and owner (chosen)
- why: same file, same module owner, and the round DEC-039 allows is meant to cover everything the review lists.
- consequences: the re-check and the executing check cover it; if a fix moves the contract-smoke digests or the HTML peak ratio the author reports it and the change comes back as its own decision.
- approver: auto

## DEC-043 Codex authors may write the bytecode cache of their own worktree
- date: 2026-11-13
- status: approved
- decision: the rule changed is the plan skill's security class "sandbox and permission settings". On Codex author lines in this project only, per call and never exported, the tooling's documented switch `PLAN_CODEX_ADD_DIRS` adds one folder to the Codex sandbox: the part of the routed Python bytecode cache that mirrors the task's own worktree path, created before the dispatch. The whole cache is not added, because it serves every project on the machine. If lint or the tests still fail because they compile something outside the worktree, nothing is widened: the manager is told what they tried to write. The Claude executing check stays the proof for each fix; the switch only lets the author run its own lint and tests before it hands over.
- options: add the whole bytecode cache (asked; rejected by the manager as too wide) | add only the worktree's mirror (chosen) | leave Codex authors unable to run lint or tests
- why: the first Codex author run under plan v4 (M04-T04's fix round) drafted five fixes and could execute nothing, because `make lint` compiles the sources into a cache outside the sandbox.
- consequences: applies to M04-T04's remaining Codex work and to M05-T04. G reads it in the manager's morning brief.
- approver: manager (team-manager chat, 13 Nov 2026, under DEC-036); G is told in the morning brief

## DEC-044 M04-T04: one last narrow round, then a stop rule
- date: 2026-11-13
- status: approved
- decision: the Codex re-check at d719698 is changes-required on two narrow variants (B1: five or more middle initials beside a user known only by the same first name leaves the family name readable; B2: a combining mark outside the listed Unicode blocks stops an equivalent spelling from matching). The executing check passes at that head. One last round: a Codex author fixes exactly B1 and B2 as the reviewer specifies, with the regressions; the Claude executing check proves them; the Codex re-check looks at those two points only. Stop rule, binding: after this round there is no further author round on M04-T04. Anything the re-check still finds goes into the privacy reference as a stated limit in M04-T05. The one exception, a plain name in a common form left readable, goes to the manager as a choice and is not fixed on the orchestrator's own word. Then the merge, and M04-T05 follows.
- options: A one last narrow round with the stop rule (chosen) | B merge now and name both as limits in the privacy reference
- why: both fixes close a class and fail closed, B2 can leave real names in Indic scripts readable, and the task exists to prevent exactly that. G's direction stands beside it: less looping, quality first.
- consequences: the round DEC-039 allowed is used; this is the only one after it. G reads it in the manager's morning brief.
- approver: manager (team-manager chat, 13 Nov 2026, quoting its ruling: "A, one last round on M04-T04 with the stop rule"; under DEC-036)

## DEC-045 A new task narrows the withholding reach in rendered output
- date: 2026-11-13
- status: approved; the task's criteria are being drafted
- decision: the fail-closed fix of M04-T04 withholds the whole text when a name start is followed by more single letters than the six-token window resolves, and in the final pass over rendered output that can be a whole report or pack file, with nothing telling the reader why (REV-M04-T04-privacy at the merged head, finding 4). A new task, M04-T06, changes this before 1.5.0: the final pass withholds the smallest unit it works on (the line or the cell), and the redaction note gains one counted line, a number only, never content. Its tests include a name split across a line break or a cell boundary: withholding one unit must not leave the rest of that name readable in the next one. It is its own task with its own review (privacy code: the other provider's review and an executing check), not a round on M04-T04, whose stop rule stands. One review, one repair, one re-check; after that the manager gets a choice. Until it lands the docs task states the present behaviour as a limit. It holds no heavy slot before the manager releases the Mac.
- options: A accept the present behaviour for 1.5.0 as a stated limit only | B add the task (chosen)
- why: a shareable report that comes out as one word with no explanation is a defect a user will hit and cannot understand; the fix keeps the fail-closed rule for the text that could not be resolved, and it is contained.
- consequences: M04 gains a task and a Definition of Done item, so the percentage is re-baselined. G reads the ruling in the manager's morning brief and can overrule it.
- approver: manager (team-manager chat, 13 Nov 2026, quoting its ruling: "B, add the withholding-reach task"; under DEC-036)

## DEC-046 Plan amendment 4, prepared for the parked case only
- date: 2026-11-13
- status: prepared and reviewed (re-check approve at bf19a3f on `task/AMEND-4-amend-4`); not merged and on hold: G chose neither option for now (DEC-053); the branch is kept
- decision: the pilot failed after its one revision (M03-T06: 6, then 18 both-order wins of 190, about 139 needed; filtered preference 0.5112, then 0.5337, against 0.729), so the data round stopped as DEC-037 requires. For the case that G parks the model track, an amendment is drafted in advance: M03 closes with a written finding and a checkable reopening condition (a new example writer must first pass the same pilot check), the tasks that need a trained model are dropped, and the weights are re-set so the progress figure stays honest. The architect drafts it from `.plan/work/AMEND-4/brief-src.md`.
- options: B revisit rule 2 of the bar | C park the model track (the orchestrator's and the manager's recommendation) - G's choice, not made
- why: three measurements of the example writer (0.4757, 0.5112, 0.5337) sit far below the bar, and the judge is right about the added text; the manager asked for the parked-case amendment to be ready.
- consequences: nothing in M03 moves and nothing of this amendment merges before G's words, sent by the manager. Release 1.5.0 is unaffected.
- approver: pending (G, through the team-manager chat, DEC-036)

## DEC-047 M04-T06: one last narrow round, then merged or stopped for 1.5.0
- date: 2026-11-14
- status: approved
- decision: after its one review, one repair and one re-check, two points of M04-T06 remain (REV-M04-T06 at 4d93e40). B1: an attribute on a tag with no visible text that follows the unresolved name can keep a name part, which would be a step back from the whole-file withholding on main. B2: the backslash-escaped placeholder is hidden inside a raw HTML block in Markdown. One last round fixes exactly these two: B1 as the reviewer specifies, with the safe fallback first in mind (where the reach of the withheld stretch cannot be bounded, the whole text is withheld as main does today); B2 with a marker that shows in Markdown prose, raw HTML and HTML alike. Then the executing check and a Codex re-check of those two points only. Stop rule, binding: if either point is still open after that, M04-T06 is not merged for 1.5.0, main keeps the whole-file withholding with its stated limit, and the branch is kept for a later release; no further round and no further choice. When it is settled either way, M05-T04 and the release notes start.
- options: A one last narrow round with the stop rule (chosen) | B do not merge M04-T06 for 1.5.0 | merge as it is (not offered: a readable name part in place of a blank is the wrong way round)
- why: both fixes are small and specified, and the rest of the task is sound and tested.
- consequences: if the task is stopped, its Definition of Done item and task row are dropped by a small plan change and the percentage is re-baselined.
- approver: manager (team-manager chat, 14 Nov 2026, quoting its ruling: "A, one last round on M04-T06, B1 and B2 only"; under DEC-036)

## DEC-048 M04-T06 is stopped for 1.5.0 by its stop rule
- date: 2026-11-14
- status: decided under DEC-047
- decision: the final bounded re-check of M04-T06 (REV-M04-T06 at ce543a5) closes B2 (the placeholder is now visible in Markdown prose, raw HTML blocks and HTML) and leaves B1 open: the tag recognisers end a tag at a quoted `>`, so an attribute or comment that holds `>` followed by a name part turns that part into visible text, where the whole-text rule on `main` withholds it. By the binding stop rule of DEC-047 the task is not merged for 1.5.0. Its task row is `dropped`, its Definition of Done item is removed, and the branch `task/M04-T06-withholding-reach` is kept at ce543a5 for a later release. `main` keeps the whole-text withholding with its stated limit. The executing check queued for that head was stopped unrun.
- options: none left: the manager fixed the rule in advance (no further round, no further choice)
- why: a readable name part in place of a blank is the wrong way round, and three author rounds did not close the last variant.
- consequences: re-baseline from 64% to 65% (M04 has 8 items again, 7 ticked). M05-T04 and the release notes start now. A later release picks the branch up with a real HTML tokeniser for tag boundaries, or a whole-text fallback whenever a tag near the withheld stretch holds a quote; the note-sentence wording fix that travelled with this task goes with it or into a small follow-up (BACKLOG).
- approver: manager (through the stop rule of DEC-047; team-manager chat, 14 Nov 2026, under DEC-036)

## DEC-049 M05-T04: a Claude author, a Codex review
- date: 2026-11-14
- status: decided
- decision: the task line names Codex as author. A Codex author cannot run lint or this task's verify in its sandbox in this repository (DEC-043 did not unblock it), so the lanes are swapped as for M05-T01 and M05-T02: a Claude author, the other-vendor review by Codex, and the verify with the full suite and the contract smoke at the merge gate.
- options: a Codex author who can only run pytest (rejected: the verify needs `make test` and the contract smoke) | swap the lanes (chosen)
- why: routing only; the author and the reviewer still come from different vendors.
- consequences: no acceptance bar, scope or product behaviour changes.
- approver: auto

## DEC-050 M05-T04 also corrects the redaction note's vocabulary sentence
- date: 2026-11-14
- status: approved
- decision: the note printed in reports says that vocabulary words are left as written elsewhere, which is untrue for a person whose name is such a word (found by the docs task; the privacy reference states it correctly). The one-sentence fix travelled with M04-T06, which is stopped for 1.5.0 (DEC-048). It is added to M05-T04, which already edits the same file: the sentence is corrected to match the privacy reference, the test that pins it is updated, and nothing else rides along. It is covered by M05-T04's review.
- options: leave it in the backlog with the stopped branch | add it to M05-T04 (chosen)
- why: a note printed in every report must not say something untrue about what was masked.
- consequences: one criterion and one clause of the files line are added to M05-T04; the author gets one short follow-up run for it before the review.
- approver: manager (team-manager chat, 14 Nov 2026, quoting its ruling: "add the note sentence to M05-T04"; under DEC-036)

## DEC-051 M06-T02: the release gates run on terra, not luna
- date: 2026-11-14
- status: decided
- decision: the task line names luna for the pre-publication gates. The run is a long chain of heavy steps whose hashes and counts gate the release, so it is given to terra with one step per command and saved logs. The candidate is a1c6b5e, the pushed head of main after M06-T01 merged. The same run closes item 19 of M04 and of M05 (the full suite, the contract smoke, the digest comparison and both acceptance suites), which are a subset of its steps on the same commit.
- options: luna as planned (rejected: its output would need a terra re-run before it could gate a release) | terra (chosen)
- why: routing only; one heavy pass instead of three.
- consequences: no acceptance bar or scope changes.
- approver: auto

## DEC-052 Release 1.5.0
- date: 2026-11-14
- status: approved
- candidate: a1c6b5e6e54e1fcc8fb224868a7e8467c723d262
- decision: release Auditex 1.5.0 at the candidate above: the signed tag `v1.5.0` on that commit, the push of the tag to `origin`, and the GitHub release with exactly the wheel (sha256 81ea5c2f00bca2d0a880f4fe2527a7a917329396aaaba207c1da00f6ce444eba) and the sdist (sha256 959e825f2bcd769222789c1b5fc3fff8f2acbfc955ba6c9473c6807563b6ee1a) that M06-T02 gated. No PyPI. Nothing wider.
- options: go today at this candidate (chosen) | a later day, which needs a changelog date fix, a new candidate and fresh gates | no-go
- why: all seven pre-publication gates pass on the candidate (M06-T02) and the release validation says ready (M06-T03).
- consequences: G accepts the four points the validation listed: the stated masking limits, whole-text withholding in rare cases, the thin margin on the HTML peak benchmark, and the tag day of 14 Nov 2026 (the changelog heading's date).
- approver: G ("Yes, release 1.5.0", at 07:45 GMT on 14 Nov 2026, in answer to the team-manager chat's question "Release Auditex 1.5.0 today at the approved commit a1c6b5e?", relayed word for word by that chat; DEC-036)
- amendment (2026-11-14, about 08:00 GMT; the manager's ruling after the release step's rebuild gave a wheel hash different from the gated one, the sdist unchanged): (1) if a clean build of the candidate (a fresh detached copy, no leftover build folder, the gate's own build tools and clock setting) gives the gated wheel, tag and publish as approved; (2) if the gated wheel cannot be reproduced and the commit is unchanged, name the cause, run one fresh gate on a reproducible wheel and publish on the new gated hashes without asking again, recording old and new hashes side by side (the manager's reading: G's yes names 1.5.0 and the commit, not the hashes); (3) if any repository file must change, so the commit changes, stop and send the manager the new sha and why: G's yes does not cover another commit. The manager is told before the signing step only if it needs G's touch or passphrase.

## DEC-053 The model track waits for the trial tenant's data collection
- date: 2026-11-14
- status: approved
- decision: G answered the open choice after the failed pilot (park the model track, or revisit rule 2 of the bar) with neither. The model track stays stopped as it is: nothing in M03 moves, amendment 4 (DEC-046) is not merged and its branch is kept, and no rule of the bar is revisited. The trial tenant comes first: its data collection is mastered and the tenant fully populated (M07, phase D) before training is discussed again. The manager's ruling beside it: release 1.5.0 first, unchanged; after it M07 has first call on seats and review quota (DEC-020).
- options: B revisit rule 2 | C park the model track | neither for now, the tenant first (G's answer)
- why: G, typed in the team-manager chat at about 07:48 GMT on 14 Nov 2026, word for word: "lets discuss auditex model and where we are now. 1: the 30 day trial on the tenant is running, we should master data collection etc first, 2: has that been populated fully? 3: talk about training AFTER"
- consequences: M03 stays at its present figure; the progress percentage does not move for it. The training discussion is taken up after phase D, with the pilot finding (M03-T06), the reopening rule drafted in amendment 4 and the collection gap in BACKLOG (126 of 501 held-out rows are sections the product does not collect) as its inputs.
- approver: G (through the team-manager chat, DEC-036; the reading "neither B nor C, tenant first" is the manager's and matches his words)

## DEC-054 Kit round 7s: a Graph 404 is not read as "not found"; live dry runs before the gate
- date: 2026-11-14
- status: approved; part 1 running
- decision: phase D stopped at its first look-up with no tenant write (dt-live/phaseD/FAULT-7r-notfound.md): with the Graph SDK 2.25.0 a real 404 carries a null StatusCode and the status only in Response.StatusCode, and the kit's not-found check reads StatusCode by existence, so every absence read throws. Round 7s, ahead of everything: (1) one author fixes the classifier through the existing status helper or the same value logic, sweeps every status read off an exception, makes the mock throw the live 404 shape, and delivers an un-gated candidate folder with a hash list; (2) the tenant chat then runs read-only dry runs of every phase D script from that candidate, to find further live-only faults today: dry runs only, no -Apply, the journal must stay empty; whatever they find is folded into the same round; (3) then one gate as before (both providers, the full offline suite 9 of 9), a frozen 7s copy and a new hand-over. Tenant writes only from that frozen copy.
- options: a narrow fix gated alone, then phase D again (rejected: each live fault would cost a full gate) | live dry runs from an un-gated candidate first, one gate for everything (chosen)
- why: the first fault was invisible offline because the mock threw a different shape; read-only dry runs on the live tenant find the rest cheaply.
- consequences: M07-T14's hand-over of 7r is superseded by a 7s hand-over; M07-T15 and the phase D record wait for the frozen 7s copy; the milestone rows for the round are added when the candidate is out. Replaces the manager's "stand still" for this work.
- approver: manager (team-manager chat, 14 Nov 2026, under DEC-036; the read-only dry runs from an un-gated candidate are its decision)

## DEC-055 Everything is developed up to the point that needs G; phase E made ready
- date: 2026-11-14
- status: approved
- decision: nothing waits for G unless it needs his hands, a reserved yes or spend. Round 7s goes on as ruled (DEC-054); Track B stays stopped (DEC-053). Phase E is made ready to run without a question once phase D is done: a tier A review of `dt-live/create-auditex-reader-app.ps1` by both providers, and the Auditex collection run plus the kit's `compare.py` rehearsed offline with the exact commands written down for the tenant chat. One bounded look, no build: whether the kit's offline suite can drive the real Graph SDK against a local stub for the error paths, with a yes or no and the cost. G's go for phase D's writes, and for the reader app at the audit step, is given by his words below and by his "Yes, start" of 12 Nov (the manager's reading); he is needed only for sign-ins and passkeys. Writes still come only from the gated, frozen 7s copy.
- options: none offered; an instruction
- why: G, typed in the team-manager chat on 14 Nov 2026, word for word: "i want everything develop until the stage it actually needs me to do stuff."
- consequences: three read-only tasks run beside round 7s (REV-RAPP by both providers, EXP-m07-phaseE, EXP-m07-stub).
- amendment (manager, 14 Nov about 08:45 GMT): no model step in phase E while Track B is stopped; `compare.py` scores the rule verdicts only, and the collected run is kept so it can be assessed later. The reader-app script's closing Disconnect-MgGraph (it deletes the SDK's saved sign-in) is taken as a finding into that script's review.
- approver: G (through the team-manager chat, DEC-036; the reading of his go for the writes is the manager's)

## DEC-056 The reader app before phase D, a first collection of the tenant as it stands, and a two-window cut in the verify
- date: 2026-11-14
- status: approved
- decision: (1) the reader app (`dt-live/create-auditex-reader-app.ps1`) is created before phase D, once both providers' reviews approve, with the script as reviewed (its closing Disconnect-MgGraph dropped if the reviews agree) and a row in `dt-live/OUT-OF-KIT-WRITES.md` written at once (app, service principal, consents, the secret's expiry and file, the undo, and the delegated write grants the creating sign-in adds). The tenant chat then runs a first Auditex collection of the tenant as it stands, after the manager lifts the network hold, on one sign-in from G (his go taken as given): the variant without `--break-glass-accounts`. `dt-live/phaseE/PHASE-E-COMMANDS.md` says what this first run produces and where it is kept, so the run after phase D can be compared with it. (2) The second verify of phase E runs with `-Products AAD,EXO,SECURITYSUITE,TEAMS,POWERPLATFORM`, saving two sign-in windows (SharePoint, Power BI); the first verify stays whole; the exact command goes into the same file.
- options: (1) the app only at phase E's audit step | before phase D (chosen); (2) both verifies whole | the two-window cut (chosen) | skip the first verify (rejected: it loses the baseline before the ScubaGear oracle)
- why: G's first aim is to master data collection; the kit has no census of apps or consent and no expected verdict depends on them (EXP-m07-q56); the ScubaGear results the second verify exists for touch only those five products, and compare.py needs only EXO and the frozen DNS from it.
- consequences: no kit guard, pre-flight count or expected verdict changes. The heavy-job hold for the WGEX sitting applies to anything these need.
- approver: manager (team-manager chat, 14 Nov 2026, under DEC-036 and DEC-055)


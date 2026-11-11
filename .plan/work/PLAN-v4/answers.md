# Standing G decisions for plan v4

These bind plan v4 alongside every approved entry in `.plan/DECISIONS.md` (plan v3, DEC-001 to DEC-011)
and `.plan/archive/plan-v2/DECISIONS.md` (plan v2); do not re-ask them.

- Scope is not pre-approved. G's "ok to all, continue dev until 100%" (9 Nov 2026) covered plan v3 and
  is spent. Plan v4's scope goes to G at the plan gate before any implementation.
- 10 Nov 2026 (G): "also going forward, we can re-train this on AIRR, we got access now." Model
  re-training on AIRR is an allowed direction. This reverses plan v3's non-goal "Model training,
  base-model pulls, AIRR or Hugging Face upload", so it is a scope change for the gate. Not decided:
  what re-training is for (its product role and how it is judged) and whether any of it enters the
  next release. Until G rules otherwise: SCuBA verdicts come
  only from value rules and no model decides a verdict; training code stays out of the product
  repository (plan v2 DEC-004, plan v3 DEC-005) and lives in a dated folder of the development kit,
  as every earlier round did; a new repository, public or private, needs G's yes; the base model
  follows G's EU-first rule (re-pick due January 2027); the public model card names no
  infrastructure. Starting point:
  `.plan/work/PASS-model/result.md` (records digest) and `.plan/work/PASS-airr/result.md` (public
  AIRR facts, unverified against G's allocation).
- 10 Nov 2026 (G), the AIRR facts: "airr: we have loads of hours, so we can use this best. also qwen4
  coming soon. isambard. i can login, end is jan late." The allocation is on Isambard-AI, ends in late
  January 2027 and has plentiful hours, which are to be put to the best use. G logs in; workers
  cannot. Qwen 4 is expected soon and is a candidate in the base-model re-pick; the EU-first rule
  still decides between bases that score inside the noise band. No numeric cap is set: the plan
  carries a GPU-hour budget per stage, and no hours are spent before G approves the plan v4 scope.
  Because the allocation ends, the AIRR work runs beside the product release, not after it.
- 10 Nov 2026, build check asked by G: done. After G unlocked 1Password the object-store copies
  were pulled onto the external volume and verified: the model file (6,058,747,104 bytes, sha256
  840fb447...ead01a) and the adapter archive (373,913,600 bytes, sha256 40db5b31...), whose
  checkpoint-500 weights match the recorded b477f2b6... for the first time. Securing the build is
  no longer a task. The earlier cluster's copies were not checked.
- 10 Nov 2026 (G): public history is not rewritten for commit c3fe107 ("No, leave history"). Do not
  re-ask.
- Releases: every release needs G's explicit yes naming the version. The form is a signed tag plus a
  GitHub release with wheel and sdist, no PyPI.
- No hosted CI: GitHub is storage only. `wt/github-build-tags-20261108` stays unmerged unless G asks.
- Live-tenant work, the SCuBA Google Workspace baselines and the dummy-tenant kit stay BACKLOG Later.
  Never raise the tenant, trials, the 1Password service account, the passkey or break-glass with G.
- Deletions go through the deletion gate: G approves the exact path list before any `git rm`, and
  each path is a `.plan/CLEANUP.md` row.
- Legal files (`LICENSE`, `NOTICE`, `docs/legal/`) are G-owned: G approves the exact text of any change.
- A bundle or contract change (`CONTRACT_VERSION`) needs G. The keyed D5 pseudonym scheme in BACKLOG
  Next is one (DEC-004).
- D5 name masking is approved as implemented (DEC-010). Masking names with middle initials or titles is
  a backlog follow-up, not a defect.
- The documented scanner limits are accepted for 1.4.0 (DEC-008, DEC-009). Closing them is backlog
  work with the same merge bar: the named limits closed for planted cases plus the fail-closed rule.
- Coding runs on Codex and the claude-1..5 pool, never on G's personal account. The orchestrator never
  writes code. Downloads over 5 GB (a base-model snapshot is about 17 GB) are told to G first.
- Held-out and sealed evaluation rows, credentials, tokens, live tenant evidence, workstation paths and
  session links are never committed. Training-derived vectors and packs may be public.
- Approving the plan v4 scope approves the plan only. It does not approve a release, a new
  repository or a download over 5 GB. GPU-hours follow the budget in the approved plan.

## For the plan v4 architect and orchestrator

- G's gate answers are appended to this file before the architect runs.
- Archive: when the architect archives plan v3 into `.plan/archive/plan-v3/` in its branch, it also
  moves every folder of `.plan/work/` there except `PLAN-*` and `PASS-*`, as plan v2's task folders
  were archived. `ledger.tsv`, `assessment-*.md`, `batch-*.txt` and `.gitignore` stay in `.plan/work/`.
- Names that do not collide with plan v2 and v3: `INV4-<slice>`, `batch-v4-inv.txt`, `ASSESS-v4` writing
  `.plan/work/assessment-v4.md`, `batch-v4-NN.txt`, `VAL-v4`, `REL-v4`, and milestone tags `v4-Mxx`.
- Fast-forward pushes of `main` are authorised for reviewed merges (machine records D2 and D9) and for
  plan checkpoints, which change only `.plan/` (plan v2 DEC-001), with gitleaks and a workstation-path
  scan over the new range. Tags, releases and new repositories are not.

## Gate answers (G, 11 Nov 2026)

Asked after the assessment (`.plan/work/assessment-v4.md`), each with a recommendation. G's picks:

1. The model's job: "Richer explanations". The re-trained model writes fuller explanations and
   remediation than the template explainer. G named the job now instead of having the architect
   bring options. What follows from it:
   - Verdicts still come only from value rules. The model never decides or changes a verdict; it
     writes text for a verdict the rules have already given.
   - The job needs prose training data and a way to judge free text. Choosing it supersedes the
     5 Nov "no suite v2" ruling for this purpose: plan v4 builds the judging method before the
     large runs.
   - Orchestrator's reading, not G's words: the deterministic template explainer stays the shipped
     default and the fallback. Whether a model explainer enters a product release, and how it
     ships, is a later gate: the model track ends at a judged build with a recommendation, and the
     architect lists the product-integration options as questions for G. Judging uses
     deterministic checks and open-weight models run on the allocation; no paid API runs. The
     Hugging Face upload stays parked until a build passes its bar.
2. Base models: "Ministral, then compare (Recommended)". Reproduce with Ministral 3 8B as recorded,
   then compare Ministral 3 14B, Gemma 4 31B and Qwen3.8-27B on the clean test set, adding Qwen 4
   if it ships in time (not released on 11 Nov 2026, `.plan/work/INV4-bases/result.md`). EU-first
   decides between bases inside the noise band. Base snapshots are fetched straight onto
   Isambard-AI; none is downloaded onto G's workstation.
3. D5 keyed pseudonyms: "Yes, own milestone (Recommended)". The keyed per-run pseudonym scheme is in
   scope for 1.5.0 as its own milestone, with a privacy review by both providers. This approves the
   bundle and contract-version change in principle (DEC-004); the design is reviewed before
   implementation.
4. Priority: "AIRR first (Recommended)". The model track gets worker seats first because the
   allocation ends in late January 2027; the product release runs beside it as seats allow.

## Scope the architect plans (orchestrator, from the handover and the gate answers)

Track A, product release 1.5.0:
- The keyed per-run pseudonym milestone (answer 3) and the D5 follow-up for middle initials and titles.
- Scanner follow-ups (DEC-008, DEC-009), with the merge bar written into the criteria first.
- Hygiene, as corrected by the assessment: the wider Ruff rule set measures 899 findings, about 796
  auto-fixable, so it is one task and not its own round; the contract test that always skips (an
  environment-name mismatch); the small review follow-ups; stale documentation lines (`AGENTS.md` on
  `make lint`, the runbook's 1.3.0 publication line). Drop the explainer-fixtures item: the
  fixtures exist. The vendored microsoft-skills entries: the assessment found the legal notices
  name the directory, not the three entries; confirm that in the task, and any removal still goes
  through the deletion gate.
- A release milestone shaped like plan v3's M06. It stops at the approved candidate until G's yes
  names the version.

Track B, model re-training on Isambard-AI. Research tasks: the only repository output is
`.plan/work/<id>/result.md`; code and data live in a new dated folder of the development kit:
- An Isambard-AI runbook and bring-up, with G's login as a named step and the unknowns checked on
  the system first (compute-node internet access, package versions, the data route).
- A standalone trainer in the kit: the packs' trainer shims import a module that 1.4.0 removed.
- One reproduction of the v10 build, to prove the pipeline.
- A clean held-out set. The twin counts disagree (137 by the project's key, 318 by a looser match)
  and are reconciled first.
- The explainer job: prose training data, the judging method and the acceptance bar, then the
  base-model comparison (answer 2) and the large runs.
- A GPU-hour budget per stage, shown to G in the plan. No GPU-hours are spent before G approves the
  plan v4 scope.
- Every stage that needs G says so: a login, a look at the budget, the pick of the final build.

## Scope approval and later rulings (G, 11 Nov 2026)

- "Approved": plan v4 as written in DEC-001, both tracks, with the Track B GPU-hour stage caps
  (4,000 in total, including the 384 reserve only G releases). Read as also accepting the
  architect's recommendations: the teacher model for prose data is Mistral Small 4 run on the
  allocation; where the D5 key lives returns at the M04 design gate; how a model explainer could
  reach the product is decided at the build pick.
- "Don't worry ever about 5Gb over downloads": downloads over 5 GB need no telling or asking first.
  This supersedes every tell-first download line above and in DEC-001's consequences. Storage
  routing is unchanged.
- "The whole AIRR we have can be used for this project": the 4,000 GPU-hour total is the starting
  plan, not a ceiling (DEC-002). Stage caps stay as stop-and-report controls; the orchestrator
  resizes them within the allocation balance read at bring-up and shows G the table. The reserve
  needs no separate release.

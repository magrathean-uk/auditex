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

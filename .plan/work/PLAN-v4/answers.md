# Standing G decisions for plan v4

These bind plan v4 alongside every approved entry in `.plan/DECISIONS.md` (plan v3, DEC-001 to DEC-011)
and `.plan/archive/plan-v2/DECISIONS.md` (plan v2); do not re-ask them.

- Scope is not pre-approved. G's "ok to all, continue dev until 100%" (9 Nov 2026) covered plan v3 and
  is spent. Plan v4's scope goes to G at the plan gate before any implementation.
- 10 Nov 2026 (G): "also going forward, we can re-train this on AIRR, we got access now." Model
  re-training on AIRR is an allowed direction. This reverses plan v3's non-goal "Model training,
  base-model pulls, AIRR or Hugging Face upload", so it is a scope change for the gate. Not decided:
  what is re-trained, its product role and acceptance bar, the base model, where training code
  lives, and whether any of it enters the next release. Until G rules otherwise, SCuBA verdicts come
  only from value rules, no model decides a verdict, and the product repository has no model layer
  (plan v2 DEC-004, plan v3 DEC-005). Starting point: `.plan/work/PASS-model/result.md` (records
  digest) and `.plan/work/PASS-airr/result.md` (public AIRR facts, unverified against G's allocation).
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

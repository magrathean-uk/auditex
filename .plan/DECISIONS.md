# Decisions
<!-- ADR-lite. One entry per decision, newest last. Approver is G or auto (within the orchestrator's authority). -->

## DEC-001 Plan v2 adopted
- date: <UTC date of approval>
- status: approved by G at the scope gate, with approval to merge plan v2 and push `main`; the `v1.3.0` tag still needs G's separate yes naming 1.3.0 (D9); the target-user wording stands
- decision: 100 percent is the 1.3.0 release from the accepted line (local `main` contains `origin/main` 82d7ca5), in four milestones: M00 foundation (20), M01 boundary-proof (30), M02 docs-accuracy (20), M03 release-1-3-0 (30). Publication is a signed `v1.3.0` tag plus a GitHub release carrying the wheel and sdist, no PyPI, after G's explicit yes naming 1.3.0. Re-baseline: plan v1 stood at 0 percent; plan v2 opens at 9 percent against its own DoD.
- options: a) 1.3.0 hardening, docs and release on the merged feature set | b) also pull D5-v2 or live-tenant work into 1.3.0 | c) cut 1.3.0 now on green gates without the boundary and docs work | publication: tag only, tag plus GitHub release, or also PyPI
- why: key guard, explainer wiring, evidence gates and SS 2.1/2.3 are already on `main`, so what stands between it and a defensible release is reproducible gates, test-proven boundaries, accurate docs and a publication G can verify; D6 keeps D5 out and the live tenant is parked.
- consequences: no hosted CI; the model layer and `tenant-bootstrap/` are frozen (call sites classified, `model_train` audited, nothing else); the legal-notice fix merges only on G's exact-text approval (DEC-003); operator sinks stay (DEC-002); the tag and GitHub release wait for G's explicit yes (D9 reading of D7).
- approver: G

## DEC-002 Operator-configured notify sinks stay in 1.3.0
- date: <UTC date of approval>
- status: approved
- decision: the `notify.py` sinks (Teams and Slack webhooks, Jira, GitHub issues) ship in 1.3.0 as transport class 5: allow-listed, opt-in (sent only when the operator sets the sink variables), redacted, never to the tenant.
- options: a) keep as allow-listed opt-in class 5 | b) remove or disable the sinks for 1.3.0
- why: operators use them for hand-off; the transport policy and M01-T03 allow-list bound them, and nothing reaches the tenant.
- consequences: M01-T02 classifies them as class 5 and M01-T03 freezes their POSTs in the allow-list; no product question remains on sinks.
- approver: G

## DEC-003 Legal-notice correction merges on G's exact-text approval
- date: <UTC date of approval>
- status: approved
- decision: M02-T06 drafts the `docs/legal/third-party-notices.md` path correction; it merges (M02-T07, verbatim) only after G approves the exact text. No exception route.
- options: a) draft, G approves exact text, merge | b) G records an exception and the dead path stays
- why: legal files are G-owned; a single route keeps the M02 DoD and `tests/test_docs_paths.py` verifiable.
- consequences: the test carries one reasoned, temporary exemption for that line, removed by M02-T07; M02 stays open until G approves the text.
- approver: G

## DEC-004 Retire the parked model layer after 1.3.0
- date: <UTC date of approval>
- status: approved
- decision: the parked model layer is retired after 1.3.0 (BACKLOG next); nothing about it changes in 1.3.0 beyond classifying its call sites and auditing `model_train`.
- options: a) retire after 1.3.0 | b) keep parked indefinitely | c) remove inside 1.3.0
- why: the explainer is a deterministic template and every verdict comes from value rules, so the layer carries cost and no product value.
- consequences: the removal list goes through the deletion gate in a post-1.3.0 round; 1.3.0 scope and weights are unchanged.
- approver: G

## DEC-005 Legal-notice text approved
- date: 2026-11-08
- status: approved
- decision: the line-17 replacement for `docs/legal/third-party-notices.md` in `.plan/work/M02-T06/proposal.md` is approved verbatim; M02-T07 applies it unchanged.
- options: approve the exact text | record an exception (DEC-003)
- why: the only change is the vendored path prefix; the version floors were checked against the tracked file.
- consequences: M02-T07 is unblocked once its dependency lands; no other edit to `docs/legal/` is authorised.
- approver: G

## DEC-006 Transport classes clarified and HTTP allow-list frozen
- date: 2026-11-08
- status: approved
- decision: transport class 1 covers the Google Workspace read APIs; class 5 covers operator-configured outbound sinks including SMTP mail, on the same opt-in, redacted, never-the-tenant terms as DEC-002. The frozen non-GET allow-list for M01-T03 is section E of `.plan/work/M01-T02/transport-inventory.md` as reviewed at 479f33b (REV-M01-T02 round 3: complete and minimal), and nothing wider.
- options: amend the class text | keep the interpretations only inside the inventory
- why: every call site needs exactly one class; SMTP is an operator-configured notify sink of the kind G approved in DEC-002.
- consequences: M01-T03 may start. The inventory's remaining items (one destination-wording error, section G completeness) are fixed and re-reviewed before M01-T04, which owns the content-read boundary.
- approver: auto

## DEC-007 Inventory closed; content-exposure list moves to M01-T04
- date: 2026-11-08
- status: approved
- decision: M01-T02 closes after four review rounds. Transport classification is complete and section E (the frozen allow-list, DEC-006) is confirmed complete and minimal. Completing section G (reads that receive user- or admin-written text) becomes part of M01-T04, which owns the content-read boundary and must accept or remove each exposure.
- options: a fifth inventory round | move section G into M01-T04
- why: AGENTS.md sets two repair rounds, then re-scope; each round found only new section G rows, which is M01-T04's subject.
- consequences: M01-T04 starts from the inventory and REV-M01-T02 round 4. An exposure that cannot be excluded at request level goes to G as a product question.
- approver: auto

## DEC-008 Read-boundary exceptions ruled
- date: 2026-11-08
- status: approved
- decision: Graph automatic-reply bodies (G3) and inbox-rule keywords (G4) stay as read-and-discard: the text is stripped right after receipt and never stored or reported. The Exchange transport-rule PrependSubject text (G7) is kept because MS.EXO.7.1 judges it. Intune custom profiles stay read and their `payload` is stripped after receipt (G10, M01-T10).
- options: keep read-and-discard or drop the reads | keep the prefix text or reduce it to set/not-set | keep and strip the payload or stop reading custom profiles
- why: the checks keep working while user- and admin-written text never reaches evidence or reports.
- consequences: M01-T10 is unblocked; the tests in M01-T04 prove each discard.
- approver: G

## DEC-009 Six read-boundary follow-ups added to M01
- date: 2026-11-08
- status: approved
- decision: M01-T07 to M01-T12 (Gmail fields masks, ApplyHtmlDisclaimerText removal, alerts and groups fields masks, Intune payload strip, gmail.settings.sharing scope removal, runtime content-cmdlet refusal) join M01. They implement M01's existing DoD item on content reads; no weight or DoD change.
- options: add the tasks | accept the exposures
- why: M01-T04 found exposures (G8 is real message text) and a runtime guard that accepts any Get-* cmdlet; the DoD cannot be met without them.
- consequences: they depend on M01-T04 merging and merge one at a time because they share tests/test_read_boundaries.py.
- approver: auto

## DEC-010 Write-capable Google scopes accepted as documented exceptions
- date: 2026-11-08
- status: approved
- decision: admin.directory.user.security, apps.alerts, gmail.settings.basic and apps.groups.settings (no read-only form exists) stay on by default for Google audits as documented exceptions: blast radius recorded per scope, used only for list and get calls, proved by tests. gmail.settings.sharing is dropped (M01-T11).
- options: accept as documented exceptions | gate behind an opt-in | drop the dependent checks
- why: keeps 2SV, Alert Center, Gmail-settings and group-settings coverage; matches the AGENTS.md rule that a write-capable scope never authorises a mutating call and must record its blast radius.
- consequences: M01-T04 turns its strict expected failures into an explicit accepted-exception table instead of suppressed failures.
- approver: G

## DEC-011 Bounded final rounds for the static boundary scanners
- date: 2026-11-08
- status: approved
- decision: M01-T03 and M01-T04 each get one final bounded repair round fixing exactly the open review items; scanner limits found after that go to BACKLOG as documented limitations instead of further rounds.
- options: escalate to an astra opinion | re-scope per AGENTS.md (two repair rounds, then re-scope)
- why: each review round found new static-analysis corner cases without any real call site breaching the boundary; the tests fail closed on untraceable sites.
- consequences: the boundary proof ships with named limitations in the backlog.
- approver: auto

## DEC-012 Gmail masks drop text-derived fields; M01-T11 file set widened
- date: 2026-11-08
- status: approved
- decision: where Gmail settings text can be excluded at request level (M01-T07), it is excluded and live output drops the length fields derived from it; presence stays only where a non-text field reports it, and offline fixtures and the contract follow. If any value rule reads a dropped field, the task stops and asks G. Read-and-discard (DEC-008) stays reserved for text that cannot be excluded. M01-T11 may update the two existing test assertions that still name the retired gmail.settings.sharing scope.
- options: drop the derived fields | read and discard to keep them
- why: request-level exclusion is the stricter boundary and the derived lengths are informational.
- consequences: a small change to Google live evidence fields, to be listed in the 1.3.0 release notes.
- approver: auto

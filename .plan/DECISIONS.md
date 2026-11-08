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

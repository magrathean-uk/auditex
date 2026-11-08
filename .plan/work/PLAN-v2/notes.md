# PLAN-v2 notes - revision 2 (REV-PLAN-v2 residuals at 55fdbfc, G's scope-gate answers)

scaffold.sh not rerun (critique). Weights unchanged; percentage unchanged at 9% (no DoD item added or ticked).

1. Finding 5, doc coverage: M02-T05 takes its file list from `git ls-files '*.md'` (top-level, `.github/**` incl. SUPPORT.md, `docs/**` incl. legal, agent, skills, profiles, tenant-bootstrap templates, future files); reasoned excluded roots vendor, tests, .plan, released CHANGELOG; M02 DoD item 1 now also asserts only the `tests/providers/m365` exemption remains (.plan/milestones/M02-docs-accuracy.md, .plan/master-plan.md).
2. Finding 5, legal route: exception branch dropped (DEC-003); the notice line carries one reasoned temporary exemption; new M02-T07 (orchestrator, S, mechanical) applies G's approved text verbatim and removes the exemption; DoD item 2 verify checks the vendored path is named and the dead path gone (.plan/milestones/M02-docs-accuracy.md).
3. Uncovered risk 1, cmdlet scan: M01-T04 splits tokens into trusted wrapper operations (exactly Import-Module, Connect-ExchangeOnline, Invoke-Expression) accepted only from a closed file-and-purpose table (powershell_graph connect preamble, m365dsc VettedCommand guard, probe availability check) and audited commands on the read allow-list, which gains no wrapper verb; a test asserts check_command still refuses each wrapper verb (.plan/milestones/M01-boundary-proof.md).
4. Work-record paths: no action (accepted); plan files re-scanned, no absolute workstation paths.
5. DEC-001 approved by G (merge plan v2, push main; tag still needs the yes naming 1.3.0, D9; target-user wording stands); master-plan target-user line, M02-T04, M03 item 8 and M03-T05 updated (.plan/DECISIONS.md, .plan/master-plan.md, .plan/milestones/M02-docs-accuracy.md, .plan/milestones/M03-release-1-3-0.md).
6. DEC-002 sinks stay as class 5 opt-in redacted outbound; risk 1 updated (.plan/DECISIONS.md, .plan/master-plan.md).
7. DEC-003 legal notice merges after exact-text approval (.plan/DECISIONS.md, M02).
8. DEC-004 retire the parked model layer after 1.3.0; BACKLOG next item and non-goal updated (.plan/DECISIONS.md, .plan/BACKLOG.md, .plan/master-plan.md).
9. STATE pending G items: exact legal-notice text, later the 1.3.0 tag yes; re-baseline marked approved (.plan/STATE.md).

# PLAN-v2 notes - revision 1 (astra VAL-v2 gaps, reviewed 3122ac5, with the orchestrator's rulings)

scaffold.sh not rerun (ruling). Percentage after revision: 9% (M00 2/11, M02 2/8). Gap 7 alone gave 10%; the new DoD items for gaps 3-6 lower it to 9%.

1. Circular release gate: M03 split into the pre-publication gate (items 1-7), G's yes naming 1.3.0 and the publication form (item 8), publication (items 9-10: signed tag on the astra-reviewed sha, GitHub release with wheel and sdist, no PyPI) and close-out (item 11, new M03-T06 verifies downloaded hashes); M03-T04 waits only on M00-M02 and M03 items 1-6 (.plan/milestones/M03-release-1-3-0.md, .plan/master-plan.md).
2. notify.py and model_serving.py POSTs: ARCHITECTURE.md now freezes an 8-class transport policy (sinks class 5, parked model endpoint class 6); new M01-T02 (terra, read-only) maps every HTTP, SDK and subprocess call site to a class, M01-T03 enforces only that frozen list; model layer classified, not changed (.plan/ARCHITECTURE.md, .plan/milestones/M01-boundary-proof.md).
3. Dependency coverage: M00-T03 audits the base install and every extra including model_train (host and Linux aarch64, metadata-only resolution, no install), ignores need a G-approved DECISIONS entry; success criterion and DoD item 8 reworded to match (.plan/milestones/M00-foundation.md, .plan/master-plan.md).
4. sdist and reproducibility: new M00-T05 owns scripts/release-smoke.sh (wheel and sdist, base/Google/MCP) and adds scripts/check-reproducible-build.py (byte-identical wheel, member-identical sdist under SOURCE_DATE_EPOCH); M00 DoD item 9, M03 item 5 and M03-T03 use it (.plan/milestones/M00-foundation.md, .plan/milestones/M03-release-1-3-0.md).
5. Public-doc paths and legal notice: new M02-T05 tests/test_docs_paths.py over all first-party Markdown (promoted from BACKLOG, which drops the item); new M02-T06 drafts the third-party-notices correction (the file is tracked under tenant-bootstrap/vendor/microsoft-skills/); DoD item "G approved the exact text and it is merged, or G recorded an exception" (.plan/milestones/M02-docs-accuracy.md, .plan/BACKLOG.md).
6. Branch triage gate: M00 DoD item 11 requires terra's spot-check pass and no needed-for-1.3.0 row left open; M00-T04 gains a disposition column (.plan/milestones/M00-foundation.md).
7. Stale reconciliation: ancestor item ticked with evidence (main cd6b134 contains 82d7ca5), blocker removed from STATE, risk 1 replaced (.plan/milestones/M00-foundation.md, .plan/STATE.md, .plan/master-plan.md).
8. DEC-001 marked proposed with the publication form; STATE re-baseline "from 0% (plan v1) to 9% (plan v2, DEC-001)" (.plan/DECISIONS.md, .plan/STATE.md).
S1. Sequencing: M00-T01 runs after T02, T03 and T05 merge; M01-T03 after M01-T02 and its DECISIONS freeze; triage dispositions close before M00 (.plan/milestones/M00-foundation.md, .plan/milestones/M01-boundary-proof.md).
R1. Content, SDK, subprocess: new M01-T04 tests content reads, PowerShell cmdlets, Microsoft 365 CLI commands (read_guard.check_command) and Google methods and scopes (.plan/milestones/M01-boundary-proof.md).
R2. Review binding: M01 review item checks each Tier A task separately, the other-vendor launcher and the Plan-Review trailer merge.sh writes on the squash commit; the tag must sit on astra's reviewed sha (.plan/milestones/M01-boundary-proof.md, .plan/milestones/M03-release-1-3-0.md).
R3. Lifecycle registration: out of scope by G's 5 Nov 2026 ruling; listed as a non-goal, no plan dependency (.plan/master-plan.md).
X1. M03-T05 owner is the orchestrator (integrator): AGENTS.md says only the integrator pushes (.plan/milestones/M03-release-1-3-0.md).

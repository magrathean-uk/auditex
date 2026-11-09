## RESULT M00-T04
status: done
summary: 44 unmerged local wt/* branches classified: 3 post-1.3.0 live tenant, 35 post-1.3.0 D5, 1 post-1.3.0 model, 4 superseded, 1 needed-for-1.3.0 (open).
summary: No row is merged-equivalent by patch-id; git cherry finds zero equivalent commits on 40 of 44 branches.
summary: The only open row is wt/docs-rules-and-scan-limits, which M02 lands. Terra's spot-check is not done here.
summary: clean-development doctor reports FAIL on cleanup locks (dead owner, explicit recovery required). Outside this slice; not repaired.
changes: none. Evidence written to .plan/work/M00-T04/notes.md; result.md not written, so the orchestrator files this block.
verification: git branch --list 'wt/*' --no-merged origin/main | wc -l = 44, equal to table rows (pass). clean-development doctor = FAIL 1, WARN 24 (report only). Grep for '^| wt/' in result.md not run; file not written.
risks: D5 class rests on branch names and DEC-001/BACKLOG.md:9; 35 rows are not checked commit by commit.
risks: wt/d5-k-material-stage1-20261107-b and wt/d5-material-proof-v-20261108-b touch five core modules; whether either is a 1.3.0 boundary fix is unverified.
risks: the superseded rows (redact-key-guard, release-1.2.4 x3) need git range-diff before deletion; ancestry alone does not prove it.
questions_for_g: Authorise recovery of the clean-development cleanup lock (doctor FAIL), or hand it to the tool owner?
questions_for_g: Confirm the D5 chain (35 rows) is a post-1.3.0 deferral, not a branch-deletion decision; no deletion is proposed now.

### Findings

1. exists
- 44 unmerged local wt/* refs; chains: d5 (27), ff-d5 (5), release-1.2.4 (3). Plan sources: .plan/milestones/M00-foundation.md:59-66; .plan/BACKLOG.md:8-19; .plan/DECISIONS.md:4-38; .plan/master-plan.md:43-61.
- Remote-only origin/wt/* (9, outside slice): collect-argv-1-pub, collect-defaults-1r, collect-partner-domains-1, collect-presets-1, dayone-certauth, dayone-ipps, model-explainer-clean, model-redact, product-su.

2. works
- Branch count 44 = table rows (command: git branch --list 'wt/*' --no-merged origin/main | wc -l).
- origin/main = main = HEAD = dd55f15 (git rev-parse --short).
- CHANGELOG.md:590 has [1.2.4] on main; .gitignore:8 ignores build/; origin/main tracks no build/ files (git ls-tree -r origin/main -- build).

3. broken
- clean-development doctor: FAIL cleanup locks; WARN 7 unexpected dot-folders (~/.agent-reach, ~/.asc and others), 14 misplaced cache extras, 3 literal cache paths in LaunchAgents plists (porn-allpictures.plist:16; porn-c-authority.plist:6,39). Output cut at 60 lines.
- No failing command inside the slice.

4. dead candidates
- Stale refs by behind count: release-1.2.4 x3 (280), redact-key-guard (146), redact-person-names (138), collect-presets-1 (133), collect-certauth-1 and collect-ipps-1 (125).
- Duplicate ref: collect-certauth-1 and collect-ipps-1 both at 23f9186.
- D5 predecessors by name (inferred): m-r1 (by m-r2), scalar-s1 (by s2, decision-s), k-material-stage1 (by k-producer-stage3). No rg dead-code check; the files exist only on branches.

5. contradictions
- .plan/master-plan.md:43 cites origin/main 82d7ca5; current origin/main is dd55f15 (stale pin, inferred; ancestry not checked).
- None found among BACKLOG.md, DECISIONS.md and M00-foundation.md on the post-1.3.0 rule.

6. open questions
- redact-key-guard vs redact-key-guard-2: git range-diff origin/main wt/redact-key-guard wt/redact-key-guard-2.
- docs-rules-and-scan-limits: which M02 task lands it (.plan/milestones/M02-docs-accuracy.md:17,43); orchestrator sets disposition.
- d5-k-material-stage1 and d5-material-proof-v: git diff --stat origin/main...<b> plus .plan/milestones/M01-boundary-proof.md.
- ss21-composed-20261107: subjects of origin/main..<b> against BACKLOG.md:18.
- release-1.2.4 family: git range-diff origin/main wt/release-1.2.4 wt/release-1.2.4-r2.
- Neighbouring area: 9 remote-only origin/wt/* branches, outside this slice.

| branch | tip | ahead | class | disposition | evidence |
|---|---|---|---|---|---|
| wt/collect-certauth-1 | 23f9186 | 8 | post-1.3.0 (live tenant) | none; deferred BACKLOG.md:18 | cert-auth live acceptance; same tip as collect-ipps-1 |
| wt/collect-ipps-1 | 23f9186 | 8 | post-1.3.0 (live tenant) | none; deferred BACKLOG.md:18 | IPPS; duplicate tip of collect-certauth-1 |
| wt/collect-presets-1 | e922b8c | 1 | post-1.3.0 (live tenant) | none; deferred BACKLOG.md:18 | teams_policy in presets; Teams parked BACKLOG.md:18 |
| wt/d5-actor-boundary-b-20261108-b | 46b78af | 90 | post-1.3.0 (D5) | none; DEC-001 | D5 Shared actor copies |
| wt/d5-coherent-fixtures-r2-20261108-b | 4bdce1d | 122 | post-1.3.0 (D5) | none; DEC-001 | D5 fixtures |
| wt/d5-copy-collision-c1-20261108-b | 2a41162 | 112 | post-1.3.0 (D5) | none; DEC-001 | D5 copy relations |
| wt/d5-copy-duty-c2-20261108-b | 43904b4 | 120 | post-1.3.0 (D5) | none; DEC-001 | D5 copy duties |
| wt/d5-copy-lineage-c-20261108-b | d15d6ec | 104 | post-1.3.0 (D5) | none; DEC-001 | D5 actor copy lineage |
| wt/d5-discovery-diagnostics-r-20261108-b | 312b657 | 74 | post-1.3.0 (D5) | none; DEC-001 | D5 refusal codes; touches cli.py |
| wt/d5-existing-consumer-fixtures-20261108-b | 4e72aa8 | 60 | post-1.3.0 (D5) | none; DEC-001 | D5 Shared consumer tests |
| wt/d5-finding-origin-c4-20261108-b | ce17772 | 131 | post-1.3.0 (D5) | none; DEC-001 | D5 finding origins |
| wt/d5-framework-theme-p3-20261108-b | 6b9d835 | 123 | post-1.3.0 (D5) | none; DEC-001 | D5 Cyber Essentials themes |
| wt/d5-joined-lexer-j-20261108-b | 8242c70 | 103 | post-1.3.0 (D5) | none; DEC-001 | D5 joined person-name lexing |
| wt/d5-joined-overlap-j1-20261108-b | 187e1e1 | 114 | post-1.3.0 (D5) | none; DEC-001 | D5 name overlap |
| wt/d5-joined-terminal-j2-20261108-b | 06f7be9 | 121 | post-1.3.0 (D5) | none; DEC-001 | D5 joined terminal names |
| wt/d5-k-material-stage1-20261107-b | b8462ea | 9 | post-1.3.0 (D5) | none; DEC-001 | private Shared redaction material, +3001/-7; open Q3 |
| wt/d5-k-producer-stage3-20261107-b | baa7003 | 28 | post-1.3.0 (D5) | none; DEC-001 | K-producer refusals |
| wt/d5-k3-local-r1-20261108-b | cd8f41d | 34 | post-1.3.0 (D5) | none; DEC-001 | Local audit refusals |
| wt/d5-m-identity-20261107-b | 4c92148 | 7 | post-1.3.0 (D5) | none; DEC-001 | M-track identity; touches reporting.py |
| wt/d5-m-r1-20261107-b | 5ce5682 | 38 | post-1.3.0 (D5) | none; DEC-001 | M-track r1; successor m-r2 (inferred) |
| wt/d5-m-r2-20261108-b | 8ee6e94 | 62 | post-1.3.0 (D5) | none; DEC-001 | M-track r2 |
| wt/d5-material-proof-v-20261108-b | bb66370 | 12 | post-1.3.0 (D5) | none; DEC-001 | coherent material reads; open Q3 |
| wt/d5-mcp-constraints-20261108-b | 8690005 | 78 | post-1.3.0 (D5) | none; DEC-001 | Shared MCP refusals |
| wt/d5-middle-name-j3-20261108-b | e2c9621 | 132 | post-1.3.0 (D5) | none; DEC-001 | D5 middle names |
| wt/d5-product-fixtures-r1-20261108-b | 4192981 | 86 | post-1.3.0 (D5) | none; DEC-001 | D5 fixture classification |
| wt/d5-provenance-p-20261108-b | 04f0827 | 93 | post-1.3.0 (D5) | none; DEC-001 | D5 provenance binding |
| wt/d5-scalar-decision-s-20261108-b | fbb100d | 68 | post-1.3.0 (D5) | none; DEC-001 | D5 scalar proof |
| wt/d5-scalar-s1-20261108-b | fe08e9a | 79 | post-1.3.0 (D5) | none; DEC-001 | D5 scalar s1; chain (inferred) |
| wt/d5-scalar-s2-20261108-b | 1b08351 | 81 | post-1.3.0 (D5) | none; DEC-001 | D5 scalar s2 |
| wt/d5-temporary-retention-20261108-b | 114808b | 57 | post-1.3.0 (D5) | none; DEC-001 | D5 material read order and run roots |
| wt/docs-rules-and-scan-limits | fe78ee1 | 1 | needed-for-1.3.0 | M02-T02 | README coverage split; M02-docs-accuracy.md:17,43 |
| wt/ff-d5-m-complete-20261108-b | 1730eac | 33 | post-1.3.0 (D5) | none; DEC-001 | final M-track regressions |
| wt/ff-d5-mcp-complete-20261108-b | de4e86e | 39 | post-1.3.0 (D5) | none; DEC-001 | final MCP regressions |
| wt/ff-d5-model-case-20261107-b | 6f74ea8 | 10 | post-1.3.0 (model) | none; DEC-004 | model-case test; touches model_serving.py; DECISIONS.md:31-38 |
| wt/ff-d5-model-complete-20261108-b | 5dc2ed4 | 26 | post-1.3.0 (D5) | none; DEC-001 | name says model; file set is D5 (inferred) |
| wt/ff-d5-root-cli-20261107-b | 4c3a0bf | 3 | post-1.3.0 (D5) | none; DEC-001 | adds tests/test_d5_cli_registration.py only |
| wt/ff-d5-root-provenance-20261107-b | 504ccab | 8 | post-1.3.0 (D5) | none; DEC-001 | provenance tests; touches model_serving.py |
| wt/lead-20261107-b | a88b74a | 86 | post-1.3.0 (D5) | none; DEC-001 | alias-collision test; D5 file set (inferred) |
| wt/redact-key-guard | fcd1ec4 | 3 | superseded | none | successor redact-key-guard-2 merged; not an ancestor of it (inferred) |
| wt/redact-person-names | 3e495d6 | 11 | post-1.3.0 (D5) | none; deferred to D5-v2 | BACKLOG.md:9 forbids merging this branch |
| wt/release-1.2.4 | d9a9f7c | 6 | superseded | none | 1.2.4 on main at CHANGELOG.md:590; 1 of 5 commits patch-equivalent |
| wt/release-1.2.4-final | fa99bad | 5 | superseded | none | same release |
| wt/release-1.2.4-r2 | c9edea5 | 5 | superseded | none | same release |
| wt/ss21-composed-20261107 | ef8679d | 130 | post-1.3.0 (D5) | none; DEC-001 | consumer fixture reports; D5 file set (inferred) |
| wt/github-build-tags-20261108 | 6ded82a | 1 | post-1.3.0 | deferred: created by another session at 18:43 after this triage; adds a workflow that tags default-branch commits, outside plan v2 where hosted CI and release automation are non-goals (DEC-001) | git log origin/main..wt/github-build-tags-20261108 |

Full evidence (commands, file reads, class rules): .plan/work/M00-T04/notes.md

spot-check: pass (M00-T04-check, terra: 11 rows incl. the needed-for-1.3.0 row and both core-touching D5 branches; 2 minor partial-equivalence notes, neither a 1.3.0 fix)

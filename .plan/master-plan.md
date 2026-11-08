# Master plan - Auditex 1.3.0
<!-- Hub document, max 150 lines. sol-architect writes it, the orchestrator makes small edits, G approves scope. -->

## Vision
Auditex 1.3.0 is the release in which an IT administrator or consultant runs one read-only command against a
Microsoft 365 tenant and receives a validated, sealed run bundle in which every one of the 102 CISA SCuBA
policies is answered by a deterministic value rule, explained by a deterministic template, and shareable with
the D3 redaction profile applied, without granting write access or reading message or file content, and with
nothing sent off the machine except to endpoints the operator configures (notification sinks, the parked
model endpoint). Google Workspace collection ships as an internal control map. The release is cut only after
every local gate runs green and reproducibly, the read-only and secret-handling boundaries are proven by tests,
and the public docs say exactly what the code does.

## Target user
IT administrators and consultants auditing their own or a customer's Microsoft 365 or Google Workspace tenant
who need defensible, reproducible evidence without write access (wording confirmed by G at the scope gate, DEC-001).

## Success criteria
- `make release-check` and `make test` exit 0 on the release commit.
- The full acceptance suites (`value_rule_acceptance`, `explainer_acceptance`) pass once on the release commit.
- Every outbound call site under `src/` (HTTP, SDK, subprocess) is classified against the transport policy in
  ARCHITECTURE.md, and a test fails on any non-GET HTTP request outside the allow-list frozen from it.
- Tests prove that no collector requests message or file content, every PowerShell cmdlet and Microsoft 365 CLI command at an executable command site (docstrings, comments and documentation strings excluded) is on a read
  allow-list, with the three wrapper verbs accepted only at their known wrapper sites, and every Google API call is a read method under read-only scopes.
- Every parser flag that can carry a secret is in its redaction list and has an abbreviation and redaction test.
- `make audit-deps` exits 0 over the base install and every declared extra, `model_train` included; any
  accepted advisory carries a G-approved DECISIONS.md entry.
- `pyproject.toml` says `1.3.0`, `CHANGELOG.md` has a `1.3.0` section that states the D6 limit (names in free
  text and ids are not masked in shareable output), and `.github/SECURITY.md` supports 1.3.x.
- The wheel and the sdist each pass `scripts/release-smoke.sh` for the base, Google and MCP installs, and two
  clean builds of the release commit give a byte-identical wheel and a member-identical sdist.
- `tests/test_docs_paths.py` passes: no first-party public doc names a repository path that does not exist;
  the G-owned third-party notice carries the correction text G approved (DEC-003), and the test keeps only
  the reasoned `tests/providers/m365` exemption.
- No public doc claims SCuBA Google Workspace coverage.
- Tier A changes (M01-T01, M01-T03, M01-T04, M03-T01) carry an approving other-vendor review bound to the
  reviewed head by the `Plan-Review` trailer on the squash commit.
- astra's pre-publication release gate returns ready; G's explicit yes naming 1.3.0 is recorded; the signed tag
  `v1.3.0` on the gated commit and a GitHub release carrying the gated wheel and sdist exist, and the downloaded
  assets match the gated hashes. No PyPI.

## Scope of 100 percent
The 1.3.0 release from the accepted line: local `main` already contains `origin/main` 82d7ca5, which carries the
key-guard reader, explainer wiring, read-aware evidence gates and the SS 2.1 and SS 2.3 private inputs. What
remains: make the local gates green and reproducible, including a dependency audit over every extra and a
wheel and sdist smoke (no hosted CI, by G's decision that GitHub is storage only); resolve the `wt/*` branch
triage; classify every outbound call and prove the tenant read-only, content and secret-redaction boundaries
with tests; correct the docs and land the legal-notice fix once G approves its exact text; write the release notes and bump the
version; pass the pre-publication gate; on G's yes publish the signed tag and a GitHub release with the wheel
and sdist, then verify what was published. 100 percent means every DoD item in M00-M03 is ticked.

## Non-goals
- Live-tenant work of any kind: playground tenant, trials, certificate auth live checks, IPPS, presets,
  Teams coverage, the day-one run, the dummy-tenant kit and its gates. All in BACKLOG later.
- D5 person-name masking beyond the typed D3 fields (redesign track after 1.3.0, per D6).
- Any development or removal of the parked model layer (training, base-model pulls, AIRR, Hugging Face
  upload); 1.3.0 only classifies its call sites and audits the `model_train` extra. Its retirement after
  1.3.0 is approved (DEC-004, BACKLOG next) and goes through the deletion gate.
- Answering the SCuBA Google Workspace baselines; the Google provider stays an internal control map.
- Hosted CI, a separate kit repository, or deleting `wt/*` branches and worktrees.
- PyPI or any other registry upload; any release other than 1.3.0; any tenant write path (response features
  stay lab-only behind `AUDITEX_ENABLE_RESPONSE`).
- Workstation tooling issues (clean-development doctor and lifecycle registration), by G's 5 Nov 2026 ruling.

## Architecture
See ARCHITECTURE.md. Parallel work only across modules with different owners; sol agrees interfaces before any parallel dispatch.

## Milestones
<!-- milestones:begin -->
| id | name | weight | % | status |
|---|---|---|---|---|
| M00 | foundation | 20 | 36 | active |
| M01 | boundary-proof | 30 | 43 | planned |
| M02 | docs-accuracy | 20 | 75 | planned |
| M03 | release-1-3-0 | 30 | 0 | planned |
<!-- milestones:end -->

## Top risks
1. The transport inventory may surface a call class the policy does not cover (operator sinks are settled:
   class 5, DEC-002); M01-T03 waits on the frozen allow-list, so an unclassified row blocks M01 until sol or
   G rules.
2. The `model_train` audit covers exact pins of the parked layer; an advisory there needs a pin change
   (not development) or G's acceptance, and resolution stays metadata-only so no multi-gigabyte pull happens.
3. The assessment predates the 120 accepted commits; some findings are stale (`tests/providers/m365` is an
   upstream path). Every task re-checks its finding on current `main` before changing code.
4. Heavy runs (about 20,000 tests, then the 26,898-vector acceptance replay): one heavy job at a time on
   the Mac, under `run-job`, behind the load rule.
5. Squash merges give `main` commits no review saw; the M01 and M03 review items bind each approval to the
   reviewed head through the `Plan-Review` trailer, and the tag must sit on the commit astra reviewed.
6. Release authority: D9 keeps D7's 1.3.0 approval unused; publication runs only after G's separate yes
   naming 1.3.0 (form fixed by DEC-001). M02 cannot close until G approves the exact notice text (DEC-003).
7. The repo is public: plan files, committed briefs and release notes carry no workstation paths, credentials
   or live evidence; gitleaks and the taint scan run before every push.

## Links
STATE.md, ARCHITECTURE.md, milestones/, BACKLOG.md, DECISIONS.md, CLEANUP.md, RETRO.md

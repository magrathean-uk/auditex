---
id: M03
name: release-1-3-0
weight: 30
status: active
---
# M03 release-1-3-0
Three stages in order: the pre-publication gate (DoD items 1-7), G's explicit yes naming 1.3.0 (item 8, D9), then publication and close-out (items 9-11). Tagging and publishing are reserved actions; the integrator does them, nobody else pushes.

## Goal
1.3.0 is cut from `main` per the runbook: version bumped, release notes stating D3 masking only and the D5 limit, acceptance suites, reproducible wheel and sdist smoke and the release check green on the release commit, astra's pre-publication gate ready, then on G's yes the signed tag `v1.3.0` and a GitHub release carrying the gated wheel and sdist (no PyPI), verified after publication.

## Definition of Done
- [ ] The full acceptance suites pass on the release commit: `.venv/bin/python -m pytest -m "value_rule_acceptance or explainer_acceptance"`
- [x] The packaged version is 1.3.0 and the changelog has its section: `grep -qx 'version = "1.3.0"' pyproject.toml && grep -q '^## \[1.3.0\]' CHANGELOG.md` (evidence: merge.sh verify for M03-T01 ran this command and passed; release commit d9f050f)
- [x] Review: the 1.3.0 notes state that shareable output applies the D3 masking and that names in free text and ids are not masked (D6), and carry no stale "planned" explainer line `sed -n '/^## \[1.3.0\]/,/^## \[1.2.4\]/p' CHANGELOG.md` (evidence: REV-M03-T01 Codex approve at 2385009 after two bounded rounds; release commit d9f050f)
- [x] The security policy supports 1.3.x: `grep -q '| 1.3.x | Yes |' .github/SECURITY.md` (evidence: merge.sh verify for M03-T01 ran this grep and passed; release commit d9f050f)
- [x] The 1.3.0 wheel and sdist build reproducibly and pass the base, Google and MCP release smoke on the release commit: `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py` (evidence: M03-T03 on release commit d9f050f: make dist, release smoke for wheel and sdist, reproducible-build check all passed; sha256 recorded in .plan/work/M03-T03/result.md)
- [x] Release check is green on the release commit: `make release-check` (evidence: M03-T02 on release commit d9f050f: make release-check passed, 23714 passed, 0 failed, taint scan and gitleaks clean)
- [ ] Review: astra's pre-publication release gate returns ready on the release commit, after every M00-M02 DoD item and M03 items 1-6 are ticked `grep -qx 'verdict: ready' .plan/work/M03-T04/result.md`
- [ ] Review: G's explicit yes naming 1.3.0 (D9; the publication form is fixed by DEC-001) is recorded in DECISIONS.md with approver G `grep -n -A8 '^## DEC-[0-9]* Release 1.3.0' .plan/DECISIONS.md | grep -q 'approver: G'`
- [ ] The signed tag `v1.3.0` points at the gated release commit and is on `origin`: `git tag -v v1.3.0 && test "$(git rev-parse 'v1.3.0^{commit}')" = "$(sed -n 's/^reviewed: *\([0-9a-f]\{40\}\).*/\1/p' .plan/work/M03-T04/result.md | head -1)" && git ls-remote --exit-code --tags origin refs/tags/v1.3.0`
- [ ] The GitHub release `v1.3.0` exists and carries the wheel and the sdist: `test "$(gh release view v1.3.0 --json assets --jq '[.assets[].name | select(endswith(".whl") or endswith(".tar.gz"))] | length')" -eq 2`
- [ ] Close-out: the published wheel and sdist, downloaded fresh, match the sha256 values M03-T03 recorded, and the downloaded wheel installs and reports 1.3.0: `grep -qx 'published-artefacts: verified' .plan/work/M03-T06/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M03-T01 | Write the 1.3.0 release notes and bump the version | terra | M | - | done |
| M03-T02 | Run the acceptance suites on the release commit | luna | S | - | todo |
| M03-T03 | Build, smoke-test and hash the release artefacts | luna | S | - | done |
| M03-T04 | Pre-publication release gate validation | astra | S | gate | todo |
| M03-T05 | Tag and publish 1.3.0 after G's yes | orchestrator | S | gate | todo |
| M03-T06 | Verify the published release | luna | S | - | todo |

## Acceptance criteria
### M03-T01 Write the 1.3.0 release notes and bump the version
- Runs after M00, M01 and M02 are done, so the notes describe the final tree; its merge commit on `main` is the release commit, and nothing outside `.plan/` lands on `main` between it and the tag.
- `CHANGELOG.md` `[Unreleased]` becomes `[1.3.0]`, dated as the runbook requires and ordered by user impact; stale lines are corrected (explainer report wiring is shipped, not planned, `CHANGELOG.md:115` at 82d7ca5); the D6 limit is stated: shareable output applies the D3 masking, and person names in free text and ids are not masked.
- `pyproject.toml` version is `1.3.0`; `.github/SECURITY.md` lists 1.3.x as supported and 1.2.x as unsupported.
- `CONTRACT_VERSION` and the output-contract date are checked against the bundle changes since 1.2.4; a bump, or the reason for none, is recorded as an auto entry in `.plan/DECISIONS.md` by the orchestrator.
- Release is Tier A: the review runs on the other vendor at the frozen head. No workstation path, session URL or internal infrastructure name in any changed file.
- verify: `grep -qx 'version = "1.3.0"' pyproject.toml && grep -q '^## \[1.3.0\]' CHANGELOG.md && grep -q '| 1.3.x | Yes |' .github/SECURITY.md && .venv/bin/python -m pytest tests/test_architecture_modules.py tests/test_contract.py`
- files: `CHANGELOG.md`, `pyproject.toml`, `.github/SECURITY.md`, `src/azure_tenant_audit/contracts.py` (only on a bump), `docs/reference/output-contract.md` (date only, only on a bump)

### M03-T02 Run the acceptance suites on the release commit
- Runs at the M03-T01 merge commit, under `run-job` in a detached worktree, as the only heavy job on the Mac.
- Both `value_rule_acceptance` (all 26,898 vectors plus A2) and `explainer_acceptance` pass; `result.md` records the commit and pass, skip and fail counts, and on failure the failing ids (no fixes in this task).
- verify: `.venv/bin/python -m pytest -m "value_rule_acceptance or explainer_acceptance"`
- files: `.plan/work/M03-T02/result.md` (read-only run)

### M03-T03 Build, smoke-test and hash the release artefacts
- At the M03-T01 merge commit, `make dist` builds the `auditex-1.3.0` wheel and sdist, `scripts/release-smoke.sh` passes the base, Google and MCP installs of both, `scripts/check-reproducible-build.py` passes, and `make release-check` exits 0.
- `result.md` records the commit, the artefact file names and their sha256 values, and keeps the `dist/` artefacts that M03-T05 publishes (git-ignored, not rebuilt).
- verify: `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py && make release-check`
- files: `.plan/work/M03-T03/result.md` (read-only run; `dist/` is git-ignored)

### M03-T04 Pre-publication release gate validation
- astra-validate in release mode at the release commit, once every M00-M02 DoD item and M03 items 1-6 are ticked; it does not wait for G's yes, the tag or the release, so the gate is not circular.
- Reads the DoD evidence, the Tier A review results with their `Plan-Review` trailers, the M03-T03 hashes and the release notes.
- `result.md` carries `verdict: ready` and `reviewed: <40-character release commit sha>`, or a numbered list of blocking gaps.
- verify: `grep -h 'verdict:' .plan/work/M03-T04/result.md`
- files: `.plan/work/M03-T04/result.md` (read-only)

### M03-T05 Tag and publish 1.3.0 after G's yes
- Precondition: M03 items 1-8 are ticked; G's yes names 1.3.0 (publication form per DEC-001: signed tag plus GitHub release with wheel and sdist, no PyPI) and is recorded in the operator decisions log and in `.plan/DECISIONS.md`.
- The integrator creates the signed annotated tag `v1.3.0` on the commit astra reviewed, pushes `main` (fast-forward, gitleaks over the new range) and the tag, and creates the GitHub release from the 1.3.0 changelog section with the M03-T03 wheel and sdist; no PyPI or other registry upload. If G's yes changes the form, the orchestrator edits items 9-10 before this task runs.
- verify: `git tag -v v1.3.0 && git ls-remote --exit-code --tags origin refs/tags/v1.3.0 && gh release view v1.3.0`
- files: none in the tree (tag, push and GitHub release only)

### M03-T06 Verify the published release
- After M03-T05: downloads the release assets with `gh release download v1.3.0` into a fresh directory under `$TMPDIR`, compares each sha256 with the M03-T03 record, installs the downloaded wheel in a fresh environment and checks `auditex --version` reports 1.3.0.
- `result.md` lists each asset with both hashes and ends `published-artefacts: verified`, or names the mismatch and stops (no re-publication without G).
- verify: `grep -qx 'published-artefacts: verified' .plan/work/M03-T06/result.md`
- files: `.plan/work/M03-T06/result.md` (read-only)

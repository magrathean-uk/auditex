---
id: M06
name: release-1-4-0
weight: 15
status: planned
---
# M06 release-1-4-0
Starts after every M00-M05 DoD item is ticked. The version name and publication need G's explicit yes naming 1.4.0 (D9); the form stays a signed tag plus a GitHub release with the wheel and sdist, no PyPI (v2 DEC-001).

## Goal
1.4.0 is cut from `main` after the full gate chain, both acceptance suites with the full v3.9.1 replay, and a byte-reproducible build pass on the release commit; astra's gate returns ready and G's yes is recorded; the signed tag and GitHub release are published and the downloaded assets match the gated hashes.

## Definition of Done
- [ ] The packaged version is 1.4.0, the changelog has its section and the security policy supports 1.4.x: `grep -qx 'version = "1.4.0"' pyproject.toml && grep -q '^## \[1.4.0\]' CHANGELOG.md && grep -q '| 1.4.x | Yes |' .github/SECURITY.md`
- [ ] The 1.4.0 notes name the removal of the parked `model` command and the `model_train` extra (G, DEC-001): `sed -n '/^## \[1.4.0\]/,/^## \[1.3/p' CHANGELOG.md | grep -q 'model_train' && sed -n '/^## \[1.4.0\]/,/^## \[1.3/p' CHANGELOG.md | grep -q -i -E 'model.{0,2} command'`
- [ ] Review: an other-vendor review of the plan v3 merge of M06-T01 approves notes that also name the D5 boundary, the byte-reproducible build and the removed paths, at the exact merged head (ARCHITECTURE.md review binding): `ok=1; for T in M06-T01; do ( c=$(git log v1.3.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/REV-$T/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/REV-$T/result.md" ) || ok=0; done; test $ok = 1` Orchestrator check at close (ARCHITECTURE.md provider binding): the dispatch record names a launcher of the other vendor from the author's.
- [ ] Release check and dependency audit are green on the release commit: `make release-check && make audit-deps`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass on the release commit: `make acceptance`
- [ ] Two plain builds of the release commit give byte-identical wheel and sdist bytes, and both pass the base, Google and MCP release smoke: `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py`
- [ ] Review: astra's pre-publication release gate returns ready on the release commit: `grep -qx 'verdict: ready' .plan/work/M06-T03/result.md`
- [ ] Review: G's explicit yes naming 1.4.0 is recorded in DECISIONS.md with approver G: `grep -n -A8 '^## DEC-[0-9]* Release 1.4.0' .plan/DECISIONS.md | grep -q 'approver: G'`
- [ ] The signed tag `v1.4.0` points at the gated commit and is on `origin`: `git tag -v v1.4.0 && test "$(git rev-parse 'v1.4.0^{commit}')" = "$(sed -n 's/^reviewed: *\([0-9a-f]\{12,40\}\).*/\1/p' .plan/work/M06-T03/result.md | head -1)" && git ls-remote --exit-code --tags origin refs/tags/v1.4.0`
- [ ] The GitHub release `v1.4.0` carries the wheel and the sdist, and both, downloaded fresh, byte-match the hashes gated in M06-T02: `grep -qx 'published-artefacts: verified' .plan/work/M06-T05/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M06-T01 | Write the 1.4.0 release notes and bump the version | terra | M | - | todo |
| M06-T02 | Run the pre-publication gates on the release candidate | luna | S | - | todo |
| M06-T03 | Pre-publication release gate validation | astra | S | gate | todo |
| M06-T04 | Tag and publish 1.4.0 after G's yes | orchestrator | S | gate | todo |
| M06-T05 | Verify the published release | luna | S | - | todo |

## Acceptance criteria
### M06-T01 Write the 1.4.0 release notes and bump the version
- `pyproject.toml` says `1.4.0`; `CHANGELOG.md` turns `[Unreleased]` into `[1.4.0]` covering every change merged in plan v3, and names the removal of the parked `model` command, its flags and the `model_train` extra as a CLI and packaging change; `.github/SECURITY.md` supports 1.4.x and moves 1.3.x to upgrade-only.
- `CONTRACT_VERSION` and `docs/reference/output-contract.md` are unchanged unless G approved a re-baseline during M02 or M05; then both carry the new version and the notes name it.
- verify: `grep -qx 'version = "1.4.0"' pyproject.toml && grep -q '^## \[1.4.0\]' CHANGELOG.md && sed -n '/^## \[1.4.0\]/,/^## \[1.3/p' CHANGELOG.md | grep -q 'model_train' && grep -q '| 1.4.x | Yes |' .github/SECURITY.md && make test && make contract-smoke`
- files: `pyproject.toml` (version only), `CHANGELOG.md`, `.github/SECURITY.md`, `src/azure_tenant_audit/contracts.py` and `docs/reference/output-contract.md` (only on a contract change)

### M06-T02 Run the pre-publication gates on the release candidate
- In a detached worktree at the candidate commit, under `run-job`, behind the load rule: `make release-check`, `make audit-deps`, `make acceptance`, `make dist`, the release smoke and the reproducible-build check each exit 0.
- `result.md` records the commit, each step's exit status, the pytest counts, the replay's zero skips, and the sha256 of the wheel and of the sdist from both reproducible builds (equal byte for byte); on failure it names the step and stops.
- verify: `make release-check && make audit-deps && make acceptance && make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py`
- files: `.plan/work/M06-T02/result.md` (read-only run)

### M06-T03 Pre-publication release gate validation
- astra in release mode on the candidate commit, after every M00-M05 DoD item and M06 items 1-6 are ticked; `result.md` carries `verdict: ready` or the gaps, and `reviewed: <40-hex sha>`.
- verify: `grep -qx 'verdict: ready' .plan/work/M06-T03/result.md`
- files: `.plan/work/M06-T03/result.md`

### M06-T04 Tag and publish 1.4.0 after G's yes
- Precondition: G's yes naming 1.4.0 recorded in DECISIONS.md.
- Builds the gated commit with plain `make dist`, confirms the wheel and the sdist sha256 both equal the M06-T02 record, signs and pushes `v1.4.0` on that commit, creates the GitHub release with exactly the wheel and the sdist and records the uploaded hashes. No PyPI.
- verify: `git tag -v v1.4.0 && gh release view v1.4.0 --json assets`
- files: `.plan/work/M06-T04/result.md`

### M06-T05 Verify the published release
- Downloads both assets fresh, compares sha256 with the M06-T04 record, installs the wheel in a scratch venv and checks it reports 1.4.0; writes `published-artefacts: verified` on its own line only when all three hold.
- verify: `grep -qx 'published-artefacts: verified' .plan/work/M06-T05/result.md`
- files: `.plan/work/M06-T05/result.md`

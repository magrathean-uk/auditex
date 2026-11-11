---
id: M06
name: release-1-5-0
weight: 15
status: planned
---
# M06 release-1-5-0
Track A. Starts after every M00, M04 and M05 DoD item is ticked; it does not wait for Track B, and no model explainer enters 1.5.0 (a later G gate). The version name and publication need G's explicit yes naming 1.5.0; the form stays a signed tag plus a GitHub release with the wheel and sdist, no PyPI (v2 DEC-001). Without that yes the milestone stops at the approved candidate. Build, gate and reproducibility checks run only in the candidate worktree (ARCHITECTURE.md candidate binding), never on a later `HEAD`; the orchestrator removes that worktree (`git worktree remove`, no `--force`) when M06 closes.

## Goal
1.5.0 is cut from `main` after the full gate chain, both acceptance suites with the full v3.9.1 replay, and a byte-reproducible build pass on the release commit; astra's gate returns ready and G's yes is recorded; the signed tag and GitHub release are published and the downloaded assets match the gated hashes.

## Definition of Done
- [ ] The packaged version is 1.5.0, the changelog has its section and the security policy supports 1.5.x: `grep -qx 'version = "1.5.0"' pyproject.toml && grep -q '^## \[1.5.0\]' CHANGELOG.md && grep -q '| 1.5.x | Yes |' .github/SECURITY.md`
- [ ] The 1.5.0 notes name the bundle contract change and the keyed pseudonyms: `sed -n '/^## \[1.5.0\]/,/^## \[1.4/p' CHANGELOG.md | grep -q 'CONTRACT_VERSION' && sed -n '/^## \[1.5.0\]/,/^## \[1.4/p' CHANGELOG.md | grep -qi 'keyed'`
- [ ] Review: an other-vendor review of the plan v4 merge of M06-T01 approves notes that also name the wider lint, the masking boundary and the scanner limits, at the exact merged head (ARCHITECTURE.md review binding): `T=M06-T01; c=$(git log v1.4.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/REV-$T/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/REV-$T/result.md"` Orchestrator check at close: the dispatch record names a launcher of the other vendor from the author's.
- [ ] Release check, dependency audit and the digest comparison are green in the candidate worktree (ARCHITECTURE.md candidate binding): `r=$(pwd) && c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && w="${CLEAN_DEV_WORK:?}/worktrees/auditex/v4-M06-candidate" && { test -e "$w" || git worktree add --detach "$w" "$c"; } && test "$(git -C "$w" rev-parse HEAD)" = "$c" && test -z "$(git -C "$w" status --porcelain)" && p="$r/.venv/bin/python" && cd "$w" && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" release-check && make PYTHON="$p" VENV="$r/.venv" audit-deps && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" contract-smoke && PYTHONPATH="$w/src" "$p" scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass in the candidate worktree: `r=$(pwd) && c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && w="${CLEAN_DEV_WORK:?}/worktrees/auditex/v4-M06-candidate" && { test -e "$w" || git worktree add --detach "$w" "$c"; } && test "$(git -C "$w" rev-parse HEAD)" = "$c" && test -z "$(git -C "$w" status --porcelain)" && p="$r/.venv/bin/python" && cd "$w" && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" acceptance`
- [ ] Two plain builds of the candidate, made in the candidate worktree, give byte-identical wheel and sdist bytes equal to the hashes M06-T02 recorded, and both pass the base, Google and MCP release smoke: `r=$(pwd) && c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && w="${CLEAN_DEV_WORK:?}/worktrees/auditex/v4-M06-candidate" && { test -e "$w" || git worktree add --detach "$w" "$c"; } && test "$(git -C "$w" rev-parse HEAD)" = "$c" && test -z "$(git -C "$w" status --porcelain)" && p="$r/.venv/bin/python" && cd "$w" && make PYTHON="$p" VENV="$r/.venv" dist && test "$(ls dist/*.whl | wc -l)" -eq 1 && test "$(ls dist/*.tar.gz | wc -l)" -eq 1 && PYTHON="$p" bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && "$p" scripts/check-reproducible-build.py && grep -qx "wheel-sha256: $(shasum -a 256 dist/*.whl | cut -d' ' -f1)" "$r/.plan/work/M06-T02/result.md" && grep -qx "sdist-sha256: $(shasum -a 256 dist/*.tar.gz | cut -d' ' -f1)" "$r/.plan/work/M06-T02/result.md"`
- [ ] Review: astra's pre-publication release gate returns ready on the full candidate sha, which is on `main`: `c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && git merge-base --is-ancestor "$c" main && grep -qE "^[[:space:]]*(summary: )?reviewed: $c\$" .plan/work/M06-T03/result.md && grep -qE '^[[:space:]]*(summary: )?verdict: ready$' .plan/work/M06-T03/result.md`
- [ ] Review: G's explicit yes naming 1.5.0 and the candidate sha is recorded in DECISIONS.md with approver G: `c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && grep -A8 '^## DEC-[0-9]* Release 1.5.0' .plan/DECISIONS.md | grep -q '^- approver: G' && grep -A8 '^## DEC-[0-9]* Release 1.5.0' .plan/DECISIONS.md | grep -qx -- "- candidate: $c"`
- [ ] The signed tag `v1.5.0` verifies locally, points at the candidate, and `origin` carries the same tag object peeling to the same commit: `c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && git tag -v v1.5.0 && test "$(git rev-parse 'v1.5.0^{commit}')" = "$c" && o=$(git rev-parse v1.5.0) && git ls-remote origin refs/tags/v1.5.0 'refs/tags/v1.5.0^{}' | awk -v o="$o" -v c="$c" '$2 == "refs/tags/v1.5.0" && $1 == o {a = 1} $2 == "refs/tags/v1.5.0^{}" && $1 == c {b = 1} END {exit !(a && b)}'`
- [ ] The GitHub release `v1.5.0` carries exactly the wheel and the sdist, and both, downloaded fresh, byte-match the hashes gated in M06-T02: `d=$(mktemp -d) && gh release download v1.5.0 --dir "$d" && test "$(ls "$d" | wc -l)" -eq 2 && grep -qx "wheel-sha256: $(shasum -a 256 "$d"/*.whl | cut -d' ' -f1)" .plan/work/M06-T02/result.md && grep -qx "sdist-sha256: $(shasum -a 256 "$d"/*.tar.gz | cut -d' ' -f1)" .plan/work/M06-T02/result.md && grep -qx 'published-artefacts: verified' .plan/work/M06-T05/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M06-T01 | Write the 1.5.0 release notes and bump the version | terra | M | - | todo |
| M06-T02 | Run the pre-publication gates on the release candidate | luna | S | - | todo |
| M06-T03 | Pre-publication release gate validation | astra | S | gate | todo |
| M06-T04 | Tag and publish 1.5.0 after G's yes | orchestrator | S | gate | todo |
| M06-T05 | Verify the published release | luna | S | - | todo |

## Acceptance criteria
### M06-T01 Write the 1.5.0 release notes and bump the version
- `pyproject.toml` says `1.5.0`; `CHANGELOG.md` turns `[Unreleased]` into `[1.5.0]` covering every change merged in plan v4: the new `CONTRACT_VERSION` and what it means for readers of 1.4.0 bundles, keyed per-run pseudonyms, middle-initial and title masking, the wider Ruff rule set, the closed scanner limits and the follow-ups; `.github/SECURITY.md` supports 1.5.x and moves 1.4.x to upgrade-only. No model or Track B content.
- verify: `grep -qx 'version = "1.5.0"' pyproject.toml && grep -q '^## \[1.5.0\]' CHANGELOG.md && grep -q '| 1.5.x | Yes |' .github/SECURITY.md && make test && make contract-smoke`
- files: `pyproject.toml` (version only), `CHANGELOG.md`, `.github/SECURITY.md`

### M06-T02 Run the pre-publication gates on the release candidate
- Precondition: M06-T01 merged; the candidate is the `main` head after that merge.
- In the candidate worktree (ARCHITECTURE.md candidate binding: `$CLEAN_DEV_WORK/worktrees/auditex/v4-M06-candidate`, which this task creates detached at the candidate), under `run-job`, behind the load rule, with `PYTHON`, `VENV` and `PYTHONPATH` as the binding sets them: `make release-check`, `make audit-deps`, `make contract-smoke` with the digest comparison, `make acceptance`, `make dist`, the release smoke and the reproducible-build check each exit 0.
- `result.md` records, each on its own line under `### Findings`, `candidate: <40-hex sha>`, `wheel-sha256: <64 hex>` and `sdist-sha256: <64 hex>` (equal across both reproducible builds), plus each step's exit status, the pytest counts and the replay's zero skips; on failure it names the step and stops.
- verify: `r=$(pwd) && c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && w="${CLEAN_DEV_WORK:?}/worktrees/auditex/v4-M06-candidate" && { test -e "$w" || git worktree add --detach "$w" "$c"; } && test "$(git -C "$w" rev-parse HEAD)" = "$c" && test -z "$(git -C "$w" status --porcelain)" && p="$r/.venv/bin/python" && cd "$w" && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" release-check && make PYTHON="$p" VENV="$r/.venv" audit-deps && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" contract-smoke && PYTHONPATH="$w/src" "$p" scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && PYTHONPATH="$w/src" make PYTHON="$p" VENV="$r/.venv" acceptance && make PYTHON="$p" VENV="$r/.venv" dist && test "$(ls dist/*.whl | wc -l)" -eq 1 && test "$(ls dist/*.tar.gz | wc -l)" -eq 1 && PYTHON="$p" bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && "$p" scripts/check-reproducible-build.py && grep -qx "wheel-sha256: $(shasum -a 256 dist/*.whl | cut -d' ' -f1)" "$r/.plan/work/M06-T02/result.md" && grep -qx "sdist-sha256: $(shasum -a 256 dist/*.tar.gz | cut -d' ' -f1)" "$r/.plan/work/M06-T02/result.md"`
- files: `.plan/work/M06-T02/result.md` (read-only run; it also creates the candidate worktree, outside the repository)

### M06-T03 Pre-publication release gate validation
- Precondition: M06-T02 done; every M00, M04 and M05 DoD item and M06 items 1-6 are ticked.
- astra in release mode on the candidate commit M06-T02 recorded; `result.md` carries `verdict: ready` or the gaps, and `reviewed: <40-hex sha>` equal to that candidate. The orchestrator brings G the candidate sha with the yes question and records `## DEC-nnn Release 1.5.0` with `- candidate: <40-hex sha>` and approver G.
- verify: `c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && grep -qE "^[[:space:]]*(summary: )?reviewed: $c\$" .plan/work/M06-T03/result.md && grep -qE '^[[:space:]]*(summary: )?verdict: ready$' .plan/work/M06-T03/result.md`
- files: `.plan/work/M06-T03/result.md`

### M06-T04 Tag and publish 1.5.0 after G's yes
- Preconditions: M06-T03 done with `verdict: ready` on the candidate; G's yes naming 1.5.0 recorded in DECISIONS.md with `- candidate:` equal to the M06-T02 candidate.
- Builds the candidate with plain `make dist` in the candidate worktree (ARCHITECTURE.md candidate binding), confirms the wheel and sdist sha256 both equal the M06-T02 record, signs and pushes `v1.5.0` on that commit, checks that `origin` carries the same tag object peeling to the candidate, creates the GitHub release with exactly the wheel and the sdist and records the uploaded hashes. No PyPI.
- verify: `c=$(sed -n 's/^candidate: \([0-9a-f]\{40\}\)$/\1/p' .plan/work/M06-T02/result.md | head -1) && test -n "$c" && git tag -v v1.5.0 && test "$(git rev-parse 'v1.5.0^{commit}')" = "$c" && o=$(git rev-parse v1.5.0) && git ls-remote origin refs/tags/v1.5.0 | awk -v o="$o" '$2 == "refs/tags/v1.5.0" && $1 == o {f = 1} END {exit !f}' && gh release view v1.5.0 --json assets`
- files: `.plan/work/M06-T04/result.md`

### M06-T05 Verify the published release
- Precondition: M06-T04 done (tag on `origin`, release created).
- Downloads both assets fresh, compares their sha256 with the M06-T02 record (which M06-T04's record must equal), confirms the release has no other asset, installs the wheel in a scratch venv and checks it reports 1.5.0; writes `published-artefacts: verified` on its own line only when all hold.
- verify: `grep -qx 'published-artefacts: verified' .plan/work/M06-T05/result.md`
- files: `.plan/work/M06-T05/result.md`

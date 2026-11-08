# PLAN-v2 evidence

Evidence behind the ticked DoD items and the plan's premises. Commands ran in a detached worktree at
`origin/main` 82d7ca5 (the accepted line) with the project venv and `PYTHONPATH=src`. No repository file
was changed by these runs.

## Bases
- Local `main` de3a25d = b591772 plus the two plan commits (8b3a334 scaffold, de3a25d checkpoint).
- `origin/main` 82d7ca5 = b591772 plus 120 accepted commits; local `main` and `origin/main` have diverged.
- Plan branch `task/PLAN-v2-plan-v2`: reset commit 0625b87 (archive in `.plan/archive/plan-v1/`), then the plan commit.

## Branch state at plan time (`git merge-base --is-ancestor <tip> origin/main`)
| branch | tip | state |
|---|---|---|
| wt/redact-key-guard-2 | 8c23d24 | merged (D7's 1.3.0 gate condition met) |
| wt/key-guard-3 | 13a288b | merged |
| wt/explainer-wire | 88a379b | merged |
| wt/gates-zero-row-trust | 89b5e9d | merged |
| wt/docs-rules-and-scan-limits | fe78ee1 | unmerged, 1 commit, README.md only (M02-T02) |
| wt/redact-person-names | 3e495d6 | unmerged, 11 ahead; D5 reference only (D6) |
| wt/collect-certauth-1 | 23f9186 | unmerged, 8 ahead; live-tenant work, parked |
| wt/redact-key-guard | fcd1ec4 | unmerged, 3 ahead; superseded by -2/-3 (inferred; M00-T04 confirms) |
`git branch --list 'wt/*'` = 88; `--no-merged origin/main` = 44 (M00-T04 triages them).

## Ownership map check (M00 DoD item 9)
Result at 82d7ca5: 895 tracked non-`.plan` files; 0 non-test files unmatched; 0 files matched by two
modules; 198 `tests/test_*.py` files owned by the import convention stated under the map.
Script (brace globs expanded; `/**` = any depth; `*` = one path segment):

```python
import re, subprocess, sys
arch, repo = sys.argv[1], sys.argv[2]
files = [f for f in subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True,
         check=True).stdout.split() if not f.startswith(".plan/")]
def expand(g):
    m = re.search(r"\{([^{}]*)\}", g)
    if not m: return [g]
    return [x for alt in m.group(1).split(",") for x in expand(g[:m.start()] + alt + g[m.end():])]
def match(p, g):
    if g.endswith("/**"): return p.startswith(g[:-3] + "/")
    return re.match("^" + re.escape(g).replace(r"\*\*", ".*").replace(r"\*", "[^/]*") + "$", p) is not None
rows = {}
for line in open(arch):
    if not line.startswith("| ") or line.startswith("| module"): continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    rows[cells[0]] = [e for g in re.findall(r"`([^`]+)`", cells[1]) for e in expand(g)]
un = [f for f in files if not any(match(f, g) for gs in rows.values() for g in gs)]
dbl = [f for f in files if sum(any(match(f, g) for g in gs) for gs in rows.values()) > 1]
print(len(files), len([f for f in un if not re.match(r"tests/test_[^/]*\.py$", f)]), len(dbl))
```

## Docs checks (M02 ticked items)
- `! git grep -q -i -E 'MS\.GWS|GWS\.[A-Z]+\.[0-9]|scuba (gws|google)' -- README.md docs` passed.
- `docs/guides/admin-permission-guide.md:284` "extended scope, off by default"; `:320` and `:332` state the
  write-capable roles used read-only and their blast radius.

## Assessment findings re-checked at 82d7ca5
| finding | state |
|---|---|
| `Makefile:54` `$$TMPDIR` under `set -eu` | still present (M00-T02) |
| `docs/guides/admin-permission-guide.md` -> `docs/prerequisites/` | still present at :371 (M02-T01) |
| `docs/legal/third-party-notices.md` -> `skills/mcp-builder/` | still present; legal file, G-owned |
| `docs/guides/model-development.md` -> `tests/providers/m365` | not a defect: upstream sparse-checkout path |
| explainer "planned and unimplemented" | still in `docs/guides/ai-assessment.md:82-83` and `CHANGELOG.md:115` (M02-T03, M03-T01) |
| `defender_spam.py:6` "held until P4" | still present (M02-T01) |
| `auditex validate` cited | text says it does not apply; not a defect |
| Google redaction list lacks `--access-token` etc. | Google parser has no such flags; its set covers key, OAuth client and token cache. `guided.py:316,547` builds argv with `--client-secret` - checked in M01-T01 |
| `security-privacy.md` "Read-only annotations are unchanged" | still at line 103 (M01-T03) |
| `.github/SECURITY.md` supports 1.2.x | still present (M03-T01) |
| `examples/model_development/cases.jsonl` | 48 synthetic rows, `split` in train/validation/test, `provenance` field (M01-T04) |

## Gate run (M00 DoD items 2-8)
Not run in the plan session (the first attempt hit the 1800-second worker timeout). The items stay unticked:
they apply to the reconciled `main`, which does not exist yet, and M00-T01 runs them there under `run-job`.

## Resume round re-checks (at 82d7ca5, read-only, `git grep` and `git show` against the commit)
- Ownership map re-run with `git ls-tree -r --name-only 82d7ca5` instead of `ls-files`: 895 files, 0 unmatched
  non-test, 0 in two modules, 198 test files by convention, 13 modules (M00 DoD item 9 ticked).
- Engine redaction sets are `secret_hygiene.SENSITIVE_ARG_FLAGS` (:14) and `auth_runtime.SENSITIVE_CLI_ARGS` (:13);
  Google `run._SENSITIVE_COMMAND_FLAGS` (:66); product `command_runner.SENSITIVE_ARGS` (:13).
- `test_build_probe_command_never_carries_a_client_secret` is `tests/test_auditex_product.py:456`;
  `build_probe_command` is `src/auditex/command_builders.py:170`.
- Explainer "planned" wording: `docs/guides/ai-assessment.md:83,89,130,181`, `docs/guides/model-development.md:120`.
- `release-check` scans with `gitleaks dir . --no-banner --redact` (`Makefile:68`); `scripts/release-smoke.sh` takes
  `DIST_DIR` and `SMOKE_ROOT`; `pyproject.toml` version `1.3.0.dev0`; `.github/SECURITY.md:22` `| 1.2.x | Yes |`.
- Runbook (`docs/development/runbook.md:101`) names a tag only; no GitHub release or PyPI step.
- Every test file and source path named in a verify or files line exists at 82d7ca5.

## Revision 1 re-checks (plan branch 3122ac5; non-plan tree differs from 82d7ca5 only in AGENTS.md)
- `git merge-base --is-ancestor 82d7ca5 main` passed with `main` at cd6b134; `main` is an ancestor of 3122ac5 (M00 DoD item 1).
- Ownership map re-run after the ARCHITECTURE.md revision with `git ls-tree -r --name-only HEAD`: 895 files, 13 modules, 0 unmatched non-test, 0 in two modules, 198 tests by convention (M00 DoD item 10).
- `! git grep -q -i -E 'MS\.GWS|GWS\.[A-Z]+\.[0-9]|scuba (gws|google)' -- README.md docs` passed; admin guide :284 "off by default", :320 and :332 "write-capable admin role used read-only" (M02 items 6-7).
- Non-GET call sites: `graph.py:342,384` session POSTs and `:800` `$batch`; `notify.py:306` webhook, `:476` Jira issue, `:583` GitHub comment, `:619` GitHub issue; `model_serving.py:259` chat-completions POST, default endpoint `http://127.0.0.1:8080/v1` (:114); `collectors/power_platform.py:199` `client.request(method, ...)`; `google_workspace/auth.py:122` token refresh.
- Existing read-boundary code: `api_inventory.py` content rules (:258-263) and cmdlet scan (:411); `adapters/read_guard.py:391` `check_command` for the Microsoft 365 CLI.
- `scripts/release-smoke.sh` installs only the wheel; default smoke root `/tmp/auditex-release-smoke`.
- `pyproject.toml` extras: `mcp`, `test`, `google`, `model_train` (exact pins: torch, transformers, trl, peft, accelerate, datasets).
- `merge.sh` squash-merges and writes `Plan-Review: <review id> <verdict> <head[:12]>` on the squash commit.
- First-party Markdown scan: 3 backticked missing paths (`docs/guides/admin-permission-guide.md:371`, `docs/guides/model-development.md:830` upstream path, `docs/legal/third-party-notices.md:17`); 1 dead relative link, in vendored `tests/schemas/LICENSE-OSCAL.md:34`. The notice's file is tracked at `tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt`.
- `percent.py --check` exit 0: M00 18, M01 0, M02 25, M03 0, overall 9%.

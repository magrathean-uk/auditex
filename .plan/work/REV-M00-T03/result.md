## RESULT REV-M00-T03
status: done
summary:
verdict: changes-required
reviewed: 6280844a43c62108c8e6124bcd0018e66aa8c1ae
Metadata-only resolution is not enforced. Runtime verification was blocked by the sandbox.
changes: none
verification:
- `make audit-deps`: blocked by sandbox, exit 2; first failing lines: `mkdir: build: Operation not permitted`; `make: *** [audit-deps] Error 1`.
- `git diff --check main...HEAD`: pass.
- `git check-ignore -q build/audit-deps/base.txt`: pass.
- M00-T02 commit ancestry check: pass.
- `clean-development doctor`: fail; environment, Xcode routing and lifecycle-lock checks.
risks:
- Audit results and vulnerability failure handling remain unverified here; `merge.sh --verify` remains the gate.
- Storage lifecycle registration is unreliable; doctor reports a dead/unverifiable lock, configuration mismatches and unexpected dot-folders. No repairs attempted.
- Full tests and `make release-check` skipped in this read-only review; the author also reports these were not run.
questions_for_g: none

### Findings
Criteria checklist:
- Met - M00-T02 precedes this work: its commit is an ancestor; `Makefile:86` contains its release targets.
- Not met - metadata-only resolution: `Makefile:62` permits source-distribution builds.
- Met statically - base, every current extra, host and Linux aarch64 resolution, pinned outputs, required audit flags and non-zero failure aggregation: `Makefile:62`, `Makefile:64`, `Makefile:65`, `Makefile:72`, `Makefile:74`. Runtime results untestable here.
- Met - development-only tooling and ignored, registered output directory: `pyproject.toml:48`, `Makefile:48`, `.gitignore:8`, `.clean-development.json:7`.
- Untestable - finding outcomes: `.plan/work/M00-T03/result.md:5` in the source checkout reports no findings. No ignore file or dependency fixes were added; required ignore fields are checked at `Makefile:68`.
- Untestable - dependency-audit DoD at `.plan/milestones/M00-foundation.md:21`: sandbox blocked execution; no advisory exceptions exist to check.
- Met - files restriction: only `Makefile` and `pyproject.toml` changed; both belong to packaging-release. Out-of-scope paths: none.

Required changes:
1. `Makefile:62` - unrestricted `uv pip compile` can download source distributions and execute build backends to obtain metadata, violating the metadata-only criterion. Add `--no-build` or equivalent controls and fail clearly when metadata-only resolution is unavailable.

Other review checks:
- No added secrets, unsafe deserialisation, tenant permissions, file-mode changes or demonstrated injection issue found.
- `pyproject.toml:49`: pip-audit is justified, development-only and version-bounded; generated lists pin versions. Cached pip-audit 2.10.1 metadata and licence confirm Apache-2.0.
- Naming and failure aggregation are clear; no dead code found. Behavioural failure-path tests were not supplied.

Non-blocking suggestion:
- `Makefile:54` claims a fresh directory each run, but `Makefile:61` reuses it. Correct the comment or create a fresh directory; existing output pins influence subsequent uv resolutions.

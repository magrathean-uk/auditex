## RESULT M03-T05
status: done
summary: Signed tag v1.3.0 (tag object 5f61f29df4b2b6c0d56cc0fde64028813dc693d7) points at d9f050f1be6b4ce9c04d8a7caa7e493c22546a8c; only the tag was pushed. Release: https://github.com/magrathean-uk/auditex/releases/tag/v1.3.0 (assets auditex-1.3.0-py3-none-any.whl 2184464 bytes, auditex-1.3.0.tar.gz 3122427 bytes)
sha256: 6b2efad8860c82aa7bb8c845f7b3f09d558de3f2152b7af27ef86e0ce35527e0  auditex-1.3.0-py3-none-any.whl
sha256: 3780b561da3b71eecb4b31cd1d1a050f6efc6e380d05626efa0d16e0583c1d84  auditex-1.3.0.tar.gz
Built with SOURCE_DATE_EPOCH=1794158384 and not rebuilt afterwards; release notes are the CHANGELOG 1.3.0 section (63.5 KB).
changes: none to tracked files (git-ignored .venv link and dist/ only; evidence.md and release-notes-1.3.0.md written to .plan/work/M03-T05/)
verification: preflight (HEAD, empty local and remote tag) pass; make dist pass; release-smoke.sh on dist pass; check-reproducible-build.py pass; gh auth (repo scope) pass; tag -v with temporary allowed-signers pass; ls-remote pass; gh release view (both assets uploaded, digests match local) pass
risks: check-reproducible-build.py wheel (c78c95c1...) is not byte-equal to the make dist wheel (mode bits only, zero content diffs; cause in evidence.md), so the script proves determinism of its own method; M03-T06 must verify against the hashes above, not the script's
questions_for_g: none

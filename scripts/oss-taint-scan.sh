#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for forbidden in \
  docs/research \
  src/auditex/research.py \
  tests/test_research.py; do
  if [ -e "$forbidden" ]; then
    echo "forbidden path present: $forbidden" >&2
    exit 1
  fi
done

for derived in \
  .venv \
  .secrets \
  outputs \
  .pytest_cache \
  src/auditex.egg-info; do
  if git ls-files --error-unmatch "$derived" >/dev/null 2>&1; then
    echo "derived path is tracked: $derived" >&2
    exit 1
  fi
done

PATTERN='(^|[^[:alnum:]_])steal([^[:alnum:]_]|$)|Competitor harvest|auditex research competitors|docs/research|src/auditex/research|ThomasKur/M365Documentation|System-Admins/m365assessment|ThomasKur__M365Documentation|System-Admins__m365assessment'
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

git ls-files -z -- \
  ':!:docs/provenance/**' \
  ':!:tenant-bootstrap/vendor/microsoft-skills/**' \
  ':!:scripts/oss-taint-scan.sh' \
  ':!:**/third-party-notices.md' \
  ':!:*.pyc' \
  | xargs -0 grep -nIE "$PATTERN" > "$TMP" || true

if [ -s "$TMP" ]; then
  echo "taint markers found outside private provenance/taint records:" >&2
  cat "$TMP" >&2
  exit 1
fi

echo "oss-taint-scan: clean"

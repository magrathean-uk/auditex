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

find . \
  -path './.git' -prune -o \
  -path './.venv' -prune -o \
  -path './.secrets' -prune -o \
  -path './outputs' -prune -o \
  -path './.pytest_cache' -prune -o \
  -path './docs/taint' -prune -o \
  -path './docs/provenance' -prune -o \
  -path './tenant-bootstrap/vendor/microsoft-skills' -prune -o \
  -path './scripts/oss-taint-scan.sh' -prune -o \
  -name 'license.md' -prune -o \
  -name 'THIRD_PARTY_NOTICES.md' -prune -o \
  -name '*.pyc' -prune -o \
  -name '__pycache__' -prune -o \
  -type f -print0 \
  | xargs -0 grep -nIE "$PATTERN" > "$TMP" || true

if [ -s "$TMP" ]; then
  echo "taint markers found outside private provenance/taint records:" >&2
  cat "$TMP" >&2
  exit 1
fi

echo "oss-taint-scan: clean"

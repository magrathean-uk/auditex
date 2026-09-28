#!/usr/bin/env bash
set -euo pipefail

min_major=3
min_minor=11
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_venv_python="${script_dir}/../.venv/bin/python"

is_supported() {
  local candidate="$1"
  local version
  version="$("$candidate" - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)"
  local major="${version%%.*}"
  local minor="${version#*.}"
  if [[ "${major}" -gt "${min_major}" ]]; then
    return 0
  fi
  if [[ "${major}" -eq "${min_major}" && "${minor}" -ge "${min_minor}" ]]; then
    return 0
  fi
  return 1
}

if [[ -n "${PYTHON_BIN:-}" ]] && command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  if is_supported "${PYTHON_BIN}"; then
    command -v "${PYTHON_BIN}"
    exit 0
  fi
fi

if [[ -x "${repo_venv_python}" ]] && is_supported "${repo_venv_python}"; then
  printf '%s\n' "${repo_venv_python}"
  exit 0
fi

for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "${candidate}" >/dev/null 2>&1 && is_supported "${candidate}"; then
    command -v "${candidate}"
    exit 0
  fi
done

exit 1

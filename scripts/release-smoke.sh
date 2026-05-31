#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${1:-${REPO_ROOT}/dist}"
SMOKE_ROOT="${2:-/tmp/auditex-release-smoke}"

WHEEL_PATH="$(printf '%s\n' "${DIST_DIR}"/*.whl | head -n 1)"
if [[ ! -f "${WHEEL_PATH}" ]]; then
  echo "wheel not found under ${DIST_DIR}" >&2
  exit 2
fi

python - "${SMOKE_ROOT}" <<'PY'
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
if root.exists():
    shutil.rmtree(root)
root.mkdir(parents=True, exist_ok=True)
PY

create_venv() {
  local name="$1"
  local venv_path="${SMOKE_ROOT}/${name}-venv"
  python -m venv "${venv_path}"
  # shellcheck disable=SC1090
  . "${venv_path}/bin/activate"
  python -m pip install --upgrade pip >/dev/null
}

deactivate_venv() {
  deactivate >/dev/null 2>&1 || true
}

create_venv base
python -m pip install "${WHEEL_PATH}" >/dev/null
auditex --help >/dev/null
auditex run --offline \
  --sample "${REPO_ROOT}/examples/sample_audit_bundle/sample_result.json" \
  --tenant-name ci \
  --run-name release-smoke \
  --out "${SMOKE_ROOT}/base-output" >/dev/null
deactivate_venv

create_venv google
python -m pip install "${WHEEL_PATH}[google]" >/dev/null
python - <<'PY'
import json
import subprocess

payload = json.loads(
    subprocess.check_output(
        ["auditex", "google", "doctor", "--json"],
        text=True,
    )
)
assert payload["dependencies"]["available"] is True, payload
PY
deactivate_venv

create_venv mcp
python -m pip install "${WHEEL_PATH}[mcp]" >/dev/null
python - <<'PY'
from mcp.server.fastmcp import FastMCP

assert FastMCP is not None
PY
deactivate_venv

echo "release smoke ok"

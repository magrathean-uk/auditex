#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${1:-${REPO_ROOT}/dist}"
SMOKE_PARENT="${2:-${TMPDIR:?TMPDIR must be set}/auditex-release-smoke}"

# Exactly one wheel and one sdist, both of the version in pyproject.toml: a stale or newer build left in
# the folder must never stand in for the one being released.
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "${REPO_ROOT}/pyproject.toml" | head -n 1)"
shopt -s nullglob
wheels=("${DIST_DIR}"/*.whl)
sdists=("${DIST_DIR}"/*.tar.gz)
shopt -u nullglob
if [[ ${#wheels[@]} -ne 1 || ${#sdists[@]} -ne 1 ]]; then
  echo "expected exactly one wheel and one sdist under ${DIST_DIR}, found ${#wheels[@]} and ${#sdists[@]}; run make dist" >&2
  exit 2
fi
WHEEL_PATH="${DIST_DIR}/auditex-${VERSION}-py3-none-any.whl"
SDIST_PATH="${DIST_DIR}/auditex-${VERSION}.tar.gz"
if [[ -z "${VERSION}" || "${wheels[0]}" != "${WHEEL_PATH}" || "${sdists[0]}" != "${SDIST_PATH}" ]]; then
  echo "the artefacts under ${DIST_DIR} are not auditex-${VERSION} (the pyproject.toml version); run make dist" >&2
  exit 2
fi
if [[ -n "${PYTHON:-}" ]]; then
  BASE_PYTHON="${PYTHON}"
elif [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  BASE_PYTHON="${REPO_ROOT}/.venv/bin/python"
else
  BASE_PYTHON="python3"
fi
mkdir -p "${SMOKE_PARENT}"
SMOKE_ROOT="$(mktemp -d "${SMOKE_PARENT}/run.XXXXXX")"

create_venv() {
  local name="$1"
  local venv_path="${SMOKE_ROOT}/${name}-venv"
  "${BASE_PYTHON}" -m venv "${venv_path}"
  # shellcheck disable=SC1090
  . "${venv_path}/bin/activate"
  VPY="${venv_path}/bin/python"
  "${VPY}" -m pip install --upgrade pip >/dev/null
}

deactivate_venv() {
  deactivate >/dev/null 2>&1 || true
}

for kind in wheel sdist; do
if [[ "${kind}" == wheel ]]; then artifact="${WHEEL_PATH}"; else artifact="${SDIST_PATH}"; fi
create_venv "${kind}-base"
"${VPY}" -m pip install "${artifact}" >/dev/null
auditex --help >/dev/null
auditex run --offline \
  --sample "${REPO_ROOT}/examples/sample_audit_bundle/sample_result.json" \
  --tenant-name ci \
  --run-name release-smoke \
  --out "${SMOKE_ROOT}/${kind}-base-output" >/dev/null
deactivate_venv

create_venv "${kind}-google"
"${VPY}" -m pip install "${artifact}[google]" >/dev/null
"${VPY}" - <<'PY'
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

create_venv "${kind}-mcp"
"${VPY}" -m pip install "${artifact}[mcp]" >/dev/null
"${VPY}" - <<'PY'
from mcp.server.fastmcp import FastMCP

assert FastMCP is not None
PY
deactivate_venv

done

echo "release smoke ok"

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${1:-${REPO_ROOT}/dist}"
SMOKE_PARENT="${2:-${TMPDIR:?TMPDIR must be set}/auditex-release-smoke}"
if [[ ! -d "${DIST_DIR}" ]]; then
  echo "dist folder not found: ${DIST_DIR}" >&2
  exit 2
fi
DIST_DIR="$(cd "${DIST_DIR}" && pwd)"

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
# A relative interpreter path is anchored here, before the script changes into its empty folder.
if [[ "${BASE_PYTHON}" == */* ]]; then
  BASE_PYTHON="$(cd "$(dirname "${BASE_PYTHON}")" && pwd)/$(basename "${BASE_PYTHON}")"
fi
mkdir -p "${SMOKE_PARENT}"
SMOKE_ROOT="$(cd "$(mktemp -d "${SMOKE_PARENT}/run.XXXXXX")" && pwd)"
# Every installed command runs from an empty folder, never the checkout, so a shipped file missing from the
# wheel or sdist cannot be supplied by the source tree.
SMOKE_CWD="${SMOKE_ROOT}/cwd"
mkdir "${SMOKE_CWD}"
cd "${SMOKE_CWD}"

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
"${VPY}" - <<'PY'
import sysconfig
from pathlib import Path

from azure_tenant_audit import resources
from auditex import bootstrap

# Only this environment's data tree: an older Auditex under the base interpreter must not supply missing files.
adapters = resources._resource_adapters()
assert adapters and {a.name for a in adapters} == {"installed"}, adapters
assert {a.root for a in adapters} == {Path(sysconfig.get_paths()["data"]) / "auditex"}, adapters
readiness = bootstrap.build_doctor_report()["readiness"]
assert readiness["core_ready"], readiness
PY
auditex setup >/dev/null
demo_dir="${SMOKE_ROOT}/${kind}-demo"
mkdir "${demo_dir}"
(cd "${demo_dir}" && auditex demo --no-pause --no-html >/dev/null)
# Both demo runs prove the demo tenant and its remediated twin shipped (the demo falls back otherwise).
test -d "${demo_dir}/outputs/demo/runs/halcyon-demo"
test -d "${demo_dir}/outputs/demo/runs/halcyon-after-fixes"
# Every shipped file committed in HEAD is in the installed data.
git -C "${REPO_ROOT}" ls-files > "${SMOKE_ROOT}/${kind}-tracked.txt"
"${VPY}" - "${SMOKE_ROOT}/${kind}-tracked.txt" <<'PY'
import sys
from pathlib import PurePosixPath

from azure_tenant_audit import resources
from azure_tenant_audit.shipped_content import SHIPPED_CONTENT_AREAS

patterns = [pattern for area in SHIPPED_CONTENT_AREAS for pattern in area.package_patterns]
tracked = {
    name for name in open(sys.argv[1], encoding="utf-8").read().splitlines()
    if any(len(PurePosixPath(name).parts) == len(PurePosixPath(p).parts) and PurePosixPath(name).match(p) for p in patterns)
}
installed = set(resources.shipped_resource_manifest()["resources"])
missing = sorted(tracked - installed)
assert tracked and not missing, missing
PY
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

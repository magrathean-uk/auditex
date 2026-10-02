#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-${ROOT_DIR}/.venv}"
INSTALL_EXCHANGE=0
INSTALL_PWSH=0
INSTALL_MCP=0
PYTHON_BIN="${PYTHON_BIN:-}"
PACKAGE_MANAGER="manual"

usage() {
  cat <<'USAGE'
Usage: bootstrap-local-tools.sh [--exchange] [--pwsh] [--mcp]

Installs the local Python package into .venv and adds optional tool packs on demand.
The default path stays runtime-only.
USAGE
}

detect_package_manager() {
  if command -v brew >/dev/null 2>&1; then
    PACKAGE_MANAGER="brew"
  elif command -v apt-get >/dev/null 2>&1; then
    PACKAGE_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PACKAGE_MANAGER="dnf"
  else
    PACKAGE_MANAGER="manual"
  fi
}

run_package_manager_plan() {
  local install_line="$1"
  local manual_line="$2"

  case "${PACKAGE_MANAGER}" in
    brew)
      echo "Plan: brew install ${install_line}"
      brew install ${install_line}
      ;;
    apt)
      echo "Plan: sudo apt-get update && sudo apt-get install -y ${install_line}"
      sudo apt-get update
      sudo apt-get install -y ${install_line}
      ;;
    dnf)
      echo "Plan: sudo dnf install -y ${install_line}"
      sudo dnf install -y ${install_line}
      ;;
    manual)
      echo "${manual_line}"
      return 1
      ;;
  esac
}

ensure_python() {
  if [[ -n "${PYTHON_BIN}" ]] && command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "${PYTHON_BIN}")"
    if ensure_supported_python_version "${PYTHON_BIN}"; then
      return 0
    fi
  fi

  if PYTHON_BIN="$("${ROOT_DIR}/scripts/select-python.sh")"; then
    return 0
  fi

  case "${PACKAGE_MANAGER}" in
    brew)
      echo "Plan: brew install python@3.14"
      brew install python@3.14
      ;;
    apt)
      echo "Plan: sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
      sudo apt-get update
      sudo apt-get install -y python3 python3-venv python3-pip
      ;;
    dnf)
      echo "Plan: sudo dnf install -y python3 python3-venv python3-pip"
      sudo dnf install -y python3 python3-venv python3-pip
      ;;
    manual)
      echo "Python 3.11+ missing. Install it and rerun."
      exit 1
      ;;
  esac

  if ! PYTHON_BIN="$("${ROOT_DIR}/scripts/select-python.sh")"; then
    echo "Python 3.11+ missing. Install it and rerun."
    exit 1
  fi
}

ensure_supported_python_version() {
  local candidate="$1"
  if ! "${candidate}" - <<'PY'
import sys
raise SystemExit(0 if (sys.version_info.major, sys.version_info.minor) >= (3, 11) else 1)
PY
  then
    return 1
  fi
  return 0
}

ensure_azure_cli() {
  if command -v az >/dev/null 2>&1; then
    return 0
  fi

  run_package_manager_plan \
    "azure-cli" \
    "Azure CLI missing. Install it with your platform package manager."
}

ensure_exchange_pack() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    :
  else
    case "${PACKAGE_MANAGER}" in
      brew)
        echo "Plan: brew install node"
        brew install node
        ;;
      apt)
        echo "Plan: sudo apt-get update && sudo apt-get install -y nodejs npm"
        sudo apt-get update
        sudo apt-get install -y nodejs npm
        ;;
      dnf)
        echo "Plan: sudo dnf install -y nodejs npm"
        sudo dnf install -y nodejs npm
        ;;
      manual)
        echo "Node.js 20+ and npm missing. Install them, then rerun."
        exit 1
        ;;
    esac
  fi

  local node_major
  node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
  if [[ ! "${node_major}" =~ ^[0-9]+$ ]] || (( node_major < 20 )); then
    echo "Node.js 20+ is required by the current CLI for Microsoft 365 release. Upgrade Node.js, then rerun." >&2
    return 1
  fi

  if ! command -v m365 >/dev/null 2>&1; then
    echo "Plan: npm install -g @pnp/cli-microsoft365@latest"
    npm install -g @pnp/cli-microsoft365@latest
  fi
}

ensure_pwsh_pack() {
  if command -v pwsh >/dev/null 2>&1; then
    return 0
  fi

  run_package_manager_plan \
    "powershell" \
    "PowerShell 7+ missing. Install it with your platform package manager."
}

ensure_exchange_online_module() {
  if ! command -v pwsh >/dev/null 2>&1; then
    echo "PowerShell 7+ missing. Install it and rerun."
    exit 1
  fi
  if pwsh -NoLogo -NoProfile -Command "Get-Module -ListAvailable ExchangeOnlineManagement | Select-Object -First 1 Name | ConvertTo-Json -Compress" | grep -q ExchangeOnlineManagement; then
    return 0
  fi
  echo "Plan: pwsh Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber"
  pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exchange)
      INSTALL_EXCHANGE=1
      shift
      ;;
    --pwsh)
      INSTALL_PWSH=1
      shift
      ;;
    --mcp)
      INSTALL_MCP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

detect_package_manager
ensure_python

venv_python="${VENV_DIR}/bin/python"
if [[ -x "${venv_python}" ]] && ! ensure_supported_python_version "${venv_python}"; then
  rm -rf "${VENV_DIR}"
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# Venvs made by uv have no pip; install through uv then, or bootstrap pip with ensurepip.
venv_pip_install() {
  if python -m pip --version >/dev/null 2>&1; then
    python -m pip install "$@"
  elif command -v uv >/dev/null 2>&1; then
    uv pip install --python "${VENV_DIR}/bin/python" "$@"
  else
    python -m ensurepip --upgrade
    python -m pip install "$@"
  fi
}

venv_pip_install -e "${ROOT_DIR}"

if [[ "${INSTALL_MCP}" -eq 1 ]]; then
  venv_pip_install -e "${ROOT_DIR}[mcp]"
fi

if ! ensure_azure_cli; then
  exit 1
fi

if [[ "${INSTALL_EXCHANGE}" -eq 1 ]]; then
  if ! ensure_exchange_pack; then
    exit 1
  fi
  if ! ensure_pwsh_pack; then
    exit 1
  fi
  ensure_exchange_online_module
fi

if [[ "${INSTALL_PWSH}" -eq 1 ]]; then
  if ! ensure_pwsh_pack; then
    exit 1
  fi
fi

hash -r
echo "Bootstrap done."

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_BOOTSTRAP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${TENANT_BOOTSTRAP_ROOT}/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: run-audit-collector.sh [options]

The lab audit runs one way only: the reader app with its certificate (DEC-107).

  --tenant-name NAME       Tenant display name (default: tenant)
  --tenant-id ID           Lab tenant ID (required; default: $AZURE_TENANT_ID)
  --client-id ID           Reader app client ID (required; default: $AZURE_CLIENT_ID)
  --certificate-path FILE  Reader app certificate private key, PEM or PFX, readable only by its owner (required)
  --certificate-thumbprint SHA1  Thumbprint of the certificate on the app registration (required)
  --certificate-password-env NAME  Environment variable holding the key password (optional)
  --certificate-password-file FILE File holding the key password (optional)
  --collectors LIST        Comma-separated collectors (default: identity,security,intune,teams,exchange)
  --include-exchange       Enable command-based exchange collector (full collector set)
  --top N                  Max items per endpoint (default: 500)
  --out PATH               Output directory (default: tenant-bootstrap/audit-output)
  --run-name NAME          Optional run name
  --auditor-profile PROFILE  Audit profile: auto|enterprise|global-reader (default: auto)
  --dry-run                Print the command without running it
  --help
USAGE
}

TENANT_NAME="tenant"
TENANT_ID="${AZURE_TENANT_ID:-}"
COLLECTORS="identity,security,intune,teams,exchange"
TOP="500"
OUT_DIR=""
RUN_NAME=""
INCLUDE_EXCHANGE=0
CLIENT_ID="${AZURE_CLIENT_ID:-}"
CERTIFICATE_PATH=""
CERTIFICATE_THUMBPRINT=""
CERTIFICATE_PASSWORD_ENV=""
CERTIFICATE_PASSWORD_FILE=""
AUDITOR_PROFILE="auto"
DRY_RUN=0
FULL_AUDIT_ROOT=""
CONFIG_ROOT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant-name)
      TENANT_NAME="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
      shift 2
      ;;
    --collectors)
      COLLECTORS="$2"
      shift 2
      ;;
    --top)
      TOP="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --client-id)
      CLIENT_ID="$2"
      shift 2
      ;;
    --certificate-path)
      CERTIFICATE_PATH="$2"
      shift 2
      ;;
    --certificate-thumbprint)
      CERTIFICATE_THUMBPRINT="$2"
      shift 2
      ;;
    --certificate-password-env)
      CERTIFICATE_PASSWORD_ENV="$2"
      shift 2
      ;;
    --certificate-password-file)
      CERTIFICATE_PASSWORD_FILE="$2"
      shift 2
      ;;
    --interactive|--browser-command|--token-env|--scopes)
      echo "$1 was removed: the lab audit runs only with the reader app's certificate (--client-id, --certificate-path, --certificate-thumbprint)." >&2
      exit 1
      ;;
    --auditor-profile)
      AUDITOR_PROFILE="$2"
      shift 2
      ;;
    --include-exchange)
      INCLUDE_EXCHANGE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
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

if [[ -z "$TENANT_ID" || -z "$CLIENT_ID" || -z "$CERTIFICATE_PATH" || -z "$CERTIFICATE_THUMBPRINT" ]]; then
  echo "The lab audit needs --tenant-id, --client-id, --certificate-path and --certificate-thumbprint (the reader app with its certificate)." >&2
  exit 2
fi
if [[ -n "$CERTIFICATE_PASSWORD_ENV" && -n "$CERTIFICATE_PASSWORD_FILE" ]]; then
  echo "Use one of --certificate-password-env and --certificate-password-file." >&2
  exit 2
fi

# The audit runs from another folder below, so relative key and password paths are made absolute first.
absolute_path() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$PWD" "$1" ;;
  esac
}
CERTIFICATE_PATH="$(absolute_path "$CERTIFICATE_PATH")"
if [[ -n "$CERTIFICATE_PASSWORD_FILE" ]]; then
  CERTIFICATE_PASSWORD_FILE="$(absolute_path "$CERTIFICATE_PASSWORD_FILE")"
fi

OUT_DIR="$(absolute_path "${OUT_DIR:-${TENANT_BOOTSTRAP_ROOT}/audit-output}")"
if [[ ! -d "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python not found. Set PYTHON_BIN to a valid python3 executable."
  exit 2
fi

HAS_FULL_AUDIT=0
if [[ -f "${REPO_ROOT}/src/azure_tenant_audit/cli.py" && -f "${REPO_ROOT}/configs/collector-definitions.json" && -f "${REPO_ROOT}/configs/collector-permissions.json" ]]; then
  HAS_FULL_AUDIT=1
  # The engine package sits under src/; its collector configs sit at the repository root.
  FULL_AUDIT_ROOT="${REPO_ROOT}/src"
  CONFIG_ROOT="${REPO_ROOT}"
elif [[ -f "${TENANT_BOOTSTRAP_ROOT}/azure_tenant_audit/cli.py" && -f "${TENANT_BOOTSTRAP_ROOT}/configs/collector-definitions.json" && -f "${TENANT_BOOTSTRAP_ROOT}/configs/collector-permissions.json" ]]; then
  HAS_FULL_AUDIT=1
  FULL_AUDIT_ROOT="${TENANT_BOOTSTRAP_ROOT}"
  CONFIG_ROOT="${TENANT_BOOTSTRAP_ROOT}"
fi

ARGS=(
  "--tenant-name" "$TENANT_NAME"
  "--tenant-id" "$TENANT_ID"
  "--client-id" "$CLIENT_ID"
  "--certificate-path" "$CERTIFICATE_PATH"
  "--certificate-thumbprint" "$CERTIFICATE_THUMBPRINT"
  "--collectors" "$COLLECTORS"
  "--top" "$TOP"
  "--out" "$OUT_DIR"
)

if [[ -n "$CERTIFICATE_PASSWORD_ENV" ]]; then
  ARGS+=(--certificate-password-env "$CERTIFICATE_PASSWORD_ENV")
fi
if [[ -n "$CERTIFICATE_PASSWORD_FILE" ]]; then
  ARGS+=(--certificate-password-file "$CERTIFICATE_PASSWORD_FILE")
fi
if [[ -n "$RUN_NAME" ]]; then
  ARGS+=(--run-name "$RUN_NAME")
fi
if [[ -n "$AUDITOR_PROFILE" ]]; then
  ARGS+=(--auditor-profile "$AUDITOR_PROFILE")
fi

if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
  ARGS+=(--config "${CONFIG_ROOT}/configs/collector-definitions.json")
  ARGS+=(--permission-hints "${CONFIG_ROOT}/configs/collector-permissions.json")
  if [[ "$INCLUDE_EXCHANGE" -eq 1 || "$COLLECTORS" == *"exchange"* ]]; then
    ARGS+=(--include-exchange)
  fi

  PYTHONPATH_VALUE="${FULL_AUDIT_ROOT}"
  if [[ -n "${PYTHONPATH:-}" ]]; then
    PYTHONPATH_VALUE="${PYTHONPATH_VALUE}:${PYTHONPATH}"
  fi
else
  if [[ "$INCLUDE_EXCHANGE" -eq 1 ]]; then
    echo "warning: include-exchange requested; local fallback audit module does not support exchange collectors."
  fi
fi

# Certificate location, thumbprint and password source are sensitive (secret_hygiene.py); only the
# executed argv carries them, never what this script prints.
DISPLAY_ARGS=()
REDACT_NEXT=0
for arg in "${ARGS[@]}"; do
  if [[ "$REDACT_NEXT" -eq 1 ]]; then
    DISPLAY_ARGS+=("<redacted>")
    REDACT_NEXT=0
    continue
  fi
  case "$arg" in
    --certificate-path|--certificate-thumbprint|--certificate-password-env|--certificate-password-file)
      REDACT_NEXT=1
      ;;
  esac
  DISPLAY_ARGS+=("$arg")
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Audit dry run command:"
  printf "  %q " "$PYTHON_BIN" -m azure_tenant_audit "${DISPLAY_ARGS[@]}"
  echo
  if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
    echo "  PYTHONPATH=$PYTHONPATH_VALUE"
  fi
  exit 0
fi

if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
  echo "Running full audit package at: ${FULL_AUDIT_ROOT}/azure_tenant_audit."
  (
    export PYTHONPATH="${PYTHONPATH_VALUE}"
    cd "$FULL_AUDIT_ROOT"
    "$PYTHON_BIN" -m azure_tenant_audit "${ARGS[@]}"
  )
else
  echo "Running fallback audit collector in tenant-bootstrap."
  "$PYTHON_BIN" -m azure_tenant_audit "${ARGS[@]}"
fi

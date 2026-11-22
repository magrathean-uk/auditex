#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_BOOTSTRAP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: run-auditor.sh [options]

Forwards to run-audit-collector.sh, which runs the lab audit one way only: the reader app with its
certificate (DEC-107).

  --tenant-name NAME         Tenant display name (default: tenant)
  --tenant-id ID             Lab tenant ID (required; default: $AZURE_TENANT_ID)
  --client-id ID             Reader app client ID (required; default: $AZURE_CLIENT_ID)
  --certificate-path FILE    Reader app certificate private key (required)
  --certificate-thumbprint SHA1  Thumbprint of the certificate on the app registration (required)
  --certificate-password-env NAME  Environment variable holding the key password (optional)
  --certificate-password-file FILE File holding the key password (optional)
  --collectors LIST          Comma-separated collectors (default: identity,security,intune,teams,exchange)
  --include-exchange         Enable command-style exchange collector
  --top N                    Max items per endpoint (default: 500)
  --out PATH                 Output base directory (default: tenant-bootstrap/audit-output)
  --run-name NAME            Optional audit run name
  --auditor-profile PROFILE  Audit profile: auto|enterprise|global-reader (default: auto)
  --inspect                  Print compact audit summary after run
  --dry-run                  Print the collector command without running it
  --help
USAGE
}

TENANT_NAME="tenant"
TENANT_ID="${AZURE_TENANT_ID:-}"
CLIENT_ID="${AZURE_CLIENT_ID:-}"
CERTIFICATE_PATH=""
CERTIFICATE_THUMBPRINT=""
CERTIFICATE_PASSWORD_ENV=""
CERTIFICATE_PASSWORD_FILE=""
COLLECTORS="identity,security,intune,teams,exchange"
TOP="500"
OUT_DIR="${TENANT_BOOTSTRAP_ROOT}/audit-output"
RUN_NAME=""
INCLUDE_EXCHANGE=0
AUDITOR_PROFILE="auto"
INSPECT=0
DRY_RUN=0

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
    --collectors)
      COLLECTORS="$2"
      shift 2
      ;;
    --include-exchange)
      INCLUDE_EXCHANGE=1
      shift
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
    --interactive|--browser-command|--token-env|--scopes)
      echo "$1 was removed: the lab audit runs only with the reader app's certificate (--client-id, --certificate-path, --certificate-thumbprint)." >&2
      exit 1
      ;;
    --auditor-profile)
      AUDITOR_PROFILE="$2"
      shift 2
      ;;
    --inspect)
      INSPECT=1
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

if [[ -z "$TENANT_NAME" ]]; then
  echo "--tenant-name cannot be empty"
  exit 1
fi

if [[ -z "$RUN_NAME" ]]; then
  RUN_NAME="auditor-${TOP}-$(date +%Y%m%d_%H%M%S)"
fi

AUDIT_ARGS=(
  --tenant-name "$TENANT_NAME"
  --tenant-id "$TENANT_ID"
  --client-id "$CLIENT_ID"
  --certificate-path "$CERTIFICATE_PATH"
  --certificate-thumbprint "$CERTIFICATE_THUMBPRINT"
  --collectors "$COLLECTORS"
  --top "$TOP"
  --out "$OUT_DIR"
  --run-name "$RUN_NAME"
  --auditor-profile "$AUDITOR_PROFILE"
)
if [[ -n "$CERTIFICATE_PASSWORD_ENV" ]]; then
  AUDIT_ARGS+=(--certificate-password-env "$CERTIFICATE_PASSWORD_ENV")
fi
if [[ -n "$CERTIFICATE_PASSWORD_FILE" ]]; then
  AUDIT_ARGS+=(--certificate-password-file "$CERTIFICATE_PASSWORD_FILE")
fi
if [[ "$INCLUDE_EXCHANGE" -eq 1 || "$COLLECTORS" == *"exchange"* ]]; then
  AUDIT_ARGS+=(--include-exchange)
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  AUDIT_ARGS+=(--dry-run)
fi

# run-audit-collector.sh validates the options and redacts the certificate details in what it prints.
"${SCRIPT_DIR}/run-audit-collector.sh" "${AUDIT_ARGS[@]}"

if [[ "$INSPECT" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
  RESOLVED_OUT="$(ls -dt "${OUT_DIR}"/*/ 2>/dev/null | head -n 1 || true)"
  if [[ -n "${RESOLVED_OUT}" ]]; then
    echo "Inspecting ${RESOLVED_OUT}"
    "${SCRIPT_DIR}/inspect-audit-logs.sh" "${RESOLVED_OUT}"
  else
    echo "No audit evidence directory found for inspection."
  fi
fi

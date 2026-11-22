#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${ROOT_DIR}/config.enterprise-lab-max.json"
RUN_NAME="enterprise-lab-max-$(date +%Y%m%d_%H%M%S)"
STEPS="licenses,windows365,teams,intune,security,devices,exchange,sample"
LIVE=0
DISABLE_SECURITY_DEFAULTS=0
SKIP_IDENTITY=0
SKIP_WORKLOAD=0
SKIP_VERIFY=0
DAYS=""
INTERACTIVE_WORKLOAD=0
CLIENT_ID=""
TOKEN_ENV_PATH="${ROOT_DIR}/.secrets/lab-populator-token.env"

usage() {
  cat <<'USAGE'
Usage: ./run-enterprise-lab-max.sh [options]

  --live              Run live tenant writes. Default is dry-run.
  --run-name NAME     Use a specific run name.
  --days N            Limit sample-data days for this run.
  --disable-security-defaults
                     Disable Entra security defaults before enforced CA policy creation.
  --steps CSV         Workload steps (default: licenses,windows365,teams,intune,security,devices,exchange,sample).
  --interactive-workload
                     Use delegated interactive Graph auth for workload seeding.
  --client-id ID     Public client app ID for delegated interactive Graph auth.
  --token-env PATH    Path to token env file (default: .secrets/lab-populator-token.env if present).
  --skip-identity     Skip identity/group seeding.
  --skip-workload     Skip workload seeding.
  --skip-verify       Skip population verification.
  --help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --live)
      LIVE=1
      shift
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --days)
      DAYS="$2"
      shift 2
      ;;
    --disable-security-defaults)
      DISABLE_SECURITY_DEFAULTS=1
      shift
      ;;
    --steps)
      STEPS="$2"
      shift 2
      ;;
    --interactive-workload)
      INTERACTIVE_WORKLOAD=1
      shift
      ;;
    --client-id)
      CLIENT_ID="$2"
      shift 2
      ;;
    --token-env)
      TOKEN_ENV_PATH="$2"
      shift 2
      ;;
    --skip-identity)
      SKIP_IDENTITY=1
      shift
      ;;
    --skip-workload)
      SKIP_WORKLOAD=1
      shift
      ;;
    --skip-verify)
      SKIP_VERIFY=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ -f "${ROOT_DIR}/scripts/token-env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${ROOT_DIR}/scripts/token-env.sh"
fi
if [[ -n "${TOKEN_ENV_PATH:-}" && -f "$TOKEN_ENV_PATH" ]]; then
  if ! load_token_env "$TOKEN_ENV_PATH"; then
    echo "Warning: token env not usable from ${TOKEN_ENV_PATH}; running without token fallback."
  else
    echo "Loaded token source from ${TOKEN_ENV_PATH}"
  fi
fi

MODE_ARGS=()
if [[ "$LIVE" -eq 0 ]]; then
  MODE_ARGS+=(--dry-run)
fi

if [[ "$SKIP_IDENTITY" -eq 0 ]]; then
  python3 "${ROOT_DIR}/scripts/identity_seed_az.py" \
    --config "$CONFIG" \
    --run-name "${RUN_NAME}-identity" \
    ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}
fi

if [[ "$SKIP_WORKLOAD" -eq 0 ]]; then
  WORKLOAD_ARGS=(
    --config "$CONFIG"
    --run-name "${RUN_NAME}-workload"
    --steps "$STEPS"
  )
  if [[ -n "$DAYS" ]]; then
    WORKLOAD_ARGS+=(--days "$DAYS")
  fi
  if [[ "$DISABLE_SECURITY_DEFAULTS" -eq 1 ]]; then
    WORKLOAD_ARGS+=(--disable-security-defaults)
  fi
  if [[ "$INTERACTIVE_WORKLOAD" -eq 1 ]]; then
    WORKLOAD_ARGS+=(--interactive --browser-command firefox)
  fi
  if [[ -n "$CLIENT_ID" ]]; then
    WORKLOAD_ARGS+=(--client-id "$CLIENT_ID")
  fi
  python3 "${ROOT_DIR}/scripts/seed-workload-az.py" "${WORKLOAD_ARGS[@]}" ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}
fi

if [[ "$SKIP_VERIFY" -eq 0 ]]; then
  VERIFY_ARGS=(
    --config "$CONFIG"
    --run-name "$RUN_NAME"
    --run-dir "${ROOT_DIR}/runs/${RUN_NAME}"
    --bootstrap-root "$ROOT_DIR"
  )
  python3 "${ROOT_DIR}/scripts/verify-population-az.py" "${VERIFY_ARGS[@]}" ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}
fi

echo "enterprise lab max run: ${RUN_NAME}"

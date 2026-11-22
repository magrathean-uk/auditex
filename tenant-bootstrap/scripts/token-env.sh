#!/usr/bin/env bash

set -euo pipefail

_extract_token_from_env_file() {
  local token_env_path="$1"
  if [[ ! -f "$token_env_path" ]]; then
    echo ""
    return 1
  fi

  local token
  token="$(python3 - "$token_env_path" <<'PY'
import sys

path = sys.argv[1]
token = ""
with open(path, "r", encoding="utf-8") as handle:
    for raw in handle:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() != "AZURE_ACCESS_TOKEN":
            continue
        token = value.strip().strip().strip('"').strip("'")
        break

print(token)
PY
)"
  printf '%s' "${token}"
}

_is_token_valid_heuristic() {
  local token="$1"
  if [[ -z "$token" ]]; then
    return 1
  fi

  local expired
  # The token reaches Python through its environment only: argv is visible to every local user via ps.
  expired="$(AUDITEX_TOKEN_UNDER_CHECK="$token" python3 - <<'PY'
import os, time

token = os.environ.get("AUDITEX_TOKEN_UNDER_CHECK", "")
parts = token.split(".")
if len(parts) < 2:
    print("unknown")
    raise SystemExit(0)

import base64, json
payload = parts[1]
payload += "=" * (-len(payload) % 4)
try:
    claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
except Exception:
    print("invalid")
    raise SystemExit(0)

exp = claims.get("exp")
if not exp:
    print("no-exp")
    raise SystemExit(0)

try:
    exp_ts = int(exp)
except Exception:
    print("invalid-exp")
    raise SystemExit(0)

print("expired" if exp_ts <= int(time.time()) else "valid")
PY
)"

  case "$expired" in
    expired)
      return 1
      ;;
    invalid|invalid-exp)
      return 1
      ;;
    valid)
      return 0
      ;;
    *)
      return 2
      ;;
  esac
}

load_token_env() {
  local token_env_path="$1"

  local token
  token="$(_extract_token_from_env_file "$token_env_path")"
  if [[ -z "$token" ]]; then
    return 1
  fi

  if ! _is_token_valid_heuristic "$token"; then
    return 2
  fi

  export AZURE_ACCESS_TOKEN="$token"
  return 0
}


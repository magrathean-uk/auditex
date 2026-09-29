#!/usr/bin/env bash
# Sourced by the tenant-audit scripts. Run the Microsoft 365 CLI through run_m365 instead of calling m365 directly.
#
# m365 has no setting for where it keeps its tokens and connections (.cli-m365-tokens.json and similar): it derives
# the folder from the home directory. run_m365 therefore starts it with HOME pointing at a private folder. Only the
# m365 process sees the changed HOME. src/azure_tenant_audit/m365_home.py applies the same rule to the Python
# commands, so a sign-in made here is found there and the other way round.
#
#   AUDITEX_M365_HOME  folder to use. Set it empty to keep the m365 default (the home folder).
#   XDG_DATA_HOME      used as $XDG_DATA_HOME/auditex/m365 when AUDITEX_M365_HOME is unset.
#
# With neither variable set, m365 runs unchanged.

m365_cli_home() {
  local folder="" tilde='~'
  if [[ -n "${AUDITEX_M365_HOME+x}" ]]; then
    folder="${AUDITEX_M365_HOME}"
  elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
    folder="${XDG_DATA_HOME}/auditex/m365"
  fi
  if [[ -z "${folder}" ]]; then
    return 0
  fi
  case "${folder}" in
    "${tilde}" | "${tilde}/"*) folder="${HOME}${folder#"${tilde}"}" ;;
  esac
  if [[ "${folder}" != /* ]]; then
    folder="${PWD}/${folder}"
  fi
  printf '%s\n' "${folder}"
}

run_m365() {
  local folder
  folder="$(m365_cli_home)"
  if [[ -z "${folder}" ]]; then
    m365 "$@"
    return
  fi
  (umask 077 && mkdir -p "${folder}")
  HOME="${folder}" m365 "$@"
}

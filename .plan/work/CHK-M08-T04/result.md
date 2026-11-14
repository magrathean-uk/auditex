## RESULT CHK-M08-T04
status: done
summary:
check: pass
checked: cce84e205924f84701572ab4975531063e6bc279
Verify passed: 705 tests, then `make contract-smoke` exit 0. 48 negative cases against the new checks all failed as they must. Out-of-contract probes of my own (NUL characters, whitespace-only name) were accepted; see risks.
changes: none (scratch removed; evidence in .plan/work/CHK-M08-T04/evidence.md)
verification:
- `.venv/bin/python -m pytest tests/test_teams_app_settings.py tests/test_scuba_adapters_teams.py tests/test_teams_admin_rest.py tests/test_teams_policy_collector.py tests/test_api_inventory.py`: exit 0, pass
- `make contract-smoke`: exit 0, pass
- negative pytest probes under `$TMPDIR` (token gate, REST shapes and statuses, envelope, coverage row, collection gap, manifest gap, collector environment, adapter rows): the 48 in-contract cases failed as they must, pass
risks:
- The comment in `src/auditex/scuba_adapters_teams.py` says `SettingValue` text is checked for control characters, but `_clean_text` only rejects lone surrogates. NUL characters and a whitespace-only `SettingName` pass into the rule input. This is not part of the acceptance criteria.
- `git status --porcelain` was empty after the verify (`outputs/` is git-ignored). I linked `.venv` in for the run and removed the link afterwards.
- `src/azure_tenant_audit/api_inventory.py` is not in the diff. The new GET is covered through `collector-definitions.json` and the tests pass, but I did not separately confirm the inventory's allow-list entry for the new host.
questions_for_g: none

### Findings
- Token gate: a list `aud`, `aud` with a suffix, a host-suffix `aud`, a malformed JWT, a non-string token and a null `aud` all returned `teams_token_unavailable` with no request. Failed as it must.
- Unknown operation raised `ValueError`; uppercase environment returned `unsupported_environment` with no request. Failed as it must.
- Bad response shapes (`{value:null}`, nested list, row with `error`, `{}`, text, int) all returned an `error_class` with no value. Failed as it must.
- HTTP 302, 404, 500 and 503 all returned an error with no value. Failed as it must.
- Certificate-skip envelope with an extra or odd key, `status` ok, `value` None or a padded reason: the section stayed `NOT_COLLECTED`. Failed as it must.
- Manifest gaps (string-form, item-named, nested other-reason, `rows_collected`, `bounded_sample`, `resolver_error`): the section stayed `NOT_COLLECTED`. Failed as it must.
- Coverage-row conflicts (failed status, `complete` true, no reason, truncation, nextLink, empty `error_classes`): the section stayed `NOT_COLLECTED`. Failed as it must.
- Collection-gap conflicts (`rows_collected`, `item_count`, partial, incomplete): the section stayed `NOT_COLLECTED`. Failed as it must.
- `coverage.json` that is not a list gave no certificate marker. Failed as it must.
- Collector with environment `dod` recorded `unsupported_environment`, no skip and no request. Failed as it must.
- Adapter rows (non-dict, None, list, lone surrogate in name or value, empty name) all returned `NOT_COLLECTED`. Failed as it must.
- Accepted, outside the check's contract: NUL in name or value, whitespace-only name, and an unknown extra field (lenient by design in `known_fields`).

## RESULT CHK-M08-T12
status: done
summary: check: pass
checked: caeabd8452c5ad888db0dd7fc80528217ca3f095
The M08-T12 verify line passes, and so does the full suite (exit 0, one skip). The two earlier failures are repaired.
changes: none
verification: M08-T12 verify line (10 test files, `make lint`, `make contract-smoke`) pass; full suite `pytest tests` pass, run through hostload with slot acquired. Log in .plan/work/CHK-M08-T12/suite-3.log and evidence.md.
risks: none
questions_for_g: none

### Findings
1. Delta `git diff 04ad35e caeabd8` touches three files and nothing else: src/azure_tenant_audit/adapters/read_guard.py (comment only, now says the host comes from the root site's `siteCollection.hostname`), src/azure_tenant_audit/collectors/sharepoint_admin.py, and tests/test_collection_coverage_fixes.py.
2. In sharepoint_admin.py the one `GET /sites/root` read keeps the same endpoint and `$select=siteCollection`. Only the `ROOT_SITE_PARAMS` constant is removed and the call is written inline, plus a trailing blank line removed.
3. The test change is one allow-list entry for `sharepoint_admin.py` (single root site object), with no other test edits.
4. No guard logic, verb allow-list, scope or credential path changed, so I did not re-run the fake guard probes. The previous round's guard findings stand.
5. The stale host comment from the previous round (finding 3) is fixed.

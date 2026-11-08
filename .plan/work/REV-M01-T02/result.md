## RESULT REV-M01-T02
status: done
summary:
verdict: changes-required
reviewed: 11d88e97f27d7e37c4b336babe0e16e3e0a29e5d
All three round-3 findings are fixed.
Section E is complete and minimal; section G remains incomplete.
No additional tenant-mutating path identified.
changes: none
verification: PASS - git status/diff, rg sweep, in-memory AST enumeration, source and primary SDK/API documentation review. Tests/builds/installs skipped as instructed. FAIL - developer-required clean-development doctor.
risks: Static review only. Doctor reported GUI/DerivedData routing failures, unverifiable lifecycle-lock ownership and unexpected dot-folders; no repairs attempted.
questions_for_g: none
### Findings

- Missing message-body exposure: src/auditex/google_workspace/client.py:260 (B11) calls alerts.list without a field restriction. MailPhishing alerts can contain data.messages[].messageBodySnippet and subjectText from reported emails. These fields are not minimised. Record this actual message-content path for T04. [Google response schema](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/GmailMessageInfo).
- Missing file-content exposure: src/azure_tenant_audit/collectors/intune.py:42 and src/azure_tenant_audit/collectors/intune_depth.py:58 request deviceConfigurations without $select. Documented iOS and macOS custom-profile responses include uploaded profile-file bytes in payload. Record both paths for T04; excluding scriptContent elsewhere does not cover them. [iOS response](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-ioscustomconfiguration-list?view=graph-rest-1.0), [macOS response](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-macoscustomconfiguration-list?view=graph-rest-1.0).
- Section G omits src/auditex/google_workspace/client.py:340 (B22): unrestricted groups.get can receive customFooterText and defaultMessageDenyNotificationText. These administrator-written message templates are retained without minimisation. Add them alongside the Exchange disclaimer exposure. [Google Groups schema](https://developers.google.com/workspace/admin/groups-settings/v1/reference/groups).

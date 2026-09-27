# app-readonly-full

Customer-local app-only read path for deep unattended evidence collection.

- Role hints in the runtime: App authentication; no delegated role hint.
- Default collectors: `identity`, `app_consent`, `security`, `conditional_access`, `defender`, `service_health`, `auth_methods`, `reports_usage`, `external_identity`, `consent_policy`, `domains_hybrid`, `licensing`, `identity_governance`, `intune`, `intune_depth`, `sharepoint`, `sharepoint_access`, `onedrive_posture`, `teams`, `teams_policy`, `purview`, `ediscovery`, `exchange`, `exchange_policy`.
- Audit planes: inventory, full, export.

These are profile defaults from `src/azure_tenant_audit/profiles.py`, not a guarantee of tenant visibility. Explicit collector selections, presets, exclusions, installed adapters, licenses, and permissions affect the run. Generate `auditex setup-guide m365 --auditor-profile app-readonly-full --format md`, then probe the selected surface before collection.

Review the generated permission plan rather than granting every profile hint. Some hints carry write capability even though audit calls are read-only. Never use an audit profile as authorization for tenant changes. See the [administrator permission guide](../docs/guides/admin-permission-guide.md).

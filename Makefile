PYTHON := $(shell ./scripts/select-python.sh)
VENV ?= .venv
TENANT ?= organizations

.PHONY: test
test:
	$(PYTHON) -m pytest

.PHONY: login
login:
	@if command -v az >/dev/null 2>&1; then \
		BROWSER=firefox az login --tenant "$(TENANT)" --allow-no-subscriptions; \
	else \
		echo "Azure CLI is required. Install it with: brew install azure-cli"; \
		exit 2; \
	fi

.PHONY: lint
lint:
	$(PYTHON) -m compileall -q src tests

.PHONY: sample
sample:
	$(PYTHON) -m azure_tenant_audit --offline --tenant-name sample --sample examples/sample_audit_bundle/sample_result.json

.PHONY: audit-full
audit-full:
	@./scripts/tenant-audit-full --tenant-id $(TENANT_ID) --tenant-name $(TENANT_NAME)

.PHONY: install
install:
	@test -x "$(VENV)/bin/python" || $(PYTHON) -m venv "$(VENV)"
	"$(VENV)/bin/python" -m pip install -e ".[test]"

.PHONY: bootstrap
bootstrap:
	@./scripts/bootstrap-local-tools.sh

.PHONY: setup
setup:
	@auditex setup

.PHONY: doctor
doctor:
	@auditex doctor


.PHONY: release-check
release-check:
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) contract-smoke
	$(PYTHON) scripts/generate-rule-packs.py --check
	./scripts/oss-taint-scan.sh
	gitleaks dir . --no-banner --redact

.PHONY: contract-smoke
contract-smoke:
	rm -rf outputs/ci-contract outputs/ci-contract-input
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-contract"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; assert manifest["contract_status"] == "valid"; assert (run / "index" / "evidence.sqlite").exists()'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/identity_controls_result.json --tenant-name ci --run-name identity-controls --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-identity-controls"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; verdicts = {row["control"]: row["verdict"] for row in json.loads((run / "normalized" / "identity_control_verdicts.json").read_text(encoding="utf-8"))["records"]}; assert verdicts == {"effective_mfa": "not_enforced", "administrator_mfa": "not_enforced", "legacy_authentication_block": "not_blocked", "user_consent": "unrestricted"}, verdicts; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced", "ca.legacy_auth_not_blocked", "consent_policy.user_consent_unrestricted", "identity.privileged_mfa_not_registered", "identity.user_mfa_not_registered"}; assert expected <= rules, sorted(expected - rules)'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/admin_set_result.json --tenant-name ci --run-name admin-set --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-admin-set"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; records = json.loads((run / "normalized" / "effective_admin_set.json").read_text(encoding="utf-8"))["records"]; summary = next(row for row in records if row["kind"] == "effective_admin_set_summary"); assert summary["state"] == "complete" and summary["global_admin_count"] == 5 and summary["non_user_principal_count"] == 2, summary; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"identity.global_admin_sprawl", "identity.global_admin_mfa_not_registered", "identity.admin_holds_productivity_licence", "identity.guest_with_privileged_role", "identity.service_principal_privileged_role", "identity.stale_guest"}; assert expected <= rules, sorted(expected - rules); assert "identity.admin_set_unverified" not in rules and "identity.global_admin_singleton" not in rules'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/endpoint_posture_result.json --tenant-name ci --run-name endpoint-posture --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-endpoint-posture"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; summary = next(row for row in json.loads((run / "normalized" / "device_posture.json").read_text(encoding="utf-8"))["records"] if row["kind"] == "device_posture_summary"); assert summary["encryption_unknown"] == 1 and summary["last_sync_unknown"] == 1 and summary["read_state"] == "collected", summary; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"intune.device_encryption_off", "intune.device_jailbroken", "intune.device_stale_sync", "intune.device_os_end_of_life", "intune.compliance_policy_missing_platform", "intune.defender_av_off", "intune.defender_realtime_protection_off", "intune.defender_signatures_stale", "intune_depth.update_ring_deferral_excessive", "exchange.malware_filter_weakened", "exchange.smtp_auth_enabled_tenant_wide", "exchange.dkim_signing_disabled"}; assert expected <= rules, sorted(expected - rules); assert "intune_depth.update_ring_not_assigned" not in rules; ce = {row["control_id"]: row for row in json.loads((run / "reports" / "report-pack.json").read_text(encoding="utf-8"))["baseline_alignment"]["frameworks"]["cyber_essentials"]["controls"]}; assert ce["ce.mp.antimalware"]["status"] == "fail" and ce["ce.sum.supported_software"]["status"] == "fail" and ce["ce.mp.app_allow_listing"]["status"] == "not_assessed", {key: ce[key]["status"] for key in ce if key.startswith(("ce.sum", "ce.mp"))}'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/update_rings_missing_result.json --tenant-name ci --run-name update-rings-missing --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-update-rings-missing"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; assert "intune_depth.update_ring_not_assigned" in rules and "intune_depth.update_ring_deferral_excessive" not in rules, sorted(rules)'
	$(PYTHON) -m auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name ci --run-name google --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-google"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; snapshot = json.loads((run / "normalized" / "snapshot.json").read_text(encoding="utf-8")); assert snapshot["internal_domains_status"] == "known" and snapshot["subject_scope"]["google_drive_posture"] == "admin", snapshot; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"google.user_2sv_not_enforced", "google.org_2sv_policy_not_enforced", "google.stale_user", "google.never_logged_in_user", "google.chromeos_device_past_aue", "google.mobile_device_encryption_off", "google.evidence_unknown"}; assert expected <= rules, sorted(expected - rules)'
	$(PYTHON) -c 'import json; from pathlib import Path; sample = json.loads(Path("examples/sample_audit_bundle/admin_set_result.json").read_text(encoding="utf-8")); sample["identity"]["users"].update(collection_truncated=True, truncation_reason="operator_limit", result_limit=5); sample["auth_methods"]["userRegistrationDetails"] = {"error": "Forbidden", "error_class": "insufficient_permissions"}; out = Path("outputs/ci-contract-input"); out.mkdir(parents=True, exist_ok=True); (out / "partial.json").write_text(json.dumps(sample), encoding="utf-8")'
	$(PYTHON) -m azure_tenant_audit --offline --sample outputs/ci-contract-input/partial.json --tenant-name ci --run-name partial --out outputs/ci-contract; test $$? -eq 1
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-partial"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8")); assert manifest["overall_status"] == "partial" and manifest["coverage_gaps"], manifest["overall_status"]; ledger = {row["collector"]: row["coverage_status"] for row in json.loads((run / "normalized" / "coverage_ledger.json").read_text(encoding="utf-8"))["records"]}; assert ledger["identity"] == "partial_success" and ledger["auth_methods"] == "blocked_permission" and ledger["licensing"] == "complete_offline_sample", ledger; gaps = {row["source"] for row in json.loads((run / "normalized" / "collection_gaps.json").read_text(encoding="utf-8"))["records"]}; assert "identity.users" in gaps, gaps'

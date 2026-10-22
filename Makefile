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
	rm -rf outputs/ci-contract
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-contract"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; assert manifest["contract_status"] == "valid"; assert (run / "index" / "evidence.sqlite").exists()'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/identity_controls_result.json --tenant-name ci --run-name identity-controls --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-identity-controls"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; verdicts = {row["control"]: row["verdict"] for row in json.loads((run / "normalized" / "identity_control_verdicts.json").read_text(encoding="utf-8"))["records"]}; assert verdicts == {"effective_mfa": "not_enforced", "legacy_authentication_block": "not_blocked", "user_consent": "unrestricted"}, verdicts; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"ca.mfa_not_enforced", "ca.legacy_auth_not_blocked", "consent_policy.user_consent_unrestricted", "identity.privileged_mfa_not_registered", "identity.user_mfa_not_registered"}; assert expected <= rules, sorted(expected - rules)'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/admin_set_result.json --tenant-name ci --run-name admin-set --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-admin-set"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; records = json.loads((run / "normalized" / "effective_admin_set.json").read_text(encoding="utf-8"))["records"]; summary = next(row for row in records if row["kind"] == "effective_admin_set_summary"); assert summary["state"] == "complete" and summary["global_admin_count"] == 5 and summary["non_user_principal_count"] == 2, summary; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"identity.global_admin_sprawl", "identity.global_admin_mfa_not_registered", "identity.admin_holds_productivity_licence", "identity.guest_with_privileged_role", "identity.stale_guest"}; assert expected <= rules, sorted(expected - rules); assert "identity.admin_set_unverified" not in rules and "identity.global_admin_singleton" not in rules'
	$(PYTHON) -m auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name ci --run-name google --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-google"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; snapshot = json.loads((run / "normalized" / "snapshot.json").read_text(encoding="utf-8")); assert snapshot["internal_domains_status"] == "known" and snapshot["subject_scope"]["google_drive_posture"] == "admin", snapshot; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"google.user_2sv_not_enforced", "google.org_2sv_policy_not_enforced", "google.stale_user", "google.never_logged_in_user", "google.chromeos_device_past_aue", "google.mobile_device_encryption_off", "google.evidence_unknown"}; assert expected <= rules, sorted(expected - rules)'

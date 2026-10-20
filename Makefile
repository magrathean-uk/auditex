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
	"$(VENV)/bin/python" -m pip install -e .

.PHONY: bootstrap
bootstrap:
	@./scripts/bootstrap-local-tools.sh

.PHONY: setup
setup:
	@auditex setup

.PHONY: doctor
doctor:
	@auditex doctor


.PHONY: contract-smoke
contract-smoke:
	rm -rf outputs/ci-contract
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-contract"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; assert manifest["contract_status"] == "valid"; assert (run / "index" / "evidence.sqlite").exists()'
	$(PYTHON) -m azure_tenant_audit --offline --sample examples/sample_audit_bundle/identity_controls_result.json --tenant-name ci --run-name identity-controls --out outputs/ci-contract
	$(PYTHON) -c 'import json; from pathlib import Path; run = Path("outputs/ci-contract/ci-identity-controls"); validation = json.loads((run / "validation.json").read_text(encoding="utf-8")); assert validation["valid"], validation["issues"]; verdicts = {row["control"]: row["verdict"] for row in json.loads((run / "normalized" / "identity_control_verdicts.json").read_text(encoding="utf-8"))["records"]}; assert verdicts == {"effective_mfa": "not_enforced", "legacy_authentication_block": "not_blocked", "user_consent": "unrestricted"}, verdicts; rules = {row.get("rule_id") for row in json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))}; expected = {"ca.mfa_not_enforced", "ca.legacy_auth_not_blocked", "consent_policy.user_consent_unrestricted", "identity.privileged_mfa_not_registered", "identity.user_mfa_not_registered"}; assert expected <= rules, sorted(expected - rules)'

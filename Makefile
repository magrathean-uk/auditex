PYTHON := $(shell ./scripts/select-python.sh)
VENV ?= .venv
TENANT ?= organizations

.PHONY: test
test:
	$(PYTHON) -m pytest

# Full acceptance replays: the v3.9.1 vectors replay, then the explainer acceptance jobs, serially.
# The replay never skips silently: the kit variable must name an existing file.
.PHONY: acceptance
acceptance:
	@test -n "$$AUDITEX_TEST_VALUE_RULE_VECTORS_V391" || { echo "make acceptance: AUDITEX_TEST_VALUE_RULE_VECTORS_V391 is unset; point it at the replay kit vectors.jsonl" >&2; exit 2; }
	@test -f "$$AUDITEX_TEST_VALUE_RULE_VECTORS_V391" || { echo "make acceptance: AUDITEX_TEST_VALUE_RULE_VECTORS_V391 names a missing file: $$AUDITEX_TEST_VALUE_RULE_VECTORS_V391" >&2; exit 2; }
	$(PYTHON) -m pytest tests/test_value_rules_replay.py -m value_rule_acceptance -p no:cacheprovider -q -s -o addopts=
	for chunk in 00 01 02 03; do \
		PYTHONPATH="$$PWD/src" perl -e 'alarm 300; exec @ARGV' $(PYTHON) -B -I -m pytest tests/explainer_checks/test_mutation.py -m explainer_acceptance -k "chunk-$$chunk" -p no:cacheprovider -q -s -o addopts= || exit 1; \
	done
	PYTHONPATH="$$PWD/src" perl -e 'alarm 300; exec @ARGV' $(PYTHON) -B -I -m pytest tests/test_explainer_integration.py -m explainer_acceptance -k twins -p no:cacheprovider -q -s -o addopts=
	PYTHONPATH="$$PWD/src" perl -e 'alarm 300; exec @ARGV' $(PYTHON) -B -I -m pytest tests/test_explainer_integration.py -m explainer_acceptance -k byte_identical -p no:cacheprovider -q -s -o addopts=

.PHONY: login
login:
	@if command -v az >/dev/null 2>&1; then \
		BROWSER=firefox az login --tenant "$(TENANT)" --allow-no-subscriptions; \
	else \
		echo "Azure CLI is required. Install it with: brew install azure-cli"; \
		exit 2; \
	fi

# Ruff is pinned once, in the `dev` extra of pyproject.toml, at the .pre-commit-config.yaml hook
# version; the rule set and target version come from [tool.ruff] there. Lookup order: RUFF, .venv,
# the make audit-deps tool environment, then PATH.
RUFF_VERSION = $(shell sed -n 's/^ *"ruff==\([0-9.]*\)".*/\1/p' pyproject.toml)
RUFF_HOOK_VERSION = $(shell sed -n '/astral-sh\/ruff-pre-commit/{n;s/^ *rev: *v//p;}' .pre-commit-config.yaml)
RUFF ?= $(firstword $(wildcard $(VENV)/bin/ruff $(AUDIT_DEPS_DIR)/tool/bin/ruff) ruff)

.PHONY: lint
lint:
	$(PYTHON) -m compileall -q src tests
	@test -n "$(RUFF_VERSION)" && test "$(RUFF_VERSION)" = "$(RUFF_HOOK_VERSION)" || { echo "make lint: the Ruff pin in pyproject.toml ($(RUFF_VERSION)) must equal the .pre-commit-config.yaml hook version ($(RUFF_HOOK_VERSION))" >&2; exit 2; }
	@command -v "$(RUFF)" >/dev/null 2>&1 || { echo "make lint: Ruff $(RUFF_VERSION) not found; install the dev extra (.venv/bin/python -m pip install -e '.[dev]') or put ruff $(RUFF_VERSION) on PATH" >&2; exit 2; }
	@found="$$("$(RUFF)" --version 2>/dev/null)"; test "$$found" = "ruff $(RUFF_VERSION)" || { echo "make lint: Ruff $(RUFF_VERSION) is required, $(RUFF) reports '$$found'; install the dev extra (.venv/bin/python -m pip install -e '.[dev]')" >&2; exit 2; }
	"$(RUFF)" check .

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


AUDIT_DEPS_DIR ?= build/audit-deps
AUDIT_DEPS_IGNORE ?= scripts/audit-deps-ignore.json

# Resolves the base install and every extra to a pinned list with uv (metadata only: --no-build
# forbids source distribution builds; no install into $(VENV)), resolves model_train again for Linux aarch64, then audits each list with
# pip-audit --no-deps --disable-pip. pip-audit lives in the dev extra and runs from a tool
# environment under $(AUDIT_DEPS_DIR), never from $(VENV). Stale lists are removed first
# so earlier pins never steer resolution; ignore entries need id, package, reason and decision (a DECISIONS.md id).
.PHONY: audit-deps
audit-deps:
	@set -eu; \
		command -v uv >/dev/null 2>&1 || { echo "uv is required for audit-deps (brew install uv)" >&2; exit 2; }; \
		out="$(AUDIT_DEPS_DIR)"; \
		mkdir -p "$$out"; \
		rm -f "$$out"/*.txt; \
		resolve() { name=$$1; shift; uv pip compile --quiet --no-build --no-header --no-annotate --python "$(PYTHON)" "$$@" pyproject.toml -o "$$out/$$name.txt" || { echo "audit-deps: metadata-only resolution of $$name failed (--no-build forbids source builds; a dependency without a wheel needs a pin change)" >&2; exit 1; }; }; \
		resolve base; \
		for extra in mcp test google model_train dev; do resolve "$$extra" --extra "$$extra"; done; \
		resolve model_train-linux-aarch64 --extra model_train --python-platform aarch64-unknown-linux-gnu; \
		test -x "$$out/tool/bin/python" || uv venv --quiet --python "$(PYTHON)" "$$out/tool"; \
		uv pip install --quiet --python "$$out/tool/bin/python" -r "$$out/dev.txt"; \
		ignores=$$($(PYTHON) -c 'import json, pathlib, sys; p = pathlib.Path(sys.argv[1]); rows = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []; [sys.exit("ignore entry needs id, package, reason, decision: %r" % r) for r in rows if not all(r.get(k) for k in ("id", "package", "reason", "decision"))]; print(" ".join("--ignore-vuln " + r["id"] for r in rows))' "$(AUDIT_DEPS_IGNORE)"); \
		status=0; \
		for list in "$$out"/*.txt; do \
			echo "== pip-audit $$(basename $$list)"; \
			"$$out/tool/bin/pip-audit" --no-deps --disable-pip --progress-spinner off $$ignores -r "$$list" || status=1; \
		done; \
		exit $$status

.PHONY: release-check
release-check:
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) contract-smoke
	$(MAKE) release-archive
	$(PYTHON) scripts/generate-rule-packs.py --check
	./scripts/oss-taint-scan.sh
	gitleaks dir . --no-banner --redact

.PHONY: release-archive
release-archive:
	@set -eu; \
		dir=$$(mktemp -d "$${TMPDIR:-/tmp}/auditex-archive.XXXXXX"); \
		trap 'rm -rf "$$dir"' 0; \
		trap 'exit 1' HUP INT TERM; \
		git archive HEAD > "$$dir/source.tar"; \
		tar -tf "$$dir/source.tar" > "$$dir/files"; \
		if grep -E '(^build/|(^|/)[^/]*[.]egg-info/)' "$$dir/files"; then \
			echo "Archive contains build or egg-info directory" >&2; exit 1; \
		fi; \
		mkdir "$$dir/source" "$$dir/wheel"; \
		tar -xf "$$dir/source.tar" -C "$$dir/source"; \
		$(PYTHON) -m pip wheel --no-deps --no-build-isolation --no-index --wheel-dir "$$dir/wheel" "$$dir/source"; \
		$(PYTHON) scripts/check-archive-wheel.py "$$dir/source/src" "$$dir"/wheel/*.whl

.PHONY: dist
dist:
	@set -eu; \
		dir=$$(mktemp -d "$${TMPDIR:-/tmp}/auditex-dist.XXXXXX"); \
		trap 'rm -rf "$$dir"' 0; \
		trap 'exit 1' HUP INT TERM; \
		git archive HEAD > "$$dir/source.tar"; \
		mkdir "$$dir/source" "$$dir/artifacts"; \
		tar -xf "$$dir/source.tar" -C "$$dir/source"; \
		: "$${SOURCE_DATE_EPOCH:=$$(git show -s --format=%ct HEAD)}"; export SOURCE_DATE_EPOCH; \
		cd "$$dir/source"; \
		$(abspath $(PYTHON)) -c 'import setuptools.build_meta as b, sys; b.build_sdist(sys.argv[1])' "$$dir/artifacts"; \
		$(abspath $(PYTHON)) "$(CURDIR)/scripts/check-reproducible-build.py" --normalise-sdist "$$dir"/artifacts/*.tar.gz "$$SOURCE_DATE_EPOCH"; \
		$(abspath $(PYTHON)) -c 'import setuptools.build_meta as b, sys; b.build_wheel(sys.argv[1])' "$$dir/artifacts"; \
		set -- "$$dir"/artifacts/*.whl; test -f "$$1"; \
		set -- "$$dir"/artifacts/*.tar.gz; test -f "$$1"; \
		mkdir -p "$(CURDIR)/dist"; \
		cp "$$dir"/artifacts/*.whl "$$dir"/artifacts/*.tar.gz "$(CURDIR)/dist/"

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

	$(PYTHON) -m azure_tenant_audit --offline --sample examples/demo_tenant/demo_tenant.json --tenant-name ci --run-name projection-demo --out outputs/ci-contract
	$(PYTHON) -c 'import sys; from pathlib import Path; from auditex.rule_assessment import assess_run; from auditex.scuba_projection import project_run; from azure_tenant_audit.bundle_integrity import verify_bundle_hashes; run = Path("outputs/ci-contract/ci-projection-demo"); projection = project_run(run); projected = sum(s["status"] == "projected" for s in projection.report["sections"].values()); assert projected == 5, projected; roles = projection.report["sections"]["privileged_roles"]; assert (roles["reason"], roles["detail"]["kind"]) == ("incomplete_shape", "unseen_shape"), roles; assessment = assess_run(run); rows = assessment["policies"]; assert (len(rows), assessment["totals"]["rule_answered"], sum(r["reason"] == "rule_not_implemented" for r in rows)) == (102, 102, 0), assessment["totals"]; assert (assessment["endpoint_host"], assessment["model_name"]) == ("none", "rules-only") and "serving" not in assessment; assert verify_bundle_hashes(run)["status"] == "verified"; loaded = sorted(m for m in sys.modules if m.startswith(("auditex.model_", "azure_tenant_audit.model_"))); assert not loaded, loaded; print("Projection demo: 5 projected sections (scuba_config synthesised, accepted_domains extra fields ignored), 102 value-rule rows, 0 not assessed for want of a rule; no model calls; privileged_roles artefact written, withheld by the frozen shape gate; bundle seal verified")'

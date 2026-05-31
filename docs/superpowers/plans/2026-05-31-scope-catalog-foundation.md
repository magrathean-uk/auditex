# Scope Catalog Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one provider-neutral scope catalog foundation so setup guidance, capability rows, and evidence ledgers stop drifting.

**Architecture:** Add a shared scope catalog module in core that can assemble M365 collector access metadata from existing config plus hint files, and Google collector access metadata from the shipped registry plus scope-risk notes. Then rewire setup-guide, capability matrix builders, auth capability checks, and API inventory declared-collector rows to read from this catalog instead of duplicating access truth in separate modules.

**Tech Stack:** Python 3.11+, pytest, existing Auditex config/resources loading, CodeGraph-guided refactor

---

### Task 1: Add failing tests for shared scope truth

**Files:**
- Create: `tests/test_scope_catalog.py`
- Modify: `tests/test_setup_guide.py`
- Modify: `tests/test_api_inventory.py`

- [ ] **Step 1: Write failing catalog tests**

Add tests that assert:

- M365 collector metadata merges config permissions and hint role/tool metadata into one catalog entry.
- Google collector metadata exposes required scopes, API enablement, and scope-risk warnings for Gmail and Drive.
- The same collector metadata can be consumed by setup-guide and API inventory without losing role/scope truth.

- [ ] **Step 2: Run catalog-focused tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_api_inventory.py -q
```

Expected: FAIL because `azure_tenant_audit.scope_catalog` and the new declared-collector fields do not exist yet.

### Task 2: Build scope catalog module

**Files:**
- Create: `src/azure_tenant_audit/scope_catalog.py`
- Modify: `src/auditex/setup_guide.py`

- [ ] **Step 1: Add minimal shared catalog API**

Implement provider-neutral helpers for:

- building M365 collector scope catalog rows from collector config plus permission hints
- building Google collector scope catalog rows from Google registry plus scope-risk metadata
- aggregating required permissions, role hints, tool requirements, API enablement, and scope warnings across selected collectors

- [ ] **Step 2: Rewire setup-guide to use the catalog**

Update Google and M365 setup-guide builders so required scopes/permissions, role hints, tool requirements, and warnings come from the shared catalog instead of separate inline merge logic.

- [ ] **Step 3: Run tests and verify green**

Run:

```bash
.venv/bin/python -m pytest tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_api_inventory.py -q
```

Expected: PASS for the new shared-catalog behavior.

### Task 3: Rewire capability and ledger seams

**Files:**
- Modify: `src/azure_tenant_audit/run.py`
- Modify: `src/auditex/auth_runtime.py`
- Modify: `src/azure_tenant_audit/api_inventory.py`
- Modify: `src/auditex/mcp_server.py`
- Modify: `tests/test_auditex_product.py`

- [ ] **Step 1: Write failing assertions for capability and declared-collector metadata**

Add tests that expect:

- capability rows use catalog-derived `minimum_role_hints`
- API inventory declared collector rows expose stable role/tool metadata from the same catalog
- MCP list-collectors returns catalog-backed required permissions

- [ ] **Step 2: Implement minimal code to satisfy those tests**

Route M365 capability builders and auth capability helpers through the shared catalog. Extend API inventory declared collector rows with additive metadata fields sourced from the catalog. Reuse the catalog in MCP collector listing where practical.

- [ ] **Step 3: Run focused tests and verify green**

Run:

```bash
.venv/bin/python -m pytest tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_api_inventory.py tests/test_auditex_product.py -q
```

Expected: PASS.

### Task 4: Full verification for this slice

**Files:**
- Modify if needed: docs text only when tests show stale wording

- [ ] **Step 1: Run repo checks for the implemented slice**

Run:

```bash
make test
make lint
make contract-smoke
```

Expected: all pass.

- [ ] **Step 2: Review roadmap alignment**

Confirm this slice advances:

- scope catalog module
- setup guide truth
- capability gate truth
- API inventory declared-collector truth
- Google Gmail/Drive scope-risk regression coverage


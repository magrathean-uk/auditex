"""Review lane integrate-w2, final cross-lane round: changes the wave-2 lanes named outside their own files."""
from __future__ import annotations

OPTIONAL_FOLDER_SCOPE = "Mail.ReadBasic.All"


# R006 (lead decision): Mail.ReadBasic.All is optional. It is never in the default reader-app plan, nor in the
# permission list of a plan that selects mailbox_forwarding; the setup guide names it under an optional heading with
# its blast radius and says the inbox-rule folder check reads unknown without it.
def test_r006_default_reader_app_plan_omits_the_optional_folder_scope() -> None:
    from auditex.setup_guide import build_m365_setup_guide

    guide = build_m365_setup_guide()

    assert OPTIONAL_FOLDER_SCOPE not in guide["graph_permissions"]
    assert OPTIONAL_FOLDER_SCOPE not in guide["graph_permissions_csv"]
    assert not [row for row in guide.get("optional_graph_permissions") or [] if row["collector"] != "mailbox_forwarding"]


def test_r006_mailbox_forwarding_plan_lists_the_folder_scope_only_as_optional() -> None:
    from auditex.setup_guide import build_m365_setup_guide

    guide = build_m365_setup_guide(collectors="mailbox_forwarding")

    assert OPTIONAL_FOLDER_SCOPE not in guide["graph_permissions"]
    assert OPTIONAL_FOLDER_SCOPE not in guide["graph_permissions_csv"]
    assert all(OPTIONAL_FOLDER_SCOPE not in row["required_permissions"] for row in guide["collector_permissions"])
    [optional] = guide["optional_graph_permissions"]
    assert optional["permission"] == OPTIONAL_FOLDER_SCOPE
    assert optional["collector"] == "mailbox_forwarding"
    note = optional["note"]
    assert "basic message properties" in note and "never a body" in note
    assert "unknown" in note


def test_r006_setup_guide_markdown_names_the_folder_scope_under_an_optional_heading() -> None:
    from auditex.setup_guide import build_m365_setup_guide, render_setup_guide_markdown

    markdown = render_setup_guide_markdown(build_m365_setup_guide(collectors="mailbox_forwarding"))

    required, _, rest = markdown.partition("## Optional Microsoft Graph Permissions")
    assert rest, "the optional heading is missing"
    assert OPTIONAL_FOLDER_SCOPE not in required
    optional_section = rest.split("\n## ", 1)[0]
    assert f"`{OPTIONAL_FOLDER_SCOPE}`" in optional_section
    assert "never a body" in optional_section and "unknown" in optional_section


def test_r006_default_plan_markdown_has_no_optional_heading() -> None:
    from auditex.setup_guide import build_m365_setup_guide, render_setup_guide_markdown

    markdown = render_setup_guide_markdown(build_m365_setup_guide())

    assert OPTIONAL_FOLDER_SCOPE not in markdown
    assert "## Optional Microsoft Graph Permissions" not in markdown


def test_r006_scope_catalog_keeps_optional_scopes_apart_from_required_ones() -> None:
    from azure_tenant_audit.scope_catalog import (
        aggregate_catalog_rows,
        load_m365_scope_catalog,
    )

    catalog = load_m365_scope_catalog()
    row = catalog["mailbox_forwarding"]

    assert OPTIONAL_FOLDER_SCOPE not in row["required_permissions"]
    assert row["optional_permissions"] == [OPTIONAL_FOLDER_SCOPE]
    aggregate = aggregate_catalog_rows(catalog, ["mailbox_forwarding", "identity"])
    assert OPTIONAL_FOLDER_SCOPE not in aggregate["required_permissions"]
    assert aggregate["optional_permissions"] == [OPTIONAL_FOLDER_SCOPE]

"""R085/R149: Graph cmdlets that return post bodies, list rows, pages, tasks or chat text are refused like their REST paths."""
from __future__ import annotations

import pytest

from azure_tenant_audit.adapters.read_guard import CommandRefused, check_command, classify_command, words_are_read
from azure_tenant_audit.api_inventory import _CONTENT_PATHS, _content_reason

# One Graph PowerShell cmdlet per content path rule the API inventory applies to REST reads (``_CONTENT_PATHS``).
# ``None`` marks a path no Get-* cmdlet reaches (search is Invoke-MgQuerySearch, which the verb allow-list refuses).
CMDLETS_BY_CONTENT_PATH = {
    r"(?:^|/)messages(?:/|$)": ("/users/{id}/mailFolders/{id}/messages", ["Get-MgUserMailFolderMessage", "Get-MgChatMessage", "Get-MgUserMessageMention", "Get-MgChatPinnedMessage"]),
    r"(?:^|/)attachments(?:/|$)": ("/users/{id}/messages/{id}/attachments", ["Get-MgUserMessageAttachment", "Get-MgUserTodoListTaskAttachment"]),
    r"/\$value$": ("/drives/{id}/items/{id}/content/$value", ["Get-MgDriveItemContent"]),
    r"/content$": ("/users/{id}/onenote/pages/{id}/content", ["Get-MgUserOnenotePageContent", "Get-MgGroupDriveItemContent"]),
    r"^/(?:users/\{id\}|me|groups/\{id\})/(?:calendar/|calendars/\{id\}/|calendarGroups/\{id\}/calendars/\{id\}/)?(?:events|calendarView)(?:/|$)": (
        "/users/{id}/calendars/{id}/events",
        ["Get-MgUserCalendarEventInstance", "Get-MgUserEventExtension", "Get-MgGroupCalendarViewDelta", "Get-MgUserCalendarGroupCalendarEventDelta"],
    ),
    r"(?:^|/)onenote(?:/|$)": ("/users/{id}/onenote/pages", ["Get-MgUserOnenotePage", "Get-MgSiteOnenotePage", "Get-MgGroupOnenoteSectionPage"]),
    r"^/search/query$": ("/search/query", None),
    r"(?:^|/)(?:threads|conversations|posts)(?:/|$)": (
        "/groups/{id}/threads/{id}/posts",
        ["Get-MgGroupThreadPostInReplyTo", "Get-MgGroupConversationThreadPostInReplyTo", "Get-MgGroupThreadPostExtension"],
    ),
    r"(?:^|/)getAllMessages(?:\(|/|$)": ("/teams/{id}/channels/getAllMessages(...)", ["Get-MgTeamChannelAllMessage", "Get-MgAllChatMessage"]),
    r"(?:^|/)lists/\{id\}/items(?:/|$)": ("/sites/{id}/lists/{id}/items", ["Get-MgSiteListItem", "Get-MgSiteListItemVersion", "Get-MgSiteListItemField"]),
    r"(?:^|/)todo/lists/\{id\}/tasks(?:/|$)": ("/users/{id}/todo/lists/{id}/tasks", ["Get-MgUserTodoListTask", "Get-MgUserTodoListTaskChecklistItem"]),
}

EXTRA_CONTENT_CMDLETS = ("Get-MgSitePage", "Get-MgSitePageCanvasLayout", "Get-MgSitePageWebPart", "Get-MgTeamPrimaryChannelMessageReply")

# -ExpandProperty or -Property naming a content navigation on a Graph cmdlet inlines content into a metadata read.
CONTENT_EXPANSIONS = (
    "Get-MgUserChat -UserId u -ExpandProperty lastMessagePreview",
    "Get-MgUserChat -UserId u -ExpandProperty 'lastMessagePreview'",
    "Get-MgUserChat -UserId u -ExpandProperty:lastMessagePreview",
    "Get-MgUserChat -UserId u -Expand lastMessagePreview",
    "Get-MgUserChat -UserId u -ExpandProperty members,lastMessagePreview",
    "Get-MgChat -ExpandProperty messages",
    "Get-MgSiteList -SiteId s -ExpandProperty items",
    "Get-MgUserMailFolder -UserId u -ExpandProperty messages",
    "Get-MgGroup -GroupId g -ExpandProperty threads",
    "Get-MgUserTodoList -UserId u -ExpandProperty tasks",
    "Get-MgUserMailFolder -UserId u -Property id,body",
    "Get-MgBetaUserChat -UserId u -ExpandProperty lastMessagePreview",
)

METADATA = (
    "Get-MgUser",
    "Get-MgUserChat -UserId u -ExpandProperty members",
    "Get-MgSite -SiteId s",
    "Get-MgSiteList -SiteId s",
    "Get-MgSiteContentType -SiteId s",
    "Get-MgUserTodoList -UserId u",
    "Get-MgUserMailFolder -UserId u -Property id,displayName",
    "Get-MgUserMailFolderMessageRule -UserId u -MailFolderId inbox",
    "Get-MgUserMessageRule",
    "Get-MgServiceAnnouncementMessage",
    "Get-MgDeviceManagementTroubleshootingEvent",
    "Get-MgUserDeviceManagementTroubleshootingEvent",
    "Get-MgDeviceManagementDeviceCompliancePolicy",
    "Get-MgSecuritySecureScore",
    "Get-MgUserAuthenticationMethod -UserId u",
    "Get-MgDriveList -DriveId d",
    "Get-MgGroup -GroupId g -ExpandProperty members",
    "Get-OrganizationConfig | Select-Object -Property Name,Content",
    "Get-MgBetaRoleManagementDirectoryRoleAssignmentScheduleInstance -ExpandProperty principal",
)


def test_every_rest_content_path_rule_has_its_cmdlet_family() -> None:
    assert {pattern.pattern for pattern in _CONTENT_PATHS} == set(CMDLETS_BY_CONTENT_PATH)
    for pattern, (template, _) in CMDLETS_BY_CONTENT_PATH.items():
        assert _content_reason(template, None) is not None, pattern


@pytest.mark.parametrize("adapter", ["powershell_graph", "m365dsc"])
@pytest.mark.parametrize(
    "cmdlet",
    [name for _, names in CMDLETS_BY_CONTENT_PATH.values() if names for name in names] + list(EXTRA_CONTENT_CMDLETS),
)
def test_graph_content_cmdlets_are_refused(adapter: str, cmdlet: str) -> None:
    for script in (cmdlet, f"{cmdlet} -UserId u", f"Get-MgUser | {cmdlet}", cmdlet.replace("Get-Mg", "Get-MgBeta", 1)):
        with pytest.raises(CommandRefused):
            check_command(adapter, script)
    assert not words_are_read(adapter, [cmdlet])


@pytest.mark.parametrize("adapter", ["powershell_graph", "m365dsc"])
@pytest.mark.parametrize("command", CONTENT_EXPANSIONS)
def test_graph_content_expansions_are_refused(adapter: str, command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command(adapter, command)
    assert not classify_command(adapter, command).read_only


@pytest.mark.parametrize("command", METADATA)
def test_graph_metadata_reads_stay_allowed(command: str) -> None:
    assert check_command("powershell_graph", command)

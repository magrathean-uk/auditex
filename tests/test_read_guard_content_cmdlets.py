"""Content-returning cmdlets must not cross the runtime read boundary."""
import pytest
from test_read_guard import _shipped_powershell_commands

from azure_tenant_audit.adapters.read_guard import (
    CONTENT_CMDLET_DENY,
    CommandRefused,
    check_command,
    classify_command,
    words_are_read,
)

DENIED = (
    # Microsoft Graph mail, chats and channels
    "Get-MgUserMessage",
    "Get-MgUserMailFolderMessage",
    "Get-MgUserMailFolderChildFolderMessage",
    "Get-MgUserMessageDelta",
    "Get-MgChatMessage",
    "Get-MgUserChatMessage",
    "Get-MgTeamChannelMessage",
    "Get-MgTeamChannelMessageReply",
    "Get-MgGroupThreadPost",
    "Get-MgGroupConversationThreadPost",
    # Microsoft Graph calendars
    "Get-MgUserEvent",
    "Get-MgUserCalendarEvent",
    "Get-MgUserCalendarView",
    "Get-MgGroupEvent",
    # Graph pattern rules: any Get-Mg*Attachment* and any Get-Mg*Content
    "Get-MgUserMessageAttachment",
    "Get-MgUserMailFolderMessageAttachment",
    "Get-MgUserEventAttachment",
    "Get-MgGroupThreadPostAttachment",
    "Get-MgUserMessageAttachmentCount",
    "Get-MgDriveItemContent",
    "Get-MgUserDriveItemContent",
    "Get-MgUserMessageContent",
    "Get-MgGroupDriveItemContent",
    "Get-MgSiteDriveItemContent",
    "Get-MgDriveRootContent",
    "Get-MgChatMessageHostedContent",
    "Get-MgUserOnenotePageContent",
    # Graph beta names are judged as their v1.0 equivalent
    "Get-MgBetaUserMessage",
    "Get-MgBetaUserEvent",
    "Get-MgBetaUserMessageAttachment",
    # Exchange Online
    "Get-QuarantineMessageHeader",
    "Get-Message",
    "Export-Message",
    "Export-QuarantineMessage",
    "Preview-QuarantineMessage",
    "Search-Mailbox",
    "New-MailboxExportRequest",
    # PnP PowerShell
    "Get-PnPFile",
    "Get-PnPListItem",
    # Local file system, registry and environment
    "Get-Content",
    "Get-Item",
    "Get-ChildItem",
    "Get-ItemProperty",
    "Get-ItemPropertyValue",
)

# Metadata reads that share a noun with a content cmdlet; they must stay allowed.
METADATA = (
    "Get-Module",
    "Get-Command",
    "Get-MessageTrace",
    "Get-MessageTraceDetail",
    "Get-EXOMailbox",
    "Get-MgServiceAnnouncementMessage",
    "Get-MgUserMessageRule",
    "Get-MgUserMailFolderMessageRule",
    "Get-MgUserMailFolder",
    "Get-MgUserCalendar",
    "Get-MgUserDriveItem",
    "Get-MgDeviceManagementTroubleshootingEvent",
    "Get-MgSiteContentType",
    "Get-MgBetaUser",
    "Get-QuarantineMessage",
    "Get-SafeAttachmentPolicy",
    "Get-HostedContentFilterPolicy",
    "Get-CsTeamsMessagingPolicy",
)

VARIANTS = {
    "as-written": lambda s: s,
    "swapped-case": str.swapcase,
    "lower-case": str.lower,
    "module-prefixed": lambda s: "Microsoft.Graph.Mail\\" + s,
    "module-prefixed-upper": lambda s: "MICROSOFT.GRAPH.MAIL\\" + s.upper(),
}


def test_every_named_cmdlet_is_on_the_deny_list_or_a_graph_pattern() -> None:
    assert all(name == name.lower() for name in CONTENT_CMDLET_DENY)
    for name in ("get-mgusermessage", "get-mgusermailfoldermessage", "get-mguserevent",
                 "get-mgdriveitemcontent", "get-mguserdriveitemcontent", "get-content",
                 "get-childitem", "get-item", "get-pnpfile"):
        assert name in CONTENT_CMDLET_DENY


@pytest.mark.parametrize("adapter", ["powershell_graph", "m365dsc"])
@pytest.mark.parametrize("cmdlet", DENIED)
@pytest.mark.parametrize("variant", VARIANTS.values(), ids=VARIANTS.keys())
def test_content_cmdlets_are_refused_everywhere(adapter, cmdlet, variant):
    word = variant(cmdlet)
    for script in (
        word,
        f"{word} -UserId a@contoso.com",
        f"Get-Module | {word}",
        f"Get-OrganizationConfig | Select-Object Name; {word}",
        f"& {{ {word} }}",
        f"$r = @({word}); $r | ConvertTo-Json",
    ):
        with pytest.raises(CommandRefused):
            check_command(adapter, script)
        assert not classify_command(adapter, script).read_only
    assert not words_are_read(adapter, [word])
    assert not words_are_read(adapter, ["Get-Module", word])


@pytest.mark.parametrize("command", _shipped_powershell_commands() + list(METADATA))
def test_shipped_and_metadata_commands_remain_allowed(command):
    assert check_command("powershell_graph", command)
    assert classify_command("powershell_graph", command).read_only


@pytest.mark.parametrize("cmdlet", METADATA)
def test_metadata_words_remain_reads(cmdlet):
    for adapter in ("powershell_graph", "m365dsc"):
        assert words_are_read(adapter, [cmdlet])
        assert words_are_read(adapter, [cmdlet.swapcase()])

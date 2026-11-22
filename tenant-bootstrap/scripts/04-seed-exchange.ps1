param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory
Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null
$cfg = $global:BootstrapSession.Config

if ($DryRun) {
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "exchange" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
  Connect-BootstrapExchange
}

function Ensure-MailboxUser {
  param([string]$Alias, [string]$DisplayName, [switch]$Room)
  $upn = Get-Upn -Alias $Alias
  # A dry run has no tenant-checked Graph session, so it plans without any tenant lookup.
  if ($DryRun) {
    Write-BootstrapEvent -Message "mailbox.user.wouldEnsure" -Status "success" -Step "exchange" -Details @{upn=$upn}
    Write-BootstrapEvent -Message "mailbox.wouldCreate" -Status "success" -Step "exchange" -Details @{type=$(if ($Room) { "room" } else { "shared" }); alias=$Alias}
    return
  }

  if (-not (Get-MgUser -Filter "userPrincipalName eq '$($upn.Replace("'", "''"))'" -ErrorAction SilentlyContinue)) {
    Invoke-BootstrapCommand -Name "create-exchange-owner-user-$Alias" -Module "graph" -Step "exchange" -Action {
      New-MgUser -DisplayName $DisplayName -GivenName $DisplayName.Split(" ")[0] -Surname $DisplayName.Split(" ")[-1] -UserPrincipalName $upn -MailNickName $Alias.Replace(".", "") -UsageLocation $cfg.tenant.usageLocation -AccountEnabled $true -PasswordProfile @{password = New-SamplePassword; forceChangePasswordNextSignIn = $true}
    } | Out-Null
  }

  if ($Room) {
    Invoke-BootstrapCommand -Name "create-room-$Alias" -Module "exchange" -Step "exchange" -Action {
      if (-not (Get-Mailbox -Identity $upn -ErrorAction SilentlyContinue)) {
        New-Mailbox -Room -Name $DisplayName -Alias $Alias -DisplayName $DisplayName
      }
    } | Out-Null
  } else {
    Invoke-BootstrapCommand -Name "create-shared-$Alias" -Module "exchange" -Step "exchange" -Action {
      if (-not (Get-Mailbox -Identity $upn -ErrorAction SilentlyContinue)) {
        New-Mailbox -Shared -Name $DisplayName -Alias $Alias -DisplayName $DisplayName
      }
    } | Out-Null
  }
}

Invoke-BootstrapCommand -Name "seed-shared-mailboxes" -Module "exchange" -Step "exchange" -Action {
  @("it.helpdesk", "finance.request") | ForEach-Object {
    Ensure-MailboxUser -Alias $_ -DisplayName "$_ mailbox" -Room:$false
  }
  @("conf-bridge-1", "conf-bridge-2") | ForEach-Object {
    Ensure-MailboxUser -Alias $_ -DisplayName "Resource $_" -Room
  }
}

if ($DryRun) {
  Write-BootstrapEvent -Message "exchange.defender.wouldSeed" -Status "success" -Step "exchange" -Details @{policies="DEF-Standard-SafeLinks,DEF-Standard-SafeAttachment,DEF-Standard-AntiPhish"}
}
elseif (-not (Get-Command New-SafeLinksPolicy -ErrorAction SilentlyContinue)) {
  Write-BootstrapEvent -Message "exchange.cmdlet.missing" -Status "warn" -Step "exchange" -Details @{cmdlets="SafeLinks/SafeAttachment cmdlets"}
}
else {
  Invoke-BootstrapCommand -Name "seed-defender-preset" -Module "exchange" -Step "exchange" -Action {
    if (-not (Get-SafeLinksPolicy -Identity "DEF-Standard-SafeLinks" -ErrorAction SilentlyContinue)) {
      New-SafeLinksPolicy -Name "DEF-Standard-SafeLinks" -IsEnabled $true -TrackClicks $true -ScanUrls $true -DoNotAllowClickThrough $true
    }
    if (-not (Get-SafeAttachmentPolicy -Identity "DEF-Standard-SafeAttachment" -ErrorAction SilentlyContinue)) {
      New-SafeAttachmentPolicy -Name "DEF-Standard-SafeAttachment" -Enabled $true -Action Protect -EnableForInternalSenders $true
    }
    if (-not (Get-AntiPhishPolicy -Identity "DEF-Standard-AntiPhish" -ErrorAction SilentlyContinue)) {
      New-AntiPhishPolicy -Name "DEF-Standard-AntiPhish" -EnableMailboxIntelligence $true
    }
  } | Out-Null
}

Write-BootstrapEvent -Message "exchange.seed.done" -Status "success" -Step "exchange" -Details @{shared="it.helpdesk,finance.request"; rooms="conf-bridge-1,conf-bridge-2"}

End-BootstrapSession

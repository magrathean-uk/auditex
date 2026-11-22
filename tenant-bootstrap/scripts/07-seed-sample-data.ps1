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
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "data" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
}

$allUsers = @()
Invoke-BootstrapCommand -Name "load-core-users" -Module "graph" -Step "data" -Action {
  $groupId = Get-GroupId -DisplayName $cfg.groupNames.allUsers
  if ($groupId) {
    $allUsers = Get-MgGroupMember -GroupId $groupId -All | ForEach-Object { $_.Id }
  }
}

if (-not $allUsers -or $allUsers.Count -eq 0) {
  throw "No members found in all-users group. Run identities first."
}

$subjectSamples = @("Budget Check-in", "Customer Escalation", "Quarterly Ops", "Proposal Draft", "Follow-up and Open Actions")
$teams = @()
Invoke-BootstrapCommand -Name "load-teams" -Module "graph" -Step "data" -Action {
  foreach ($alias in @($cfg.groupNames.itM365, $cfg.groupNames.salesM365, $cfg.groupNames.financeM365)) {
    $group = Get-MgGroup -Filter "displayName eq '$($alias.Replace("'", "''"))'" -ErrorAction SilentlyContinue
    if ($group) {
      try {
        $teams += Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/team" -ErrorAction SilentlyContinue
      } catch {}
    }
  }
}

$days = [int]$cfg.counts.daysOfHistory
if ($DryRun) {
  Write-BootstrapEvent -Message "sampledata.dryrun" -Status "success" -Step "data" -Details @{days=$days}
  End-BootstrapSession
  return
}

for ($offset = 0; $offset -lt $days; $offset++) {
  $day = (Get-Date).Date.AddDays(-$offset)
  $seedUsers = $allUsers | Select-Object -First 12
  foreach ($senderId in $seedUsers) {
    $toId = Get-Random -InputObject $allUsers
    $subject = "$($subjectSamples[(Get-Random -Maximum $subjectSamples.Count)]) - $($day.ToString('yyyy-MM-dd'))"
    $body = @{
      message = @{
        subject = $subject
        body = @{
          contentType = "Text"
          content = "Operational context for $($day.ToShortDateString()). Include blockers, owners, and due dates."
        }
        toRecipients = @(
          @{ emailAddress = @{ address = (Get-MgUser -UserId $toId).UserPrincipalName } }
        )
      }
      saveToSentItems = $true
    } | ConvertTo-Json -Depth 12

    Invoke-BootstrapCommand -Name "seed-mail-$senderId-$offset" -Module "graph" -Step "data" -Action {
      Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$senderId/sendMail" -Body $body
    } | Out-Null
  }

  $eventOwner = Get-Random -InputObject $allUsers
  Invoke-BootstrapCommand -Name "seed-event-$offset" -Module "graph" -Step "data" -Action {
    $start = $day.AddHours(9).ToString("o")
    $end = $day.AddHours(10).ToString("o")
    $eventPayload = @{
      subject = "Ops Sync - $($day.ToString('yyyy-MM-dd'))"
      body = @{ contentType = "Text"; content = "Status, blockers, action owners, and dependencies."}
      start = @{ dateTime = $start; timeZone = $cfg.tenant.timeZone }
      end = @{ dateTime = $end; timeZone = $cfg.tenant.timeZone }
      attendees = @(
        @{
          emailAddress = @{ address = (Get-MgUser -UserId $eventOwner).UserPrincipalName }
          type = "required"
        }
      )
    } | ConvertTo-Json -Depth 12
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$eventOwner/events" -Body $eventPayload
  } | Out-Null

  $contactOwner = Get-Random -InputObject $allUsers
  Invoke-BootstrapCommand -Name "seed-contact-$offset" -Module "graph" -Step "data" -Action {
    $contact = @{
      givenName = "Vendor"
      surname = "Ops"
      emailAddresses = @(@{address = "vendor.$($offset + 1)@contoso-partner.com"; name = "Vendor Ops"})
      companyName = "Contoso Partner"
      mobilePhone = "+1-555-01$((1000 + $offset) - 1000)"
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$contactOwner/contacts" -Body $contact
  } | Out-Null

  $seedUser = Get-Random -InputObject $allUsers
  $safeSubject = "proposal-$offset.md"
  Invoke-BootstrapCommand -Name "seed-onedrive-$offset" -Module "graph" -Step "data" -Action {
    $content = "Seeded document from $day. Topic: $subject. Contains business history."
    $path = "Documents/$safeSubject"
    Invoke-MgGraphRequest -Method PUT -Uri "https://graph.microsoft.com/v1.0/users/$seedUser/drive/root:/${path}:/content" -Body $content -ContentType "text/plain"
  } | Out-Null
}

if ($teams.Count -gt 0) {
  foreach ($team in $teams) {
    $teamId = $team.id
    if (-not $teamId) { continue }
    $channels = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" | Select-Object -ExpandProperty Value
    foreach ($channel in ($channels | Where-Object { $_.displayName -in @("General","Incidents","Projects") })) {
      $payload = @{ body = @{ contentType = "html"; content = "<p>Seed activity from $(Get-Date -Format 'o') with context and action points.</p>" } } | ConvertTo-Json -Depth 10
      Invoke-BootstrapCommand -Name "seed-teams-message-$($teamId)-$($channel.id)" -Module "graph" -Step "data" -Action {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels/$($channel.id)/messages" -Body $payload
      } | Out-Null
    }
  }
}

Write-BootstrapEvent -Message "sampledata.seed.done" -Status "success" -Step "data" -Details @{days=$days; mails=($allUsers.Count * $days)}
End-BootstrapSession

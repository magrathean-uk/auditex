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
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "teams" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
}

function Ensure-TeamFromGroup {
  param([string]$GroupDisplayName)
  $group = Get-MgGroup -Filter "displayName eq '$($GroupDisplayName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
  if (-not $group) { throw "Missing M365 group $GroupDisplayName." }

  if ($DryRun) {
    Write-BootstrapEvent -Message "team.wouldSeedFromGroup" -Status "success" -Step "teams" -Details @{group=$GroupDisplayName}
    return $group
  }

  $teamState = $null
  try {
    $teamState = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/team" -ErrorAction SilentlyContinue
  } catch {
    $teamState = $null
  }
  if (-not $teamState) {
    Invoke-BootstrapCommand -Name "create-team-$GroupDisplayName" -Module "graph" -Step "teams" -Action {
      $body = @{
        "@odata.type" = "#microsoft.graph.team"
        "template@odata.bind" = "https://graph.microsoft.com/beta/teamsTemplates('standard')"
        displayName = $group.DisplayName
        description = "Seed team for $($group.DisplayName)"
      } | ConvertTo-Json -Depth 10
      Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/groups/$($group.Id)/team" -Body $body
    } | Out-Null
    Start-Sleep -Seconds 15
  }
  return $group
}

foreach ($teamGroup in @($cfg.groupNames.itM365, $cfg.groupNames.salesM365, $cfg.groupNames.financeM365)) {
  $group = Ensure-TeamFromGroup -GroupDisplayName $teamGroup
  if ($DryRun) { continue }

  Invoke-BootstrapCommand -Name "seed-channels-$teamGroup" -Module "graph" -Step "teams" -Action {
    $team = $null
    for ($i = 0; $i -lt 6; $i++) {
      try {
        $team = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/team" -ErrorAction SilentlyContinue
      } catch {}
      if ($team -and $team.id) { break }
      Start-Sleep -Seconds 10
    }
    if (-not $team -or -not $team.id) {
      throw "Team provisioning did not complete for $($group.DisplayName)"
    }

    $teamId = $team.id
    $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" -OutputType PSObject | Select-Object -ExpandProperty Value
    $existingNames = @{}
    foreach ($channelName in ($existing | ForEach-Object { $_.displayName })) {
      $existingNames[$channelName.ToLower()] = $true
    }
    foreach ($channel in $cfg.teamChannels) {
      if ($existingNames[$channel.ToLower()]) { continue }
      $uri = "https://graph.microsoft.com/v1.0/teams/$teamId/channels"
      $payload = @{
        displayName = $channel
        description = "Seed channel"
        membershipType = "standard"
      } | ConvertTo-Json -Depth 10
      Invoke-MgGraphRequest -Method POST -Uri $uri -Body $payload
    }
  } | Out-Null
}

Write-BootstrapEvent -Message "teams.seed.done" -Status "success" -Step "teams" -Details @{teamGroups=3}

End-BootstrapSession

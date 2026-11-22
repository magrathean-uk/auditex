param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun,
  [switch]$DisableSecurityDefaults
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory
Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null
$cfg = $global:BootstrapSession.Config
if ($DryRun) {
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "security" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
}

$policyPath = Join-Path (Split-Path $PSScriptRoot -Parent) "policies/entra"
$templates = Get-ChildItem -Path $policyPath -Filter *.json -File | Sort-Object Name | Select-Object -ExpandProperty Name

if (-not $DryRun) {
  $allUsersGroupId = Get-GroupId -DisplayName $cfg.groupNames.allUsers
  $adminGroupId = Get-GroupId -DisplayName $cfg.groupNames.admins
  $breakGlassGroupId = Get-GroupId -DisplayName $cfg.groupNames.breakGlass

  $templatesRequiringDefaultsOff = @()
  foreach ($template in $templates) {
    $path = Join-Path $policyPath $template
    if (-not (Test-Path $path)) { continue }
    $payload = (Get-Content $path -Raw | ConvertFrom-Json)
    if ($payload.state -and $payload.state -ne "reportOnly" -and $payload.state -ne "disabled") {
      $templatesRequiringDefaultsOff += $template
    }
  }

  if ($templatesRequiringDefaultsOff.Count -gt 0) {
    $securityDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    Write-BootstrapEvent -Message "security.defaults.detected" -Status "success" -Step "security" -Details @{isEnabled=$securityDefaults.isEnabled}
    if ($securityDefaults.isEnabled -and $DisableSecurityDefaults) {
      Invoke-BootstrapCommand -Name "disable-security-defaults" -Module "graph" -Step "security" -Action {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Body '{"isEnabled":false}'
      } | Out-Null
    } elseif ($securityDefaults.isEnabled) {
      Write-BootstrapEvent -Message "security.defaults.blocking" -Status "warn" -Step "security" -Details @{templates=$templatesRequiringDefaultsOff}
    }
  }

  foreach ($template in $templates) {
    $path = Join-Path $policyPath $template
    if (-not (Test-Path $path)) { continue }
    $raw = Get-Content $path -Raw
    $raw = $raw.Replace("{{ALL_USERS_GROUP_ID}}", $allUsersGroupId)
    $raw = $raw.Replace("{{ADMINS_GROUP_ID}}", $adminGroupId)
    $raw = $raw.Replace("{{BREAKGLASS_GROUP_ID}}", $breakGlassGroupId)
    $payload = $raw | ConvertFrom-Json
    if ($payload.state -eq "reportOnly") {
      $payload.state = "enabledForReportingButNotEnforced"
    }

    if ($payload.state -and $payload.state -ne "enabledForReportingButNotEnforced" -and $payload.state -ne "disabled") {
      $securityDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
      if ($securityDefaults.isEnabled) {
        Write-BootstrapEvent -Message "ca.policy.skipped.securityDefaultsEnabled" -Status "warn" -Step "security" -Details @{policy=$payload.displayName}
        continue
      }
    }

    $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$filter=displayName eq '$($payload.displayName.Replace("'", "''"))'" |
      Select-Object -ExpandProperty Value |
      Where-Object displayName -eq $payload.displayName
    if ($existing) {
      Write-BootstrapEvent -Message "ca.policy.exists" -Status "success" -Step "security" -Details @{policy=$payload.displayName}
      continue
    }

    Invoke-BootstrapCommand -Name "create-ca-$($payload.displayName)" -Module "graph" -Step "security" -Action {
      Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body ($payload | ConvertTo-Json -Depth 20)
    } | Out-Null
  }

  Write-BootstrapEvent -Message "secure.baseline.pim" -Status "warn" -Step "security" -Details @{
    note = "Enable Entra PIM eligibility for admin groups manually (Global/Privileged roles) in portal or Microsoft Graph privileged-access flows."
  }
} else {
  Write-BootstrapEvent -Message "security.dryrun" -Status "success" -Step "security" -Details @{templates=$templates.Count}
}

End-BootstrapSession

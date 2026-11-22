param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory
Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null
$cfg = $global:BootstrapSession.Config
$fallbackOwner = Get-Upn -Alias $cfg.actors.dailyUser
if ($DryRun) {
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "sharepoint-intune" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
  Connect-BootstrapPnP
}

if (-not $DryRun) {
foreach ($site in $cfg.sharePoint.sites) {
  $siteUrl = "https://$($cfg.tenant.tenantDomain)/sites/$($site.urlSuffix)"
  $ownerAlias = if ($site.ownerAlias) { $site.ownerAlias } else { $cfg.actors.dailyUser }
  $ownerUpn = Get-Upn -Alias $ownerAlias
  if (-not (Get-MgUser -Filter "userPrincipalName eq '$($ownerUpn.Replace("'", "''"))'" -ErrorAction SilentlyContinue)) {
    Write-BootstrapEvent -Message "sharepoint.owner.fallback" -Status "warn" -Step "sharepoint-intune" -Details @{
      requestedOwner = $ownerAlias
      fallback = $cfg.actors.dailyUser
    }
    $ownerUpn = $fallbackOwner
  }
  Invoke-BootstrapCommand -Name "ensure-site-$($site.urlSuffix)" -Module "sharepoint" -Step "sharepoint" -Action {
      if (-not (Get-PnPTenantSite -Identity $siteUrl -ErrorAction SilentlyContinue)) {
        New-PnPTenantSite -Title $site.title -Url $siteUrl -Owner $ownerUpn -Template STS#3 -TimeZone 4 -Description $site.description
      }
      Connect-PnPOnline -Url $siteUrl -UseWebLogin:$false | Out-Null
      $root = Get-PnPFolder -Url "Shared Documents" -ErrorAction SilentlyContinue
      if (-not $root) {
        New-PnPFolder -Name "Shared Documents"
      }
      foreach ($template in $cfg.sharePoint.templateFiles) {
        $templatePath = Join-Path $PSScriptRoot ".." $template
        if (Test-Path $templatePath) {
          Add-PnPFile -Path $templatePath -Folder "Shared Documents" -ErrorAction SilentlyContinue | Out-Null
        }
      }
    } | Out-Null
  }
}

$policyFolder = Join-Path (Split-Path $PSScriptRoot -Parent) "policies/intune"
$policies = @(Get-ChildItem -Path $policyFolder -Filter *.json -File | Sort-Object Name | Select-Object -ExpandProperty Name)

if (-not $DryRun) {
  foreach ($policyFile in $policies) {
    $path = Join-Path $policyFolder $policyFile
    if (-not (Test-Path $path)) { continue }
    $payload = Get-Content -Path $path -Raw | ConvertFrom-Json
    $payloadJson = $payload | ConvertTo-Json -Depth 20

    Invoke-BootstrapCommand -Name "seed-intune-$policyFile" -Module "intune" -Step "intune" -Action {
      $odataType = ""
      if ($payload.PSObject.Properties["`@odata.type"]) {
        $odataType = $payload."`@odata.type"
      }
      $kind = if ($odataType -like "*compliance*") { "deviceCompliancePolicy" } else { "deviceConfiguration" }

      $name = $payload.displayName
      $escaped = $name.Replace("'", "''")
      $queryName = [uri]::EscapeDataString("displayName eq '$escaped'")
      if ($kind -eq "deviceCompliancePolicy") {
        if (-not (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$filter=$queryName" -OutputType PSObject | Select-Object -ExpandProperty Value | Where-Object displayName -eq $name)) {
          Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Body $payloadJson
        }
      } else {
        if (-not (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=$queryName" -OutputType PSObject | Select-Object -ExpandProperty Value | Where-Object displayName -eq $name)) {
          Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $payloadJson
        }
      }
    } | Out-Null
  }
}

Write-BootstrapEvent -Message "sharepoint-intune.seed.done" -Status "success" -Step "sharepoint-intune" -Details @{sites=$cfg.sharePoint.sites.Count; policies=$policies.Count}

End-BootstrapSession

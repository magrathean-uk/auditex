param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName = "",
  [string]$RunDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Initialize-BootstrapSession {
  param(
    [string]$ConfigPath,
    [string]$RunName = "",
    [string]$RunDirectory = ""
  )

  if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
  }

  $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
  $tenantName = if ($config.tenant.tenantName) { $config.tenant.tenantName } else { "seed-tenant" }

  if ([string]::IsNullOrWhiteSpace($RunName)) {
    $RunName = "bootstrap-{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
  }
  if ([string]::IsNullOrWhiteSpace($RunDirectory)) {
    $bootstrapRoot = Split-Path -Parent (Resolve-Path $ConfigPath)
    $RunDirectory = Join-Path $bootstrapRoot "runs/$RunName"
  }

  if (-not (Test-Path $RunDirectory)) {
    New-Item -Path $RunDirectory -ItemType Directory -Force | Out-Null
  }

  $bootstrapManifest = @{
    runName = $RunName
    tenantName = $tenantName
    tenantId = $config.tenant.tenantId
    tenantDomain = $config.tenant.tenantDomain
    startedAt = (Get-Date).ToString("o")
    status = "running"
    stepLog = @()
    errors = 0
  }
  $manifestPath = Join-Path $RunDirectory "run-manifest.json"
  $bootstrapManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -NoNewline

  $logPath = Join-Path $RunDirectory "bootstrap-log.jsonl"
  $debugPath = Join-Path $RunDirectory "bootstrap-debug.log"

  Start-Transcript -Path $debugPath -Append

  $session = [ordered]@{
    Config = $config
    RunDirectory = (Resolve-Path $RunDirectory).Path
    RunName = $RunName
    ManifestPath = $manifestPath
    LogPath = $logPath
    DebugPath = $debugPath
    Manifest = $bootstrapManifest
    Context = @{}
  }

  $global:BootstrapSession = $session
  Write-BootstrapEvent -Message "session.start" -Status "success" -Details @{
    runName = $RunName
    config = $ConfigPath
    tenant = $tenantName
  }
  return $session
}

function Write-BootstrapEvent {
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][string]$Status,
    [hashtable]$Details = @{},
    [string]$Step = ""
  )

  $entry = [ordered]@{
    time = (Get-Date).ToString("o")
    status = $Status
    message = $Message
    step = $Step
    tenant = $global:BootstrapSession.Config.tenant.tenantDomain
    details = $Details
  }
  $entry | ConvertTo-Json -Depth 20 | Add-Content -Path $global:BootstrapSession.LogPath

  if ($Step -ne "") {
    $global:BootstrapSession.Manifest.stepLog += @{
      time = $entry.time
      step = $Step
      status = $Status
      message = $Message
    }
  }
  if ($Status -eq "error") {
    $global:BootstrapSession.Manifest.errors += 1
  }
  $global:BootstrapSession.Manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $global:BootstrapSession.ManifestPath -NoNewline
}

function Invoke-BootstrapCommand {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Action,
    [string]$Step = "",
    [string]$Module = "unknown"
  )
  $start = Get-Date
  Write-BootstrapEvent -Message "${Module}:$Name.started" -Status "started" -Step $Step -Details @{module=$Module}
  try {
    $result = & $Action
    $durationMs = [int]((Get-Date) - $start).TotalMilliseconds
    Write-BootstrapEvent -Message "${Module}:$Name.completed" -Status "success" -Step $Step -Details @{
      module = $Module
      durationMs = $durationMs
    }
    return $result
  } catch {
    $durationMs = [int]((Get-Date) - $start).TotalMilliseconds
    Write-BootstrapEvent -Message "${Module}:$Name.failed" -Status "error" -Step $Step -Details @{
      module = $Module
      durationMs = $durationMs
      error = $_.Exception.Message
    }
    throw
  }
}

# Returns the config tenant GUID; refuses a missing, malformed or all-zero placeholder value.
function Get-BootstrapTenantId {
  $raw = [string]$global:BootstrapSession.Config.tenant.tenantId
  $parsed = [guid]::Empty
  if (-not [guid]::TryParseExact($raw.Trim(), "D", [ref]$parsed) -or $parsed -eq [guid]::Empty) {
    throw "tenant_id_required: set tenant.tenantId in the config to the lab tenant GUID (the all-zero placeholder is refused)."
  }
  return $parsed.ToString()
}

function Connect-BootstrapGraph {
  $cfg = $global:BootstrapSession.Config
  $auth = $cfg.authentication
  $tenantId = Get-BootstrapTenantId

  if ($auth.mode -eq "app") {
    if (-not $auth.app.clientId) {
      throw "App mode requires authentication.app.clientId in config."
    }
    Invoke-BootstrapCommand -Name "connect-mggraph-app" -Module "graph" -Step "auth" -Action {
      Connect-MgGraph -TenantId $tenantId -ClientId $auth.app.clientId -CertificateThumbprint $auth.app.certificateThumbprint -NoWelcome
      Select-MgProfile -Name "beta"
    }
  } else {
    Invoke-BootstrapCommand -Name "connect-mggraph-cli" -Module "graph" -Step "auth" -Action {
      if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI is required when using azure_cli auth mode."
      }
      # Always the named lab tenant: a hint such as "organizations" would take the az default tenant.
      $tokenResponse = az account get-access-token --resource $cfg.authentication.azureCli.resource --tenant $tenantId --query accessToken -o tsv
      if (-not $tokenResponse) {
        throw "No Azure CLI access token was returned."
      }
      Connect-MgGraph -AccessToken $tokenResponse -NoWelcome
      Select-MgProfile -Name "beta"
    }
  }

  Invoke-BootstrapCommand -Name "graph-context" -Module "graph" -Step "auth" -Action {
    # Every later step writes through this Graph session, so prove it is the named lab tenant first.
    $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName" -OutputType PSObject -ErrorAction Stop
    $orgs = @($org.value)
    if ($orgs.Count -ne 1 -or ([string]$orgs[0].id).ToLowerInvariant() -ne $tenantId) {
      throw "tenant_mismatch: the Graph session is not in tenant $tenantId. Nothing was written."
    }
    $sessionUser = $null
    try {
      $sessionUser = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -OutputType PSObject -ErrorAction Stop
    } catch {
      $sessionUser = $orgs[0]
    }

    $global:BootstrapSession.Context.signedInUser = $sessionUser
    Write-BootstrapEvent -Message "graph-session-user" -Status "info" -Step "auth" -Details @{
      principal = if ($sessionUser.userPrincipalName) { $sessionUser.userPrincipalName } else { $sessionUser.displayName }
    }
  }
}

function Connect-BootstrapExchange {
  if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-BootstrapEvent -Message "exchange.module-missing" -Status "warn" -Step "exchange" -Details @{ module = "ExchangeOnlineManagement" }
    return
  }

  $organization = [string]$global:BootstrapSession.Config.tenant.tenantDomain
  if ([string]::IsNullOrWhiteSpace($organization)) {
    throw "tenant_domain_required: set tenant.tenantDomain in the config to the lab tenant domain."
  }
  Invoke-BootstrapCommand -Name "connect-exchange-online" -Module "exchange" -Step "exchange" -Action {
    if ($global:BootstrapSession.Config.authentication.mode -eq "app" -and $global:BootstrapSession.Config.authentication.app.clientId) {
      Connect-ExchangeOnline -AppId $global:BootstrapSession.Config.authentication.app.clientId -CertificateThumbprint $global:BootstrapSession.Config.authentication.app.certificateThumbprint -Organization $organization -ShowBanner:$false
    } else {
      Connect-ExchangeOnline -ShowBanner:$false
    }
    # A delegated sign-in lands in the account's own tenant, so prove it is the named lab tenant.
    $tenantId = Get-BootstrapTenantId
    $connection = @(Get-ConnectionInformation) | Select-Object -Last 1
    if (-not $connection -or ([string]$connection.TenantID).ToLowerInvariant() -ne $tenantId) {
      Disconnect-ExchangeOnline -Confirm:$false
      throw "tenant_mismatch: the Exchange Online session is not in tenant $tenantId. Nothing was written."
    }
  }
}

function Connect-BootstrapPnP {
  if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    Write-BootstrapEvent -Message "pnp.module-missing" -Status "warn" -Step "sharepoint" -Details @{ module = "PnP.PowerShell" }
    return
  }

  Invoke-BootstrapCommand -Name "connect-pnp" -Module "sharepoint" -Step "sharepoint" -Action {
    if ($global:BootstrapSession.Config.authentication.mode -eq "app" -and $global:BootstrapSession.Config.authentication.app.clientId) {
      Connect-PnPOnline -Url "https://$($global:BootstrapSession.Config.tenant.tenantDomain)" -ClientId $global:BootstrapSession.Config.authentication.app.clientId -Thumbprint $global:BootstrapSession.Config.authentication.app.certificateThumbprint -Tenant $global:BootstrapSession.Config.tenant.tenantId
    } else {
      Connect-PnPOnline -Url "https://$($global:BootstrapSession.Config.tenant.tenantDomain)" -Interactive
    }
  }
}

function Ensure-Folder {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

function Get-GroupId {
  param([Parameter(Mandatory)][string]$DisplayName)
  $group = Get-MgGroup -Filter "displayName eq '$($DisplayName.Replace("'", "''"))'" -ConsistencyLevel eventual -CountVariable c -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $group) { return $null }
  return $group.Id
}

function Get-Upn {
  param([Parameter(Mandatory)][string]$Alias)
  return "$Alias@$($global:BootstrapSession.Config.tenant.tenantDomain)"
}

function New-SamplePassword {
  return "P@ssw0rd-" + -join ((65..90 + 97..122 + 48..57) | Get-Random -Count 14 | ForEach-Object { [char]$_ })
}

function End-BootstrapSession {
  if ($global:BootstrapSession) {
    $global:BootstrapSession.Manifest.status = "completed"
    $global:BootstrapSession.Manifest.completedAt = (Get-Date).ToString("o")
    $global:BootstrapSession.Manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $global:BootstrapSession.ManifestPath -NoNewline
    Stop-Transcript
  }
}

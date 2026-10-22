param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun,
  [string]$AuditRoot = "audit-output"
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory
Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null
$cfg = $global:BootstrapSession.Config

if ($DryRun) {
  Write-BootstrapEvent -Message "evidence.wouldRun" -Status "success" -Step "evidence" -Details @{
    command="./scripts/run-audit-collector.sh"
    collectors="identity,security,intune,teams,exchange"
    top="500"
    includeExchange=$true
    tenantName=$cfg.tenant.tenantName
    tenantId=$cfg.tenant.tenantId
  }
  End-BootstrapSession
  return
}

$tenantBootstrapRoot = (Resolve-Path (Split-Path $PSScriptRoot -Parent)).Path
$auditOutput = Join-Path $tenantBootstrapRoot $AuditRoot
Ensure-Folder -Path $auditOutput
$outDir = Join-Path $auditOutput "$($cfg.tenant.tenantName)-$($global:BootstrapSession.RunName)"

Invoke-BootstrapCommand -Name "collect-audit" -Module "audit" -Step "evidence" -Action {
  $python = Get-Command bash -ErrorAction SilentlyContinue
  if (-not $python) {
    throw "bash executable was not found in PATH."
  }
  $collectorScript = Join-Path $tenantBootstrapRoot "scripts/run-audit-collector.sh"
  if (-not (Test-Path $collectorScript)) {
    throw "run-audit-collector.sh is missing at $collectorScript."
  }

  $top = 500
  $collectors = "identity,security,intune,teams,exchange"
  $collectorArgs = @(
    "--tenant-name", $cfg.tenant.tenantName,
    "--tenant-id", $cfg.tenant.tenantId,
    "--out", $outDir,
    "--collectors", $collectors,
    "--top", $top,
    "--run-name", "$($global:BootstrapSession.RunName)-evidence",
    "--include-exchange"
  )
  $quotedCollectorArgs = $collectorArgs | ForEach-Object {
    if ($_.Contains(" ")) { "'$_'" } else { $_ }
  }
  Write-BootstrapEvent -Message "evidence.command" -Status "info" -Step "evidence" -Details @{
    command = "$($python.Source) $tenantBootstrapRoot/scripts/run-audit-collector.sh"
    args = $quotedCollectorArgs
    output = $outDir
    top = $top
    collectors = $collectors
  }

  Push-Location $tenantBootstrapRoot
  try {
    & $python.Source $collectorScript @collectorArgs | Out-Null
  } finally {
    Pop-Location
  }
} | Out-Null

Write-BootstrapEvent -Message "evidence.complete" -Status "success" -Step "evidence" -Details @{output=$outDir}
End-BootstrapSession

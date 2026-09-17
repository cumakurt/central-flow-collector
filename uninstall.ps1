[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\CentralFlowCollector",
    [string]$DataDir = "$env:ProgramData\CentralFlowCollector",
    [switch]$PurgeData
)
$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run uninstall.ps1 as Administrator." }
Stop-Service -Name CentralFlowCollector -ErrorAction SilentlyContinue
& sc.exe delete CentralFlowCollector 2>$null | Out-Null
if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
if ($PurgeData -and (Test-Path -LiteralPath $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
Write-Host "Central Flow Collector service and binaries removed. Data retained: $(-not $PurgeData)."

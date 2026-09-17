[CmdletBinding()]
param(
    [string]$Version = "4.0.0",
    [string]$InstallDir = "$env:ProgramFiles\CentralFlowCollector",
    [string]$DataDir = "$env:ProgramData\CentralFlowCollector",
    [string]$ConfigPath = "",
    [string]$Repository = "cumakurt/central-flow-collector",
    [string]$SourceDir = "$PSScriptRoot",
    [switch]$NoService,
    [switch]$NoStart,
    [switch]$Force,
    [switch]$BuildFromSource
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run install.ps1 from an elevated PowerShell prompt."
    }
}

function Set-YamlValue([string]$Path, [string]$Section, [string]$Key, [string]$Value) {
    $lines = [System.Collections.Generic.List[string]](Get-Content -LiteralPath $Path)
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^$([regex]::Escape($Section)):\s*$") { $start = $i; break }
    }
    if ($start -lt 0) { throw "Configuration section '$Section' was not found in $Path" }
    $end = $lines.Count
    for ($i = $start + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^[^\s#]') { $end = $i; break }
    }
    $escaped = $Value.Replace('\', '/').Replace('"', '\"')
    $replacement = '  ' + $Key + ': "' + $escaped + '"'
    for ($i = $start + 1; $i -lt $end; $i++) {
        if ($lines[$i] -match "^\s+$([regex]::Escape($Key)):") { $lines[$i] = $replacement; [IO.File]::WriteAllLines($Path, [string[]]$lines, (New-Object Text.UTF8Encoding($false))); return }
    }
    $lines.Insert($start + 1, $replacement)
    [IO.File]::WriteAllLines($Path, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
}

function Get-ArchName {
    switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

Assert-Administrator
$arch = Get-ArchName
$source = (Resolve-Path -LiteralPath $SourceDir).Path
$localBinary = Join-Path $source "dist\flowcollector-windows-$arch.exe"
$binary = Join-Path $InstallDir "flowcollector.exe"
$temp = Join-Path ([IO.Path]::GetTempPath()) ("flowcollector-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    if ((Test-Path -LiteralPath $binary) -and -not $Force) { throw "$binary already exists. Use -Force to replace it." }
    New-Item -ItemType Directory -Path $InstallDir, $DataDir -Force | Out-Null
    if (Test-Path -LiteralPath $localBinary) {
        Copy-Item -LiteralPath $localBinary -Destination $binary -Force
    } elseif ($BuildFromSource -or (Test-Path (Join-Path $source "go.mod"))) {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "Go is required to build the Windows binary from source." }
        Push-Location $source
        try { & go build -buildvcs=false -trimpath -ldflags "-s -w -X central-flow-collector/internal/buildinfo.Version=$Version" -o $binary ./cmd/flowcollector }
        finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { throw "Go build failed." }
    } else {
        $url = "https://github.com/$Repository/releases/download/v$Version/flowcollector-windows-$arch.exe"
        Invoke-WebRequest -Uri $url -OutFile (Join-Path $temp "flowcollector.exe")
        Copy-Item (Join-Path $temp "flowcollector.exe") $binary -Force
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $InstallDir "config.yaml" }
    New-Item -ItemType Directory -Path (Split-Path -Parent $ConfigPath) -Force | Out-Null
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        $example = Join-Path $source "config.example.yaml"
        if (-not (Test-Path -LiteralPath $example)) { throw "config.example.yaml was not found." }
        Copy-Item $example $ConfigPath
    }
    Set-YamlValue $ConfigPath "storage" "data_dir" $DataDir
    Set-YamlValue $ConfigPath "security" "bootstrap_file" (Join-Path $DataDir "bootstrap-admin.txt")
    Set-YamlValue $ConfigPath "analytics" "baseline_state_file" (Join-Path $DataDir "baseline-state.json")
    & $binary config validate --config $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }
    if (-not $NoService) {
        $serviceName = "CentralFlowCollector"
        & sc.exe stop $serviceName 2>$null | Out-Null
        & sc.exe delete $serviceName 2>$null | Out-Null
        $binPath = '"' + $binary + '" run --config "' + $ConfigPath + '"'
        & sc.exe create $serviceName binPath= $binPath start= auto DisplayName= "Central Flow Collector" | Out-Null
        & sc.exe description $serviceName "Central Flow Collector network flow ingestion service" | Out-Null
        if (-not $NoStart) { Start-Service -Name $serviceName }
    }
    Write-Host "Central Flow Collector installed at $InstallDir"
    Write-Host "Configuration: $ConfigPath"
    Write-Host "Data directory: $DataDir"
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}

#Requires -Version 5.1
<#
Windows dev environment bootstrap for Service Port Scanner.

Run from an elevated PowerShell (winget needs admin for VS workload install):
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  .\scripts\bootstrap-windows.ps1

Steps:
  1. Install Git, CMake, Ninja, Visual Studio 2022 Build Tools (C++ workload) via winget.
  2. Clone vcpkg to %USERPROFILE%\vcpkg and bootstrap.
  3. Set VCPKG_ROOT user env var.
  4. Run `vcpkg install` (manifest mode) for core deps. GUI feature is opt-in (-WithGui).
  5. Configure CMake with the vcpkg toolchain.

Flags:
  -WithGui      Also install Qt6 (gui feature). Adds 1-2 hours on first build.
  -WithExtras   Install boost-beast, tomlplusplus, magic-enum, tl-expected.
  -SkipInstall  Skip winget step (assume tools already present).
#>

[CmdletBinding()]
param(
    [switch]$WithGui,
    [switch]$WithExtras,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Have($cmd)  { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

if (-not $SkipInstall) {
    Step "winget: install build tools"
    if (-not (Have winget)) { throw "winget not found. Install App Installer from Microsoft Store." }

    $packages = @(
        @{ id = 'Git.Git';                                  name = 'Git' },
        @{ id = 'Kitware.CMake';                            name = 'CMake' },
        @{ id = 'Ninja-build.Ninja';                        name = 'Ninja' }
    )
    foreach ($p in $packages) {
        Write-Host "Installing $($p.name) ($($p.id))..."
        winget install --id $p.id -e --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Host
    }

    Step "winget: Visual Studio 2022 Build Tools + C++ workload"
    $vsArgs = @(
        '--passive', '--wait', '--norestart',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621',
        '--includeRecommended'
    ) -join ' '
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --silent `
        --accept-source-agreements --accept-package-agreements `
        --override $vsArgs 2>&1 | Out-Host
}

Step "vcpkg: clone + bootstrap"
$VcpkgRoot = Join-Path $env:USERPROFILE 'vcpkg'
if (-not (Test-Path $VcpkgRoot)) {
    git clone https://github.com/microsoft/vcpkg.git $VcpkgRoot
}
& (Join-Path $VcpkgRoot 'bootstrap-vcpkg.bat') -disableMetrics
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', $VcpkgRoot, 'User')
$env:VCPKG_ROOT = $VcpkgRoot

Step "vcpkg: install manifest deps"
$features = @()
if ($WithGui)    { $features += 'gui' }
if ($WithExtras) { $features += 'extras' }
$featureArg = if ($features) { '--x-feature=' + ($features -join ',') } else { '' }

Push-Location $RepoRoot
try {
    & (Join-Path $VcpkgRoot 'vcpkg.exe') install --triplet x64-windows $featureArg
} finally {
    Pop-Location
}

Step "CMake: configure"
$ToolchainFile = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
Push-Location $RepoRoot
try {
    cmake -B build -S . -G Ninja `
        -DCMAKE_TOOLCHAIN_FILE="$ToolchainFile" `
        -DVCPKG_TARGET_TRIPLET=x64-windows
    Write-Host "`nReady. Build with:" -ForegroundColor Green
    Write-Host "  cmake --build build --parallel" -ForegroundColor Green
} finally {
    Pop-Location
}

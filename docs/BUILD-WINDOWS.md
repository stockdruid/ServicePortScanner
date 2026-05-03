# Windows Dev Environment Setup

For a fresh Windows machine. Tested: Windows 11, PowerShell 5.1+.

## Quick start

```powershell
# 1. Open elevated PowerShell (Run as Administrator)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2. From the repo root:
.\scripts\bootstrap-windows.ps1                 # core deps only (fast)
.\scripts\bootstrap-windows.ps1 -WithGui        # + Qt6 (adds 1-2h first build)
.\scripts\bootstrap-windows.ps1 -WithExtras     # + boost-beast/toml/magic-enum/tl-expected
```

## What it installs

| Tool | Source | Note |
|------|--------|------|
| Git | winget `Git.Git` | skip if already present |
| CMake | winget `Kitware.CMake` | 3.25+ |
| Ninja | winget `Ninja-build.Ninja` | fast generator |
| VS 2022 Build Tools | winget `Microsoft.VisualStudio.2022.BuildTools` | C++ workload + Win11 SDK 22621 |
| vcpkg | `git clone` to `%USERPROFILE%\vcpkg` | manifest mode |

Sets `VCPKG_ROOT` user env var so future shells pick it up.

## Manual fallback

If `bootstrap-windows.ps1` fails partway:

```powershell
# Install tooling individually
winget install Git.Git Kitware.CMake Ninja-build.Ninja

# VS BuildTools with C++ workload
winget install Microsoft.VisualStudio.2022.BuildTools --override `
  "--passive --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended"

# vcpkg
git clone https://github.com/microsoft/vcpkg.git $env:USERPROFILE\vcpkg
& $env:USERPROFILE\vcpkg\bootstrap-vcpkg.bat -disableMetrics
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', "$env:USERPROFILE\vcpkg", 'User')
```

## Build

```powershell
# From repo root, in a Developer PowerShell (or after VS BuildTools env activated):
cmake -B build -S . -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake
cmake --build build --parallel
```

## GUI (Qt6) note

Qt is in the `gui` feature of `vcpkg.json` — opt-in. First build takes 1-2 hours and ~10 GB. Use `vcpkg`'s binary cache to share artifacts across machines:

```powershell
$env:VCPKG_BINARY_SOURCES = "clear;files,$env:USERPROFILE\vcpkg-cache,readwrite"
```

For team development without rebuilding Qt, consider the official Qt 6.6+ online installer instead and point CMake at it via `-DCMAKE_PREFIX_PATH`.

## Branch

Default working branch: `feat/async-engine`. See [Service Port Scanner](../) main planning doc in the Obsidian vault for module ownership and stage roadmap.

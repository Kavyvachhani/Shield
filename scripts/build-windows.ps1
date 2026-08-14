<#
.SYNOPSIS
    Builds the SentinelVAPT Windows installers (.exe wizard and .msi).

.DESCRIPTION
    Run this on the Windows machine you want the installer for. Tauri links
    against the platform's native webview, so a Windows installer cannot be
    produced from macOS or Linux — this script is the local equivalent of the
    "windows" job in .github/workflows/release.yml.

    It checks the toolchain first and explains exactly what is missing, rather
    than failing several minutes into a build.

.PARAMETER SkipTests
    Skip the Rust test suite. Faster, but you lose the check that the engine
    behaves before you ship the installer.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DesktopDir = Join-Path $RepoRoot 'apps\desktop'

function Write-Step { param($Text) Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Ok   { param($Text) Write-Host "    OK  $Text" -ForegroundColor Green }
function Write-Bad  { param($Text) Write-Host "    !!  $Text" -ForegroundColor Red }

# ── Prerequisites ────────────────────────────────────────────────────────────

Write-Step 'Checking the build toolchain'

$missing = @()

function Test-Tool {
    param($Command, $Name, $Fix)
    $found = Get-Command $Command -ErrorAction SilentlyContinue
    if ($found) {
        $version = (& $Command --version 2>&1 | Select-Object -First 1)
        Write-Ok "$Name — $version"
        return $true
    }
    Write-Bad "$Name not found. $Fix"
    $script:missing += $Name
    return $false
}

Test-Tool -Command 'cargo' -Name 'Rust (cargo)' `
    -Fix 'Install from https://rustup.rs and choose the MSVC toolchain.' | Out-Null
Test-Tool -Command 'node' -Name 'Node.js' `
    -Fix 'Install Node 20 or newer from https://nodejs.org.' | Out-Null
Test-Tool -Command 'npm' -Name 'npm' `
    -Fix 'Ships with Node.js.' | Out-Null

# Tauri needs the MSVC linker; the GNU toolchain will not produce a bundle.
$rustHost = (rustc -vV 2>$null | Select-String '^host:').ToString()
if ($rustHost -and $rustHost -notmatch 'msvc') {
    Write-Bad "Rust is on the GNU toolchain ($rustHost). Tauri needs MSVC."
    Write-Host '        Fix: rustup default stable-x86_64-pc-windows-msvc' -ForegroundColor Yellow
    $missing += 'MSVC Rust toolchain'
} elseif ($rustHost) {
    Write-Ok "Toolchain — $($rustHost.Trim())"
}

# The C++ build tools supply link.exe, which the MSVC toolchain shells out to.
if (-not (Get-Command 'link.exe' -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        Write-Bad 'Visual Studio C++ build tools not found.'
        Write-Host '        Fix: install "Desktop development with C++" from' -ForegroundColor Yellow
        Write-Host '        https://visualstudio.microsoft.com/visual-cpp-build-tools/' -ForegroundColor Yellow
        $missing += 'MSVC build tools'
    } else {
        Write-Ok 'Visual Studio build tools present (linker resolved at build time)'
    }
} else {
    Write-Ok 'MSVC linker (link.exe)'
}

if ($missing.Count -gt 0) {
    Write-Host "`nMissing: $($missing -join ', '). Install these, reopen the terminal, and re-run." -ForegroundColor Red
    exit 1
}

# ── Build ────────────────────────────────────────────────────────────────────

Write-Step 'Installing frontend dependencies'
Push-Location $DesktopDir
try {
    if (Test-Path (Join-Path $DesktopDir 'package-lock.json')) {
        npm ci
    } else {
        npm install
    }
    if ($LASTEXITCODE -ne 0) { throw 'npm dependency install failed.' }
} finally {
    Pop-Location
}

if (-not $SkipTests) {
    Write-Step 'Running the test suite'
    Push-Location $RepoRoot
    try {
        cargo test --workspace --locked
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed — not building an installer from a broken tree.' }
    } finally {
        Pop-Location
    }
} else {
    Write-Step 'Skipping tests (--SkipTests)'
}

Write-Step 'Building the installers (this takes a while on a cold cache)'
Push-Location $DesktopDir
try {
    npm run tauri -- build --bundles nsis,msi
    if ($LASTEXITCODE -ne 0) { throw 'Tauri build failed.' }
} finally {
    Pop-Location
}

# ── Report ───────────────────────────────────────────────────────────────────

Write-Step 'Installers produced'

$bundleRoot = Join-Path $RepoRoot 'target\release\bundle'
$artifacts = Get-ChildItem -Path $bundleRoot -Recurse -Include *.exe, *.msi -ErrorAction SilentlyContinue

if (-not $artifacts) {
    Write-Bad "Nothing found under $bundleRoot"
    exit 1
}

foreach ($a in $artifacts) {
    $kind = if ($a.Extension -eq '.exe') { 'wizard installer' } else { 'MSI (for Intune/Group Policy)' }
    Write-Host ('    {0,-52} {1,7:N1} MB  {2}' -f $a.Name, ($a.Length / 1MB), $kind) -ForegroundColor Green
    Write-Host "        $($a.FullName)" -ForegroundColor DarkGray
}

Write-Host "`nRun the .exe to launch the setup wizard." -ForegroundColor Cyan

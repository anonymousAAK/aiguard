# aiguard Windows installer
# Downloads and installs the aiguard binary from GitHub Releases.
# Usage: irm https://raw.githubusercontent.com/aiguard-dev/aiguard/main/install.ps1 | iex
#
# Optional environment variables:
#   AIGUARD_VERSION  - pin a specific release tag  (e.g. "v0.1.0")
#   AIGUARD_INSTALL  - override the install directory

#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo      = "aiguard-dev/aiguard"
$Binary    = "aiguard"
$GithubBase = "https://github.com/$Repo/releases"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Status([string]$Message) {
    Write-Host "aiguard-install: $Message"
}

function Write-Warn([string]$Message) {
    Write-Host "aiguard-install: warning: $Message" -ForegroundColor Yellow
}

function Fail([string]$Message) {
    Write-Host "aiguard-install: error: $Message" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------

function Get-Target {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        "ARM64" { return "aarch64-pc-windows-msvc" }
        default { Fail "unsupported architecture: $arch" }
    }
}

# ---------------------------------------------------------------------------
# Resolve latest version
# ---------------------------------------------------------------------------

function Resolve-Version {
    if ($env:AIGUARD_VERSION) {
        return $env:AIGUARD_VERSION
    }

    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl `
            -Headers @{ "Accept" = "application/vnd.github+json" } `
            -UseBasicParsing
        return $response.tag_name
    } catch {
        Fail "could not determine latest release version: $_`nSet `$env:AIGUARD_VERSION to override."
    }
}

# ---------------------------------------------------------------------------
# Determine install directory
# ---------------------------------------------------------------------------

function Resolve-InstallDir {
    if ($env:AIGUARD_INSTALL) {
        return $env:AIGUARD_INSTALL
    }

    # Prefer CARGO_HOME\bin (mirrors the dist install-path = "CARGO_HOME" setting)
    if ($env:CARGO_HOME) {
        return Join-Path $env:CARGO_HOME "bin"
    }

    $cargoDefault = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoDefault) {
        return $cargoDefault
    }

    # Fall back to %LOCALAPPDATA%\aiguard\bin
    return Join-Path $env:LOCALAPPDATA "aiguard\bin"
}

# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------

function Verify-Checksum([string]$FilePath, [string]$Expected) {
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    $expected = $Expected.ToLower().Trim()

    if ($hash -ne $expected) {
        Fail "checksum mismatch for $FilePath`n  expected: $expected`n  actual:   $hash"
    }
    Write-Status "checksum verified"
}

# ---------------------------------------------------------------------------
# Add directory to user PATH (idempotent)
# ---------------------------------------------------------------------------

function Add-ToUserPath([string]$Dir) {
    $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $entries = $currentPath -split ";"

    if ($entries -contains $Dir) {
        return  # already present
    }

    $newPath = ($entries + $Dir) -join ";"
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, "User")

    # Also update PATH for the current session
    $env:PATH = "$env:PATH;$Dir"

    Write-Status "added '$Dir' to your user PATH (restart your terminal for changes to take effect)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Main {
    $target  = Get-Target
    Write-Status "detected target: $target"

    $version = Resolve-Version
    Write-Status "installing aiguard $version"

    $installDir = Resolve-InstallDir
    Write-Status "install directory: $installDir"

    $archiveName  = "$Binary-$version-$target.zip"
    $archiveUrl   = "$GithubBase/download/$version/$archiveName"
    $checksumUrl  = "$GithubBase/download/$version/$archiveName.sha256"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "aiguard-install-$([System.Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        # Download archive
        $archivePath = Join-Path $tmpDir $archiveName
        Write-Status "downloading $archiveUrl"
        try {
            Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing
        } catch {
            Fail "download failed: $_`nCheck that version $version exists at $GithubBase"
        }

        # Download and verify checksum
        $checksumPath = Join-Path $tmpDir "$archiveName.sha256"
        try {
            Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumPath -UseBasicParsing
            $expectedHash = (Get-Content $checksumPath -Raw).Split()[0]
            Verify-Checksum -FilePath $archivePath -Expected $expectedHash
        } catch [System.Net.WebException] {
            Write-Warn "no checksum file found at $checksumUrl; skipping verification"
        } catch {
            # Checksum file downloaded but verification failed — rethrow
            throw
        }

        # Extract archive
        Write-Status "extracting archive"
        $extractDir = Join-Path $tmpDir "extracted"
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        # Locate binary
        $extractedBin = Get-ChildItem -Path $extractDir -Filter "$Binary.exe" -Recurse -File | Select-Object -First 1
        if (-not $extractedBin) {
            # Some releases may ship without .exe in the archive name
            $extractedBin = Get-ChildItem -Path $extractDir -Filter $Binary -Recurse -File | Select-Object -First 1
        }
        if (-not $extractedBin) {
            Fail "binary '$Binary.exe' not found in archive"
        }

        # Create install directory if needed
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        # Copy binary
        $destBin = Join-Path $installDir "$Binary.exe"
        Copy-Item -Path $extractedBin.FullName -Destination $destBin -Force
        Write-Status "installed to $destBin"

        # Ensure install directory is in PATH
        Add-ToUserPath -Dir $installDir

        # Confirm installation
        try {
            $installedVersion = & $destBin --version 2>&1
            Write-Status $installedVersion
        } catch {
            Write-Status "aiguard installed successfully"
        }

    } finally {
        Remove-Item -Recurse -Force -Path $tmpDir -ErrorAction SilentlyContinue
    }
}

Main

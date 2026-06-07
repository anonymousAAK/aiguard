# Install

aiguard is distributed as a single static binary with no runtime dependencies. Pick the channel that fits your workflow.

## Shell script (macOS / Linux)

```sh
curl -fsSL https://aiguard.sh/install | sh
```

The script detects your OS and architecture, downloads the appropriate binary from the GitHub release, verifies its SHA-256 checksum, and installs to `/usr/local/bin/aiguard` (or `~/.local/bin` if you do not have write access to `/usr/local/bin`).

## PowerShell (Windows)

```powershell
irm https://aiguard.sh/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\aiguard\bin` and appends that directory to your `PATH` for the current user. Requires PowerShell 5.1 or later.

> **Windows SmartScreen note:** The v1.0 MSI and binary are not yet code-signed. Windows Defender SmartScreen will show a warning the first time you run the installer or the binary. Click "More info" then "Run anyway" to proceed. Code signing is planned for v1.1. If your organization's policy blocks unsigned executables, use the Cargo or npm channels below, or build from source.

## Homebrew (macOS / Linux)

```sh
brew install aiguard-dev/aiguard/aiguard
```

This taps the `aiguard-dev/aiguard` Homebrew tap and installs the pre-built bottle for your platform.

## Cargo

```sh
cargo install aiguard
```

Requires Rust 1.85 or later. Run `rustup update stable` to ensure you have a recent toolchain. The crate compiles all dependencies (including a bundled SQLite) into a single binary; a first build takes 2–4 minutes depending on your machine.

## npm wrapper

```sh
npm i -g aiguard
```

Installs a thin JavaScript wrapper that downloads the correct platform binary on first run and delegates all commands to it. Useful in Node.js-heavy environments where `npm` is the preferred package manager.

## MSI installer (Windows)

Direct download: `https://github.com/aiguard-dev/aiguard/releases/latest/download/aiguard-x86_64-windows.msi`

Double-click the MSI to install. See the SmartScreen note above regarding unsigned binaries in v1.0.

## macOS quarantine

If macOS Gatekeeper quarantines the binary after a manual download, remove the quarantine attribute before running:

```sh
xattr -d com.apple.quarantine /usr/local/bin/aiguard
```

This is not needed if you installed via Homebrew or the shell script, as those methods handle the attribute automatically.

## Verify the install

After installation, run:

```sh
aiguard --version
aiguard doctor
```

`aiguard doctor` checks that the binary is reachable, that your `aiguard.toml` (if present) is valid, and that hooks are correctly wired for each detected agent.

## Updating

```sh
# Shell script
curl -fsSL https://aiguard.sh/install | sh

# Homebrew
brew upgrade aiguard

# Cargo
cargo install aiguard --force

# npm
npm update -g aiguard
```

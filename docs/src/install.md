# Install

tether is distributed as a single static binary with no runtime dependencies. Pick the channel that fits your workflow.

## Shell script (macOS / Linux)

```sh
curl -fsSL https://tether.sh/install | sh
```

The script detects your OS and architecture, downloads the appropriate binary from the GitHub release, verifies its SHA-256 checksum, and installs to `/usr/local/bin/tether` (or `~/.local/bin` if you do not have write access to `/usr/local/bin`).

## PowerShell (Windows)

```powershell
irm https://tether.sh/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\tether\bin` and appends that directory to your `PATH` for the current user. Requires PowerShell 5.1 or later.

> **Windows SmartScreen note:** The v1.0 MSI and binary are not yet code-signed. Windows Defender SmartScreen will show a warning the first time you run the installer or the binary. Click "More info" then "Run anyway" to proceed. Code signing is planned for v1.1. If your organization's policy blocks unsigned executables, use the Cargo or npm channels below, or build from source.

## Homebrew (macOS / Linux)

```sh
brew install tether-dev/tether/tether
```

This taps the `tether-dev/tether` Homebrew tap and installs the pre-built bottle for your platform.

## Cargo

```sh
cargo install tether-cli
```

Requires Rust 1.85 or later. Run `rustup update stable` to ensure you have a recent toolchain. The crate compiles all dependencies (including a bundled SQLite) into a single binary; a first build takes 2–4 minutes depending on your machine.

## npm wrapper

```sh
npm i -g @tether-security/tether
```

Installs a thin JavaScript wrapper that downloads the correct platform binary on first run and delegates all commands to it. Useful in Node.js-heavy environments where `npm` is the preferred package manager.

## MSI installer (Windows)

Direct download: `https://github.com/tether-dev/tether/releases/latest/download/tether-x86_64-windows.msi`

Double-click the MSI to install. See the SmartScreen note above regarding unsigned binaries in v1.0.

## macOS quarantine

If macOS Gatekeeper quarantines the binary after a manual download, remove the quarantine attribute before running:

```sh
xattr -d com.apple.quarantine /usr/local/bin/tether
```

This is not needed if you installed via Homebrew or the shell script, as those methods handle the attribute automatically.

## Verify the install

After installation, run:

```sh
tether --version
tether doctor
```

`tether doctor` checks that the binary is reachable, that your `tether.toml` (if present) is valid, and that hooks are correctly wired for each detected agent.

## Updating

```sh
# Shell script
curl -fsSL https://tether.sh/install | sh

# Homebrew
brew upgrade tether

# Cargo
cargo install tether-cli --force

# npm
npm update -g @tether-security/tether
```

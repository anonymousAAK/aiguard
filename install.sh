#!/usr/bin/env sh
# aiguard installer
# Downloads and installs the aiguard binary from GitHub Releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/aiguard-dev/aiguard/main/install.sh | sh

set -eu

REPO="aiguard-dev/aiguard"
BINARY="aiguard"
GITHUB_BASE="https://github.com/${REPO}/releases"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

say() {
    printf "aiguard-install: %s\n" "$1"
}

err() {
    say "error: $1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "required command not found: '$1'"
    fi
}

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------

detect_platform() {
    local _os
    local _arch
    local _target

    _os="$(uname -s)"
    _arch="$(uname -m)"

    case "$_os" in
        Linux)
            case "$_arch" in
                x86_64)  _target="x86_64-unknown-linux-musl" ;;
                aarch64) _target="aarch64-unknown-linux-musl" ;;
                arm64)   _target="aarch64-unknown-linux-musl" ;;
                *)       err "unsupported Linux architecture: $_arch" ;;
            esac
            ;;
        Darwin)
            case "$_arch" in
                x86_64)  _target="x86_64-apple-darwin" ;;
                arm64)   _target="aarch64-apple-darwin" ;;
                aarch64) _target="aarch64-apple-darwin" ;;
                *)       err "unsupported macOS architecture: $_arch" ;;
            esac
            ;;
        *)
            err "unsupported operating system: $_os (use install.ps1 on Windows)"
            ;;
    esac

    echo "$_target"
}

# ---------------------------------------------------------------------------
# Resolve latest version (or use AIGUARD_VERSION env var)
# ---------------------------------------------------------------------------

resolve_version() {
    if [ -n "${AIGUARD_VERSION:-}" ]; then
        echo "$AIGUARD_VERSION"
        return
    fi

    need_cmd curl

    local _latest_url="https://api.github.com/repos/${REPO}/releases/latest"
    local _version

    _version="$(curl -fsSL "$_latest_url" \
        -H "Accept: application/vnd.github+json" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

    if [ -z "$_version" ]; then
        err "could not determine latest release version; set AIGUARD_VERSION to override"
    fi

    echo "$_version"
}

# ---------------------------------------------------------------------------
# Determine install directory
# ---------------------------------------------------------------------------

resolve_install_dir() {
    # Prefer CARGO_HOME/bin, fall back to ~/.cargo/bin, then /usr/local/bin
    if [ -n "${CARGO_HOME:-}" ]; then
        echo "${CARGO_HOME}/bin"
    elif [ -d "$HOME/.cargo/bin" ]; then
        echo "$HOME/.cargo/bin"
    else
        echo "/usr/local/bin"
    fi
}

# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------

verify_checksum() {
    local _file="$1"
    local _expected="$2"
    local _actual

    if command -v sha256sum > /dev/null 2>&1; then
        _actual="$(sha256sum "$_file" | awk '{print $1}')"
    elif command -v shasum > /dev/null 2>&1; then
        _actual="$(shasum -a 256 "$_file" | awk '{print $1}')"
    else
        say "warning: no sha256sum or shasum found; skipping checksum verification"
        return 0
    fi

    if [ "$_actual" != "$_expected" ]; then
        err "checksum mismatch for $_file\n  expected: $_expected\n  actual:   $_actual"
    fi

    say "checksum verified"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    need_cmd uname
    need_cmd curl
    need_cmd tar

    local _target
    local _version
    local _install_dir
    local _archive_name
    local _archive_url
    local _checksum_url
    local _tmp_dir

    _target="$(detect_platform)"
    say "detected target: $_target"

    _version="$(resolve_version)"
    say "installing aiguard $_version"

    _install_dir="$(resolve_install_dir)"
    say "install directory: $_install_dir"

    _archive_name="${BINARY}-${_version}-${_target}.tar.gz"
    _archive_url="${GITHUB_BASE}/download/${_version}/${_archive_name}"
    _checksum_url="${GITHUB_BASE}/download/${_version}/${_archive_name}.sha256"

    _tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t aiguard-install)"
    trap 'rm -rf "$_tmp_dir"' EXIT

    say "downloading $_archive_url"
    curl -fsSL --progress-bar "$_archive_url" -o "${_tmp_dir}/${_archive_name}" \
        || err "download failed; check that version $_version exists"

    # Download and verify checksum if available
    if curl -fsSL "$_checksum_url" -o "${_tmp_dir}/${_archive_name}.sha256" 2>/dev/null; then
        _expected="$(awk '{print $1}' "${_tmp_dir}/${_archive_name}.sha256")"
        verify_checksum "${_tmp_dir}/${_archive_name}" "$_expected"
    else
        say "warning: no checksum file found at $_checksum_url; skipping verification"
    fi

    say "extracting archive"
    tar -xzf "${_tmp_dir}/${_archive_name}" -C "$_tmp_dir" \
        || err "failed to extract archive"

    # The binary may be at the root or inside a subdirectory
    local _extracted_bin
    _extracted_bin="$(find "$_tmp_dir" -name "$BINARY" -type f | head -1)"
    if [ -z "$_extracted_bin" ]; then
        err "binary '$BINARY' not found in archive"
    fi

    chmod +x "$_extracted_bin"

    # Create install directory if needed
    if [ ! -d "$_install_dir" ]; then
        mkdir -p "$_install_dir" \
            || err "could not create install directory: $_install_dir (try running with sudo)"
    fi

    # Copy binary, using sudo for /usr/local/bin if needed
    if [ -w "$_install_dir" ]; then
        cp "$_extracted_bin" "${_install_dir}/${BINARY}"
    else
        say "install directory not writable; attempting with sudo"
        sudo cp "$_extracted_bin" "${_install_dir}/${BINARY}" \
            || err "copy failed; re-run with sudo or set CARGO_HOME"
    fi

    say "installed to ${_install_dir}/${BINARY}"

    # PATH hint
    case ":${PATH}:" in
        *":${_install_dir}:"*)
            ;;
        *)
            say "note: add $_install_dir to your PATH if it is not already present"
            say "  e.g. add this to ~/.bashrc or ~/.zshrc:"
            say "    export PATH=\"\$PATH:${_install_dir}\""
            ;;
    esac

    # Confirm installation
    if command -v aiguard > /dev/null 2>&1; then
        say "$(aiguard --version)"
    else
        "${_install_dir}/${BINARY}" --version 2>/dev/null \
            && say "aiguard installed successfully" \
            || say "aiguard installed successfully (restart your shell to update PATH)"
    fi
}

main "$@"

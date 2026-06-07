#!/usr/bin/env node
// postinstall.js — copies the platform-specific aiguard binary into npm/bin/
// so that `npx aiguard` and the `aiguard` bin entry both work after install.

"use strict";

const fs   = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Platform → optional-dependency package name
// ---------------------------------------------------------------------------

const PLATFORM_PACKAGES = {
  "darwin-arm64":  "@aiguard-dev/aiguard-darwin-arm64",
  "darwin-x64":    "@aiguard-dev/aiguard-darwin-x64",
  "linux-x64":     "@aiguard-dev/aiguard-linux-x64",
  "linux-arm64":   "@aiguard-dev/aiguard-linux-arm64",
  "win32-x64":     "@aiguard-dev/aiguard-win32-x64",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(msg) {
  process.stdout.write("aiguard-postinstall: " + msg + "\n");
}

function warn(msg) {
  process.stderr.write("aiguard-postinstall: warning: " + msg + "\n");
}

function fail(msg) {
  process.stderr.write("aiguard-postinstall: error: " + msg + "\n");
  process.exit(1);
}

/** Return the key into PLATFORM_PACKAGES for the current runtime. */
function detectPlatformKey() {
  const plat = process.platform;   // e.g. "darwin", "linux", "win32"
  const arch = process.arch;       // e.g. "x64", "arm64"
  return `${plat}-${arch}`;
}

/**
 * Resolve the path to a package that was installed as an optionalDependency.
 * We search node_modules relative to __dirname (this file lives inside the
 * wrapper package).
 */
function resolvePackagePath(pkgName) {
  // Walk up from __dirname looking for a node_modules directory that contains
  // the package.  This handles both flat and hoisted layouts (npm, pnpm, yarn).
  let dir = __dirname;
  for (let i = 0; i < 10; i++) {
    const candidate = path.join(dir, "node_modules", pkgName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** Return the binary path declared in the platform package's package.json. */
function findBinaryInPackage(pkgPath) {
  const pkgJsonPath = path.join(pkgPath, "package.json");
  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
  } catch (e) {
    fail(`could not read ${pkgJsonPath}: ${e.message}`);
  }

  // The platform packages expose a single `bin` entry.
  const binField = pkgJson.bin;
  if (!binField) {
    fail(`no 'bin' field in ${pkgJsonPath}`);
  }

  // bin can be a string (single binary) or an object { name: path }
  let relBinPath;
  if (typeof binField === "string") {
    relBinPath = binField;
  } else {
    // Take the first (and typically only) entry
    relBinPath = Object.values(binField)[0];
  }

  return path.resolve(pkgPath, relBinPath);
}

/** Optionally verify a SHA-256 checksum file alongside the binary. */
function verifyChecksum(binPath) {
  const sumPath = binPath + ".sha256";
  if (!fs.existsSync(sumPath)) {
    warn("no .sha256 file found alongside binary; skipping checksum verification");
    return;
  }

  const expected = fs.readFileSync(sumPath, "utf8").split(/\s+/)[0].toLowerCase();
  const actual   = crypto.createHash("sha256").update(fs.readFileSync(binPath)).digest("hex");

  if (actual !== expected) {
    fail(
      `checksum mismatch for ${binPath}\n` +
      `  expected: ${expected}\n` +
      `  actual:   ${actual}`
    );
  }
  log("checksum verified");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const platformKey = detectPlatformKey();
  log(`detected platform: ${platformKey}`);

  const pkgName = PLATFORM_PACKAGES[platformKey];
  if (!pkgName) {
    // Not a fatal error — the user may be building from source or on an
    // unsupported platform.
    warn(
      `no prebuilt binary available for platform '${platformKey}'. ` +
      "Install aiguard from source with: cargo install --locked aiguard"
    );
    process.exit(0);
  }

  const pkgPath = resolvePackagePath(pkgName);
  if (!pkgPath) {
    // The optional dependency was not installed (e.g. wrong platform + --no-optional).
    warn(
      `optional dependency '${pkgName}' is not installed. ` +
      "This can happen if npm was run with --no-optional. " +
      "Try: npm install (without --no-optional)"
    );
    process.exit(0);
  }

  log(`found platform package at: ${pkgPath}`);

  const srcBin = findBinaryInPackage(pkgPath);
  if (!fs.existsSync(srcBin)) {
    fail(`binary not found at expected path: ${srcBin}`);
  }

  // Verify checksum before copying
  verifyChecksum(srcBin);

  // Destination: npm/bin/aiguard  (or aiguard.exe on Windows)
  const binDir  = path.join(__dirname, "bin");
  const binName = process.platform === "win32" ? "aiguard.exe" : "aiguard";
  const destBin = path.join(binDir, binName);

  // Also write the shim script that the `bin` field in package.json points to.
  // On Unix the shim is a small shell wrapper; on Windows it already points to .exe.
  const shimPath = path.join(binDir, "aiguard"); // always no extension (npm uses this)

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // Copy the real binary
  fs.copyFileSync(srcBin, destBin);
  log(`copied binary to ${destBin}`);

  // Make the binary executable on Unix
  if (process.platform !== "win32") {
    fs.chmodSync(destBin, 0o755);

    // Write a thin shell shim so the `bin` entry (which has no extension)
    // resolves correctly regardless of whether npm creates a symlink.
    if (destBin !== shimPath) {
      const shim =
        "#!/usr/bin/env sh\n" +
        `exec "$(dirname "$0")/aiguard.real" "$@"\n`;
      // Simpler: just make the no-extension file a symlink or copy
      try {
        if (fs.existsSync(shimPath)) fs.unlinkSync(shimPath);
        fs.symlinkSync(destBin, shimPath);
      } catch (_) {
        // If symlink fails (e.g. on certain filesystems) copy instead
        fs.copyFileSync(destBin, shimPath);
        fs.chmodSync(shimPath, 0o755);
      }
    }
  }

  // Quick sanity check: file exists and is non-empty
  const stat = fs.statSync(destBin);
  if (stat.size === 0) {
    fail("installed binary is empty — the download may be corrupt");
  }

  log("aiguard installed successfully");
}

main();

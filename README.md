<div align="center">

<img src="https://raw.githubusercontent.com/anonymousAAK/aiguard/master/docs/src/logo.svg" alt="aiguard" width="120" />

# aiguard

**A portable security harness for CLI coding agents.**

[![Crates.io](https://img.shields.io/crates/v/aiguard.svg)](https://crates.io/crates/aiguard)
[![CI](https://github.com/anonymousAAK/aiguard/actions/workflows/ci.yml/badge.svg)](https://github.com/anonymousAAK/aiguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

Intercept every tool call your AI agent makes. Block prompt injection. Redact secrets. Pin MCP servers. Review sessions in a TUI. **One config, eight agents, zero trust.**

[**Install**](#install) · [**Quick start**](#quick-start) · [**Docs**](https://github.com/anonymousAAK/aiguard/tree/master/docs) · [**Changelog**](CHANGELOG.md)

</div>

---

## Why aiguard?

AI coding agents are powerful — and they execute real commands on your machine. They read files, run shell commands, reach out to MCP servers, and sometimes receive instructions embedded *inside* the tools they call. aiguard sits between the agent and your system and applies defense-in-depth on every interaction:

```
 your terminal
      │
      ▼
 ┌─────────────────────────────────────┐
 │              aiguard                │
 │                                     │
 │  ① prompt-injection scan            │
 │  ② MCP tool-description audit       │
 │  ③ shell / path deny rules          │
 │  ④ secret redaction                 │
 │  ⑤ dual-write audit log (SQLite+JSONL)│
 └──────────────┬──────────────────────┘
                │  allow / block / mutate / ask
                ▼
          coding agent
      (Claude Code, Codex, …)
```

---

## Features

| | |
|---|---|
| 🛡 **Prompt injection detection** | 80+ regex rules with Aho-Corasick pre-filter. Zero-width Unicode steganography and base64-payload checks included. |
| 🔐 **Secret redaction** | 52 gitleaks-compatible patterns with Shannon entropy gating — AWS keys, GitHub PATs, private keys, and more. |
| 📌 **MCP tool pinning** | SHA-256 pin on every `tools/list` response. Rug-pull detection alerts when a server's tool manifest changes between calls. |
| 🚫 **Shell & path deny rules** | Glob-pattern allow/deny lists for shell commands and file paths. Block `rm -rf /` or restrict writes to `/etc` in five config lines. |
| 📋 **Tamper-evident audit log** | Every evaluation → SQLite row + JSONL line with SHA-256 input hash. Dual-write means one failure cannot silence the log. |
| 🎬 **Session replay TUI** | `aiguard replay` opens a three-pane ratatui interface: timeline, event detail, and raw payload viewer. |
| ⚡ **Sub-millisecond hot path** | Aho-Corasick pre-filter + async scanner fan-out. Policy evaluation completes in < 1 ms for most tool calls. |
| 🔌 **Eight agents, one config** | Shell hooks for Claude Code, Codex, Gemini CLI, Crush, Cline. MCP proxy for Aider and Goose. TypeScript shim for opencode. |

---

## Install

**Cargo (all platforms):**
```sh
cargo install aiguard
```

**Shell script (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/anonymousAAK/aiguard/master/install.sh | sh
```

**PowerShell (Windows):**
```powershell
irm https://raw.githubusercontent.com/anonymousAAK/aiguard/master/install.ps1 | iex
```

**From source (Rust 1.85+):**
```sh
git clone https://github.com/anonymousAAK/aiguard
cd aiguard
cargo build --release
# binary at ./target/release/aiguard
```

---

## Quick start

```sh
# 1. Auto-detect installed agents and write their hook configs
aiguard init

# 2. Verify everything is wired up
aiguard doctor

# 3. Start your agent as normal — aiguard runs in the background
claude code .

# 4. Review the session afterwards
aiguard replay --last
```

That's it. No daemons. No sidecars. No modified agent binaries.

---

## Configuration

aiguard looks for `aiguard.toml` by walking up from the current directory, then falls back to `~/.config/aiguard/aiguard.toml`. All fields are optional — the defaults are conservative and safe.

```toml
schema = "1.0"

[policy]
default_action = "warn"   # allow | warn | block
strict         = false    # block on scanner error instead of warn
fail_open      = false

[scanners.prompt_injection]
enabled   = true
threshold = 0.7           # 0.0–1.0; above this → block

[scanners.secrets]
enabled = true
action  = "block"         # redact | block

[scanners.mcp]
enabled   = true
pin_tools = true          # SHA-256 pin MCP tool manifests

[tools]
deny_shell_patterns = [
  "rm -rf /",
  "curl * | sh",
  "wget * | bash",
]
deny_path_patterns = [
  "/etc/passwd",
  "/etc/shadow",
  "~/.ssh/*",
]
```

See [`aiguard.toml.example`](aiguard.toml.example) for every available field with inline documentation.

---

## Supported agents

| Agent | Integration | Coverage |
|---|---|---|
| **Claude Code** | Shell hook (`PreToolUse` / `PostToolUse`) | Full — pre + post + session events |
| **Codex CLI** | Shell hook | Full |
| **Gemini CLI** | Shell hook | Full |
| **Crush** | Shell hook | Pre-tool |
| **Cline** | Shell hook | macOS / Linux |
| **opencode** | TypeScript plugin shim | Via `aiguard-adapter-opencode` |
| **Aider** | MCP stdio proxy | Filesystem watcher + proxy |
| **Goose** | MCP proxy + config registration | Auto-registers on `aiguard init` |

---

## Architecture

aiguard is an 11-crate Rust workspace. Each crate is independently versioned and published to crates.io.

```
aiguard (workspace)
├── aiguard-core                    # Policy engine, Scanner trait, audit log, config
├── aiguard-cli                     # aiguard binary (clap subcommands)
├── aiguard-scanner-prompt-injection # Regex + Aho-Corasick prompt-injection detection
├── aiguard-scanner-mcp             # MCP tool-pinning, rug-pull, cross-origin scan
├── aiguard-scanner-secrets         # 52 gitleaks-compatible rules + entropy gating
├── aiguard-adapter-shellhook       # Shell hook normalizer for 5 agents
├── aiguard-adapter-opencode        # opencode TypeScript plugin shim
├── aiguard-adapter-aider           # Aider filesystem watcher + PTY wrapper
├── aiguard-adapter-goose           # Goose config registration
├── aiguard-replay                  # Ratatui session replay TUI
└── aiguard-mcp-proxy               # MCP stdio JSON-RPC proxy server
```

The `Scanner` trait is async and object-safe. Adding a new scanner is ~50 lines:

```rust
#[async_trait]
impl Scanner for MyScanner {
    fn name(&self) -> &str { "my-scanner" }
    async fn scan(&self, ctx: &ScanContext<'_>) -> Result<ScanVerdict> {
        // inspect ctx.tool_input, ctx.tool_response, ctx.raw_text …
        Ok(ScanVerdict::Pass)
    }
}
```

---

## Security

aiguard is a **defense-in-depth layer**. It reduces risk but cannot eliminate all attacks — see Debenedetti et al., NeurIPS 2024 ([arXiv:2406.13352](https://arxiv.org/abs/2406.13352)) for residual attack rates with secondary detectors.

To report a vulnerability: **do not open a public issue.** See [`SECURITY.md`](SECURITY.md).

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). TL;DR:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -Dwarnings
cargo fmt --all -- --check
```

---

## License

Apache-2.0 OR MIT — your choice. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).

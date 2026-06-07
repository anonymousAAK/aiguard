# tether

> A portable security harness for CLI coding agents. One config, eight agents.

## Install

```sh
cargo install tether-cli
```

Or via the install script:

```sh
curl -fsSL https://tether.sh/install | sh
```

## Quick start

```sh
tether init          # detect agents, write hook configs
tether doctor        # verify installation
tether replay --last # review most recent session
```

## What it does

- **Prompt-injection scanning** -- regex + aho-corasick tier on every tool output
- **MCP server auditing** -- tool-description poisoning detection, SHA-256 tool pinning, rug-pull defense
- **Shell and filesystem deny rules** -- block `rm -rf /`, restrict path access, configured once
- **Secret redaction** -- gitleaks-compatible rules with Shannon entropy gating
- **Audit log + replay** -- SQLite + JSONL dual-write, ratatui TUI for session review

## Supported agents

| Agent | Hook type | Status |
|---|---|---|
| Claude Code | shell hook | full support |
| Codex CLI | shell hook | full support |
| Gemini CLI | shell hook | full support |
| Crush | shell hook | pre-tool only |
| Cline | shell hook | macOS/Linux |
| opencode | TS plugin | via shim |
| Aider | MCP proxy | fallback |
| Goose | MCP proxy | fallback |

## Configuration

tether uses a single `tether.toml` at the project root (or `~/.config/tether/tether.toml` globally).
Run `tether init` to generate one, or start from the included `tether.toml.example`.

Minimal example:

```toml
schema = "1.0"

[policy]
default_action = "warn"
strict = false

[scanners.prompt_injection]
enabled = true
threshold = 0.7

[scanners.secrets]
enabled = true
action = "block"

[tools]
deny_shell_patterns = ["rm -rf /", "curl * | sh"]
```

All fields have sensible defaults. See `tether.toml.example` for the full reference.

## Architecture

11-crate Rust workspace:

| Crate | Purpose |
|---|---|
| `tether-core` | Policy engine, verdict types, shared traits |
| `tether-cli` | `tether` binary -- init, doctor, replay subcommands |
| `tether-adapter-shellhook` | Shell hook adapter for Claude Code, Codex, Gemini, Crush, Cline |
| `tether-adapter-opencode` | TypeScript plugin shim for opencode |
| `tether-adapter-aider` | MCP proxy adapter for Aider |
| `tether-adapter-goose` | MCP proxy adapter for Goose |
| `tether-scanner-prompt-injection` | Prompt-injection detection engine |
| `tether-scanner-mcp` | MCP tool-description poisoning and rug-pull scanner |
| `tether-scanner-secrets` | Secret detection with gitleaks-compatible rules |
| `tether-replay` | Audit log reader and ratatui TUI |
| `tether-mcp-proxy` | Standalone MCP proxy server for fallback agents |

## Building from source

```sh
git clone https://github.com/adarsh/tether.git
cd tether
cargo build --release
```

Requires Rust 1.85+.

## Running tests

```sh
cargo test --workspace
```

## License

Apache-2.0 OR MIT

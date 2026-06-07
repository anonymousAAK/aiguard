# Architecture

aiguard is an 11-crate Rust workspace. This page describes the module topology, the hot-path data flow for a single tool call, and the crate responsibilities.

## Module topology

```
                          +------------------------+
                          |     aiguard.toml       |
                          +-----------+------------+
                                      |
          +---------------------------v------------------------------+
          |                  aiguard-core                           |
          |  +----------+ +----------+ +--------+ +----------+      |
          |  | Policy   | | Scanner  | | Audit  | | Redactor |      |
          |  | Engine   | | Registry | | Log    | |          |      |
          |  +----------+ +----------+ +--------+ +----------+      |
          +--+-------------+---------------+------------------+-----+
             |             |               |                  |
+------------+--+ +---------+--+ +---------+------+ +---------+---+
| Scanners      | | Adapters   | | Replay (TUI)   | | CLI          |
| - prompt-inj  | | shell-hook | | ratatui        | | clap-v4      |
| - mcp         | | ts-plugin  | |                | |              |
| - secrets     | | fallback   | |                | |              |
+---------------+ +------------+ +----------------+ +-------------+
```

## Crate responsibilities

| Crate | Purpose |
|---|---|
| `aiguard-core` | Policy engine, `Scanner` trait, `Decision` algebra, `AuditLog`, `Redactor`, config types |
| `aiguard` (cli) | `aiguard` binary — `init`, `doctor`, `replay`, `hook`, `mcp`, `log`, `models` subcommands (clap v4) |
| `aiguard-adapter-shellhook` | Shell-hook adapter for Claude Code, Codex CLI, Gemini CLI, Crush, and Cline |
| `aiguard-adapter-opencode` | TypeScript plugin shim writer; handles `aiguard hook opencode <stage>` dispatch |
| `aiguard-adapter-aider` | Filesystem watcher (via `notify` crate) and `aiguard wrap aider` PTY wrapper |
| `aiguard-adapter-goose` | Goose config registration and permission shim |
| `aiguard-scanner-prompt-injection` | Tier-1 regex (Aho-Corasick), Tier-2 ONNX (`ort`), Tier-3 LLM judge |
| `aiguard-scanner-mcp` | Tool-description poisoning scan, SHA-256 tool pinning, rug-pull detection, XORIGIN rules |
| `aiguard-scanner-secrets` | Gitleaks-compatible TOML ruleset with Shannon entropy gating |
| `aiguard-replay` | Audit log reader and ratatui TUI for session review |
| `aiguard-mcp-proxy` | Standalone MCP stdio JSON-RPC proxy (wraps other servers for Aider and Goose) |

## Data flow: single tool call (hot path)

```
Agent decides to call a tool
  |
  v
PreToolUse hook fires
  |
  v  stdin JSON {session_id, tool_name, tool_input, hook_event_name, ...}
aiguard hook <agent> pre  (< 5 ms cold start; policy snapshot mmap'd from disk)
  |
  v
Policy engine evaluates:
  1. tool_name + tool_input against [tools.deny] shell patterns (Aho-Corasick)
  2. file paths against deny_path_patterns (glob matching)
  3. tool overrides in [tools.tool_overrides]
  |
  v
Decision:
  - allow  --> JSON {permissionDecision: "allow"} on stdout, exit 0
  - block  --> exit 2, stderr message; event written to audit log
  - mutate --> JSON {updatedInput: {...}} on stdout, exit 0
  |
  v
PostToolUse hook fires with tool_response
  |
  v
Response pipeline:
  1. Secret redactor  (gitleaks-compatible regex + entropy gating)
  2. Prompt-injection scanner  (Tier-1 regex, optional Tier-2 ONNX)
  3. MCP scanner  (if tool_name starts with "mcp__")
  |
  v
If injection or secret found:
  - "warn"   --> annotate, log, pass through
  - "block"  --> emit system message back to agent, discard response
  - "redact" --> emit updatedToolOutput with secrets replaced
  |
  v
Append AuditEvent to SQLite + append-only JSONL
```

## Config loading precedence

```
1. ./aiguard.toml  (project root; walks up from cwd)
2. $AIGUARD_CONFIG  (environment variable override)
3. ~/.config/aiguard/aiguard.toml  (user global)
4. compiled-in defaults
```

Fields in higher-precedence files override lower-precedence ones on a per-field basis. Agent-level overrides in `[agents.<name>.overrides]` are merged on top of the resolved base policy.

## Key design decisions

**Single static binary.** aiguard compiles all dependencies — including SQLite via `rusqlite`'s `bundled` feature — into one binary under 15 MB. No system libraries are required. This makes installation trivial and prevents dependency confusion attacks.

**Synchronous hot path.** The `aiguard hook` entry path is intentionally synchronous. The shell hook must exit in under 10 seconds (Claude Code's hook timeout); aiguard targets under 5 ms for Tier-1 only and under 100 ms with Tier-2 ONNX enabled. Async is used only for the optional Tier-3 LLM judge and audit log writes (which are fire-and-forget via a background thread).

**Append-only audit log.** The JSONL audit log is never edited. The SQLite database is the indexed copy used for replay queries; the JSONL is the authoritative record. If the SQLite database is corrupted, it can be rebuilt from the JSONL with `aiguard log rebuild`.

**Adapter strategy.** Claude Code, Codex, Gemini, Crush, and Cline all speak a compatible shell-hook wire format (JSON on stdin, exit code + JSON on stdout). One shared `aiguard-adapter-shellhook` crate handles all five, with thin per-agent normalization for field name differences and output shape variations. opencode requires a TypeScript plugin shim that calls the Rust binary via `spawnSync`. Aider and Goose, which have no lifecycle hooks, are handled via an MCP proxy that sits in front of all their MCP servers.

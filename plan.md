# tether v0.0.0 → v1.0.0 — Engineering Spec & 3–4 Week Execution Plan

## 1. Executive Summary

**tether** is a single static Rust binary that sits between you and every CLI coding agent on your machine (Claude Code, OpenAI Codex CLI, Gemini CLI, opencode, Cline, Crush, Aider, Goose) and enforces five guarantees regardless of which agent is being driven:

1. **Prompt-injection scanning** on every tool output before it re-enters the model context
2. **MCP server auditing** before any server is loaded (tool-poisoning, rug-pull, shadowing checks)
3. **Deterministic shell-command and filesystem deny rules** (configured once, applied everywhere)
4. **Secret redaction** in tool outputs, logs, and audit trails
5. **Local audit logging + session replay** so every agentic action is reviewable

A single `tether.toml` drives policy across all eight agents. The strategy is **adapter-per-agent on a shared core**: Claude Code, Codex, Gemini, and Crush share the JSON-on-stdin shell-hook convention, so one shared adapter handles four agents with thin per-agent shims; opencode and Cline can be reached via TS plugin shims that IPC into the Rust process; Aider and Goose currently have no lifecycle hooks, so tether ships **MCP-proxy and filesystem-watcher fallbacks** for them.

The opportunity is real and time-bound. The hook ecosystem across major agents converged on the Claude-Code wire format between mid-2025 and Q1 2026 (Codex marked hooks stable in v0.124.0; Gemini shipped hooks in v0.26.0 with an explicit `CLAUDE_PROJECT_DIR` alias; Crush accepts Claude-Code hook output verbatim; Cline merged Claude-spec hooks in PR #6440). At the same time, MCP attack research (Invariant Labs tool poisoning, full-schema poisoning, rug pulls) and the Kai MCP registry scan (where, per Kai's correction post, **38% of registered MCP servers lack authentication at Tier-1 and 46% lack it if Tier-2 schema-exposed servers are included**, across 525 servers in February 2026) have created a clear, named threat surface that nothing portable currently defends.

**A unified, security-first harness is the gap, and a 3–4 week sprint to v1.0.0 by a focused solo author at 40+ hrs/week is realistic.** This document is the daily reference: full architecture, module API surfaces, complete `tether.toml`, full `Cargo.toml`, day-by-day execution plan (Week 0 → Week 4), risk register, and launch sequence.

## 2. Product Spec Recap

| Field | Value |
|---|---|
| Name | tether |
| License | Apache-2.0 OR MIT (dual, like Rust convention) |
| Language | Rust (MSRV 1.83) |
| Binary | single static binary, < 15 MB, < 100 ms cold start |
| Config | `tether.toml` (project) / `~/.config/tether/tether.toml` (user) |
| Agents supported at v1.0 | Claude Code, Codex CLI, Gemini CLI, Crush, opencode, Cline, Aider (fallback), Goose (fallback) |
| Primary value props | (1) prompt-injection scanning on tool outputs (2) MCP audit before load (3) shell/path deny rules (4) secret redaction (5) audit log + replay |
| Distribution | cargo, Homebrew tap, install.sh, install.ps1, npm wrapper, MSI |
| Anti-features (v1.0) | no remote control plane, no SaaS, no telemetry, no key escrow |

## 3. Architecture

### 3.1 Module Topology

```
                              ┌────────────────────────┐
                              │     tether.toml        │
                              └───────────┬────────────┘
                                          │
              ┌───────────────────────────▼─────────────────────────┐
              │                  tether-core                         │
              │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐  │
              │  │ Policy   │ │ Scanner  │ │ Audit  │ │ Redactor │  │
              │  │ Engine   │ │ Registry │ │ Log    │ │          │  │
              │  └──────────┘ └──────────┘ └────────┘ └──────────┘  │
              └─┬──────────────┬─────────────┬──────────────┬──────┘
                │              │             │              │
   ┌────────────┴──┐ ┌─────────┴──┐ ┌────────┴──────┐ ┌─────┴─────┐
   │ Scanners      │ │ Adapters   │ │ Replay (TUI)  │ │ CLI       │
   │ - prompt-inj  │ │ shell-hook │ │ ratatui       │ │ clap-v4   │
   │ - mcp         │ │ ts-plugin  │ │               │ │           │
   │ - secrets     │ │ fallback   │ │               │ │           │
   └───────────────┘ └────────────┘ └───────────────┘ └───────────┘
```

### 3.2 Adapter classification

| Agent | Hook type | Wire format | Adapter strategy |
|---|---|---|---|
| Claude Code | shell hook | `~/.claude/settings.json` hooks; JSON on stdin; exit-code + JSON-on-stdout | **shared-shell-hook** |
| Codex CLI | shell hook | `.codex/hooks.json` or inline `[hooks]` in `config.toml`; same Claude-style schema | **shared-shell-hook** |
| Gemini CLI | shell hook | `.gemini/settings.json` `hooks`; BeforeTool/AfterTool; Claude-compat env vars | **shared-shell-hook** |
| Crush | shell hook | `crush.json` `hooks.PreToolUse` only; accepts Claude `hookSpecificOutput` verbatim | **shared-shell-hook** |
| opencode | TS plugin | `@opencode-ai/plugin` TS module; `tool.execute.before/after` etc. | **TS shim → IPC to tether daemon** |
| Cline | both | v3.36+ shell hooks (`~/Documents/Cline/Rules/Hooks/`) AND Claude-spec hooks via PR #6440 | **shared-shell-hook (primary), TS extension fallback** |
| Aider | none | no native lifecycle hooks (issue #2196 confirmed) | **MCP-proxy + filesystem watcher** |
| Goose | none | no lifecycle hooks; tool permissions only; six extension types | **MCP-proxy + permission shim** |

This means **one well-built shell-hook adapter covers 5 of 8 agents** (and Cline on macOS/Linux). The remaining three need bespoke approaches, but two of them (Aider, Goose) share an MCP-proxy fallback.

### 3.3 Data flow per tool call (the hot path)

```
Agent decides to call tool
  │
  ▼
Hook fires (PreToolUse / tool.execute.before)
  │
  ▼  stdin JSON {session_id, tool_name, tool_input, ...}
[tether hook entry binary, < 5 ms cold] ──► loads policy snapshot from
  │                                          ~/.config/tether/policy.bin
  │                                          (CBOR, mmap'd, < 1 ms parse)
  ▼
Policy engine evaluates:
  1. tool_name + tool_input against [tools.deny] regex set (aho-corasick)
  2. paths against [tools.allow] / deny path globs
  3. command against shell deny rules
  ▼
Decision:
  - allow → JSON {permissionDecision: "allow"} on stdout, exit 0
  - block → exit 2, stderr explains; written to audit log
  - mutate → JSON {updatedInput: {...}} on stdout, exit 0
  ▼
PostToolUse / tool.execute.after fires with tool_response
  ▼
Pipeline on tool_response:
  1. Secret redactor (regex set, gitleaks-rule compatible)
  2. Prompt-injection scanner (regex tier → optional model tier)
  3. MCP-specific scanner if tool_name starts with "mcp__"
  ▼
If injection found:
  - "warn" mode → annotate, log, allow
  - "block" mode → write {decision: "block", reason: "..."} via Claude
    PostToolUse output (sent back to agent as system message)
  - "redact" mode → emit hookSpecificOutput.updatedToolOutput with
    sanitized content (Claude Code v2.1.121+ supports this for all tools)
  ▼
Append AuditEvent to SQLite + append-only JSONL
```

## 4. Detailed Component Specs

### 4.1 tether-core (the policy engine)

**Responsibility:** owns the canonical `Policy` struct, the `Scanner` trait, the `AuditLog`, the `Redactor`, and the `Decision` algebra.

**Key types:**

```rust
// crates/tether-core/src/policy.rs
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Policy {
    pub default_action: DefaultAction,        // warn | block | allow
    pub strict: bool,
    pub agents: AgentsConfig,
    pub scanners: ScannersConfig,
    pub tools: ToolsConfig,
    pub logging: LoggingConfig,
    pub redact: RedactConfig,
    pub replay: ReplayConfig,
}

// crates/tether-core/src/scanner.rs
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, ctx: &ScanContext<'_>) -> Result<ScanVerdict>;
}

pub struct ScanContext<'a> {
    pub session_id: &'a str,
    pub agent: AgentKind,
    pub stage: Stage,                // PreTool | PostTool | UserPrompt | SessionStart
    pub tool_name: Option<&'a str>,
    pub tool_input: Option<&'a serde_json::Value>,
    pub tool_response: Option<&'a serde_json::Value>,
    pub raw_text: Option<&'a str>,
}

pub enum ScanVerdict {
    Pass,
    Warn { message: String, score: f32, hits: Vec<Hit> },
    Block { message: String, score: f32, hits: Vec<Hit> },
    Mutate { replacement: serde_json::Value, message: String },
}

// crates/tether-core/src/decision.rs
pub enum Decision {
    Allow,
    AllowWithContext(String),
    Mutate(serde_json::Value),
    Block(String),
    Ask,
}
```

**Decision aggregation:** when multiple scanners run, the worst verdict wins (`Block > Mutate > Warn > Pass`), with `Allow > none` for explicit allowlists. This matches Crush's documented aggregation: "Deny wins over allow — if any hook denies, the tool call is blocked."

### 4.2 tether-adapter-shellhook (covers Claude Code, Codex, Gemini, Crush, and Cline)

**Responsibility:** parse stdin JSON, normalize to the canonical `ScanContext`, run the policy engine, emit the correct output format per agent.

**Per-agent quirks the adapter must handle:**

| Quirk | Claude Code | Codex | Gemini | Crush | Cline |
|---|---|---|---|---|---|
| Event name field | `hook_event_name` | `hook_event_name` | event-specific | `event` | `hookName` (camelCase) |
| `additionalContext` on PreToolUse | supported | **rejected** (issue #19385) | supported | not supported | supported |
| `updatedToolOutput` on PostToolUse | all tools (v2.1.121+) | MCP tools only | yes | n/a | yes |
| Env var | `CLAUDE_PROJECT_DIR` | `CODEX_PROJECT_DIR` | `GEMINI_PROJECT_DIR` (+ `CLAUDE_PROJECT_DIR` alias) | `CRUSH_PROJECT_DIR` | `CLAUDE_PROJECT_DIR` |
| Block exit code | `2` | `2` | `2` | `2` | `cancel: true` JSON |
| Output JSON shape | `hookSpecificOutput.permissionDecision` | same | `decision: "deny" \| "approve"` + `hookSpecificOutput` | accepts both Claude `hookSpecificOutput` and own `{decision, context}` | `{cancel, errorMessage, contextModification}` |
| Tool names | `Bash, Write, Edit, Read, Grep, Glob, WebFetch, Task, apply_patch` | `Bash, apply_patch, Edit, Write, MCP tools` | `read_file, write_file, replace, run_shell_command, mcp_<server>_<tool>` | `bash, edit, write, multiedit, view, grep, glob` | maps to Claude names via ToolNameMapper in PR #6440 |

**Adapter binary mode:** `tether hook <agent>` is the entry point. It is the same binary as `tether` — argv[0] dispatches. Each agent is invoked via a one-line config:

```jsonc
// ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "tether hook claude-code pre"  }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "tether hook claude-code post" }] }],
    "SessionStart":[{ "hooks": [{ "type": "command", "command": "tether hook claude-code session-start" }] }],
    "UserPromptSubmit":[{ "hooks": [{ "type": "command", "command": "tether hook claude-code prompt" }] }]
  }
}
```

```toml
# ~/.codex/config.toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = ".*"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "tether hook codex pre"
timeout = 10
```

```json
// ~/.gemini/settings.json
{
  "hooks": {
    "BeforeTool": [{ "matcher": ".*", "hooks": [{ "name": "tether", "type": "command", "command": "tether hook gemini pre", "timeout": 10000 }] }],
    "AfterTool":  [{ "matcher": ".*", "hooks": [{ "name": "tether", "type": "command", "command": "tether hook gemini post" }] }]
  }
}
```

```json
// crush.json
{ "hooks": { "PreToolUse": [{ "matcher": ".*", "command": "tether hook crush pre", "timeout": 10 }] } }
```

**`tether init` writes all four** with backup of existing files.

### 4.3 tether-adapter-opencode (TS plugin shim)

opencode plugins are JavaScript/TypeScript modules loaded from `.opencode/plugin/` or `~/.config/opencode/plugin/`. A Rust binary cannot be a plugin directly. Strategy:

1. `tether init` writes `~/.config/opencode/plugin/tether.ts`:
   ```typescript
   import type { Plugin } from "@opencode-ai/plugin"
   import { spawnSync } from "node:child_process"

   const TETHER = process.env.TETHER_BIN ?? "tether"
   const call = (stage: string, payload: unknown) => {
     const r = spawnSync(TETHER, ["hook", "opencode", stage], {
       input: JSON.stringify(payload), encoding: "utf8", timeout: 5000,
     })
     return { code: r.status ?? 0, stdout: r.stdout, stderr: r.stderr }
   }

   export const Tether: Plugin = async (ctx) => ({
     "tool.execute.before": async (input, output) => {
       const r = call("pre", { tool: input.tool, args: output.args, project: ctx.project })
       if (r.code === 2) throw new Error(r.stderr || "blocked by tether")
       if (r.stdout) {
         const o = JSON.parse(r.stdout)
         if (o.updatedInput) Object.assign(output.args, o.updatedInput)
       }
     },
     "tool.execute.after": async (input, output) => {
       const r = call("post", { tool: input.tool, args: output.args ?? null,
         output: output.output, metadata: output.metadata, project: ctx.project })
       if (r.stdout) {
         const o = JSON.parse(r.stdout)
         if (o.updatedOutput) output.output = o.updatedOutput
       }
     },
     "permission.ask": async (perm, out) => {
       const r = call("permission", { perm })
       if (r.code === 0 && r.stdout) {
         const o = JSON.parse(r.stdout)
         if (o.status) out.status = o.status
       }
     },
   })
   ```
2. The Rust binary handles `tether hook opencode <stage>` exactly like a shell hook — same wire format, normalized internally.

**Known limitations (document explicitly in README):** opencode issue #2319 confirms `tool.execute.before/after` does NOT fire for MCP tool calls, and issue #5894 confirms it doesn't fire for subagent tool calls. tether mitigates by also subscribing to the `event` handler and recording subagent activity from there, but block-level enforcement on MCP tools in opencode requires the MCP-proxy fallback.

### 4.4 tether-adapter-cline (TS extension + shell hooks)

Cline supports **two** hook mechanisms now:
- v3.36+ shell hooks in `~/Documents/Cline/Rules/Hooks/<HookName>` (macOS/Linux only, no Windows) with its own JSON format (`{preToolUse: {tool, parameters}}`, response `{cancel, errorMessage, contextModification}`).
- Claude-spec hooks merged in PR #6440 with "100% compatibility with Claude hook protocol while adapting to Cline's tool names and workflow" via `ToolNameMapper`.

Strategy: prefer Claude-spec config on Cline versions including PR #6440; fall back to v3.36 shell hooks for older Cline. `tether doctor` detects the version and installs the right shim.

### 4.5 tether-adapter-aider and tether-adapter-goose (fallback path)

Aider has no lifecycle hooks (Issue #2196: "Yes, aider does not trigger git hooks when it commits"; Aider docs explicitly only expose `--git-commit-verify` for the bare `pre-commit` flag). Goose has no lifecycle hooks; only permission modes (`autonomous`, `smart_approve`, `manual`), `.gooseignore`, and the MCP extension model.

For both, tether ships **two complementary defenses**:

1. **MCP proxy:** tether registers itself as an MCP server in the agent's config and wraps every other MCP server. All `tools/list` and `tools/call` flow through tether, which (a) hashes tool descriptions for rug-pull detection, (b) scans tool descriptions for tool-poisoning patterns, (c) applies the `[tools.deny]` rules to `tools/call` arguments, (d) scans tool responses for prompt injection and secrets.
2. **Filesystem watcher:** `notify` crate watches the working directory; any write Aider makes outside an allowed path is logged. (Not blocking — Aider has already written the file by the time the event fires — but the audit log is complete.)
3. **`tether wrap aider …` command:** for Aider specifically, an opt-in wrapper that runs Aider as a child process, intercepts stdout/stderr through a PTY (using `portable-pty`), and applies redaction to the visible transcript and to `.aider.input.history` / `.aider.chat.history.md` files. This catches secrets in real time even though we can't gate tool calls.

### 4.6 Scanner: tether-scanner-prompt-injection

Three-tier scanner with budget-driven escalation, each layer optional:

| Tier | Backend | Latency | Cost | Catches |
|---|---|---|---|---|
| 1 | regex + aho-corasick over `ScanContext.tool_response` | ~0.5 ms / KB | 0 | "ignore previous instructions", "IMPORTANT MESSAGE", InjecAgent canonical strings, AgentDojo `ImportantInstructionsAttack` template, base64/zero-width steganography heuristics |
| 2 | ONNX-hosted DeBERTa (ProtectAI `deberta-v3-base-prompt-injection-v2`) via `ort` crate | 30–80 ms / 512 tokens on CPU | 0 (local), one-time ~440 MB model download | learned indirect-injection patterns, novel phrasings; the ProtectAI model card reports **"Accuracy: 95.25% Precision: 91.59% Recall: 99.74% F1 Score: 95.49%"** on a post-training evaluation set of 20,000 prompts from untrained datasets |
| 3 | LLM-as-judge (Anthropic Haiku or local Ollama) — gated behind `[scanners.prompt_injection.llm_judge.enabled = true]` | 600–1500 ms | ~$0.0002/call (Haiku) | adversarial paraphrases, encoded payloads |

Defaults at v1.0: Tier 1 on, Tier 2 opt-in (`tether models pull pi-detector` downloads the ONNX), Tier 3 opt-in. This matches the published AgentDojo result from Debenedetti et al., NeurIPS 2024 (arXiv:2406.13352v3): **"When deploying existing defenses against prompt injections, such as a secondary attack detector [lakera, protectai2024deberta], the attack success rate drops to 8%."** That 8% is the documented floor we are targeting; tether explicitly does not claim to do better.

**Regex pattern library (~120 patterns, ship in `tether/data/pi-rules.toml`)**, derived from publicly-documented attack corpora (Debenedetti et al., NeurIPS 2024 covers "97 realistic tasks and 629 security test cases" — every named attack template in that 629-case corpus is encoded in this ruleset):

```toml
[[rule]]
id = "agentdojo-important-instructions"
description = "AgentDojo canonical ImportantInstructionsAttack template"
pattern = '''(?i)<\s*important[_\s-]+(message|instructions?)[\s\S]{0,500}>'''
severity = "high"
source = "arxiv:2406.13352"

[[rule]]
id = "injecagent-canonical"
description = "InjecAgent canonical override prompt"
pattern = '''(?i)IMPORTANT!!!\s*Ignore all previous instructions and strictly adhere'''
severity = "high"

[[rule]]
id = "wasp-attention-new-important"
description = "WASP benchmark attack pattern"
pattern = '''(?i)ATTENTION:\s*NEW\s+IMPORTANT\s+AND\s+URGENT'''
severity = "high"

[[rule]]
id = "ssh-key-exfil"
description = "Tool description instructing SSH key read (Invariant Labs example)"
pattern = '''(?is)<important>[\s\S]{0,200}(?:\.ssh/id_rsa|~/\.ssh/)[\s\S]{0,200}</important>'''
severity = "critical"
source = "invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"

[[rule]]
id = "zero-width-tagcloak"
description = "Zero-width Unicode steganography frequently used to hide instructions"
pattern = '''[\u200B-\u200F\u202A-\u202E\uFEFF]{5,}'''
severity = "medium"
```

### 4.7 Scanner: tether-scanner-mcp

Audits MCP servers along three axes, drawn directly from Invariant Labs' published threat model and the Kai registry study:

1. **Static tool-description scanning** at `mcp init / mcp add` time: regex + Tier-2 model against every tool description and parameter schema (Full-Schema Poisoning per CyberArk). Blocks server load if `critical` hit found.
2. **Tool pinning (rug-pull defense):** on first approval, SHA-256 the `tools/list` response and store under `~/.local/share/tether/mcp-pins/<server-id>.json`. On every subsequent session start, re-hash and **refuse to load** if changed unless the user explicitly re-approves with `tether mcp approve <server-id>`. This mirrors Invariant Labs' published mcp-scan behavior — "Tool Pinning to detect and prevent MCP rug pull attacks, i.e. detects changes to MCP tools via hashing" — but is implemented in-process so it works for every agent uniformly.
3. **Authentication audit:** when adding a remote MCP server, probe the URL with an empty-arg `tools/call`; if it returns 200 without auth, flag it as Tier-1 unauthenticated. This directly addresses Kai's published finding (corrected in their follow-up post): *"If you're using our data and cited 41%, update to 38% for Tier 1 only, or 46% if you include Tier 2 (schema-exposed) in your threat model."* Configurable to block by default in strict mode.

Plus runtime guardrails (active during sessions):
- `mcp__<server>__<tool>` calls are subject to the same `[tools.deny]` rules
- Cross-origin escalation detection: if `mcp_A__tool_X` description references `mcp_B`, warn
- A `tether mcp scan` subcommand performs a full one-shot audit (works offline; can opt-in to `mcp-scan` API for richer guardrails, but **default is fully local**)

### 4.8 Scanner: tether-scanner-secrets

Gitleaks-rule-compatible TOML format (so users can drop in their existing `gitleaks.toml`). Ship 150+ built-in rules from the gitleaks default ruleset — "The default ruleset covers 150+ patterns including AWS keys, GitHub tokens, Slack webhooks, database connection strings, and private keys" (appsecsanta.com on LLM Guard / gitleaks parity), with the gitleaks-maintained `config/gitleaks.toml` in `github.com/gitleaks/gitleaks` as the upstream source of truth. Entropy gate on the captured group (default 3.5) to suppress documentation examples like `AKIAIOSFODNN7EXAMPLE`.

```toml
# data/secrets-rules.toml (excerpt)
[[rule]]
id = "aws-access-key-id"
description = "AWS Access Key ID"
regex = '''(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'''
entropy = 3.2
keywords = ["AKIA", "ABIA", "ACCA", "ASIA"]

[[rule]]
id = "anthropic-api-key"
description = "Anthropic API key"
regex = '''sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9\-_]{93}'''
keywords = ["sk-ant-"]

[[rule]]
id = "openai-api-key"
description = "OpenAI API key"
regex = '''sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{20,}'''
keywords = ["sk-"]
```

Three actions: `block` (refuse to send tool response back to model), `redact` (replace with `[REDACTED:<rule-id>]`), `warn` (log only). Default: `redact` in tool outputs, `redact` in logs, `warn` on user prompts.

### 4.9 Audit log

Dual-write:
- **JSONL append-only** at `~/.local/share/tether/audit/YYYY-MM-DD.jsonl` (human-greppable, never edited)
- **SQLite** at `~/.local/share/tether/tether.db` (indexed for replay)

Schema:
```sql
CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,                  -- unix micros
  session_id TEXT NOT NULL,
  agent TEXT NOT NULL,                  -- 'claude-code' | 'codex' | ...
  stage TEXT NOT NULL,                  -- 'PreToolUse' | ...
  tool_name TEXT,
  decision TEXT NOT NULL,               -- 'allow' | 'block' | 'mutate' | 'warn'
  scanners TEXT NOT NULL,               -- JSON array of {name, verdict, score, hits}
  duration_us INTEGER NOT NULL,
  input_hash TEXT,                      -- SHA-256 of tool_input (for dedup)
  payload BLOB                          -- zstd-compressed CBOR of full event
);
CREATE INDEX idx_events_session ON events(session_id, ts);
CREATE INDEX idx_events_decision ON events(decision) WHERE decision != 'allow';
```

Retention: configurable (default 30 days for JSONL, 90 days for SQLite). `tether log prune` honors retention.

Crate choice: **`rusqlite` with `bundled` feature**, NOT `sqlx`. Reasons: synchronous is fine (we're not a web server); bundled means no system SQLite dep, so the single static binary truly is single. As the Aarambh Dev Hub 2026 ORM comparison puts it: "Bundled SQLite is chef's kiss. Enable the bundled feature flag, and Rusqlite compiles SQLite directly into your binary. No system dependency. No 'please install sqlite3-dev.' Your binary runs anywhere."

### 4.10 Replay TUI (tether-replay)

`tether replay <session-id>` or `tether replay --last`. Built on ratatui (which the official site documents as having "Sub-millisecond rendering with zero-cost abstractions and immediate-mode rendering" — appropriate for the < 16 ms per-frame budget). Three-pane layout:

```
┌────────────── tether replay · session abc123 · 2026-05-23 14:02 ──────────────┐
│ Timeline (j/k)                  │ Event detail (←/→)              │ Verdict │
├─────────────────────────────────┼─────────────────────────────────┼─────────┤
│ 14:02:01 SessionStart           │ tool: Bash                      │ ALLOW   │
│ 14:02:14 UserPromptSubmit       │ command: rg --json "TODO"       │         │
│ 14:02:15 PreToolUse Bash        │                                 │         │
│ 14:02:15 PostToolUse Bash       │ scanners:                       │         │
│ 14:02:22 PreToolUse Edit  ⚠     │   prompt_injection: pass        │         │
│ 14:02:22 PostToolUse Edit       │   secrets:          pass        │         │
│ 14:02:30 PreToolUse mcp__db__q… │   policy:           pass        │         │
│ 14:02:30 PreToolUse Bash  ⛔    │                                 │         │
│ 14:02:35 Stop                   │ duration: 4.3 ms                │         │
└─────────────────────────────────┴─────────────────────────────────┴─────────┘
 [r] re-run scanner   [e] export  [c] copy event id   [q] quit
```

Key crates: `ratatui`, `crossterm`, `tui-textarea` for filter input, `tachyonfx` (optional) for the warn/block highlight animation. There is prior art for agent-monitoring TUIs (claudectl, crmux, bosun) in the curated `awesome-ratatui` list — useful for code reference and for community discoverability.

## 5. Complete `tether.toml`

```toml
# tether.toml — full annotated example
# Loaded from (in precedence order):
#   1. ./tether.toml (project root, walked up from cwd)
#   2. $TETHER_CONFIG (env override)
#   3. ~/.config/tether/tether.toml (user)
#   4. compiled-in defaults

schema = "tether/1"

# ─── policy ──────────────────────────────────────────────────────────
[policy]
default_action = "warn"        # warn | block | allow
strict         = false         # strict=true forces block on any scanner Warn
fail_open      = false         # if tether itself crashes, allow tool call?
ask_on_first_run = true

# ─── agents ──────────────────────────────────────────────────────────
[agents]
claude_code = { enabled = true, install = "auto" }
codex       = { enabled = true, install = "auto" }
gemini      = { enabled = true, install = "auto" }
crush       = { enabled = true, install = "auto" }
opencode    = { enabled = true, install = "auto" }
cline       = { enabled = true, install = "auto" }
aider       = { enabled = true, install = "fallback" }   # MCP proxy + watcher
goose       = { enabled = true, install = "fallback" }

# Per-agent overrides
[agents.claude_code.overrides]
# Skip tether on these matchers (e.g., trusted internal tools)
skip_matchers = ["Read", "Glob", "Grep"]

# ─── scanners ────────────────────────────────────────────────────────
[scanners.prompt_injection]
enabled            = true
tier_regex         = true
tier_model         = false                  # opt-in: `tether models pull pi-detector` first
tier_llm_judge     = false
model_path         = "~/.local/share/tether/models/pi-v2.onnx"
threshold          = 0.85
on_hit             = "redact"               # block | redact | warn
max_input_bytes    = 65536

[scanners.prompt_injection.llm_judge]
provider     = "anthropic"                  # anthropic | openai | ollama
model        = "claude-haiku-4"
api_key_env  = "ANTHROPIC_API_KEY"
budget_usd_per_day = 1.00

[scanners.secrets]
enabled       = true
ruleset       = "builtin"                   # builtin | "path/to/gitleaks.toml" | "merged"
extra_rules   = ["~/.config/tether/secrets-extra.toml"]
on_hit        = "redact"
entropy_floor = 3.5

[scanners.mcp]
enabled         = true
audit_on_add    = true
require_pinning = true
allowlist       = [
  "modelcontextprotocol/server-filesystem",
  "modelcontextprotocol/server-github",
]
block_unauthenticated_remote = true   # rejects Kai-bucket servers in strict mode
proxy_mode      = "auto"              # auto | always | off

# ─── tools (deny + allow rules) ──────────────────────────────────────
[tools.deny]
shell_patterns = [
  '''rm\s+-rf\s+(/|\$HOME|~)''',
  '''mkfs\.\w+''',
  '''dd\s+if=.*of=/dev/''',
  '''curl\s+[^|]*\|\s*(sh|bash|zsh|fish)\b''',
  ''':\(\)\s*\{\s*:\|\:&\s*\};:''',     # fork bomb
  '''chmod\s+-R\s+777\s+/''',
]
path_patterns = [
  '''(?i)\.env(\.[a-z]+)?$''',
  '''id_(rsa|ed25519|ecdsa)$''',
  '''/etc/(shadow|sudoers)''',
  '''~/.aws/credentials''',
  '''~/.ssh/(?!known_hosts|config).*''',
]

[tools.allow]
# Explicit allowlist beats deny (use sparingly)
shell_patterns = ['''^ls\b''', '''^pwd$''', '''^git\s+(status|diff|log|show|branch)\b''']
path_patterns  = ['''^\./''', '''/tmp/''']

# ─── logging ─────────────────────────────────────────────────────────
[logging]
audit_dir      = "~/.local/share/tether/audit"
sqlite_path    = "~/.local/share/tether/tether.db"
jsonl_retention_days   = 30
sqlite_retention_days  = 90
log_level      = "info"
otel_endpoint  = ""                          # empty = disabled

# ─── redact (applied to logs and replay output) ──────────────────────
[redact]
patterns = [
  '''sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9\-_]{93}''',
  '''sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{20,}''',
  '''AKIA[0-9A-Z]{16}''',
  '''gh[pousr]_[A-Za-z0-9]{36,}''',
  '''xox[baprs]-[A-Za-z0-9-]{10,}''',
]
replacement = "[REDACTED:{rule}]"

# ─── replay ──────────────────────────────────────────────────────────
[replay]
default_session = "last"
theme           = "auto"                     # auto | dark | light
mask_secrets    = true
```

## 6. `Cargo.toml` (workspace root)

```toml
[workspace]
resolver = "2"
members  = [
  "crates/tether-core",
  "crates/tether-cli",
  "crates/tether-adapter-shellhook",
  "crates/tether-adapter-opencode",
  "crates/tether-adapter-aider",
  "crates/tether-adapter-goose",
  "crates/tether-scanner-prompt-injection",
  "crates/tether-scanner-mcp",
  "crates/tether-scanner-secrets",
  "crates/tether-replay",
  "crates/tether-mcp-proxy",
]

[workspace.package]
version      = "0.0.0"
edition      = "2021"
rust-version = "1.83"
authors      = ["Adarsh <adarsh@…>"]
license      = "Apache-2.0 OR MIT"
repository   = "https://github.com/<user>/tether"

[workspace.dependencies]
# CLI
clap            = { version = "4.5", features = ["derive", "env", "wrap_help"] }
clap_complete   = "4.5"

# Config + serde
serde           = { version = "1.0",  features = ["derive"] }
serde_json      = "1.0"
toml            = "0.8"
figment         = { version = "0.10", features = ["toml", "env"] }
ciborium        = "0.2"                  # CBOR for compiled policy snapshot

# Async + IO
tokio           = { version = "1.40", features = ["macros","rt-multi-thread","io-util","process","fs","time","signal"] }
async-trait     = "0.1"

# Error + logging
anyhow          = "1.0"
thiserror       = "1.0"
tracing         = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter","json"] }

# Storage
rusqlite        = { version = "0.31", features = ["bundled"] }
zstd            = "0.13"

# HTTP (only for optional LLM judge + MCP audit fetches)
reqwest         = { version = "0.12", default-features = false, features = ["rustls-tls","json","gzip"] }

# Regex + matching
regex           = "1.10"
aho-corasick    = "1.1"
fancy-regex     = "0.13"

# Filesystem + paths
notify          = "6.1"
directories     = "5.0"
walkdir         = "2.5"
ignore          = "0.4"

# ONNX (Tier-2 model)
ort             = { version = "2.0.0-rc.5", default-features = false, features = ["load-dynamic","ndarray"] }
ndarray         = "0.15"
tokenizers      = { version = "0.20", default-features = false, features = ["onig"] }

# TUI
ratatui         = "0.28"
crossterm       = "0.28"
tui-textarea    = "0.6"

# Misc
sha2            = "0.10"
hex             = "0.4"
base64          = "0.22"
once_cell       = "1.19"
which           = "6.0"
portable-pty    = "0.8"                  # for `tether wrap aider`
ureq            = { version = "2.10", default-features = false, features = ["rustls"] }

# Testing
insta           = { version = "1.40", features = ["yaml","redactions"] }
proptest        = "1.5"
criterion       = "0.5"
assert_cmd      = "2.0"
predicates      = "3.1"
tempfile        = "3.10"

[profile.release]
lto           = "fat"
codegen-units = 1
strip         = "symbols"
panic         = "abort"
opt-level     = 3

[profile.release-dev]
inherits      = "release"
debug         = "line-tables-only"
strip         = false
```

## 7. Repository structure

```
tether/
├── Cargo.toml                         # workspace
├── README.md                          # hero GIF, install, ten-second pitch
├── LICENSE-APACHE
├── LICENSE-MIT
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md                        # disclosure policy
├── dist-workspace.toml                # dist (formerly cargo-dist) config
├── rust-toolchain.toml
├── deny.toml                          # cargo-deny
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                     # test, clippy, fmt, deny, audit
│   │   ├── release.yml                # generated by `dist init`
│   │   └── docs.yml                   # mdbook deploy
│   ├── ISSUE_TEMPLATE/
│   └── FUNDING.yml
├── crates/
│   ├── tether-core/                   # Policy, Scanner trait, AuditLog, Redactor
│   │   ├── src/{lib,policy,scanner,decision,audit,redact,config}.rs
│   │   └── Cargo.toml
│   ├── tether-cli/                    # clap entry point; argv[0] dispatch
│   │   ├── src/{main,cmd_init,cmd_doctor,cmd_replay,cmd_log,cmd_mcp,cmd_models,cmd_hook,cmd_wrap}.rs
│   │   └── Cargo.toml
│   ├── tether-adapter-shellhook/      # Claude Code + Codex + Gemini + Crush + Cline
│   │   ├── src/{lib,claude_code,codex,gemini,crush,cline,normalize}.rs
│   │   └── tests/snapshots/
│   ├── tether-adapter-opencode/       # Rust handler + bundled TS shim source
│   │   ├── src/lib.rs
│   │   └── shim/tether.ts             # embedded as include_str!
│   ├── tether-adapter-aider/          # PTY wrap + filesystem watcher
│   ├── tether-adapter-goose/          # MCP-proxy registration
│   ├── tether-scanner-prompt-injection/
│   │   ├── data/pi-rules.toml         # ~120 patterns
│   │   └── src/{lib,regex_tier,model_tier,judge_tier}.rs
│   ├── tether-scanner-mcp/
│   │   ├── src/{lib,audit,pin,proxy}.rs
│   ├── tether-scanner-secrets/
│   │   ├── data/secrets-rules.toml    # 150+ gitleaks-compatible rules
│   ├── tether-replay/                 # ratatui session viewer
│   └── tether-mcp-proxy/              # shared by aider/goose fallback
├── data/                              # rule files copied at build via include_bytes!
├── docs/                              # mdbook
│   └── src/{introduction,install,quickstart,adapters,policy,scanners,replay,mcp-audit,cookbook}.md
├── examples/
│   ├── tether.toml.minimal
│   ├── tether.toml.strict
│   └── hooks/
└── npm/                               # thin npm wrapper (esbuild-style)
    ├── package.json
    ├── postinstall.js
    └── platforms/{darwin-arm64,darwin-x64,linux-x64,linux-arm64,win32-x64}/package.json
```

## 8. Performance budget

| Metric | Target | Why |
|---|---|---|
| Cold start (`tether hook claude-code pre`) | < 100 ms | Fires on every tool call. Claude Code default hook timeout is 10 minutes (per Claude Code hooks docs) but users feel anything > 100 ms |
| p50 hook latency | < 50 ms | Imperceptible to user |
| p99 hook latency | < 200 ms | "Won't be infuriating" |
| Memory resident | < 50 MB | Acceptable to leave a daemon running, but most invocations are short-lived hook processes |
| Binary size | < 15 MB | static + LTO + strip; ONNX runtime added only when Tier-2 enabled (load-dynamic) |
| Audit-log write | < 5 ms | SQLite + JSONL in single transaction |
| Token overhead per call | < 1 k tokens | Only `additionalContext` from SessionStart + occasional injected warnings |
| Tier-1 regex scan (10 KB tool response) | < 1 ms | aho-corasick on ~120 patterns |
| Tier-2 model scan | < 100 ms | ONNX CPU inference on 512-token chunk |

Validation: `criterion` benchmarks in `crates/tether-core/benches/` and `crates/tether-scanner-prompt-injection/benches/`, run as a non-required CI job that posts comparison to PR.

Static-binary discipline:
- `default-features = false` on `reqwest` and `ureq` to use rustls (no OpenSSL)
- `rusqlite` with `bundled`
- `ort` with `load-dynamic` so the ONNX runtime is downloaded on demand (kept out of binary)
- `panic = "abort"` and `strip = "symbols"`

## 9. Testing strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit | `cargo test` | Policy engine decision algebra, redactor, normalizer per agent format |
| Snapshot | `insta` | The exact JSON output of every adapter for every event type. Captures schema drift instantly |
| Property | `proptest` | Decision aggregation invariants (`Block > Mutate > Warn > Pass`), redactor idempotency |
| Bench | `criterion` | All hot-path scanners, hook cold start, regex set throughput |
| Fuzz | `cargo-fuzz` on the JSON parsers | Hostile hook input |
| Integration | `assert_cmd` + `tempfile` | Spawn `tether hook` as a subprocess; pipe canned JSON; assert exit + stdout |
| End-to-end | bash scripts in `tests/e2e/` | Drive each real agent in a sandboxed `/tmp/tether-e2e-<n>/` with a recorded conversation file; verify audit log content |
| Security | curated corpus of AgentDojo (629 security test cases) + InjecAgent + WASP + Invariant tool-poisoning examples | Detection regression suite. Must catch ≥ 95% of catalog at default settings |
| Replay | `insta` for TUI screenshots via `ratatui::backend::TestBackend` | Visual regression on the TUI |

CI matrix: `{linux-x64, linux-arm64, darwin-arm64, windows-x64} × {stable, MSRV}` for `cargo test`; release matrix is broader.

## 10. Distribution & packaging

Use **`dist`** (the rebranded `cargo-dist`) at v0.31.0 (released 2026-02-23). The 0.24.0 release notes describe the rename: *"cargo-dist is now just dist. This reflects our growing support for packaging software built by tools beyond just Cargo… dist has moved towards a standalone CLI tool that doesn't have to be run as a cargo subcommand. You can now run dist init, dist build and more without needing to prefix it with cargo."*

`dist-workspace.toml`:

```toml
[dist]
cargo-dist-version = "0.31.0"
ci = "github"
installers = ["shell", "powershell", "homebrew", "npm", "msi"]
targets = [
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-unknown-linux-gnu",
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-musl",
  "x86_64-pc-windows-msvc",
]
install-path     = "CARGO_HOME"
install-updater  = true
tap              = "<user>/homebrew-tether"
npm-scope        = "@tether"
publish-jobs     = ["homebrew", "npm"]
hosting          = "github"
github-attestations = true
```

Installer surface for v1.0:

| Channel | Command | Notes |
|---|---|---|
| Shell | `curl -fsSL https://tether.sh/install \| sh` | proxies to GH Release `tether-installer.sh` |
| PowerShell | `irm https://tether.sh/install.ps1 \| iex` | |
| Homebrew | `brew install <user>/tether/tether` | personal tap until accepted into homebrew-core |
| Cargo | `cargo install tether-cli` | source build, no ONNX bundled |
| npm | `npm i -g tether` | esbuild-style wrapper. Andrew Nesbitt's 2026 platform-strings essay describes the exact pattern: "Tools like esbuild publish platform-specific binaries as scoped packages (`@esbuild/darwin-arm64`, `@esbuild/linux-x64`) listed as `optionalDependencies` of a wrapper package, with `os` and `cpu` fields on each so npm silently skips the ones that don't match. The wrapper package then uses `process.platform` and `process.arch` at runtime to `require()` the right one." A `postinstall.js` script validates the binary against SHA-256s embedded at publish time, matching esbuild's v0.26 hardening. |
| MSI | `tether-<ver>-x86_64-pc-windows-msvc.msi` | unsigned at v1.0; document SmartScreen warning |
| Docker | `ghcr.io/<user>/tether:latest` | distroless/cc-debian13:nonroot, multi-arch |

**Signing for v1.0:**
- Linux/macOS tarballs: GitHub Artifact Attestations (built-in to dist 0.31)
- macOS bundle: ad-hoc-signed at v1.0; document `xattr -d com.apple.quarantine` workaround. Notarization tracked for v1.1.
- Windows MSI: unsigned at v1.0 (document SmartScreen). Code-signing tracked for v1.1.

## 11. Documentation strategy

**README** — follows the high-density pattern of the most viral 2024–2026 dev-tool launches (ruff, biome, ccusage, claude-code-router) verified against their actual READMEs:

```
# tether    [crates.io badge] [npm badge] [License] [CI] [Discord]

> A portable security harness for CLI coding agents. One config, eight agents.

[<animated VHS demo gif>]

## Install

curl -fsSL https://tether.sh/install | sh    # shell
brew install <user>/tether/tether            # homebrew
npm i -g tether                              # npm
cargo install tether-cli                     # cargo

## Quick start

tether init                                  # writes hook configs for every agent it finds
tether doctor                                # verifies install
tether replay --last                         # review the most recent session

## Features
⚡ Sub-50 ms hook latency, <15 MB single static binary
🛡  Prompt-injection scanning (regex → ONNX DeBERTa → optional LLM judge)
🔌 MCP server audit + tool-pinning (rug-pull defense)
🚧 Shell + filesystem deny rules
🔑 Gitleaks-compatible secret redaction
📼 Local SQLite audit log + ratatui session replay
🤖 Works with: Claude Code, Codex, Gemini CLI, Crush, opencode, Cline, Aider, Goose

## Documentation → tether.sh/docs
## Why tether? → tether.sh/why
## License: Apache-2.0 OR MIT
```

This mirrors the verified pattern of ruff (badges, Docs/Playground links, tagline, hero benchmark image, table of contents, testimonials, install snippet, usage, "Show Your Support" badge section), Biome (logo banner, multi-language selector, tagline "Format, lint, and more in a fraction of a second", install line, four npx command examples, feature bullets stating "Biome has sane defaults and it doesn't require configuration"), ccusage (title + tagline, badges, screenshot, Quick Start with `bunx ccusage`, install alternatives table, command table), and claude-code-router (hero banner, one-line install, emoji feature list, configuration example).

**Demo recording**: **Charm VHS** (`charmbracelet/vhs`), the project README of which describes it as *"Your CLI home video recorder 📼"*. VHS is the right choice because tape files declaratively produce `.gif`/`.mp4`/`.webm`/`.txt`/`.ascii` outputs and **GitHub renders the resulting GIFs inline in READMEs natively**. asciinema's `.cast` format requires conversion via `agg` or `svg-term-cli` to embed in READMEs, and Terminalizer is largely unmaintained in 2026. VHS install: `brew install vhs` (or `scoop install vhs` on Windows). Requires `ttyd` and `ffmpeg` on PATH. Example tape:

```
# demo.tape
Output demo.gif
Set FontSize 18
Set Width 1200
Set Height 700
Set Theme "Dracula"
Type "tether init"
Sleep 500ms
Enter
Sleep 3s
Type "tether doctor"
Enter
Sleep 4s
Type "claude 'fix the failing test'"
Enter
Sleep 8s
```

**Docs site**: `mdbook` at `tether.sh/docs`. Section order: Introduction → Install → Quickstart → Adapters (one page per agent, with the exact config snippet) → Policy → Scanners → Replay → MCP audit → Cookbook (top 10 recipes) → Architecture → Contributing → Changelog. Hosted via GitHub Pages with a Cloudflare DNS layer for the `tether.sh` apex. Link to the canonical Anthropic / MCP security best practices page (`modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices`), whose normative line tether's MCP scanner is directly defending: *"Tools represent arbitrary code execution and must be treated with appropriate caution. In particular, descriptions of tool behavior such as annotations should be considered untrusted, unless obtained from a trusted server."*

## 12. Week-by-week execution plan (4 weeks, 40+ hrs/week)

### Week 0 — pre-week (1–2 days, allowed to overflow weekend)

| Day | Tasks | Acceptance |
|---|---|---|
| W0-D1 | (1) Lock the name; check `tether`/`tether-cli` on crates.io and `tether` on npm. (2) Register `tether.sh` and a `.dev` fallback. (3) Create `github.com/<user>/tether` private repo; set MIT-or-Apache LICENSE files; add SECURITY.md; add CODE_OF_CONDUCT.md; add CONTRIBUTING.md. (4) Set up cargo workspace shell with all 11 crate skeletons. (5) Pull all 8 target agents locally; bookmark each agent's hooks doc. | Repo compiles `cargo check` cleanly. Agents installed locally. |
| W0-D2 | (1) Write tether.toml schema (this document's section 5). (2) `dist init` and commit. (3) Draft README skeleton. (4) Spin up `mdbook` skeleton. (5) Set up `cargo-deny`, `cargo-audit`, `cargo-machete` in CI. | CI green on empty workspace; `dist plan` produces a valid plan. |

### Week 1 — core engine + first agent (Claude Code)

**Definition of done:** tether v0.1 blocks `rm -rf /` on Claude Code, writes a SQLite audit row, prints a replay. All other commands are skeletons.

| Day | Tasks | Acceptance | Risks |
|---|---|---|---|
| W1-D1 | tether-core: `Policy`, `Scanner` trait, `Decision` algebra, `ScanContext`. Property tests for decision aggregation. | `cargo test` green; aggregation invariant proptest passes 10k cases. | None |
| W1-D2 | tether-core: `figment`-based config loader with the full `tether.toml` schema. `tether init` skeleton. | Loading the example config returns a fully-typed `Policy`. | TOML schema churn — freeze v0.1 schema here. |
| W1-D3 | tether-adapter-shellhook: Claude Code normalizer; insta snapshot tests for every event type. | 8 events deserialize and round-trip in tests. | Anthropic schema drift mid-sprint (see Risk #1). |
| W1-D4 | Tier-1 prompt-injection regex scanner with the seed rule set; `tools.deny` shell + path scanners. `tether hook claude-code pre/post` end-to-end. | Manual test: drive Claude Code in `/tmp/sandbox`, hooks fire, `rm -rf /` blocked. | Hook timeout misconfiguration; verify with `tracing` spans. |
| W1-D5 | Audit log: rusqlite + JSONL. zstd compression of payloads. `tether log tail` / `tether log show <id>`. | A session produces N events, all readable by `sqlite3` and grep. | None |
| W1-D6 | `tether init` writes Claude Code config with backup. `tether doctor` validates install. | `tether init && tether doctor` from a clean machine works on macOS + Linux. | File-permission edge cases on macOS Sequoia. |
| W1-D7 | Replay TUI skeleton: timeline + event detail. No filtering yet. CI matrix complete for stable + MSRV on linux + darwin. | `tether replay --last` shows last session events. | ratatui ergonomics — use the official template, don't roll layout from scratch. |

### Week 2 — scanners + shell-hook fanout (Codex, Gemini, Crush)

**Definition of done:** tether v0.5 supports four agents (Claude Code, Codex, Gemini, Crush), has a working secrets redactor with the gitleaks-compatible rules, and has the MCP scanner with tool pinning.

| Day | Tasks | Acceptance | Risks |
|---|---|---|---|
| W2-D1 | tether-adapter-shellhook: Codex normalizer + insta snapshots. Note the `additionalContext` rejection (issue #19385): document and translate into SessionStart-only context injection for Codex. Also handle `apply_patch` matcher (issue #16732 was closed by PR #18391 — current Codex hooks docs at developers.openai.com/codex/hooks now state: *"PreToolUse can intercept Bash, file edits performed through apply_patch, and MCP tool calls… For file edits through apply_patch, matcher values can use apply_patch, Edit, or Write; hook input still reports tool_name: 'apply_patch'."*). | All 10 Codex event types snapshot. End-to-end `tether init && codex …` works. | Codex hook regression risk (recall Codex Desktop 0.129.0-alpha.15 regressed hooks per issue #21639). |
| W2-D2 | Gemini normalizer + insta snapshots. Honor `CLAUDE_PROJECT_DIR` alias. | E2E Gemini session blocks deny-rule violation. | Gemini retirement (June 18 2026); see Risk #3. |
| W2-D3 | Crush normalizer; verify Crush v0.66.1+ accepts Claude `hookSpecificOutput` (confirmed in Crush docs: "Crush also supports the Claude Code hook output format… Existing Claude Code hooks should work without modification"). E2E. | Crush blocks a forbidden Bash command using shared adapter. | Crush PreToolUse-only — document `post` is no-op. |
| W2-D4 | Secrets scanner: load gitleaks-rule-compatible TOML; ship 150+ builtin rules; entropy gate. Wire into both pre (warn) and post (redact). | Test corpus: AWS key, GitHub PAT, Anthropic key, OpenAI key, Stripe key all detected at default settings. | False positives — ship `[scanners.secrets.allowlist]` with the AWS doc examples (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7…`). |
| W2-D5 | MCP scanner: static tool-description scan; SHA-256 tool-pinning; rug-pull detection. Replicate Invariant's tool-poisoning experiments in tests (their `direct-poisoning.py`, `shadowing.py`, and `whatsapp-takeover.py` reproducers in `invariantlabs-ai/mcp-injection-experiments`). | A poisoned MCP server (Invariant's `direct-poisoning.py` reproducer) is flagged at `mcp add`. Pin file rejects modified `tools/list`. | Live `mcp-scan` API: do not depend on it; default to local-only. |
| W2-D6 | Tier-2 prompt-injection model: `ort` integration with `ProtectAI/deberta-v3-base-prompt-injection-v2` ONNX. `tether models pull pi-detector` command. Document size (~440 MB) and offline usage. | 512-token scan < 100 ms on M2 CPU. | Model license — verify Apache-2.0 of weights and bundle correct attribution. |
| W2-D7 | Replay TUI: filter by decision, scanner, session. `tether log export --jsonl`. Catch-up day for snapshot drift. | Replay shows blocked events with red highlight; export round-trips. | None |

### Week 3 — TS plugin adapters + fallbacks + distribution

**Definition of done:** tether v0.9 supports all eight agents. Distribution works end-to-end (Homebrew tap, npm wrapper, install.sh, install.ps1). Docs site live.

| Day | Tasks | Acceptance | Risks |
|---|---|---|---|
| W3-D1 | tether-adapter-opencode: embed `tether.ts` shim via `include_str!`; `tether init` writes it to `.opencode/plugin/`. Wire IPC via `spawnSync(tether, ['hook','opencode',stage])`. Document MCP-tool blind spot (issue #2319) and subagent blind spot (issue #5894). | E2E opencode session blocks a deny-rule violation; MCP-tool bypass documented in README. | TS shim runtime errors silently fail-open — instrument with `console.error` to stderr. |
| W3-D2 | tether-adapter-cline: write hook scripts to `~/Documents/Cline/Rules/Hooks/` (v3.36 path) AND to `.clinerules/hooks/` (newer path). Detect Cline version via `cline --version` to choose. | E2E Cline session blocks a deny-rule violation on macOS. | Cline Windows unsupported per the v3.36 announcement; document. |
| W3-D3 | tether-mcp-proxy: stdio + streamable_http proxy that forwards `tools/list` and `tools/call` while applying tether scanners. Used by Aider and Goose. | A canned Goose session through the proxy blocks a poisoned tool; audit log shows the proxy origin. | Performance: streaming proxy must not buffer responses. Use tokio's `io::copy_bidirectional`. |
| W3-D4 | tether-adapter-aider: `tether wrap aider` (PTY) + filesystem watcher mode. `tether init` registers the MCP proxy in `.aider.conf.yml` as a `mcp-server` block. | `tether wrap aider --` runs Aider; redacted secrets in transcript; audit captures writes. | PTY behavior differs between Linux and macOS; test both. |
| W3-D5 | tether-adapter-goose: register `tether-mcp-proxy` in `~/.config/goose/config.yaml` as the only MCP server; the proxy fans out to user-listed servers downstream. | E2E Goose session uses three downstream MCP servers via tether proxy; audit complete. | Goose extension config format brittleness. |
| W3-D6 | Distribution: `dist init`; commit generated `release.yml`; cut a `v0.9.0` pre-release. Set up homebrew tap repo. Build npm wrapper using esbuild-style `optionalDependencies`; publish to npm under a personal namespace as `tether-pre`. Write `install.sh` mirror at `tether.sh/install`. | `brew install <user>/tether/tether`, `npm i -g tether-pre`, and `curl … | sh` all install a working binary on a clean VM. | First-time signing/notarization issues — defer mac notarization to v1.1. |
| W3-D7 | Docs site (mdbook) deployed to GitHub Pages with `tether.sh/docs` DNS. README finalized with VHS-recorded demo GIF. `tether init` UX polish (pretty prompts via `dialoguer`). | Docs live; README renders demo inline; `tether init` walks through detection of installed agents. | Time crunch — accept skeletal Cookbook section. |

### Week 4 — alpha, polish, launch sequence (T-7 → T+30 compressed to T-7 → T+7 with planned follow-up)

**Definition of done:** v1.0.0 tagged. Launched on HN with a top-of-page result. 20+ alpha testers across the eight agents.

| Day | Tasks | Acceptance | Risks |
|---|---|---|---|
| W4-D1 (T-7) | Private alpha: invite 15 trusted users via DM (Anthropic Discord, Codex Discord, Charmbracelet Discord, MCP Discord, /r/LocalLLaMA mods). Provide a 5-minute Loom. Open a private feedback channel. | 8+ alpha users running daily by T-3. | Negative feedback on a core design choice (see Risk #4). |
| W4-D2 | Triage alpha bugs; ship v0.9.1, v0.9.2 as needed. Performance pass: criterion benches, ensure p99 < 200 ms. | All criteria from §8 met on M2 + a Linux x64 box. | Perf regression hides in scanner — gate on criterion CI. |
| W4-D3 | Cookbook recipes (10): per-language linting on PostToolUse, blocking `.env` reads, secret redaction in JSONL export, MCP rug-pull demo, etc. | Each recipe has a paste-and-run snippet. | None |
| W4-D4 (T-3) | Pre-launch artifacts: 30-second VHS demo, 2-minute Loom walkthrough, 90-second Twitter video, blog post draft (~1500 words). | All assets in repo `assets/launch/`. | None |
| W4-D5 (T-2) | Final tag `v1.0.0`. Release notes. `dist plan` produces installers; smoke-test each on a clean VM. Update README badges and install commands. Push docs final. | `v1.0.0` GitHub Release green; six installers downloadable; binary verifies attestation. | Release pipeline failure — keep `v1.0.0-rc1` viable. |
| W4-D6 (T-1) | Prep launch posts (drafts not yet posted): HN "Show HN" body following Markepear's documented dev-tool launch guidance — *"Talk to HN as fellow builders and engineers. Imagine you're having a drink with a friend you used to work with"* and *"Don't use superlatives (fastest, biggest, first, best). Modest language is stronger"*; 8-tweet thread (hook + GIF + 6 feature tweets + CTA); LinkedIn post; /r/programming and /r/rust posts; Lobsters post. Personal-network DMs queued. | All posts in a single Notion doc, ready to copy-paste. | None |
| W4-D7 (T-0 = Tuesday 09:00 PT) | Launch. Post HN ("Show HN: Tether – Security harness for Claude Code, Codex, Gemini CLI, Aider, Goose, …"); post Twitter thread; ping personal network; respond to every comment within 30 minutes for first 8 hours. Run `Loom`-style live demo at noon PT. | First-page HN for ≥ 4 hours; ≥ 300 GitHub stars in T+24h. | HN flagging — keep the title descriptive, do not use superlatives. |
| T+1 → T+7 | Daily: triage issues, ship `v1.0.x` patches, write thank-you posts, schedule podcast/newsletter pitches. Compile v1.1 roadmap from feedback. | 1000+ stars, 5+ external PRs. | Burnout — schedule one rest day. |

### 13. Launch sequence detail (T-21 → T+30 condensed)

| T | Action |
|---|---|
| T-21 | Decide name + domain; secure crates.io + npm + GitHub org |
| T-14 | First public-feed signal: tweet "Working on tether" with a tease GIF, no link |
| T-10 | Reach out to 5 macro-influencers (no DMs to people you haven't engaged with — comment on their posts for two weeks first) |
| T-7 | Private alpha begins |
| T-5 | Submit to Console.dev newsletter, ChangelogNews, Software Engineering Daily |
| T-3 | Final review of all launch posts; have a friend HN-veteran review the body |
| T-1 | Prep launch-day calendar block: 8 hours of comment-answering, in the office, no meetings |
| T-0 (Tuesday 09:00 PT) | Show HN post; tweet thread; r/programming, r/rust, Lobsters posts; LinkedIn; personal-network DMs; Discord pings |
| T+1 | First triage round; ship v1.0.1 patch with the most-requested fix |
| T+3 | Newsletter feature requests; podcast pitches (Rustacean Station, Changelog) |
| T+7 | First retrospective blog post; v1.0 stability tag |
| T+14 | First community PR meeting (Discord voice) |
| T+21 | v1.1 alpha if scope is small |
| T+30 | Retrospective + roadmap update |

## 14. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Anthropic changes Claude Code hook schema mid-sprint | medium | high | Insta snapshot tests detect drift in CI within minutes. Schema-version field in tether-core. Pin to latest Claude Code in CI; rebuild snapshots in a single PR. |
| 2 | A new MCP CVE creates launch-timing pressure | medium | medium (timing) | Prepare a "tether responds to <CVE>" blog template. If the CVE hits in week 3, accelerate launch by 3 days; if week 4, hold launch but ship a hot-patch tagged release the same day. |
| 3 | Gemini CLI retirement (June 18, 2026, replaced by Antigravity CLI) — the Gemini CLI docs explicitly state: *"Unpaid tier and Google One users: Gemini CLI will be replaced by Antigravity CLI on June 18th."* | high | low | Build the Gemini adapter cheaply via the shared shell-hook crate. If Antigravity preserves hook compatibility (likely — Google explicitly aliases `CLAUDE_PROJECT_DIR` already), the adapter "just works"; otherwise document deprecation in `tether 1.1` and remove. |
| 4 | Alpha testers reject a core design choice (e.g., SQLite vs sled, or default-block vs default-warn) | medium | medium | Keep all such choices behind config. Have a 24-hour decision rule — if alpha consensus is clear, ship the change in v0.9.2 and document a migration. |
| 5 | Prompt-injection scanner has unacceptable false-positive rate | medium | high | Default to `on_hit = "warn"` (not block) in Tier 1. Ship a one-line `tether log fp <event-id>` to add an allowlist. Public PINT-style benchmark page on the docs site within v1.1. |
| 6 | Aider or Goose ships native hooks mid-sprint | low | low (positive) | Adapter swap is cheap because tether-core is independent of adapter. Ship an updated adapter as v1.0.x within 48 hours of the upstream release. |
| 7 | `dist` (formerly cargo-dist) breaking changes between v0.30 and v0.31 | low | medium | Pin `cargo-dist-version` exactly to `0.31.0`. Track via dependabot. |
| 8 | npm wrapper breaks on a platform we didn't test | medium | medium | Mirror the esbuild approach precisely (optionalDependencies + os/cpu filters + `postinstall` hash verification); CI matrix runs `npm i -g` on linux x64, linux arm64, darwin arm64, win32 x64. |
| 9 | Cline Windows users blocked (Cline hooks unsupported on Windows per Cline's own v3.36 announcement: *"Hooks are currently supported on macOS and Linux only. Windows support is not available."*) | high | low | Document in `tether doctor` output and the install matrix table. v1.1: investigate a TS-extension fallback that works on Windows Cline. |
| 10 | Solo author burnout in week 4 | high | high | Hard rule: one full rest day (Saturday W3 or W4). Pre-write all launch posts on T-1. Set a no-meetings T-0. Schedule T+1 light. |
| 11 | Codex apply_patch hook regression after fix | low | high | Issue #16732 was closed by PR #18391, but the Codex Desktop 0.129.0-alpha.15 incident (issue #21639: *"After updating the Codex Desktop app, hooks configured in .codex/hooks.json no longer appear to run at all"*) shows desktop releases can regress hooks. E2E test runs `apply_patch` deliberately every CI run and pins minimum-tested Codex version in `tether doctor`. |
| 12 | False security claim — tether is a defense-in-depth layer, not a perfect filter | n/a | reputational | README and docs explicitly state: "tether reduces risk; it does not eliminate prompt injection. Use it alongside strong agent permissions and least-privilege MCP servers." Cite Debenedetti et al., NeurIPS 2024 (arXiv:2406.13352v3): even with a secondary detector, attack success rate is reduced to 8% — non-zero. |

## 15. Post-1.0 roadmap

**v1.1 (T+45):**
- macOS notarization + Windows code signing
- Antigravity CLI adapter (whatever the new schema looks like)
- Tier-3 LLM judge with budget guards
- PINT-style public benchmark page
- Live `tether tail --follow` mode
- Native TS extension for Cline (Windows path)
- Docker MCP-sandbox mode (run each MCP server in a read-only container per Invariant best-practice)

**v1.2 (T+90):**
- Cursor + Windsurf adapters (per the mcp-scan auto-discovery list)
- ETDI-style OAuth-scoped tool definitions (arXiv 2506.01333: "ETDI: Mitigating Tool Squatting and Rug Pull Attacks in Model Context Protocol (MCP) by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control")
- Team mode: per-repo policy in `.tether.toml`, signed by GPG/sigstore, CI-enforced
- Telemetry-free analytics: `tether log stats` for personal weekly/monthly summaries
- Plugin SDK: third-party scanners via `wasmtime`

**v2.0 vision (T+180):**
- Multi-host distributed audit (still optional, still local-first)
- "tether console": a daemon-mode replay UI in the browser, served locally
- Policy-as-code in a small Rego-like DSL (or borrow OPA via FFI)
- Adapter for any agent that emits OTEL traces — generic auto-instrumentation
- Become the de facto standard such that new agents ship a `tether` adapter on day one

## Caveats

- **The agent hook ecosystem is fluid.** Hooks were experimental in many of these tools as recently as 6–8 months ago. Schemas will drift. tether's value relative to bespoke per-agent hooks is precisely the portability of policy across drift; the snapshot-test suite is the early-warning system.
- **No defense is perfect.** Debenedetti et al., NeurIPS 2024 (arXiv:2406.13352v3) document that even strong secondary detectors leave residual attack success around 8%; tether must clearly position itself as defense-in-depth, not a bulletproof shield.
- **The opencode plugin limitations (issues #2319 and #5894) are real.** Until fixed upstream, the MCP-proxy fallback is the recommended path for high-security opencode users. Document loudly.
- **Aider and Goose lack hooks today**; if either ships native hooks during the sprint, tether's adapter swaps cleanly because the policy engine is hook-agnostic.
- **Cline on Windows lacks hook support** per Cline's own v3.36 announcement. Document this explicitly in the install matrix. Don't pretend it works.
- **Gemini CLI retirement** is publicly announced for June 18, 2026, for unpaid tiers; tether's Gemini adapter is therefore a defensive bet but cheap because it shares the shell-hook crate.
- **The Kai 41% figure is widely cited but was corrected.** Use the corrected figures (38% Tier-1, 46% if Tier-2 included) in any marketing or documentation; the corrected Kai post is explicit: *"If you're using our data and cited 41%, update to 38% for Tier 1 only, or 46% if you include Tier 2 (schema-exposed) in your threat model."*

# TL;DR

- **What tether is.** A single static Rust binary that hooks every major CLI coding agent (Claude Code, Codex, Gemini CLI, Crush, opencode, Cline, Aider, Goose) and enforces one TOML policy across all of them — prompt-injection scanning, MCP server audit + tool-pinning, shell/path deny rules, gitleaks-compatible secret redaction, and a local SQLite + JSONL audit log with a ratatui session-replay TUI.
- **Why now, and the realistic ceiling.** The agent hook ecosystem converged on the Claude Code wire format in late 2025 / early 2026, so one shared shell-hook adapter covers five of the eight agents; Codex `apply_patch` hooks were fixed by PR #18391; opencode/Cline need TS-plugin shims; Aider/Goose need an MCP-proxy fallback because neither has lifecycle hooks. Debenedetti et al., NeurIPS 2024, document that a secondary detector reduces attack success to 8% — that's the honest residual, and the project must position as defense-in-depth, not a bulletproof shield.
- **Execution plan and launch posture.** Three to four weeks at 40+ hrs/week: Week 1 core + Claude Code, Week 2 secrets/MCP/PI scanners + Codex/Gemini/Crush, Week 3 opencode/Cline TS shims + Aider/Goose proxies + dist (formerly cargo-dist) v0.31 with Homebrew/npm/shell/MSI installers + VHS-recorded demo + mdbook docs, Week 4 private alpha (15 testers) → `v1.0.0` Tuesday 09:00 PT Show HN with the modest-language framing Markepear's HN launch guide prescribes. Risk register covers Anthropic schema drift, Gemini CLI retirement, npm wrapper portability, and burnout — all with concrete mitigations.
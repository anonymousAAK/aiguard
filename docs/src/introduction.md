# Introduction

**tether** is a single static Rust binary that sits between you and every CLI coding agent on your machine, enforcing a consistent security policy regardless of which agent is running.

## What tether does

CLI coding agents (Claude Code, Codex, Gemini CLI, and others) execute shell commands, read and write files, and call MCP servers on your behalf. Each agent has its own hook system, its own config format, and its own surface area for attack. tether unifies the defense layer: one `tether.toml`, one audit log, one replay interface — across all eight supported agents.

## Five guarantees

tether enforces five properties on every tool call, regardless of agent:

1. **Prompt-injection scanning.** Every tool output is scanned before it re-enters the model context. tether ships a three-tier pipeline: fast regex (120+ rules derived from published attack corpora), an optional ONNX-hosted DeBERTa classifier, and an optional LLM-as-judge fallback.

2. **MCP server auditing.** Before any MCP server is loaded, tether hashes its tool descriptions and checks for known tool-poisoning patterns (Invariant Labs taxonomy), rug-pull changes, and cross-origin escalation attempts.

3. **Shell and filesystem deny rules.** `[tools]` in `tether.toml` specifies glob-style shell command patterns and file path patterns that are blocked before the agent can execute them. Rules are evaluated with deterministic precedence: Block > Mutate > Warn > Allow.

4. **Secret redaction.** Tool outputs, audit records, and replay views all pass through a gitleaks-compatible secret scanner. Matched secrets are replaced with `[REDACTED:<rule-id>]` before any of this content is returned to the model or written to disk.

5. **Audit log + session replay.** Every tool call — its input, output, scanner verdicts, and timing — is written to both a JSONL append-only log and a SQLite database. `tether replay` opens a terminal UI to review any session.

## Supported agents

| Agent | Hook type | Status |
|---|---|---|
| Claude Code | shell hook | full support |
| Codex CLI | shell hook | full support |
| Gemini CLI | shell hook | full support |
| Crush | shell hook | pre-tool only |
| Cline | shell hook | macOS/Linux |
| opencode | TypeScript plugin | via shim |
| Aider | MCP proxy + filesystem watcher | fallback |
| Goose | MCP proxy | fallback |

## Limitations and honest expectations

tether reduces risk; it does not eliminate prompt injection. The attack surface for indirect prompt injection is broad: a malicious instruction can appear in a web page your agent fetches, a file it reads, a database row it queries, or an MCP tool description. tether's Tier-1 regex and Tier-2 ONNX scanner will catch the vast majority of known patterns, but novel or heavily obfuscated payloads may pass through.

The quantitative baseline comes from Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents," NeurIPS 2024 (arXiv:2406.13352v3): *"When deploying existing defenses against prompt injections, such as a secondary attack detector, the attack success rate drops to approximately 8%."* That 8% residual is the documented floor for the current generation of detectors. tether does not claim to do better; it targets that floor and makes it the default for every supported agent.

For the strongest protection, enable Tier-2 (ONNX) with `tether models pull pi-detector` and set `[policy] strict = true` in CI environments.

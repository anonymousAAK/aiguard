# Codex CLI

OpenAI Codex CLI (the open-source CLI agent at `github.com/openai/codex`) uses a hook system compatible with the Claude Code wire format. Hooks were marked stable in Codex v0.124.0.

## Hook type

Shell hook — JSON on stdin, exit code + JSON on stdout.

Hook config file: `~/.codex/config.toml`

## Install

`tether init` writes the following into your Codex config:

```toml
# ~/.codex/config.toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = ".*"
timeout = 10
[[hooks.PreToolUse.hooks]]
type = "command"
command = "tether hook codex pre"

[[hooks.PostToolUse]]
matcher = ".*"
timeout = 10
[[hooks.PostToolUse.hooks]]
type = "command"
command = "tether hook codex post"
```

## tether.toml entry

```toml
[agents.codex]
enabled = true
auto_install = false

[agents.codex.overrides]
default_action = "warn"
```

## Tool names

Codex tool names: `Bash`, `apply_patch`, `Edit`, `Write`, and `mcp__<server>__<tool>` for MCP tools.

## Known limitations

- `additionalContext` in `PreToolUse` output is **not supported** by Codex (issue #19385). tether does not send `additionalContext` to Codex; warnings are logged to the audit trail only.
- `updatedToolOutput` on `PostToolUse` is supported only for MCP tools (not shell tools) in the current Codex release.
- The `UserPromptSubmit` and `SessionStart` hooks are not available in Codex; only `PreToolUse` and `PostToolUse` fire.

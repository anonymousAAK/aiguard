# Claude Code

Claude Code is the primary target for aiguard's shell-hook adapter. It has the most complete hook support of any agent: `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, and `SessionStart` all fire reliably, and `updatedToolOutput` on `PostToolUse` is supported for all tool types (since v2.1.121).

## Hook type

Shell hook — JSON on stdin, exit code + JSON on stdout.

Hook config file: `~/.claude/settings.json`

## Install

`aiguard init` writes the following hooks automatically:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "aiguard hook claude-code pre" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "aiguard hook claude-code post" }]
      }
    ],
    "SessionStart": [
      {
        "hooks": [{ "type": "command", "command": "aiguard hook claude-code session-start" }]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [{ "type": "command", "command": "aiguard hook claude-code prompt" }]
      }
    ]
  }
}
```

To install manually without running `aiguard init`, merge the above into your existing `~/.claude/settings.json`.

## aiguard.toml entry

```toml
[agents.claude_code]
enabled = true
auto_install = false

# Optional: per-agent overrides
[agents.claude_code.overrides]
default_action = "block"
skip_matchers = ["Read", "Glob", "Grep"]
extra_deny_shell_patterns = ["git push --force*"]
```

`skip_matchers` lists tool names that aiguard skips entirely for this agent. Useful for high-frequency read-only tools where the latency overhead is not desired.

## Tool names

Claude Code tool names as they appear in the hook payload: `Bash`, `Write`, `Edit`, `Read`, `Grep`, `Glob`, `WebFetch`, `WebSearch`, `Task`, `apply_patch`, and `mcp__<server>__<tool>` for MCP tools.

## Known limitations

- `additionalContext` in `PreToolUse` output is supported and can be used to inject policy warnings into the model context.
- `updatedInput` (input mutation) is supported on `PreToolUse` for all tools.
- `updatedToolOutput` (output mutation) is supported on `PostToolUse` for all tools since v2.1.121. Older versions only support it for MCP tools.
- The `SessionStart` hook fires once per new Claude Code session. `UserPromptSubmit` fires before each user message.

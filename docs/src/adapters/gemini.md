# Gemini CLI

Google's Gemini CLI (the open-source agent at `github.com/google-gemini/gemini-cli`) shipped hook support in v0.26.0, with `BeforeTool` and `AfterTool` events using a wire format compatible with the Claude Code shell-hook convention. Gemini also sets a `CLAUDE_PROJECT_DIR` alias alongside `GEMINI_PROJECT_DIR` for cross-agent config compatibility.

## Hook type

Shell hook — JSON on stdin, exit code + JSON on stdout.

Hook config file: `~/.gemini/settings.json`

## Install

`aiguard init` writes the following hooks:

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "name": "aiguard",
            "type": "command",
            "command": "aiguard hook gemini pre",
            "timeout": 10000
          }
        ]
      }
    ],
    "AfterTool": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "name": "aiguard",
            "type": "command",
            "command": "aiguard hook gemini post"
          }
        ]
      }
    ]
  }
}
```

## aiguard.toml entry

```toml
[agents.gemini]
enabled = true
auto_install = false

[agents.gemini.overrides]
default_action = "warn"
```

## Tool names

Gemini CLI tool names differ from Claude Code: `read_file`, `write_file`, `replace`, `run_shell_command`, and `mcp_<server>_<tool>` (underscore-separated, not double-underscore). aiguard's adapter normalizes these to the canonical internal names before applying policy.

## Decision output format

Gemini uses a slightly different output format:

```json
{ "decision": "deny", "hookSpecificOutput": { "reason": "blocked by aiguard" } }
```

aiguard's adapter emits the correct format automatically.

## Known limitations

- Gemini's `AfterTool` hook does not currently support `updatedToolOutput` (output mutation). aiguard can warn on post-tool injection but cannot redact Gemini tool responses inline; redacted content is logged but the unredacted version is returned to the model.
- `UserPromptSubmit` and `SessionStart` hooks are not available in Gemini CLI.

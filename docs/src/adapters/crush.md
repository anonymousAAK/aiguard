# Crush

Crush is a CLI coding agent that supports `PreToolUse` hooks and accepts Claude Code `hookSpecificOutput` verbatim. This makes it compatible with the shared shell-hook adapter with minimal per-agent normalization.

## Hook type

Shell hook — JSON on stdin, exit code + JSON on stdout. `PreToolUse` only (no `PostToolUse` hook in Crush).

Hook config file: `crush.json` in the project directory, or `~/.config/crush/crush.json` globally.

## Install

`aiguard init` writes the following into `crush.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "command": "aiguard hook crush pre",
        "timeout": 10
      }
    ]
  }
}
```

## aiguard.toml entry

```toml
[agents.crush]
enabled = true
auto_install = false

[agents.crush.overrides]
default_action = "warn"
```

## Tool names

Crush tool names are lowercase: `bash`, `edit`, `write`, `multiedit`, `view`, `grep`, `glob`. aiguard's adapter maps these to the canonical internal names.

## Decision output

Crush accepts both the Claude Code `hookSpecificOutput.permissionDecision` format and its own `{decision, context}` format. aiguard emits the Claude format, which Crush handles correctly.

## Known limitations

- Only `PreToolUse` fires in Crush. aiguard cannot scan tool responses (post-tool injection, secret redaction in outputs) for Crush sessions. The audit log captures the pre-tool decision only.
- `additionalContext` on `PreToolUse` output is not supported by Crush; policy warnings are logged but not injected into the model context.

# Cline

Cline (the VS Code extension) supports two hook mechanisms. tether prefers the Claude-spec hook path merged in Cline PR #6440, which provides 100% compatibility with the Claude Code hook protocol. For older Cline versions, tether falls back to the v3.36+ shell-hook path.

`tether doctor` detects the installed Cline version and installs the appropriate hook config.

## Hook type

**Primary (Cline v3.36+ with PR #6440):** Shell hook, Claude-spec wire format, via `~/Documents/Cline/Rules/Hooks/`.

**Fallback (Cline v3.36+, older):** Shell hook, Cline-native JSON format (`{preToolUse: {tool, parameters}}`, response `{cancel, errorMessage, contextModification}`).

macOS and Linux only. The v3.36 shell hook path is not available on Windows; on Windows, only the Claude-spec path (PR #6440+) is supported.

## Install

`tether init` writes the hook config at:

```
~/Documents/Cline/Rules/Hooks/tether-pre.sh
~/Documents/Cline/Rules/Hooks/tether-post.sh
```

The hook scripts call `tether hook cline pre` and `tether hook cline post` respectively.

For the Claude-spec path (PR #6440+), `tether init` also writes:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "tether hook cline pre" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "tether hook cline post" }]
      }
    ]
  }
}
```

## tether.toml entry

```toml
[agents.cline]
enabled = true
auto_install = false

[agents.cline.overrides]
default_action = "warn"
```

## Tool names

Cline maps its internal tool names to Claude Code names via `ToolNameMapper` (PR #6440). When using the Claude-spec hook path, tool names visible to tether are the canonical Claude Code names (`Bash`, `Write`, `Edit`, etc.).

## Known limitations

- Shell hook path is macOS/Linux only. Windows users must be on Cline version including PR #6440 for hook support.
- `additionalContext` injection into model context is supported via the Claude-spec path; not available on the legacy v3.36 path.

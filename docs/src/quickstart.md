# Quick Start

This page gets you from a fresh install to a fully wired tether setup in under five minutes.

## Step 1: Initialize

Run `tether init` from your project directory (or your home directory for a global config):

```sh
tether init
```

`tether init` does the following:

1. Detects which agents are installed on your machine (Claude Code, Codex, Gemini CLI, Crush, Cline, opencode, Aider, Goose).
2. Writes hook configuration for each detected agent — creating or updating the agent's settings file with `tether hook <agent> pre` and `tether hook <agent> post` commands.
3. Writes a starter `tether.toml` in the current directory (or `~/.config/tether/tether.toml` if run from `$HOME`) with sensible defaults.
4. Backs up any existing hook config files before modifying them (saved as `<file>.bak.<timestamp>`).

If you want to generate the config without writing any hook files, pass `--dry-run` to preview what would change.

## Step 2: Verify

```sh
tether doctor
```

`tether doctor` checks:

- The tether binary is on your `PATH` and is the expected version.
- Each detected agent has a working hook pointing to `tether hook <agent> pre/post`.
- The `tether.toml` parses without errors and has no conflicting settings.
- The SQLite audit database directory is writable.
- (Optional) That the ONNX prompt-injection model is present if `tier_model = true` is set.

Example output:

```
tether v1.0.0
  [OK] binary: /usr/local/bin/tether
  [OK] config: ./tether.toml (schema 1.0)
  [OK] claude-code: hooks wired in ~/.claude/settings.json
  [OK] codex: hooks wired in ~/.codex/config.toml
  [WARN] gemini: not installed, skipping
  [OK] audit dir: ~/.local/share/tether/audit (writable)
  [OK] sqlite: ~/.local/share/tether/tether.db
  [INFO] ONNX model not present; tier_model is disabled (run: tether models pull pi-detector)
```

## Step 3: Run your agent

Start any supported agent as you normally would. tether's hooks fire automatically before and after each tool call. Blocked calls print a brief explanation to stderr; warnings are logged silently.

## Step 4: Review the session

After a session, open the replay TUI:

```sh
tether replay --last
```

Or replay a specific session by ID:

```sh
tether replay abc123def456
```

See [Replay](./replay.md) for the full TUI key bindings and export options.

## Minimal tether.toml

The following is the smallest useful configuration. Copy it to your project root as `tether.toml` or let `tether init` generate it for you.

```toml
schema = "1.0"

[policy]
default_action = "warn"   # warn | block | allow
strict = false            # set true to block on any scanner warning

[scanners.prompt_injection]
enabled = true
threshold = 0.7

[scanners.secrets]
enabled = true
action = "block"

[scanners.mcp]
enabled = true
action = "warn"

[tools]
deny_shell_patterns = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs*",
    "dd if=/dev/*",
    "curl * | sh",
    "wget * | sh",
    "curl * | bash",
    "wget * | bash",
    ":(){:|:&};:",
]
deny_path_patterns = [
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/*",
    "~/.aws/credentials",
    "~/.gnupg/*",
]

[logging]
audit_dir = "~/.local/share/tether/audit"
sqlite_path = "~/.local/share/tether/tether.db"
retention_days = 90
```

All fields have compiled-in defaults; only override what you need to change. See [Policy](./policy.md) for the full field reference.

## Next steps

- Add agent-specific configuration: [Adapters](./adapters/claude-code.md)
- Tune scanner thresholds and opt into the ONNX model: [Scanners](./scanners.md)
- Protect your MCP servers: [MCP Audit](./mcp-audit.md)
- Browse common recipes: [Cookbook](./cookbook.md)

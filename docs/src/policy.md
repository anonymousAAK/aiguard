# Policy

The `[policy]` section of `tether.toml` controls how tether responds when a scanner returns a verdict. This page documents every field, the deny/allow rule system for tools, and the decision precedence model.

## [policy] fields

```toml
[policy]
default_action = "warn"
strict = false
fail_open = false
ask_on_first_run = true
```

### `default_action`

**Type:** string — `"warn"` | `"block"` | `"allow"`
**Default:** `"warn"`

The action tether takes when no scanner explicitly blocks or allows a tool call. In other words, this is the fallback verdict when all scanners return `Pass`.

- `"allow"` — tool call proceeds silently.
- `"warn"` — tool call proceeds, but the event is logged with a warning.
- `"block"` — tool call is blocked. Use this only if you want tether to be maximally restrictive and you have explicit allow rules for everything your agents legitimately need to do.

### `strict`

**Type:** bool
**Default:** `false`

When `strict = true`, any scanner `Warn` verdict is escalated to `Block`. This is appropriate for CI environments where false positives are acceptable and you want a hard guarantee that nothing suspicious reaches the model.

### `fail_open`

**Type:** bool
**Default:** `false`

When `fail_open = true`, if tether itself encounters an internal error (a scanner panics, the config file is unreadable, the audit database is locked), it allows the tool call to proceed rather than blocking it. This trades security for availability.

If both `strict = true` and `fail_open = true` are set, `strict` takes precedence.

### `ask_on_first_run`

**Type:** bool
**Default:** `true`

On the very first run in a new project directory, tether prompts you to confirm the active policy before it starts intercepting tool calls. Set to `false` to skip this prompt in non-interactive environments.

## [tools] — Shell and path deny/allow rules

```toml
[tools]
deny_shell_patterns = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs*",
    "dd if=/dev/*",
    ":(){:|:&};:",
    "chmod -R 777 /",
    "curl * | sh",
    "wget * | sh",
    "curl * | bash",
    "wget * | bash",
]

allow_shell_patterns = [
    # "rm -rf ./build",
    # "rm -rf ./target",
]

deny_path_patterns = [
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/*",
    "~/.aws/credentials",
    "~/.gnupg/*",
]

allow_path_patterns = [
    # "~/.ssh/known_hosts",
]
```

### `deny_shell_patterns`

A list of glob-style patterns matched against the full shell command string. If a command matches any pattern in this list, tether blocks it immediately — before any scanner runs.

Patterns use `*` as a wildcard (matches any sequence of characters, including spaces). They are matched case-sensitively. The match is applied to the full command string as passed to the agent's shell tool.

Examples:
- `"rm -rf /"` — blocks the exact string `rm -rf /`
- `"curl * | sh"` — blocks any `curl` command piped into `sh`, regardless of the URL
- `"mkfs*"` — blocks `mkfs.ext4`, `mkfs.vfat`, and any other `mkfs` variant

### `allow_shell_patterns`

A list of patterns evaluated **after** `deny_shell_patterns`. If a command matches a deny pattern but also matches an allow pattern, the allow wins. Use this to carve out specific exceptions from broad deny rules.

Example: if you have `"rm -rf *"` in `deny_shell_patterns` but your build system uses `rm -rf ./build`, add `"rm -rf ./build"` to `allow_shell_patterns`.

### `deny_path_patterns`

Glob patterns matched against file paths in Read, Write, Edit, and similar file-system tools. `~` is expanded to the user's home directory before matching.

### `allow_path_patterns`

Path patterns evaluated after `deny_path_patterns`. Useful for carving exceptions — for example, allowing `~/.ssh/known_hosts` while still denying all other `~/.ssh/*` paths.

### `[tools.tool_overrides]`

Per-tool action overrides that bypass scanner verdicts entirely:

```toml
[tools.tool_overrides]
"Read" = "allow"      # always allow reads, no scanner check
"Bash" = "warn"       # always warn on Bash, even if scanners pass
```

Keys are the tool names exactly as reported by the agent (e.g., `Bash`, `Write`, `Edit` for Claude Code; `run_shell_command` for Gemini CLI).

## Decision precedence

When multiple scanners run on the same tool call, their verdicts are aggregated using the following precedence order (highest to lowest):

```
Block > Mutate > Warn > Pass
```

And for explicit allow rules:

```
Explicit Allow (from allow_shell_patterns or allow_path_patterns) > Block
```

In other words:

1. If any scanner returns `Block`, the tool call is blocked — regardless of what other scanners returned.
2. If no scanner blocks but at least one returns `Mutate`, the mutated input is used.
3. If no block or mutate, but at least one scanner warns, the event is logged as a warning.
4. If all scanners pass and no deny rule matched, `default_action` is applied.
5. An explicit allow rule in `allow_shell_patterns` or `allow_path_patterns` overrides a matching deny rule.

This is consistent with Crush's documented aggregation model: "Deny wins over allow — if any hook denies, the tool call is blocked."

## Per-agent overrides

You can override `default_action` and add extra deny patterns for individual agents:

```toml
[agents.claude_code.overrides]
default_action = "block"
extra_deny_shell_patterns = ["docker run --privileged*"]
extra_allow_shell_patterns = ["docker build*"]
skip_matchers = ["Read", "Glob", "Grep"]
```

`skip_matchers` lists tool names that tether does not intercept for this agent, which reduces latency for read-only tools you trust unconditionally.

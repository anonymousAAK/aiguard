# Cookbook

Ten ready-to-use recipes for common tether configurations.

---

## 1. Block .env file reads

Prevent any agent from reading `.env`, `.env.local`, or similar files that may contain API keys or database credentials.

```toml
[tools]
deny_path_patterns = [
    "**/.env",
    "**/.env.*",
    "**/.env.local",
    "**/.env.production",
    "**/.env.staging",
    # Keep existing defaults:
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/*",
    "~/.aws/credentials",
    "~/.gnupg/*",
]
```

The `**/` prefix matches in any subdirectory. Combined with the secrets scanner (`action = "block"`), this gives two independent layers: one that blocks the read before it happens, and one that redacts secrets even if the file is read by another path.

---

## 2. Block dangerous shell commands

Expand the default shell deny list to cover additional destructive patterns:

```toml
[tools]
deny_shell_patterns = [
    # Filesystem destruction
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    "find / -delete",
    "mkfs*",
    "dd if=/dev/*",
    "shred *",

    # Fork bombs
    ":(){:|:&};:",

    # Privilege escalation via piped install
    "curl * | sh",
    "curl * | bash",
    "wget * | sh",
    "wget * | bash",
    "pip install * --pre",

    # Broad permission grants
    "chmod -R 777 /",
    "chmod -R 777 ~",

    # Disk operations
    "fdisk *",
    "parted *",
]
```

---

## 3. Redact AWS keys from tool outputs

Enable the secrets scanner and ensure the AWS key rule is active with redact mode:

```toml
[scanners.secrets]
enabled = true
action = "redact"
entropy_threshold = 3.2   # AWS keys have entropy ~3.0–3.4; lower the floor to catch them

[[redact.patterns]]
name = "aws_access_key_id"
regex = "(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"

[[redact.patterns]]
name = "aws_secret_key"
regex = "(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"
```

The built-in ruleset already includes the AWS patterns above. If you see AWS keys passing through despite having the secrets scanner enabled, lower `entropy_threshold` or check that `action` is set to `"redact"` rather than `"warn"`.

---

## 4. Audit all MCP servers before load

Enable strict MCP auditing: block any server that fails the tool-poisoning scan or lacks authentication:

```toml
[policy]
strict = true

[scanners.mcp]
enabled = true
action = "block"
audit_on_add = true
require_pinning = true
```

When strict mode is on and an MCP server's `tools/list` contains a Tier-1 injection pattern, tether refuses to start the session. Run `tether mcp scan` before starting your agent to get a full pre-flight report.

---

## 5. Per-project tether.toml

Keep a project-specific config in the repository root alongside your code. tether searches upward from the current working directory and uses the first `tether.toml` it finds.

```
my-project/
  tether.toml        <-- project config (checked into git)
  src/
  tests/
```

```toml
# my-project/tether.toml
schema = "1.0"

[policy]
default_action = "warn"

[tools]
# Only allow writes inside the project directory
deny_path_patterns = [
    "/etc/*",
    "~/.ssh/*",
    "~/.aws/*",
    "~/.config/*",
]
allow_path_patterns = [
    "./src/**",
    "./tests/**",
    "./docs/**",
]
```

The global config at `~/.config/tether/tether.toml` is used as fallback for any field not specified in the project config.

---

## 6. Enable strict mode for CI

In CI, block on any scanner warning and fail-closed on tether errors:

```toml
# ci-tether.toml (or set TETHER_CONFIG=ci-tether.toml in CI)
schema = "1.0"

[policy]
default_action = "block"
strict = true
fail_open = false
ask_on_first_run = false

[scanners.prompt_injection]
enabled = true
tier_model = false        # skip ONNX in CI to save time; Tier-1 regex is sufficient
threshold = 0.6           # more aggressive in CI

[scanners.secrets]
enabled = true
action = "block"

[scanners.mcp]
enabled = true
action = "block"
require_pinning = true
```

Set the config path in your CI environment:

```yaml
env:
  TETHER_CONFIG: ./ci-tether.toml
```

---

## 7. Export audit log as JSONL

Export all sessions from today to a file:

```sh
tether log export --since today > audit-$(date +%Y-%m-%d).jsonl
```

Export all blocked events across all time:

```sh
tether log export --decision block > blocked-events.jsonl
```

Filter with jq to find all events involving a specific tool:

```sh
tether log export --since 7d | jq 'select(.tool_name == "Bash")'
```

The JSONL schema mirrors the SQLite `events` table: each line is a JSON object with fields `ts`, `session_id`, `agent`, `stage`, `tool_name`, `decision`, `scanners`, `duration_us`, and `input_hash`.

---

## 8. Replay a specific session

List recent sessions:

```sh
tether log sessions --last 10
```

Example output:

```
SESSION ID          AGENT        START                 EVENTS  BLOCKS
abc123def456        claude-code  2026-05-23 14:02:01   47      2
789xyz000111        codex        2026-05-22 09:15:44   12      0
```

Open a session in the replay TUI:

```sh
tether replay abc123def456
```

Export a session without opening the TUI:

```sh
tether replay abc123def456 --export | jq .
```

---

## 9. Add custom secret detection rules

Drop a custom rules file into `~/.config/tether/secrets-extra.toml`:

```toml
# ~/.config/tether/secrets-extra.toml

[[rule]]
id = "corp-api-key"
description = "Corp internal API key"
regex = "CORP-[A-Z]{3}-[0-9A-Z]{24}"
entropy = 3.5

[[rule]]
id = "internal-jwt-secret"
description = "Internal service JWT signing secret"
regex = "(?i)jwt[_-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{32,})['\"]?"
entropy = 4.0
```

Reference it in `tether.toml`:

```toml
[scanners.secrets]
extra_patterns = ["~/.config/tether/secrets-extra.toml"]
```

The extra rules are merged with the built-in ruleset and subject to the same `action` and `entropy_threshold` settings.

---

## 10. Use tether with multiple agents simultaneously

tether is designed for this. Each agent has its own hook config that points to `tether hook <agent> pre/post`, and all agents share the same `tether.toml` and audit log.

After running `tether init`, you can verify all hooks are in place:

```sh
tether doctor
```

To enable all agents and set per-agent overrides:

```toml
schema = "1.0"

[policy]
default_action = "warn"

[agents.claude_code]
enabled = true

[agents.codex]
enabled = true

[agents.gemini]
enabled = true

[agents.crush]
enabled = true

[agents.cline]
enabled = true

[agents.opencode]
enabled = true

[agents.aider]
enabled = true   # uses MCP proxy + filesystem watcher

[agents.goose]
enabled = true   # uses MCP proxy

# Tighter policy for the agent used in production code reviews
[agents.claude_code.overrides]
default_action = "block"
extra_deny_shell_patterns = ["git push --force*"]
```

All sessions from all agents appear in the same audit log and are navigable with `tether replay`.

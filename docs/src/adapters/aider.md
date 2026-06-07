# Aider

Aider is a CLI coding assistant that does not expose lifecycle hooks for tool calls (confirmed in Aider issue #2196). tether uses two complementary fallback defenses: an MCP proxy that wraps all of Aider's MCP servers, and a filesystem watcher that detects writes outside the allowed path set.

## Hook type

Fallback path — MCP proxy (`tether-mcp-proxy`) + filesystem watcher (`notify` crate) + optional PTY wrapper (`tether wrap aider`).

## Install

`tether init` does the following for Aider:

1. Registers `tether-mcp-proxy` as an MCP server in Aider's `.aider.conf.yml`, wrapping any other configured MCP servers.
2. Starts the filesystem watcher as a background daemon for the current working directory.

No manual config is required beyond running `tether init`.

## tether.toml entry

```toml
[agents.aider]
enabled = true
auto_install = false   # set true to have tether init manage Aider config automatically
```

## MCP proxy

When Aider is configured with MCP servers, tether inserts itself as a proxy in front of all of them. All `tools/list` and `tools/call` traffic flows through tether, which applies:

- Tool-description poisoning scan (Tier-1 regex)
- SHA-256 rug-pull detection
- `[tools.deny]` shell and path patterns on tool arguments
- Prompt-injection scan on tool responses
- Secret redaction on tool responses

To configure MCP servers through the proxy, set them in `tether.toml` rather than directly in Aider's config:

```toml
[[mcp.servers]]
id = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/dir"]
```

## PTY wrapper (opt-in)

For Aider-specific secret redaction on the visible transcript and in `.aider.chat.history.md`:

```sh
tether wrap aider -- aider --model gpt-4o
```

`tether wrap aider` runs Aider as a child process through a PTY, intercepts stdout/stderr, and applies secret redaction to the visible output in real time. This catches secrets that appear in Aider's transcript even though tether cannot gate the underlying tool calls.

## Filesystem watcher

The filesystem watcher records every file write Aider makes, whether or not the path is on the deny list. Files written to denied paths are logged as violations in the audit log. Note: the watcher is informational — Aider has already written the file by the time the event fires. The audit record is complete, but the write cannot be blocked.

## Known limitations

- Aider tool calls cannot be blocked before execution. The MCP proxy covers MCP tool calls only; shell commands run by Aider directly are not interceptable.
- The filesystem watcher cannot block writes; it can only audit them after the fact.
- `tether wrap aider` requires a PTY-capable terminal (not available in all CI environments).

# Goose

Goose (by Block) is a CLI agent with six extension types but no lifecycle hooks for tool calls. tether uses an MCP proxy fallback to intercept all MCP tool traffic and a permission shim to register itself with Goose's permission model.

## Hook type

Fallback path — MCP proxy (`tether-mcp-proxy`) + Goose config registration.

## Install

`tether init` writes a Goose extension entry that registers `tether-mcp-proxy` as an MCP extension:

```yaml
# ~/.config/goose/config.yaml  (appended by tether init)
extensions:
  tether:
    type: stdio
    cmd: tether
    args: [mcp-proxy]
    enabled: true
    timeout: 30
```

## tether.toml entry

```toml
[agents.goose]
enabled = true
auto_install = false
```

## MCP proxy coverage

All MCP servers used by Goose should be routed through the tether proxy. Configure them in `tether.toml` so the proxy manages them:

```toml
[[mcp.servers]]
id = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GITHUB_TOKEN}" }
```

The proxy applies:

- Tool-description poisoning scan
- SHA-256 rug-pull detection
- `[tools.deny]` rules on all `tools/call` arguments
- Prompt-injection scan on tool responses
- Secret redaction on tool responses and audit log

## Goose permission modes

Goose has three built-in permission modes: `autonomous`, `smart_approve`, and `manual`. tether does not replace these — it adds a policy layer on top. For the strongest protection, set Goose to `manual` mode and configure `[policy] default_action = "block"` in tether:

```toml
[policy]
default_action = "block"
strict = true
```

In this configuration, Goose will prompt for manual approval on every tool call, and tether will additionally block calls that match deny rules before Goose's approval prompt appears.

## Known limitations

- Only MCP tool calls are interceptable via the proxy. Goose's built-in tools (file I/O, shell commands via the `developer` extension) are not routed through MCP and cannot be blocked by tether.
- Goose does not have `PreToolUse`/`PostToolUse` events; there is no pre-execution block capability for non-MCP tools.

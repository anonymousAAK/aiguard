# opencode

opencode is a TUI-based coding agent (by the SST team) that supports TypeScript plugins via `@opencode-ai/plugin`. Since the plugin system requires a TypeScript module, tether installs a thin TypeScript shim that calls the Rust binary via `spawnSync`.

## Hook type

TypeScript plugin shim — IPC via `spawnSync` into `tether hook opencode <stage>`.

Plugin directory: `~/.config/opencode/plugin/` (global) or `.opencode/plugin/` (project).

## Install

`tether init` writes the following TypeScript plugin at `~/.config/opencode/plugin/tether.ts`:

```typescript
import type { Plugin } from "@opencode-ai/plugin"
import { spawnSync } from "node:child_process"

const TETHER = process.env.TETHER_BIN ?? "tether"
const call = (stage: string, payload: unknown) => {
  const r = spawnSync(TETHER, ["hook", "opencode", stage], {
    input: JSON.stringify(payload), encoding: "utf8", timeout: 5000,
  })
  return { code: r.status ?? 0, stdout: r.stdout, stderr: r.stderr }
}

export const Tether: Plugin = async (ctx) => ({
  "tool.execute.before": async (input, output) => {
    const r = call("pre", { tool: input.tool, args: output.args, project: ctx.project })
    if (r.code === 2) throw new Error(r.stderr || "blocked by tether")
    if (r.stdout) {
      const o = JSON.parse(r.stdout)
      if (o.updatedInput) Object.assign(output.args, o.updatedInput)
    }
  },
  "tool.execute.after": async (input, output) => {
    const r = call("post", {
      tool: input.tool, args: output.args ?? null,
      output: output.output, metadata: output.metadata, project: ctx.project
    })
    if (r.stdout) {
      const o = JSON.parse(r.stdout)
      if (o.updatedOutput) output.output = o.updatedOutput
    }
  },
})
```

## tether.toml entry

```toml
[agents.opencode]
enabled = true
auto_install = false

[agents.opencode.overrides]
default_action = "warn"
```

## Known limitations

- `tool.execute.before` and `tool.execute.after` do **not** fire for MCP tool calls in opencode (issue #2319). tether cannot intercept MCP tool calls via the plugin path. For MCP protection with opencode, configure the `tether-mcp-proxy` as a wrapper for your MCP servers.
- `tool.execute.before/after` does **not** fire for subagent tool calls (opencode issue #5894). Subagent activity is recorded from the `event` handler, but block-level enforcement on subagent tools is not available.
- The shim adds ~5–10 ms per tool call due to the `spawnSync` overhead (process fork + Rust startup). For low-latency workloads, the ONNX tier should be disabled when using opencode.

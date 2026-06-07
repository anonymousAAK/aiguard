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
    const r = call("post", { tool: input.tool, args: output.args ?? null,
      output: output.output, metadata: output.metadata, project: ctx.project })
    if (r.stdout) {
      const o = JSON.parse(r.stdout)
      if (o.updatedOutput) output.output = o.updatedOutput
    }
  },
  "permission.ask": async (perm, out) => {
    const r = call("permission", { perm })
    if (r.code === 0 && r.stdout) {
      const o = JSON.parse(r.stdout)
      if (o.status) out.status = o.status
    }
  },
})

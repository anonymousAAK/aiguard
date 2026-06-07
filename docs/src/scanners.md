# Scanners

tether ships three built-in scanners. Each runs as a stage in the tool-call pipeline and returns one of four verdicts: `Pass`, `Warn`, `Mutate`, or `Block`. Verdicts are aggregated with the precedence rule `Block > Mutate > Warn > Pass`.

## Prompt injection scanner

```toml
[scanners.prompt_injection]
enabled = true
threshold = 0.7
action = "warn"          # warn | block | redact
# extra_signatures = [
#     "(?i)ignore previous instructions",
#     "(?i)you are now",
# ]
```

The prompt-injection scanner uses a three-tier pipeline. Each tier is independent; higher tiers are opt-in.

### Tier 1: Regex (always on)

A library of 120+ regex patterns matched against every tool output using the Aho-Corasick algorithm for near-zero latency (~0.5 ms per KB). The ruleset covers every named attack template in the AgentDojo benchmark corpus (Debenedetti et al., NeurIPS 2024, arXiv:2406.13352v3 — 97 tasks, 629 security test cases), plus:

- "Ignore previous instructions" and variants
- `<important_message>` / `<IMPORTANT>` XML-tag injection (AgentDojo canonical `ImportantInstructionsAttack`)
- InjecAgent canonical override prompts
- WASP benchmark patterns
- Base64-encoded instruction payloads
- Zero-width Unicode steganography (Unicode ranges `U+200B–U+200F`, `U+202A–U+202E`, `U+FEFF`)
- MCP tool-description poisoning patterns (Invariant Labs taxonomy): SSH key exfiltration instructions, wallet-draining tool descriptions, cross-tool escalation patterns

Rules are stored in `data/pi-rules.toml` alongside the binary. You can append custom signatures without recompiling:

```toml
[scanners.prompt_injection]
extra_signatures = [
    "(?i)disregard all safety guidelines",
    "(?i)pretend you are",
]
```

### Tier 2: ONNX model (opt-in)

```toml
[scanners.prompt_injection]
tier_model = true
model_path = "~/.local/share/tether/models/pi-v2.onnx"
threshold = 0.85
```

Downloads and runs the ProtectAI `deberta-v3-base-prompt-injection-v2` model locally via the `ort` crate. The model card reports Accuracy: 95.25%, Precision: 91.59%, Recall: 99.74%, F1: 95.49% on a post-training evaluation set of 20,000 prompts.

Download the model with:

```sh
tether models pull pi-detector
```

The model is ~440 MB and runs on CPU. Inference takes 30–80 ms per 512-token chunk. Tool responses longer than 512 tokens are split into overlapping windows; the maximum score across windows is used.

### Tier 3: LLM judge (opt-in)

```toml
[scanners.prompt_injection.llm_judge]
enabled = true
provider = "anthropic"        # anthropic | openai | ollama
model = "claude-haiku-4"
api_key_env = "ANTHROPIC_API_KEY"
budget_usd_per_day = 1.00
```

Sends the tool output to a small LLM with a structured judge prompt. Catches adversarial paraphrases and encoded payloads that slip past Tier 1 and Tier 2. At Haiku pricing this costs roughly $0.0002 per call. The `budget_usd_per_day` cap disables the tier gracefully if the daily budget is exhausted.

### Combined effectiveness

Per Debenedetti et al. (NeurIPS 2024, arXiv:2406.13352v3): when deploying a secondary attack detector such as the ProtectAI DeBERTa model, the attack success rate in AgentDojo drops to approximately **8%**. tether targets this floor as its baseline. Tier 3 (LLM judge) can reduce residual risk further but introduces latency and API cost.

---

## Secrets scanner

```toml
[scanners.secrets]
enabled = true
action = "block"         # warn | block | redact
entropy_threshold = 4.5
# extra_patterns = [
#     "my-corp-token-[A-Za-z0-9]{32}",
# ]
```

Scans tool outputs, audit log entries, and replay views for credentials and other secrets. Uses a gitleaks-compatible TOML ruleset, so you can drop in your existing `gitleaks.toml` directly:

```toml
[scanners.secrets]
ruleset = "/path/to/gitleaks.toml"
```

### Built-in rules

The default ruleset ships with 52+ rules covering:

- AWS Access Key ID / Secret Access Key (`AKIA*`, `ABIA*`, `ACCA*`, `ASIA*`)
- Anthropic API keys (`sk-ant-api*`, `sk-ant-admin*`)
- OpenAI API keys (`sk-proj-*`, `sk-svcacct-*`)
- GitHub tokens (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*`)
- Slack webhook URLs and bot tokens
- Stripe secret keys
- Private key blocks (`-----BEGIN RSA PRIVATE KEY-----`, etc.)
- Generic high-entropy patterns (configurable entropy floor)

### Entropy gating

Each rule can specify an entropy floor. Strings that match the regex but have Shannon entropy below the threshold are ignored — this suppresses documentation examples like `AKIAIOSFODNN7EXAMPLE` (entropy ≈ 3.0) while catching real 20-character random keys (entropy ≈ 4.5+).

```toml
[scanners.secrets]
entropy_threshold = 4.5   # range ~3.0–6.0; higher = fewer false positives
```

### Actions

- `"block"` — refuse to return the tool response to the model. The agent sees a system message explaining that a secret was detected.
- `"redact"` — replace matched secrets with `[REDACTED:<rule-id>]` before returning output to the model. The raw value is never written to the audit log.
- `"warn"` — log the match and return the output unchanged.

Default: `"block"` for tool outputs, `"redact"` in audit logs.

### Custom rules

```toml
[[redact.patterns]]
name = "corp_api_key"
regex = "CORP-[A-Z0-9]{24}"

[scanners.secrets]
extra_patterns = ["~/.config/tether/secrets-extra.toml"]
```

---

## MCP scanner

```toml
[scanners.mcp]
enabled = true
action = "warn"
# allowed_servers = ["filesystem", "memory"]
# denied_tools = ["execute_raw_sql", "shell_exec"]
```

The MCP scanner has two phases: static audit at server-load time and runtime guardrails during sessions. See [MCP Audit](./mcp-audit.md) for the full threat model and configuration details.

### Static audit

When a new MCP server is added (`tether mcp add <server>` or detected via `tether init`), tether:

1. Fetches the server's `tools/list` response.
2. Scans every tool name, description, and parameter schema against the Tier-1 regex ruleset for poisoning patterns.
3. Computes a SHA-256 of the `tools/list` response and stores it as a pin under `~/.local/share/tether/mcp-pins/`.
4. Flags any remote server that responds to `tools/call` without authentication.

### Runtime guardrails

During an active session:

- All `mcp__<server>__<tool>` calls are subject to the same `[tools.deny]` rules as shell commands.
- On each session start, tether re-hashes `tools/list` and refuses to load the server if the hash differs from the stored pin (rug-pull defense).
- Cross-origin escalation: if a tool description from `mcp_A` references `mcp_B`, tether emits a warning.

### `denied_tools`

Specific MCP tool names that are always blocked regardless of server:

```toml
[scanners.mcp]
denied_tools = ["execute_raw_sql", "shell_exec", "eval_js"]
```

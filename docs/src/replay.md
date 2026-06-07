# Replay

`aiguard replay` opens a terminal UI for reviewing any recorded session. Every tool call, scanner verdict, and timing measurement from the audit log is navigable in a three-pane layout.

## Opening a session

```sh
# Open the most recent session
aiguard replay --last

# Open a specific session by ID
aiguard replay abc123def456

# Open the session picker (lists all recorded sessions)
aiguard replay
```

## TUI layout

```
+-------------- aiguard replay * session abc123 * 2026-05-23 14:02 -------------+
| Timeline (j/k)                  | Event detail (</=)              | Verdict   |
+----------------------------------+---------------------------------+-----------+
| 14:02:01 SessionStart            | tool: Bash                      | ALLOW     |
| 14:02:14 UserPromptSubmit        | command: rg --json "TODO"       |           |
| 14:02:15 PreToolUse Bash         |                                 |           |
| 14:02:15 PostToolUse Bash        | scanners:                       |           |
| 14:02:22 PreToolUse Edit  (!)    |   prompt_injection: pass        |           |
| 14:02:22 PostToolUse Edit        |   secrets:          pass        |           |
| 14:02:30 PreToolUse mcp__db__q.. |   policy:           pass        |           |
| 14:02:30 PreToolUse Bash  [X]    |                                 |           |
| 14:02:35 Stop                    | duration: 4.3 ms                |           |
+----------------------------------+---------------------------------+-----------+
 [r] re-run scanner   [e] export  [c] copy event id   [q] quit
```

The `(!)` marker indicates a warning verdict; `[X]` indicates a blocked tool call.

## Key bindings

| Key | Action |
|---|---|
| `j` / `k` | Move down / up in the timeline |
| `Arrow left/right` | Navigate between panes |
| `Enter` | Expand an event to show full payload |
| `r` | Re-run all scanners against the selected event with current config |
| `e` | Export current session as JSONL to stdout |
| `/` | Open filter input to search events by tool name, verdict, or text |
| `c` | Copy the selected event's ID to the clipboard |
| `s` | Toggle secret masking on/off in the detail pane |
| `q` / `Ctrl-C` | Quit |

## Pane descriptions

**Timeline (left pane)**

A chronological list of all events in the session. Each row shows:
- Timestamp (HH:MM:SS)
- Event type (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`)
- Tool name (for tool events)
- Verdict badge: `(!)` for warn, `[X]` for block, blank for allow

**Event detail (center pane)**

Full details of the selected event:
- Tool name and input (formatted JSON, truncated to 2000 chars by default)
- Scanner results: each scanner's verdict, score, and matched rule IDs
- Redaction summary: how many secret hits were found and which rule IDs fired
- Processing duration in milliseconds

**Verdict (right pane)**

The final aggregated verdict for the selected event, plus the `default_action` that was in effect at the time.

## Exporting

Export an entire session as JSONL:

```sh
aiguard replay --last --export > session.jsonl
```

Export a single event by ID:

```sh
aiguard replay --event abc123def456-0042 --export
```

The JSONL format matches the audit log schema, so you can pipe it into `jq` or any JSONL-aware tool:

```sh
aiguard replay --last --export | jq 'select(.decision == "block")'
```

## Audit log location

By default, audit data is stored at:

- JSONL: `~/.local/share/aiguard/audit/YYYY-MM-DD.jsonl`
- SQLite: `~/.local/share/aiguard/aiguard.db`

You can change these paths in `aiguard.toml`:

```toml
[logging]
audit_dir = "~/.local/share/aiguard/audit"
sqlite_path = "~/.local/share/aiguard/aiguard.db"
retention_days = 90
```

## Session replay config

```toml
[replay]
theme = "dark"          # "dark" | "light"
mask_secrets = true     # mask secrets in the detail pane by default
# default_session = "abc123"  # pre-select this session on open
```

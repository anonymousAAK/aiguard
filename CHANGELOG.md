# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core policy engine with Scanner trait and Decision algebra
- Shell-hook adapter supporting Claude Code, Codex, Gemini CLI, Crush, and Cline
- Prompt-injection scanner (Tier-1 regex with 80+ rules)
- Secret detection scanner (52 gitleaks-compatible rules with entropy gating)
- MCP server auditor with tool-pinning, rug-pull detection, and cross-origin scanning
- MCP stdio proxy for agents without lifecycle hooks (Aider, Goose)
- Filesystem watcher for Aider write detection
- Goose config registration
- Session replay TUI (ratatui)
- Dual-write audit log (SQLite + JSONL)
- Example config (`tether.toml.example`)

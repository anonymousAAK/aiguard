# Contributing to tether

Thank you for your interest in contributing to tether!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/tether`
3. Install Rust (MSRV 1.85): `rustup install 1.85`
4. Run the test suite: `cargo test --workspace`

## Development

```sh
# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets -- -Dwarnings

# Check formatting
cargo fmt --all -- --check

# Update insta snapshots (after intentional changes)
cargo insta review
```

## Pull Requests

- One logical change per PR
- Add tests for new functionality
- Run `cargo test --workspace` and `cargo clippy` before submitting
- Update snapshot tests with `cargo insta review` if normalizer wire formats change
- Keep commit messages concise and descriptive

## Architecture

tether is a Rust workspace with 11 crates:

| Crate | Purpose |
|---|---|
| `tether-core` | Policy engine, Scanner trait, audit log, config |
| `tether-cli` | CLI entry point (clap) |
| `tether-adapter-shellhook` | Shell-hook adapter for 5 agents |
| `tether-adapter-opencode` | opencode TS plugin shim |
| `tether-adapter-aider` | Aider filesystem watcher + config |
| `tether-adapter-goose` | Goose config registration |
| `tether-scanner-prompt-injection` | Regex + ONNX prompt-injection detection |
| `tether-scanner-mcp` | MCP tool-pinning and audit |
| `tether-scanner-secrets` | Gitleaks-compatible secret detection |
| `tether-replay` | Ratatui session replay TUI |
| `tether-mcp-proxy` | MCP stdio JSON-RPC proxy |

## Code of Conduct

Be respectful. We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## License

By contributing, you agree that your contributions will be licensed under
Apache-2.0 OR MIT, at the user's choice.

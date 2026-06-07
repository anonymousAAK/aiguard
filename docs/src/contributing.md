# Contributing to aiguard

Thank you for your interest in contributing to aiguard!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/aiguard`
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

aiguard is a Rust workspace with 11 crates:

| Crate | Purpose |
|---|---|
| `aiguard-core` | Policy engine, Scanner trait, audit log, config |
| `aiguard` (cli) | CLI entry point (clap) |
| `aiguard-adapter-shellhook` | Shell-hook adapter for 5 agents |
| `aiguard-adapter-opencode` | opencode TS plugin shim |
| `aiguard-adapter-aider` | Aider filesystem watcher + config |
| `aiguard-adapter-goose` | Goose config registration |
| `aiguard-scanner-prompt-injection` | Regex + ONNX prompt-injection detection |
| `aiguard-scanner-mcp` | MCP tool-pinning and audit |
| `aiguard-scanner-secrets` | Gitleaks-compatible secret detection |
| `aiguard-replay` | Ratatui session replay TUI |
| `aiguard-mcp-proxy` | MCP stdio JSON-RPC proxy |

## Code of Conduct

Be respectful. We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## License

By contributing, you agree that your contributions will be licensed under
Apache-2.0 OR MIT, at the user's choice.

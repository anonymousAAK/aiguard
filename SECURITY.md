# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest release | Yes |
| older releases | No |

## Reporting a Vulnerability

If you discover a security vulnerability in aiguard, please report it responsibly.

**Do not open a public issue.**

Instead, email: **security@aiguard.sh** (or open a private security advisory on GitHub).

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

aiguard is a defense-in-depth layer. It reduces risk but does not eliminate prompt injection or other attacks. See Debenedetti et al., NeurIPS 2024 (arXiv:2406.13352v3) for residual attack rates even with secondary detectors.

In-scope vulnerabilities:
- Bypass of deny rules (shell patterns, path patterns)
- Bypass of secret redaction
- Bypass of prompt-injection detection
- Audit log tampering or omission
- MCP proxy forwarding issues that skip scanning

Out of scope:
- Vulnerabilities in upstream agents (Claude Code, Codex, etc.)
- Vulnerabilities in MCP servers themselves
- Social engineering attacks against the user

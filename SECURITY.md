# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Surfinguard, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

Email **security@surfinguard.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity (critical: 7 days, high: 14 days, medium: 30 days)

### Scope

In scope:
- `@surfinguard/core-engine` — pattern bypass, false negatives for known threats
- `@surfinguard/sdk` — credential handling, telemetry privacy
- Pattern databases — missing threat coverage
- Rust engine (`engine/`) — memory safety, WASM sandboxing

Out of scope:
- Denial of service attacks against the hosted API
- Social engineering
- Issues in third-party dependencies (report upstream)

### Recognition

We credit security researchers who report valid vulnerabilities (with permission) in our release notes.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | Best effort |

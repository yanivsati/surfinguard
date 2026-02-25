# Surfinguard

[![CI](https://github.com/yanivsati/surfinguard/actions/workflows/ci.yml/badge.svg)](https://github.com/yanivsati/surfinguard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@surfinguard/sdk)](https://www.npmjs.com/package/@surfinguard/sdk)
[![PyPI](https://img.shields.io/pypi/v/surfinguard)](https://pypi.org/project/surfinguard/)
[![Tests](https://img.shields.io/badge/tests-2549-brightgreen)](#testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**The independent trust layer for AI agents.** Analyze any agent action against 5 risk primitives before it executes.

## What It Does

Surfinguard scores AI agent actions (URLs, commands, text prompts, file operations, API calls, database queries, code execution, and 10 more action types) against **152 threat patterns** across **5 risk primitives**:

| Primitive | What it catches |
|-----------|----------------|
| **DESTRUCTION** | `rm -rf /`, DROP TABLE, force-push to main, production namespace deletion |
| **EXFILTRATION** | SSH key access, credential forwarding, data export to unknown endpoints |
| **ESCALATION** | Privilege elevation, admin grants, container escape, sudo abuse |
| **PERSISTENCE** | Crontab injection, SSH authorized_keys, shell config modification |
| **MANIPULATION** | Prompt injection, goal hijacking, contract tampering, context poisoning |

**Scoring**: `SAFE` (0-2) | `CAUTION` (3-6) | `DANGER` (7-10)

## Quick Start

```bash
npm install @surfinguard/core-engine @surfinguard/types
```

```typescript
import { CoreEngine } from '@surfinguard/core-engine';

const engine = new CoreEngine();

// Check a URL
const result = engine.check({ type: 'url', value: 'https://g00gle-login.tk/verify' });
// → { score: 9, level: 'DANGER', reasons: ['Brand impersonation', 'Risky TLD'], ... }

// Check a command
const cmd = engine.check({ type: 'command', value: 'rm -rf / --no-preserve-root' });
// → { score: 10, level: 'DANGER', primitive: 'DESTRUCTION', ... }

// Check for prompt injection
const text = engine.check({ type: 'text', value: 'Ignore all previous instructions...' });
// → { score: 9, level: 'DANGER', primitive: 'MANIPULATION', ... }
```

## Packages

| Package | Description | npm |
|---------|-------------|-----|
| [`@surfinguard/sdk`](sdks/js/) | JS/TS SDK with dual local/API mode | [![npm](https://img.shields.io/npm/v/@surfinguard/sdk)](https://www.npmjs.com/package/@surfinguard/sdk) |
| [`@surfinguard/core-engine`](packages/core-engine/) | Heuristic scoring engine — 18 analyzers, 152 threats | [![npm](https://img.shields.io/npm/v/@surfinguard/core-engine)](https://www.npmjs.com/package/@surfinguard/core-engine) |
| [`@surfinguard/core-engine-wasm`](packages/core-engine-wasm/) | WASM-powered engine for near-native performance | [![npm](https://img.shields.io/npm/v/@surfinguard/core-engine-wasm)](https://www.npmjs.com/package/@surfinguard/core-engine-wasm) |
| [`@surfinguard/types`](packages/shared-types/) | Shared TypeScript type definitions | [![npm](https://img.shields.io/npm/v/@surfinguard/types)](https://www.npmjs.com/package/@surfinguard/types) |
| [`@surfinguard/compliance`](packages/compliance/) | EU AI Act compliance assessment | [![npm](https://img.shields.io/npm/v/@surfinguard/compliance)](https://www.npmjs.com/package/@surfinguard/compliance) |
| [`@surfinguard/cli`](apps/cli/) | CLI — check actions from the terminal | [![npm](https://img.shields.io/npm/v/@surfinguard/cli)](https://www.npmjs.com/package/@surfinguard/cli) |
| [`@surfinguard/mcp-server`](apps/mcp-server/) | MCP server for Claude/Cursor integration | [![npm](https://img.shields.io/npm/v/@surfinguard/mcp-server)](https://www.npmjs.com/package/@surfinguard/mcp-server) |
| [`surfinguard`](sdks/python/) | Python SDK (PyPI) | [![PyPI](https://img.shields.io/pypi/v/surfinguard)](https://pypi.org/project/surfinguard/) |
| [`threat-corpus`](threat-corpus/) | Test data: malicious + benign samples across all action types | — |

## 18 Analyzers

| Analyzer | Threats | Examples |
|----------|---------|----------|
| URL | U01-U14 | Phishing, brand impersonation, risky TLDs, IP addresses, data URIs |
| Command | C01-C20 | rm -rf, pipe-to-shell, reverse shells, fork bombs, encoded commands |
| Text | P01-P12 | Prompt injection, goal hijacking, persona manipulation, encoding evasion |
| File Read | FR01-FR10 | SSH keys, AWS credentials, .env files, browser data |
| File Write | FW01-FW12 | Crontab, authorized_keys, git hooks, shell config |
| API Call | A01-A10 | SSRF, credential forwarding, destructive methods, webhooks |
| Query | D01-D07 | SQL injection, DROP/TRUNCATE, UNION exfiltration |
| Code | G01-G08 | eval injection, backdoors, cryptomining, obfuscated payloads |
| Message | M01-M06 | Data exfiltration, CEO fraud, impersonation |
| Transaction | T01-T06 | Unauthorized transfers, money laundering, inflated amounts |
| Auth | ID01-ID06 | Privilege escalation, MFA bypass, credential exposure |
| Git | V01-V06 | Force push, CI/CD injection, branch deletion |
| UI Action | UI01-UI06 | Destructive clicks, auto-accept dialogs, malicious downloads |
| Infra | I01-I06, CL01-CL06 | Container escape, IaC tampering, IAM escalation |
| Agent Comm | MA01-MA04 | Malicious delegation, context poisoning, tool abuse |
| Data Pipeline | ML01-ML05 | Model poisoning, training data alteration, dataset export |
| Document | DC01-DC04 | Contract tampering, financial modification, public disclosure |
| IoT | IOT01-IOT04 | Lock manipulation, industrial control, vehicle injection |

## Architecture

```
Input Action
    │
    ▼
┌─────────────┐
│  CoreEngine │  ← Pattern databases (JSON)
│  18 analyzers│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Scorer    │  Within-primitive: additive (capped at 10)
│             │  Composite: max(primitive_scores)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Verdict   │  SAFE (0-2) | CAUTION (3-6) | DANGER (7+)
└─────────────┘
```

## Development

```bash
# Install
pnpm install

# Build all packages
pnpm turbo build

# Run all tests
pnpm turbo test

# Lint
pnpm turbo lint

# Format
pnpm format
```

## Rust Engine

A Rust port of the core engine is available at [`engine/`](engine/) for native performance:

```bash
cd engine && cargo build --release
cd engine && cargo test
```

Produces: native library, WASM module, Python bindings (via maturin), and C FFI.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, analyzers, and submit PRs.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT

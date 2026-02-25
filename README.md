# Surfinguard

[![npm](https://img.shields.io/npm/v/@surfinguard/sdk)](https://www.npmjs.com/package/@surfinguard/sdk)
[![PyPI](https://img.shields.io/pypi/v/surfinguard)](https://pypi.org/project/surfinguard/)
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

### JS/TS SDK

```bash
npm install @surfinguard/sdk
```

```typescript
import { Guard } from '@surfinguard/sdk';

// API mode — uses Surfinguard cloud API
const guard = new Guard({ apiKey: 'sg_live_...' });

const result = await guard.checkUrl('https://g00gle-login.tk/verify');
// → { score: 9, level: 'DANGER', reasons: ['Brand impersonation', 'Risky TLD'], ... }

const cmd = await guard.checkCommand('rm -rf / --no-preserve-root');
// → { score: 10, level: 'DANGER', primitive: 'DESTRUCTION', ... }

const text = await guard.checkText('Ignore all previous instructions...');
// → { score: 9, level: 'DANGER', primitive: 'MANIPULATION', ... }
```

### Python SDK

```bash
pip install surfinguard
```

```python
from surfinguard import Guard

guard = Guard(api_key="sg_live_...")

result = guard.check_url("https://g00gle-login.tk/verify")
# → CheckResult(score=9, level='DANGER', reasons=['Brand impersonation', ...])
```

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| [`@surfinguard/sdk`](sdks/js/) | JS/TS SDK — dual local/API mode, Express & Next.js integrations | `npm i @surfinguard/sdk` |
| [`@surfinguard/types`](packages/shared-types/) | Shared TypeScript type definitions | `npm i @surfinguard/types` |
| [`surfinguard`](https://pypi.org/project/surfinguard/) | Python SDK — Guard class, LangChain/CrewAI/AutoGen integrations | `pip install surfinguard` |
| `@surfinguard/core-engine` | Heuristic scoring engine — 18 analyzers, 152 threats | `npm i @surfinguard/core-engine` |
| `@surfinguard/cli` | CLI — check actions from the terminal | `npx @surfinguard/cli check <url>` |
| `@surfinguard/mcp-server` | MCP server for Claude/Cursor integration | `npx @surfinguard/mcp-server` |

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add patterns, analyzers, and submit PRs.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT

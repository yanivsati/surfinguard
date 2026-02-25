# @surfinguard/sdk

The trust layer for AI agents. Protect your AI agents from executing dangerous actions — phishing URLs, destructive commands, prompt injection, and sensitive file access.

## Installation

```bash
npm install @surfinguard/sdk
```

## Quick Start

### Local Mode (Zero-Latency)

Runs the heuristic engine directly in your process — no network calls, no API key needed:

```typescript
import { Guard } from '@surfinguard/sdk';

const guard = new Guard({ mode: 'local' });

// Check a URL
const result = guard.checkUrl('https://paypa1.com/login');
console.log(result.level);   // 'DANGER'
console.log(result.score);   // 9
console.log(result.reasons); // ['Brand impersonation: paypal']

// Check a command
const cmd = guard.checkCommand('rm -rf /');
console.log(cmd.level); // 'DANGER'

// Check text for prompt injection
const text = guard.checkText('Ignore all previous instructions');
console.log(text.level); // 'DANGER'

// Check file operations
const file = guard.checkFileRead('~/.ssh/id_rsa');
console.log(file.primitive); // 'EXFILTRATION'
```

### API Mode (LLM-Enhanced)

Uses the Surfinguard API for cloud-based analysis with optional LLM enhancement:

```typescript
import { Guard } from '@surfinguard/sdk';

const guard = new Guard({
  mode: 'api',
  apiKey: 'sg_live_...',
});

// All methods return Promises in API mode
const result = await guard.checkUrl('https://suspicious-site.xyz/login');
console.log(result.level);
```

## Policy Enforcement

The SDK can automatically block dangerous actions:

```typescript
import { Guard, NotAllowedError } from '@surfinguard/sdk';

// MODERATE (default): blocks DANGER, allows SAFE and CAUTION
const guard = new Guard({ mode: 'local', policy: 'moderate' });

// STRICT: blocks CAUTION and DANGER, only allows SAFE
const strict = new Guard({ mode: 'local', policy: 'strict' });

// PERMISSIVE: never blocks, returns results only
const permissive = new Guard({ mode: 'local', policy: 'permissive' });

try {
  guard.checkCommand('rm -rf /');
} catch (e) {
  if (e instanceof NotAllowedError) {
    console.log(`Blocked: ${e.result.level} (score=${e.result.score})`);
  }
}
```

## All Check Methods

| Method | Action Type | Input |
|--------|------------|-------|
| `checkUrl(url)` | URL | URL string |
| `checkCommand(command)` | Command | Shell command |
| `checkText(text)` | Text | Free text / prompt |
| `checkFileRead(path)` | File Read | File path |
| `checkFileWrite(path, content?)` | File Write | Path + optional content |
| `check(type, value, metadata?)` | Any | Universal check |

## CheckResult

Every check returns a `CheckResult`:

```typescript
interface CheckResult {
  allow: boolean;                // Should the action be allowed?
  score: number;                 // 0-10 risk score
  level: RiskLevel;              // 'SAFE', 'CAUTION', or 'DANGER'
  primitive: RiskPrimitive;      // Dominant risk primitive
  primitive_scores: PrimitiveScore[];  // Per-primitive breakdown
  reasons: string[];             // Human-readable explanations
  alternatives: string[];        // Safer alternatives (if any)
  latency_ms: number;            // Analysis time
}
```

## Express Integration

```typescript
import express from 'express';
import { Guard } from '@surfinguard/sdk';
import { surfinguardMiddleware } from '@surfinguard/sdk/express';

const app = express();
const guard = new Guard({ mode: 'local', policy: 'moderate' });

// Auto-infers action type from request body
app.post('/execute', surfinguardMiddleware({ guard }), (req, res) => {
  // req.surfinguard contains the CheckResult
  res.json({ allowed: true, risk: req.surfinguard });
});

// Custom value extraction
app.post('/run', surfinguardMiddleware({
  guard,
  actionType: 'command',
  extractValue: (req) => req.body.cmd,
}), handler);
```

## Next.js Integration

```typescript
import { Guard } from '@surfinguard/sdk';
import { withSurfinguard } from '@surfinguard/sdk/nextjs';

const guard = new Guard({ mode: 'local', policy: 'moderate' });

// Wrap your API route
export default withSurfinguard(guard, async (req, res) => {
  // req.surfinguard contains the CheckResult
  res.json({ result: req.surfinguard });
});
```

## Error Handling

```typescript
import {
  SurfinguardError,     // Base error class
  AuthenticationError,  // Invalid API key (401)
  RateLimitError,       // Rate limit exceeded (429)
  APIError,             // Server error (4xx/5xx)
  NotAllowedError,      // Policy blocked action — has .result
} from '@surfinguard/sdk';
```

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| SAFE | 0-2 | No risk detected |
| CAUTION | 3-6 | Potential risk, review recommended |
| DANGER | 7-10 | High risk, action should be blocked |

## Risk Primitives

| Primitive | Description |
|-----------|-------------|
| DESTRUCTION | Data loss, system damage |
| EXFILTRATION | Data theft, credential access |
| ESCALATION | Privilege escalation |
| PERSISTENCE | Backdoor installation, startup modification |
| MANIPULATION | Phishing, prompt injection, deception |

## License

MIT

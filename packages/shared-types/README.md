# @surfinguard/types

Shared TypeScript type definitions for the [Surfinguard](https://surfinguard.com) AI Security SDK.

## Installation

```bash
npm install @surfinguard/types
```

> **Note:** Most users should install `@surfinguard/sdk` instead, which re-exports all types.

## Exports

### Action Types

- `ActionType` — `'url' | 'command' | 'text' | 'file_read' | 'file_write'`
- `ActionInput` — Input payload for an action check
- `ActionContext` — Optional metadata context

### Verdict Types

- `RiskPrimitive` — `'DESTRUCTION' | 'EXFILTRATION' | 'ESCALATION' | 'PERSISTENCE' | 'MANIPULATION'`
- `RiskLevel` — `'SAFE' | 'CAUTION' | 'DANGER'`
- `PrimitiveScore` — Per-primitive score breakdown
- `CheckResult` — Full result of a security check

### Policy Types

- `PolicyLevel` — `'permissive' | 'moderate' | 'strict'`
- `PolicyRule`, `Policy`

### Pattern Database Interfaces

- `ThreatDefinition`, `UrlPatternDatabase`, `BrandEntry`, `BrandPatternDatabase`
- `CommandPatternDatabase`, `TextPatternDatabase`
- `SensitivePathEntry`, `FileReadPatternDatabase`
- `FileWritePathEntry`, `ContentPatternEntry`, `FileWritePatternDatabase`

## License

MIT

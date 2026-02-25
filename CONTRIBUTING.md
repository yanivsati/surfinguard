# Contributing to Surfinguard

Thank you for your interest in contributing to the Surfinguard AI security platform.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/surfinguard.git
   cd surfinguard
   ```
3. **Install dependencies**:
   ```bash
   pnpm install
   ```
4. **Build**:
   ```bash
   pnpm turbo build
   ```
5. **Run tests**:
   ```bash
   pnpm turbo test
   ```

## Adding Threat Patterns

Pattern databases are versioned JSON files in `packages/core-engine/patterns/`. Each file covers one action type.

### Steps

1. Open the relevant pattern file (e.g., `urls.json`, `commands.json`)
2. Add your pattern following the existing format
3. Add test cases to the threat corpus (`threat-corpus/`)
4. Run tests to verify: `pnpm turbo test`

### Pattern Format

```json
{
  "id": "U15",
  "name": "your-pattern-name",
  "description": "What this pattern detects",
  "primitive": "EXFILTRATION",
  "score": 5,
  "patterns": ["regex1", "regex2"],
  "matchType": "regex"
}
```

## Adding Analyzers

Analyzers live in `packages/core-engine/src/analyzers/`. Each analyzer:

1. Loads its pattern database from `patterns/`
2. Implements `analyze(input)` returning `PrimitiveScore[]`
3. Is registered in `CoreEngine`
4. Has corresponding tests in `tests/`

## Code Style

- TypeScript with strict mode
- ESM-only (no CommonJS)
- Format with Prettier: `pnpm format`
- Lint with ESLint: `pnpm turbo lint`

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Ensure all tests pass: `pnpm turbo test`
4. Ensure code is formatted: `pnpm format`
5. Submit a PR with a clear description

### PR Checklist

- [ ] Tests added/updated for new functionality
- [ ] All existing tests pass
- [ ] Code formatted with Prettier
- [ ] Threat corpus updated if adding patterns
- [ ] No secrets or credentials in the diff

## Reporting Issues

Use [GitHub Issues](https://github.com/yanivsati/surfinguard/issues) with the provided templates.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

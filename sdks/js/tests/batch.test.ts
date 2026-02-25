import { describe, it, expect } from 'vitest';
import { Guard } from '../src/guard.js';

describe('checkBatch (local mode)', () => {
  it('returns batch results', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch([
      { type: 'url', value: 'https://google.com' },
      { type: 'command', value: 'ls -la' },
    ]) as any;

    expect(result.results).toHaveLength(2);
    expect(result.sessionId).toBeDefined();
    expect(result.overallLevel).toBe('SAFE');
    expect(result.overallScore).toBe(0);
    expect(result.chainDetections).toBeDefined();
  });

  it('computes correct overall level', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch([
      { type: 'url', value: 'https://google.com' },
      { type: 'command', value: 'rm -rf /' },
    ]) as any;

    expect(result.overallLevel).toBe('DANGER');
    expect(result.overallScore).toBeGreaterThanOrEqual(7);
  });

  it('uses custom sessionId', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch(
      [{ type: 'url', value: 'https://google.com' }],
      { sessionId: 'my-batch-session' },
    ) as any;
    expect(result.sessionId).toBe('my-batch-session');
  });

  it('sequential mode includes risk trend', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch(
      [
        { type: 'url', value: 'https://google.com' },
        { type: 'command', value: 'rm -rf /' },
      ],
      { sequential: true },
    ) as any;

    expect(result.results[1].riskTrend).toBeDefined();
  });

  it('enforces policy on batch results', () => {
    const guard = new Guard({ mode: 'local', policy: 'moderate' });
    expect(() => {
      guard.checkBatch([
        { type: 'url', value: 'https://google.com' },
        { type: 'command', value: 'rm -rf /' },
      ]);
    }).toThrow();
  });

  it('handles all action types', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch([
      { type: 'url', value: 'https://google.com' },
      { type: 'command', value: 'ls' },
      { type: 'text', value: 'hello' },
      { type: 'query', value: 'SELECT 1' },
    ]) as any;

    expect(result.results).toHaveLength(4);
    expect(result.results.every((r: any) => r.level === 'SAFE')).toBe(true);
  });

  it('empty batch returns correct defaults', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkBatch([]) as any;
    expect(result.results).toHaveLength(0);
    expect(result.overallScore).toBe(0);
    expect(result.overallLevel).toBe('SAFE');
  });
});

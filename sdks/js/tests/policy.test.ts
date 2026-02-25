import { describe, it, expect } from 'vitest';
import { Guard } from '../src/guard.js';
import { NotAllowedError } from '../src/errors.js';
import type { CheckResult } from '@surfinguard/types';

describe('Policy enforcement (local mode)', () => {
  // ── PERMISSIVE ─────────────────────────────────────────────────

  it('permissive allows SAFE', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkUrl('https://www.google.com') as CheckResult;
    expect(result.level).toBe('SAFE');
  });

  it('permissive allows DANGER without throwing', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const result = guard.checkCommand('rm -rf /') as CheckResult;
    expect(result.level).toBe('DANGER');
    // No error thrown
  });

  it('permissive allows CAUTION without throwing', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    // A URL with a risky TLD that scores in CAUTION range
    const result = guard.checkUrl('https://example.xyz') as CheckResult;
    // Should not throw regardless of level
  });

  // ── MODERATE ───────────────────────────────────────────────────

  it('moderate allows SAFE', () => {
    const guard = new Guard({ mode: 'local', policy: 'moderate' });
    const result = guard.checkUrl('https://www.google.com') as CheckResult;
    expect(result.level).toBe('SAFE');
  });

  it('moderate blocks DANGER', () => {
    const guard = new Guard({ mode: 'local', policy: 'moderate' });
    expect(() => guard.checkCommand('rm -rf /')).toThrow(NotAllowedError);
  });

  it('moderate allows CAUTION', () => {
    const guard = new Guard({ mode: 'local', policy: 'moderate' });
    // Use a URL that triggers only mild suspicion (risky TLD)
    const result = guard.checkUrl('https://example.tk') as CheckResult;
    // CAUTION (3-6) should not throw; SAFE is also fine
    expect(['SAFE', 'CAUTION']).toContain(result.level);
  });

  // ── STRICT ─────────────────────────────────────────────────────

  it('strict allows SAFE', () => {
    const guard = new Guard({ mode: 'local', policy: 'strict' });
    const result = guard.checkUrl('https://www.google.com') as CheckResult;
    expect(result.level).toBe('SAFE');
  });

  it('strict blocks DANGER', () => {
    const guard = new Guard({ mode: 'local', policy: 'strict' });
    expect(() => guard.checkCommand('rm -rf /')).toThrow(NotAllowedError);
  });

  it('strict blocks CAUTION', () => {
    const guard = new Guard({ mode: 'local', policy: 'strict' });
    // Use a URL that triggers CAUTION or DANGER — either should throw
    try {
      const result = guard.checkUrl('https://example.tk') as CheckResult;
      // If SAFE, strict allows it
      expect(result.level).toBe('SAFE');
    } catch (error) {
      expect(error).toBeInstanceOf(NotAllowedError);
    }
  });
});

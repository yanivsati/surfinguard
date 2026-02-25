import { describe, it, expect } from 'vitest';
import { SurfinguardError, AuthenticationError, RateLimitError, APIError, NotAllowedError } from '../src/errors.js';
import type { CheckResult } from '@surfinguard/types';

describe('Error classes', () => {
  it('SurfinguardError is an Error', () => {
    const err = new SurfinguardError('test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(SurfinguardError);
    expect(err.name).toBe('SurfinguardError');
    expect(err.message).toBe('test');
  });

  it('AuthenticationError extends SurfinguardError', () => {
    const err = new AuthenticationError('bad key');
    expect(err).toBeInstanceOf(SurfinguardError);
    expect(err).toBeInstanceOf(AuthenticationError);
    expect(err.name).toBe('AuthenticationError');
  });

  it('RateLimitError has retryAfter', () => {
    const err = new RateLimitError('too fast', 60);
    expect(err).toBeInstanceOf(SurfinguardError);
    expect(err.retryAfter).toBe(60);
    expect(err.name).toBe('RateLimitError');
  });

  it('RateLimitError defaults retryAfter to null', () => {
    const err = new RateLimitError('too fast');
    expect(err.retryAfter).toBeNull();
  });

  it('APIError has statusCode', () => {
    const err = new APIError('Server error', 500);
    expect(err).toBeInstanceOf(SurfinguardError);
    expect(err.statusCode).toBe(500);
    expect(err.name).toBe('APIError');
  });

  it('NotAllowedError carries result', () => {
    const result: CheckResult = {
      allow: false,
      score: 9,
      level: 'DANGER',
      primitive: 'DESTRUCTION',
      primitiveScores: [{ primitive: 'DESTRUCTION', score: 9, reasons: ['bad'] }],
      reasons: ['bad'],
      latencyMs: 1,
    };
    const err = new NotAllowedError(result);
    expect(err).toBeInstanceOf(SurfinguardError);
    expect(err.result).toBe(result);
    expect(err.result.level).toBe('DANGER');
    expect(err.result.score).toBe(9);
    expect(err.name).toBe('NotAllowedError');
  });

  it('NotAllowedError message includes level and score', () => {
    const result: CheckResult = {
      allow: false,
      score: 5,
      level: 'CAUTION',
      primitive: 'ESCALATION',
      primitiveScores: [],
      reasons: [],
      latencyMs: 1,
    };
    const err = new NotAllowedError(result);
    expect(err.message).toContain('CAUTION');
    expect(err.message).toContain('5');
  });

  it('all errors have correct inheritance chain', () => {
    expect(new AuthenticationError()).toBeInstanceOf(Error);
    expect(new RateLimitError('x')).toBeInstanceOf(Error);
    expect(new APIError('x', 400)).toBeInstanceOf(Error);
  });
});

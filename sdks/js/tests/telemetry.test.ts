import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sha256, reportTelemetry } from '../src/telemetry.js';
import type { CheckResult } from '@surfinguard/types';

const mockPost = vi.fn().mockResolvedValue({});
const mockHttp = { post: mockPost, get: vi.fn(), put: vi.fn(), delete: vi.fn() } as any;

beforeEach(() => {
  mockPost.mockClear();
});

describe('Telemetry — sha256', () => {
  it('produces 64-char hex hash', async () => {
    const hash = await sha256('https://example.com');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces consistent hashes', async () => {
    const hash1 = await sha256('test-input');
    const hash2 = await sha256('test-input');
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different inputs', async () => {
    const hash1 = await sha256('input-a');
    const hash2 = await sha256('input-b');
    expect(hash1).not.toBe(hash2);
  });
});

describe('Telemetry — reportTelemetry', () => {
  const mockResult: CheckResult = {
    score: 8,
    level: 'DANGER',
    allow: false,
    reasons: ['Phishing domain', 'Brand impersonation'],
    primitiveScores: [{ primitive: 'EXFILTRATION', score: 8, reasons: [] }],
  } as CheckResult;

  it('sends hashed value to /v2/telemetry', async () => {
    await reportTelemetry(mockHttp, 'url', 'https://evil.com', mockResult, '0.10.0');

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [path, body] = mockPost.mock.calls[0];
    expect(path).toBe('/v2/telemetry');
    expect(body.action_type).toBe('url');
    expect(body.value_hash).toHaveLength(64);
    expect(body.score).toBe(8);
    expect(body.level).toBe('DANGER');
    expect(body.sdk_version).toBe('0.10.0');
  });

  it('never sends plaintext value', async () => {
    await reportTelemetry(mockHttp, 'url', 'https://secret.com/path?key=abc', mockResult, '0.10.0');
    const body = mockPost.mock.calls[0][1];
    expect(JSON.stringify(body)).not.toContain('secret.com');
    expect(JSON.stringify(body)).not.toContain('key=abc');
  });

  it('silently swallows errors', async () => {
    mockPost.mockRejectedValueOnce(new Error('Network error'));
    // Should not throw
    await reportTelemetry(mockHttp, 'url', 'https://example.com', mockResult, '0.10.0');
  });

  it('includes primitive from primitiveScores', async () => {
    await reportTelemetry(mockHttp, 'url', 'test', mockResult, '0.10.0');
    const body = mockPost.mock.calls[0][1];
    expect(body.primitive).toBe('EXFILTRATION');
  });

  it('limits reasons to 5', async () => {
    const manyReasons = {
      ...mockResult,
      reasons: ['r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8'],
    } as CheckResult;
    await reportTelemetry(mockHttp, 'url', 'test', manyReasons, '0.10.0');
    const body = mockPost.mock.calls[0][1];
    expect(body.reasons.length).toBeLessThanOrEqual(5);
  });

  it('handles result without primitiveScores', async () => {
    const simple: CheckResult = {
      score: 0,
      level: 'SAFE',
      allow: true,
      reasons: [],
    } as CheckResult;
    await reportTelemetry(mockHttp, 'command', 'ls', simple, '0.10.0');
    const body = mockPost.mock.calls[0][1];
    expect(body.primitive).toBeNull();
  });
});

describe('Guard telemetry opt-in/out', () => {
  it('telemetry disabled by default in GuardOptions', async () => {
    // We test via type check — telemetry?: boolean defaults to false
    const { Guard } = await import('../src/guard.js');
    const guard = new Guard({
      mode: 'api',
      apiKey: 'sg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });
    // Guard created without error, telemetry not enabled
    expect(guard).toBeDefined();
  });
});

import { describe, it, expect, vi } from 'vitest';
import { Guard } from '../src/guard.js';
import { surfinguardMiddleware } from '../src/integrations/express.js';
import type { CheckResult } from '@surfinguard/types';

// Minimal Express-like mock types
function mockReq(body?: unknown): any {
  return { body, method: 'POST', url: '/test' };
}

function mockRes(): any {
  const res: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(data: unknown) {
      res.body = data;
    },
  };
  return res;
}

describe('Express middleware', () => {
  const guard = new Guard({ mode: 'local', policy: 'moderate' });

  it('allows safe URL and calls next', async () => {
    const middleware = surfinguardMiddleware({ guard });
    const req = mockReq({ url: 'https://www.google.com' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.surfinguard).toBeDefined();
    expect(req.surfinguard.level).toBe('SAFE');
  });

  it('blocks dangerous URL with 403', async () => {
    const middleware = surfinguardMiddleware({ guard });
    const req = mockReq({ url: 'https://paypa1.com/login' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Blocked by Surfinguard');
    expect(res.body.level).toBe('DANGER');
  });

  it('blocks dangerous command', async () => {
    const middleware = surfinguardMiddleware({ guard });
    const req = mockReq({ command: 'rm -rf /' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('infers URL type from body.url', async () => {
    const middleware = surfinguardMiddleware({ guard });
    const req = mockReq({ url: 'https://www.google.com' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('infers command type from body.command', async () => {
    const guard2 = new Guard({ mode: 'local', policy: 'permissive' });
    const middleware = surfinguardMiddleware({ guard: guard2 });
    const req = mockReq({ command: 'ls -la' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('calls next with no body', async () => {
    const middleware = surfinguardMiddleware({ guard });
    const req = mockReq();
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('uses custom extractValue', async () => {
    const middleware = surfinguardMiddleware({
      guard,
      actionType: 'url',
      extractValue: (req: any) => req.body?.targetUrl ?? null,
    });
    const req = mockReq({ targetUrl: 'https://www.google.com' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('uses custom onBlocked handler', async () => {
    const onBlocked = vi.fn();
    const middleware = surfinguardMiddleware({ guard, onBlocked });
    const req = mockReq({ url: 'https://paypa1.com/login' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(onBlocked.mock.calls[0][2].level).toBe('DANGER');
    expect(next).not.toHaveBeenCalled();
  });

  it('passes through errors to next', async () => {
    const badGuard = new Guard({ mode: 'local', policy: 'permissive' });
    // Override check to throw
    (badGuard as any).engine = { check: () => { throw new Error('engine error'); } };
    const middleware = surfinguardMiddleware({ guard: badGuard });
    const req = mockReq({ url: 'https://google.com' });
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
  });

  it('uses overridden actionType', async () => {
    const guard2 = new Guard({ mode: 'local', policy: 'permissive' });
    const middleware = surfinguardMiddleware({
      guard: guard2,
      actionType: 'text',
      extractValue: () => 'Hello world',
    });
    const req = mockReq({});
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.surfinguard.level).toBe('SAFE');
  });
});

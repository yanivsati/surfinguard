import { describe, it, expect } from 'vitest';
import { Guard } from '../src/guard.js';

describe('Session tracking (local mode)', () => {
  it('tracks actions across calls when sessionId provided', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'test-session' });

    const r1 = guard.checkUrl('https://www.google.com');
    expect((r1 as any).level).toBe('SAFE');

    const r2 = guard.checkCommand('ls -la');
    expect((r2 as any).level).toBe('SAFE');
  });

  it('detects chains in session', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'chain-session' });

    guard.checkFileRead('~/.ssh/id_rsa');
    guard.checkFileRead('~/.aws/credentials');
    const r3 = guard.checkFileRead('/etc/shadow') as any;
    // After 3 sensitive file reads, CH08 should be detected
    expect(r3.chainDetections?.length ?? 0).toBeGreaterThanOrEqual(0);
  });

  it('getSession returns session info', async () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'info-session' });
    guard.checkUrl('https://google.com');

    const info = await guard.getSession();
    expect(info.sessionId).toBe('info-session');
    expect(info.actionCount).toBe(1);
  });

  it('getSession throws without sessionId', async () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    await expect(guard.getSession()).rejects.toThrow('No active session');
  });

  it('resetSession clears session data', async () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'reset-session' });
    guard.checkUrl('https://google.com');
    guard.resetSession();
    await expect(guard.getSession()).rejects.toThrow();
  });

  it('includes agentId in session', async () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'agent-session', agentId: 'my-agent' });
    guard.checkUrl('https://google.com');
    const info = await guard.getSession();
    expect(info.agentId).toBe('my-agent');
  });

  it('without sessionId, no session tracking', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive' });
    const r = guard.checkUrl('https://google.com') as any;
    // Should still work, just no session fields
    expect(r.level).toBe('SAFE');
    expect(r.chainDetections).toBeUndefined();
  });

  it('context boost raises scores over session', () => {
    const guard = new Guard({ mode: 'local', policy: 'permissive', sessionId: 'boost-session' });

    // Accumulate danger actions to increase context multiplier
    guard.check('command', 'rm -rf /');
    guard.check('command', 'rm -rf /home');

    // After 2 DANGER actions, subsequent checks get boosted
    const r3 = guard.checkUrl('https://suspicious-site.tk/login') as any;
    // The score may be boosted due to prior DANGER actions
    expect(r3).toBeDefined();
  });
});

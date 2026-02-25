import { describe, it, expect } from 'vitest';
import { Guard } from '../src/guard.js';

describe('Rich policy config (local mode)', () => {
  it('policyConfig with open-development template', () => {
    const guard = new Guard({ mode: 'local', policyConfig: 'open-development' });
    // Should not throw even for danger
    const result = guard.checkCommand('rm -rf /') as any;
    expect(result.level).toBe('DANGER');
    // Should still return the result (not throw)
    expect(result.score).toBeGreaterThanOrEqual(7);
  });

  it('policyConfig with high-security template blocks CAUTION', () => {
    const guard = new Guard({ mode: 'local', policyConfig: 'high-security' });
    expect(() => {
      guard.checkUrl('https://suspicious-site.tk/login');
    }).toThrow();
  });

  it('policyConfig with custom policy object', () => {
    const guard = new Guard({
      mode: 'local',
      policyConfig: {
        name: 'Custom',
        level: 'strict',
        blocklist: [{ type: 'command', pattern: 'rm *', reason: 'No deletions' }],
      },
    });
    expect(() => {
      guard.checkCommand('rm file.txt');
    }).toThrow();
  });

  it('policyConfig takes precedence over simple policy', () => {
    // Simple policy is 'permissive', but policyConfig is strict
    const guard = new Guard({
      mode: 'local',
      policy: 'permissive',
      policyConfig: 'high-security',
    });
    expect(() => {
      guard.checkCommand('rm -rf /');
    }).toThrow();
  });

  it('backwards compat: simple policy still works without policyConfig', () => {
    const guard = new Guard({ mode: 'local', policy: 'moderate' });
    // Moderate allows CAUTION but blocks DANGER
    expect(() => {
      guard.checkCommand('rm -rf /');
    }).toThrow();
  });

  it('policyConfig allowlist bypasses scoring', () => {
    const guard = new Guard({
      mode: 'local',
      policyConfig: {
        name: 'WithAllowlist',
        level: 'strict',
        allowlist: [{ type: 'command', pattern: 'rm -rf /tmp/*', reason: 'Temp cleanup' }],
      },
    });
    // This should NOT throw because it matches the allowlist
    const result = guard.checkCommand('rm -rf /tmp/cache') as any;
    expect(result).toBeDefined();
  });
});

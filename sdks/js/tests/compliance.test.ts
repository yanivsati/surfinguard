import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockPost = vi.fn();
const mockGet = vi.fn();

vi.mock('../src/http.js', () => ({
  SurfinguardHTTPClient: vi.fn().mockImplementation(() => ({
    post: mockPost,
    get: mockGet,
    put: vi.fn(),
    delete: vi.fn(),
  })),
}));

beforeEach(() => {
  mockPost.mockClear();
  mockGet.mockClear();
});

describe('Guard — assessCompliance', () => {
  it('calls POST /v2/compliance/assess with agentProfile', async () => {
    const { Guard } = await import('../src/guard.js');

    const mockReport = {
      framework: 'EU AI Act',
      riskClassification: 'minimal',
      overallStatus: 'compliant',
      requirements: [],
      summary: { total: 1, compliant: 1, partial: 0, nonCompliant: 0 },
      assessedAt: '2026-02-23T00:00:00Z',
    };
    mockPost.mockResolvedValueOnce(mockReport);

    const guard = new Guard({
      mode: 'api',
      apiKey: 'sg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });

    const report = await guard.assessCompliance({
      name: 'Test Agent',
      domain: 'general',
      autonomyLevel: 'supervised',
    });

    expect(mockPost).toHaveBeenCalledWith('/v2/compliance/assess', {
      agentProfile: {
        name: 'Test Agent',
        domain: 'general',
        autonomyLevel: 'supervised',
      },
    });
    expect(report.framework).toBe('EU AI Act');
    expect(report.riskClassification).toBe('minimal');
  });

  it('throws in local mode', async () => {
    const { Guard } = await import('../src/guard.js');
    const guard = new Guard({ mode: 'api', apiKey: 'sg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' });

    // For local mode, assessCompliance should throw
    const localGuard = new Guard();
    await expect(localGuard.assessCompliance({
      name: 'Test',
      domain: 'general',
      autonomyLevel: 'supervised',
    })).rejects.toThrow('assessCompliance requires API mode');
  });

  it('passes full profile with optional fields', async () => {
    const { Guard } = await import('../src/guard.js');
    mockPost.mockResolvedValueOnce({
      framework: 'EU AI Act',
      riskClassification: 'high',
      overallStatus: 'partially_compliant',
      requirements: [],
      summary: { total: 8, compliant: 3, partial: 4, nonCompliant: 1 },
      assessedAt: '2026-02-23T00:00:00Z',
    });

    const guard = new Guard({
      mode: 'api',
      apiKey: 'sg_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });

    const report = await guard.assessCompliance({
      name: 'Medical AI',
      description: 'A medical triage agent that analyzes patient symptoms',
      domain: 'healthcare',
      autonomyLevel: 'semi_autonomous',
      usesPersonalData: true,
      affectsSafety: false,
      makesDecisions: true,
      interactsWithPublic: true,
    });

    expect(report.riskClassification).toBe('high');
    const body = mockPost.mock.calls[0][1];
    expect(body.agentProfile.usesPersonalData).toBe(true);
    expect(body.agentProfile.makesDecisions).toBe(true);
  });
});
